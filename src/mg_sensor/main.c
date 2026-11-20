/*
 * mg_sensor - Sensor Service (critical, priority 55, core 2)
 *
 * Industrial machine-condition monitoring. All sensors are Wi-Fi nodes that
 * send UDP frames to port 5005:
 *     $ND,<id>,<seq>,<KIND>,<v1>,...,<vn>,<rssi>,<flags>*<XOR checksum>
 *   VIB (node 1, every 0.5 s): vel, vel x, vel y, vel z (mm/s RMS),
 *       acc rms, acc peak (g), freq (Hz), chip temp (C), zone (0..3 = A..D),
 *       running (0/1), mount tilt since start (deg); flags bit0 = MPU read
 *       failed, bit1 = samples lost
 *   ENV (node 2, every 0.5 s): temp (C), humidity (% or -1 on a BMP280),
 *       pressure (hPa); flags bit0 = read failed, bit1 = no humidity sensor
 *
 * Threads
 *   main  (55) : 100 Hz timer-driven loop - node liveness, health summary,
 *                machine condition (ISO 10816-3 zones), environment limits,
 *                publishes to shared memory, counts deadline misses
 *   link  (54) : talks to the Device Manager with kernel timeouts, so a
 *                hung/crashed Device Manager can never stall the 100 Hz loop
 *   udp   (53) : receives the frames, checks checksum, sequence (loss /
 *                duplicate / reorder / node reboot) and values, and relays
 *                every checked frame to the HDMI dashboard (UDP 5006)
 *
 * Invalid data does not propagate: a value outside its physical range, a
 * zone that does not match the velocity, or an impossible jump is counted,
 * dropped, and marks the node DEGRADED / FAULT. Only OK or DEGRADED nodes
 * feed the machine state sent to the Device Manager.
 *
 * Machine logic on the vibration node (zone limits MG_ZONE_AB/BC/CD)
 *   zone C                               -> VIB-ALERT warning
 *   zone D for 2 consecutive frames      -> VIBRATION_DANGER event (the
 *                                           Device Manager trips the machine);
 *                                           re-armed after 10 s in zone A/B
 *   mount tilt >= MG_MOUNT_DEG (10) for  -> SENSOR_MOUNT_LOOSE event (tilt only
 *     3 s at rest (acc < 0.5 g)             counts at rest: shaking moves the mean)
 *   gravity jump > 30 deg at rest        -> MPU FIFO axis slip: frame dropped,
 *                                           node stays OK (logged once per slip)
 *   environment >= MG_TEMP_WARN (40 C)   -> ENV-TEMP warning
 *   environment >= MG_TEMP_MAX (50 C) x2 -> OVER_TEMPERATURE event
 *
 * Adding nodes: any node id with a valid frame is registered automatically
 * (up to MG_MAX_NODES); MG_NODES lists the ids that MUST be present (default
 * "1"). A new KIND gets the generic check; give it its own rules with one
 * check function and one line in KINDS[].
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include "mg_common.h"
#include "mg_proto.h"

#define CKPT_NAME     "sensor"
#define SENSOR_CKPT_V 5
#define MAX_PENDING   8

typedef struct { uint32_t id, last_seq, valid; } seq_ck_t;

typedef struct {
    uint32_t   version;
    uint32_t   boot_count;
    uint32_t   next_event_id;
    uint32_t   danger_latched;     /* zone D event sent, waiting for A/B     */
    uint32_t   mount_latched;
    uint32_t   temp_latched;
    seq_ck_t   seq[MG_MAX_NODES];  /* per-node sequence numbers              */
    uint32_t   fault_count;
    uint32_t   pending_count;
    mg_event_t pending[MAX_PENDING];
} sensor_ckpt_t;

/* ---------------- shared state ---------------- */
static mg_shm_t       *S;
static sensor_ckpt_t   C;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv;
static uint64_t        g_ckpt_counter;
static bool            g_ckpt_dirty;
static uint64_t        g_ckpt_last_ms;
static int             g_restore_status;

/* ---------------- link state message (main -> link thread) ---------------- */
static mg_dm_state_msg_t g_state;
static bool              g_state_changed;

/* ================================================================== */
/* Checkpoint                                                          */
/* ================================================================== */
static void ckpt_save_locked(const char *why)
{
    if (mg_ckpt_save(CKPT_NAME, &C, sizeof C, &g_ckpt_counter) == 0) {
        g_ckpt_dirty = false;
        g_ckpt_last_ms = mg_now_ms();
        S->sensor.ckpt_saved_counter = g_ckpt_counter;
        S->ck[MG_SVC_SENSOR].saved_counter = g_ckpt_counter;
    } else {
        mg_log(MG_WARN, "checkpoint save failed (%s): %s", why, strerror(errno));
    }
}

static void ckpt_restore(void)
{
    mg_ckpt_result_t res;
    uint64_t expected = S->sensor.ckpt_saved_counter;
    memset(&C, 0, sizeof C);
    if (mg_ckpt_load(CKPT_NAME, &C, sizeof C, expected, &res) == 0 && C.version == SENSOR_CKPT_V) {
        g_restore_status = res.status;
        /* continue from the RESTORED counter: the next save then lands in the
           other slot and overwrites the damaged/missing newest copy, keeping
           the good one as backup */
        g_ckpt_counter = res.counter;
        mg_log(res.status == MG_CK_NEWEST ? MG_INFO : MG_WARN, "checkpoint: %s", res.detail);
        S->sensor.restore_counter = (int64_t)res.counter;
    } else {
        memset(&C, 0, sizeof C);
        C.version = SENSOR_CKPT_V;
        g_restore_status = MG_CK_NONE;
        g_ckpt_counter = expected;
        S->sensor.restore_counter = -1;
        mg_log(expected ? MG_WARN : MG_INFO, "checkpoint: %s -> safe-init (alarm latches re-armed)",
               expected ? res.detail : "first start");
    }
    /* event ids must never be reused, even without a checkpoint: the Device
       Manager de-duplicates by id and would drop a real alarm as a duplicate.
       Shared memory (owned by the supervisor) still holds the last id used. */
    uint32_t floor_id = S->sensor.last_event_id > S->dm.highest_event_id ? S->sensor.last_event_id
                                                                          : S->dm.highest_event_id;
    if (C.next_event_id <= floor_id) C.next_event_id = floor_id + 1;
    if (C.next_event_id == 0) C.next_event_id = 1;
    C.boot_count++;
    S->sensor.restore_status = g_restore_status;
    S->ck[MG_SVC_SENSOR].restore_status = g_restore_status;
    S->ck[MG_SVC_SENSOR].restore_counter = S->sensor.restore_counter;
    S->ck[MG_SVC_SENSOR].restore_slot = g_restore_status == MG_CK_NONE ? '-' : res.slot;
    ckpt_save_locked("boot");
}

/* ================================================================== */
/* Node registry                                                       */
/* ================================================================== */
struct node_s;
typedef void (*check_fn)(struct node_s *n, uint64_t now);

typedef struct {
    const char *kind;        /* matches the KIND field of the frame */
    uint32_t    min_vals;    /* fewer values than this = invalid frame */
    const char *values;      /* what the values mean (shown by mgctl) */
    check_fn    check;       /* plausibility / fault rules for this kind */
} kind_t;

typedef struct node_s {
    mg_node_pub_t p;         /* what gets published                   */
    const kind_t *k;
    uint32_t samples;        /* accepted samples (main loop watches it) */
    int      good, bad;      /* consecutive good / bad samples        */
    /* per-kind state */
    float    prev[MG_NODE_MAX_VALS];
    int      same, lost_run;
    bool     have_prev;
    int      slip_n, mount_n;         /* frames dropped in the current axis slip   */
    uint32_t slips;          /* axis slips seen (each = one log line)     */
} node_t;

static float g_zone_ab = MG_ZONE_AB_DEFAULT, g_zone_bc = MG_ZONE_BC_DEFAULT, g_zone_cd = MG_ZONE_CD_DEFAULT;
static float g_mount_deg = 10.0f;
static uint32_t g_slips;
/* below this acceleration the 0.5 s mean of the samples is gravity, so the tilt is real;
   above it (shaking) the tilt the node reports is meaningless */
#define STILL_G       0.5f
#define SLIP_DEG      30.0f   /* gravity direction cannot jump this far in 0.5 s at rest  */
#define SLIP_MAX      20      /* still turned after 10 s: a real move, accept it          */
#define MOUNT_FRAMES  6       /* tilt past the limit for 3 s at rest = mount moved        */
#define REARM_FRAMES  20      /* zone A/B for 10 s before a new VIBRATION_DANGER alarm    */

static uint32_t zone_of(float vel)
{
    return vel < g_zone_ab ? 0u : vel < g_zone_bc ? 1u : vel < g_zone_cd ? 2u : 3u;
}

/* A limit from the environment: must be a plain number inside [lo, hi], else the default is
   used and the operator is told (a typo such as MG_TEMP_WARN="room+4" used to become 0 C,
   which kept the temperature warning on all the time). */
static float env_limit(const char *name, float def, float lo, float hi)
{
    const char *s = getenv(name);
    if (!s || !*s) return def;
    char *end = NULL;
    float v = strtof(s, &end);
    while (end && (*end == ' ' || *end == '\t')) end++;
    if (end == s || (end && *end) || !isfinite(v) || v < lo || v > hi) {
        mg_evlog(MG_SVC_SENSOR, MG_WARN, "%s=\"%.20s\" is not a number in %g..%g: using %g", name, s, lo, hi, def);
        return def;
    }
    return v;
}

static node_t   g_nodes[MG_MAX_NODES];
static uint32_t g_unknown_frames, g_relayed;
static bool     g_table_full_logged;

static const char *hstr(uint32_t h) { return mg_health_name(h); }

/* g_mtx held */
static void node_set(node_t *n, uint32_t h, const char *why)
{
    if (n->p.health != h) {
        if (h == MG_H_FAULT || h == MG_H_OFFLINE) {
            C.fault_count++;
            g_ckpt_dirty = true;
            mg_evlog(MG_SVC_SENSOR, MG_WARN, "node %u %s: %s", n->p.id, hstr(h), why);
            mg_trace("MG SENSOR NODE %u %s %s", n->p.id, hstr(h), why);
        } else if (h == MG_H_OK && n->p.health != MG_H_UNVERIFIED) {
            mg_evlog(MG_SVC_SENSOR, MG_INFO, "node %u OK again (was %s)", n->p.id, hstr(n->p.health));
        } else if (h == MG_H_OK) {
            mg_evlog(MG_SVC_SENSOR, MG_INFO, "node %u (%s) verified OK", n->p.id, n->p.kind);
        }
    }
    n->p.health = h;
    snprintf(n->p.reason, sizeof n->p.reason, "%s", why);
}

static void bad_value(node_t *n, const char *why)
{
    n->p.st.invalid++;
    n->good = 0;
    if (++n->bad >= 6) node_set(n, MG_H_FAULT, why);
    else if (n->bad >= 2) node_set(n, MG_H_DEGRADED, why);
}

static bool in(float v, float lo, float hi) { return isfinite(v) && v >= lo && v <= hi; }

/* ---- kind: VIB (machine vibration, node1.ino 3.0) ----
   vel vx vy vz (mm/s) | acc_rms acc_peak (g) | freq (Hz) | temp (C) | zone | running | tilt (deg) */
static void check_vib(node_t *n, uint64_t now)
{
    (void)now;
    const float *v = n->p.v;
    if (n->p.flags & 1u) { n->good = 0; node_set(n, MG_H_FAULT, "MPU READ FAILED"); return; }
    /* +-8 g at 10 Hz is ~1250 mm/s: anything above 2000 mm/s cannot come from this sensor.
       acc rms/peak are the 3-axis magnitude after the 10 Hz high-pass: a +-8 g step per axis
       can swing 16 g, so the magnitude can reach ~28 g in hard shaking (32 = limit) */
    bool ok = in(v[0], 0, 2000) && in(v[1], 0, 2000) && in(v[2], 0, 2000) && in(v[3], 0, 2000) &&
              in(v[4], 0, 32) && in(v[5], 0, 32) && v[5] + 0.01f >= v[4] && in(v[6], 0, 500) &&
              in(v[7], -40, 100) && in(v[8], 0, 3) && v[8] == floorf(v[8]) &&
              (v[9] == 0.0f || v[9] == 1.0f) && in(v[10], 0, 180);
    if (!ok) { bad_value(n, "VALUES OUT OF RANGE"); return; }
    /* cross-check: the zone the node reports must match its own velocity,
       unless the velocity sits right on a zone limit */
    uint32_t z = zone_of(v[0]);
    float lims[3] = { g_zone_ab, g_zone_bc, g_zone_cd };
    bool near_limit = false;
    for (int k = 0; k < 3; k++) if (fabsf(v[0] - lims[k]) < 0.05f) near_limit = true;
    if ((uint32_t)v[8] != z && !near_limit) { bad_value(n, "ZONE/VELOCITY MISMATCH"); return; }
    /* MPU6050 FIFO axis slip: the FIFO read loses 2 bytes, the axes rotate (x->y->z), the
       gravity direction jumps ~90 deg with no shaking and the node's 10 Hz high-pass turns the
       1 g step into a fake ~15 mm/s zone D frame. Drop those frames (counted as invalid, so they
       never reach the machine logic) without degrading the node: the sensor is fine. */
    if (n->have_prev && v[4] < STILL_G && n->prev[4] < STILL_G) {
        bool turned = fabsf(v[10] - n->prev[10]) > SLIP_DEG;
        if (turned && n->slip_n < SLIP_MAX) {
            if (n->slip_n++ == 0) {
                n->slips++; g_slips++;
                mg_evlog(MG_SVC_SENSOR, MG_WARN, "node %u: axis-slip frame dropped (tilt %.1f -> %.1f deg at rest, %.1f mm/s)",
                         n->p.id, n->prev[10], v[10], v[0]);
            }
            n->p.st.invalid++;
            return;
        }
        if (!turned && n->slip_n > 0 && n->slip_n < SLIP_MAX) {   /* slipped back: this frame holds the step */
            n->slip_n = 0;
            n->p.st.invalid++;
            return;
        }
        if (turned) mg_evlog(MG_SVC_SENSOR, MG_WARN, "node %u: tilt %.1f deg for %d s at rest: accepted as a real move",
                             n->p.id, v[10], SLIP_MAX / 2);
    }
    n->slip_n = 0;
    n->bad = 0;
    /* a real accelerometer always has some noise: 20 identical frames (10 s) = frozen */
    n->same = n->have_prev && memcmp(v, n->prev, 11 * sizeof(float)) == 0 ? n->same + 1 : 0;
    memcpy(n->prev, v, 11 * sizeof(float));
    n->have_prev = true;
    if (n->same >= 20) { n->good = 0; node_set(n, MG_H_FAULT, "FROZEN OUTPUT"); return; }
    /* samples lost in the node's FIFO: one is noise, three in a row is a problem */
    n->lost_run = (n->p.flags & 2u) ? n->lost_run + 1 : 0;
    if (n->lost_run >= 3) { n->good = 0; node_set(n, MG_H_DEGRADED, "SAMPLES LOST"); return; }
    /* mount: only at rest (the tilt is the gravity direction) and only after 3 s */
    if (v[4] < STILL_G) n->mount_n = v[10] >= g_mount_deg ? n->mount_n + 1 : 0;
    if (n->mount_n >= MOUNT_FRAMES) { n->good = 0; node_set(n, MG_H_DEGRADED, "SENSOR MOUNT MOVED"); return; }
    if (n->good < 1000) n->good++;
    if (n->good >= 3) node_set(n, MG_H_OK, "");                /* 1.5 s of good data */
}

/* ---- kind: ENV (BME280 / BMP280): temp (C), humidity (% or -1), pressure (hPa) ---- */
static void check_env(node_t *n, uint64_t now)
{
    (void)now;
    const float *v = n->p.v;
    if (n->p.flags & 1u) { n->good = 0; node_set(n, MG_H_FAULT, "SENSOR READ FAILED"); return; }
    bool no_hum = (n->p.flags & 2u) != 0;            /* BMP280: not a fault */
    bool ok = in(v[0], -40, 85) && in(v[2], 300, 1100) && (no_hum ? v[1] == -1.0f : in(v[1], 0, 100));
    if (!ok) { bad_value(n, "VALUES OUT OF RANGE"); return; }
    /* physically impossible jumps between two frames 0.5 s apart */
    if (n->have_prev && (fabsf(v[0] - n->prev[0]) > 5.0f || fabsf(v[2] - n->prev[2]) > 10.0f)) {
        n->prev[0] = v[0];
        n->prev[2] = v[2];
        bad_value(n, "IMPOSSIBLE JUMP");
        return;
    }
    memcpy(n->prev, v, 3 * sizeof(float));
    n->have_prev = true;
    n->bad = 0;
    if (n->good < 1000) n->good++;
    if (n->good >= 3) node_set(n, MG_H_OK, "");
}

/* ---- any other kind: fault flag + finite values ---- */
static void check_generic(node_t *n, uint64_t now)
{
    (void)now;
    if (n->p.flags & 1u) { n->good = 0; node_set(n, MG_H_FAULT, "NODE REPORTS FAULT"); return; }
    for (uint32_t i = 0; i < n->p.nvals; i++) {
        if (!isfinite(n->p.v[i])) {
            n->p.st.invalid++;
            n->good = 0;
            if (++n->bad >= 3) node_set(n, MG_H_FAULT, "INVALID VALUES");
            return;
        }
    }
    n->bad = 0;
    if (n->good < 1000) n->good++;
    if (n->good >= 5) node_set(n, MG_H_OK, "");
}

/* One line per sensor type. New kinds work without a line here (generic check). */
static const kind_t KINDS[] = {
    { "VIB", 11, "vel vx vy vz (mm/s) acc_rms acc_peak (g) freq (Hz) temp (C) zone running tilt", check_vib },
    { "ENV", 3,  "temp (C) humidity (%, -1 = none) pressure (hPa)", check_env },
};
static const kind_t GENERIC = { "", 0, "values", check_generic };

static const kind_t *kind_lookup(const char *kind)
{
    for (size_t k = 0; k < sizeof KINDS / sizeof KINDS[0]; k++)
        if (strcmp(KINDS[k].kind, kind) == 0) return &KINDS[k];
    return &GENERIC;
}

/* g_mtx held */
static seq_ck_t *seq_slot(uint32_t id, bool create)
{
    for (int k = 0; k < MG_MAX_NODES; k++) if (C.seq[k].valid && C.seq[k].id == id) return &C.seq[k];
    if (!create) return NULL;
    for (int k = 0; k < MG_MAX_NODES; k++) if (!C.seq[k].valid) { C.seq[k].id = id; return &C.seq[k]; }
    return NULL;
}

/* g_mtx held */
static node_t *node_find(uint32_t id, bool create)
{
    for (int k = 0; k < MG_MAX_NODES; k++) if (g_nodes[k].p.used && g_nodes[k].p.id == id) return &g_nodes[k];
    if (!create) return NULL;
    for (int k = 0; k < MG_MAX_NODES; k++) {
        node_t *n = &g_nodes[k];
        if (n->p.used) continue;
        memset(n, 0, sizeof *n);
        n->p.used = 1;
        n->p.id = id;
        n->p.health = MG_H_UNVERIFIED;
        snprintf(n->p.reason, sizeof n->p.reason, "WAITING");
        return n;
    }
    if (!g_table_full_logged) {
        g_table_full_logged = true;
        mg_evlog(MG_SVC_SENSOR, MG_WARN, "node table full (%d nodes): ignoring node %u", MG_MAX_NODES, id);
    }
    return NULL;
}

/* "1,2,5" -> those nodes are expected (registered at boot, shown as WAITING) */
static void register_expected(void)
{
    const char *list = mg_env("MG_NODES", "1");
    char buf[128];
    snprintf(buf, sizeof buf, "%s", list);
    char *save = NULL;
    for (char *t = strtok_r(buf, ", ", &save); t; t = strtok_r(NULL, ", ", &save)) {
        char *end;
        unsigned long id = strtoul(t, &end, 10);
        if (*end || id > 65535) { mg_log(MG_WARN, "MG_NODES: ignoring '%s'", t); continue; }
        node_t *n = node_find((uint32_t)id, true);
        if (n) n->p.expected = 1;
    }
}

/* All samples, from Wi-Fi or go through here. */
static void node_ingest(uint32_t id, uint32_t seq, const char *kind, const float *vals, uint32_t nv,
                        int32_t rssi, uint32_t flags, const char *src, uint64_t now)
{
    pthread_mutex_lock(&g_mtx);
    node_t *n = node_find(id, true);
    if (!n) { g_unknown_frames++; pthread_mutex_unlock(&g_mtx); return; }
    if (n->samples == 0 && !n->p.expected && n->p.st.rx == 0)
        mg_evlog(MG_SVC_SENSOR, MG_INFO, "new node %u discovered (%s from %s)", id, kind, src);

    /* sequence: duplicate / reordered / lost / node reboot */
    seq_ck_t *sc = seq_slot(id, true);
    if (sc && sc->valid) {
        uint32_t last = sc->last_seq;
        if (seq == last) { n->p.st.dup++; pthread_mutex_unlock(&g_mtx); return; }
        if (seq < last) {
            if (seq < 5 || last - seq > 1000) {
                n->p.st.reboots++;
                mg_evlog(MG_SVC_SENSOR, MG_WARN, "node %u restarted (seq %u -> %u)", id, last, seq);
            } else {
                n->p.st.out_of_order++;
                pthread_mutex_unlock(&g_mtx);
                return;
            }
        } else if (seq > last + 1) {
            n->p.st.lost += seq - last - 1;
        }
    }
    if (sc) { sc->last_seq = seq; sc->valid = 1; g_ckpt_dirty = true; }

    /* kind binding */
    if (!n->k || strcmp(n->p.kind, kind) != 0) {
        if (n->k) mg_evlog(MG_SVC_SENSOR, MG_WARN, "node %u changed kind %s -> %s", id, n->p.kind, kind);
        n->k = kind_lookup(kind);
        snprintf(n->p.kind, sizeof n->p.kind, "%s", kind);
        n->good = n->bad = n->same = n->lost_run = n->slip_n = n->mount_n = 0;
        n->have_prev = false;
    }
    n->p.st.rx++;
    n->p.st.last_rx_ms = now;
    n->p.st.last_seq = seq;
    n->p.rssi_dbm = rssi;
    n->p.flags = flags;
    snprintf(n->p.src, sizeof n->p.src, "%s", src);
    if (nv < n->k->min_vals) {
        n->p.st.invalid++;
        n->good = 0;
        if (++n->bad >= 3) node_set(n, MG_H_FAULT, "TOO FEW VALUES");
        pthread_mutex_unlock(&g_mtx);
        return;
    }
    /* check the new values in place, but keep the last good ones: a frame the
       checks reject must never reach the machine logic or the controller */
    float keep_v[MG_NODE_MAX_VALS];
    uint32_t keep_n = n->p.nvals, inv0 = n->p.st.invalid;
    memcpy(keep_v, n->p.v, sizeof keep_v);
    memcpy(n->p.v, vals, nv * sizeof(float));
    n->p.nvals = nv;
    n->k->check(n, now);
    if (n->p.st.invalid != inv0) {
        memcpy(n->p.v, keep_v, sizeof keep_v);
        n->p.nvals = keep_n;
    } else {
        n->samples++;
    }
    pthread_mutex_unlock(&g_mtx);
}

/* ================================================================== */
/* UDP: parse, validate, relay                                         */
/* ================================================================== */
static bool parse_u32(const char *s, uint32_t *out)
{
    if (!*s) return false;
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (*end || errno || v > 0xFFFFFFFFul) return false;
    *out = (uint32_t)v;
    return true;
}

static bool parse_f(const char *s, float *out)
{
    if (!*s) return false;
    char *end;
    float v = strtof(s, &end);
    if (*end) return false;
    *out = v;
    return true;
}

static int  g_relay = -1;
static struct sockaddr_in g_relay_addr;

static void relay_open(void)
{
    int port = atoi(mg_env("MG_RELAY_PORT", "5006"));
    const char *host = mg_env("MG_RELAY_HOST", "127.0.0.1");
    S->sensor.relay_port = 0;
    if (port <= 0 || port > 65535 || port == MG_UDP_NODE_PORT) return;
    memset(&g_relay_addr, 0, sizeof g_relay_addr);
    g_relay_addr.sin_family = AF_INET;
    g_relay_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &g_relay_addr.sin_addr) != 1) {
        mg_log(MG_WARN, "MG_RELAY_HOST '%s' is not an IPv4 address - relay off", host);
        return;
    }
    g_relay = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_relay < 0) return;
    S->sensor.relay_port = (uint32_t)port;
    mg_log(MG_INFO, "relaying node frames to %s:%d (start the dashboard with --udp-port %d)", host, port, port);
}

static void handle_packet(char *buf, size_t len, const char *src, uint64_t now)
{
    while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ')) buf[--len] = 0;
    char *star = strrchr(buf, '*');
    if (len < 8 || buf[0] != '$' || !star || strlen(star) != 3) { g_unknown_frames++; return; }
    uint8_t cs = 0;
    for (char *p = buf + 1; p < star; p++) cs ^= (uint8_t)*p;
    unsigned want = 0x100;
    if (sscanf(star + 1, "%2x", &want) != 1 || want != cs) {
        uint32_t id;
        char idbuf[12] = "";
        sscanf(buf, "$%*[A-Z],%11[0-9]", idbuf);
        pthread_mutex_lock(&g_mtx);
        node_t *n = parse_u32(idbuf, &id) ? node_find(id, false) : NULL;
        if (n) n->p.st.bad_crc++;
        else g_unknown_frames++;
        pthread_mutex_unlock(&g_mtx);
        return;
    }
    /* checksum good: hand a copy to the dashboard, unchanged */
    if (g_relay >= 0 &&
        sendto(g_relay, buf, len, 0, (struct sockaddr *)&g_relay_addr, sizeof g_relay_addr) == (ssize_t)len)
        g_relayed++;

    /* split the body into fields */
    *star = 0;
    char *f[6 + MG_NODE_MAX_VALS];            /* ND,id,seq,KIND + values + rssi,flags */
    int nf = 0;
    char *save = NULL;
    for (char *t = strtok_r(buf + 1, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        if (nf == (int)(sizeof f / sizeof f[0])) { nf = -1; break; }
        f[nf++] = t;
    }
    uint32_t id, seq, flags;
    float vals[MG_NODE_MAX_VALS];
    uint32_t nv = 0;
    float rssi_f = 0;
    char kind[MG_NODE_KIND_LEN];
    bool ok = false;
    if (nf >= 6 && strcmp(f[0], "ND") == 0) {
        /* $ND,id,seq,KIND,v1..vn,rssi,flags */
        size_t kl = strlen(f[3]);
        ok = parse_u32(f[1], &id) && parse_u32(f[2], &seq) && kl >= 1 && kl < MG_NODE_KIND_LEN &&
             parse_f(f[nf - 2], &rssi_f) && parse_u32(f[nf - 1], &flags);
        for (size_t i = 0; ok && i < kl; i++) if (!isalnum((unsigned char)f[3][i])) ok = false;
        if (ok) snprintf(kind, sizeof kind, "%s", f[3]);
        for (int i = 4; ok && i < nf - 2; i++) ok = parse_f(f[i], &vals[nv++]);
    } else if (nf == 6 && strcmp(f[0], "MG") == 0) {
        /* older $MG,node,seq,v1,v2,flags frame */
        ok = parse_u32(f[1], &id) && parse_u32(f[2], &seq) && parse_f(f[3], &vals[0]) &&
             parse_f(f[4], &vals[1]) && parse_u32(f[5], &flags);
        nv = 2;
        snprintf(kind, sizeof kind, "MG");
    }
    /* $ST = the node's Wi-Fi status report (every 5 s): already relayed to the
       dashboard above, it carries no measurement, so it is neither data nor invalid */
    if (nf >= 2 && strcmp(f[0], "ST") == 0) {
        pthread_mutex_lock(&g_mtx);
        node_t *n = parse_u32(f[1], &id) ? node_find(id, false) : NULL;
        if (n) n->p.st.status_frames++;
        pthread_mutex_unlock(&g_mtx);
        return;
    }
    if (!ok || id > 65535) {
        pthread_mutex_lock(&g_mtx);
        node_t *n = (nf >= 2 && parse_u32(f[1], &id)) ? node_find(id, false) : NULL;
        if (n) n->p.st.invalid++;
        else g_unknown_frames++;
        pthread_mutex_unlock(&g_mtx);
        return;
    }
    node_ingest(id, seq, kind, vals, nv, (int32_t)lroundf(rssi_f), flags, src, now);
}

static void *udp_thread(void *arg)
{
    (void)arg;
    struct sched_param sp = { .sched_priority = MG_SVC_INFO[MG_SVC_SENSOR].priority - 2 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1) { mg_log(MG_ERROR, "udp socket: %s", strerror(errno)); return NULL; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(MG_UDP_NODE_PORT);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&a, sizeof a) == -1) {
        mg_log(MG_ERROR, "udp bind %d: %s (is node_dashboard.py still on 5005? start it with --udp-port %d)",
               MG_UDP_NODE_PORT, strerror(errno), MG_UDP_RELAY_PORT);
        return NULL;
    }
    relay_open();
    mg_log(MG_INFO, "listening for nodes on UDP %d", MG_UDP_NODE_PORT);
    char buf[512];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(s, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) {
            /* timeout / interrupted: try again. Any other error (the network
               stack went away, Wi-Fi interface reconfigured): back off, so
               this priority-53 thread can never spin and starve its core */
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) usleep(20000);
            continue;
        }
        buf[n] = 0;
        char src[16] = "?";
        inet_ntop(AF_INET, &from.sin_addr, src, sizeof src);
        handle_packet(buf, (size_t)n, src, mg_now_ms());
    }
    return NULL;
}

/* ================================================================== */
/* Link to the Device Manager (machine controller)                     */
/* ================================================================== */
static int link_send(int coid, void *msg, size_t len, void *reply, size_t rlen)
{
    uint64_t ns = 50ull * 1000000ull;
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &ns, NULL);
    return MsgSend(coid, msg, len, reply, rlen);
}

static int link_sync(int coid)
{
    mg_dm_sync_msg_t m;
    memset(&m, 0, sizeof m);
    m.hdr.type = MG_MSG_DM_SYNC;
    m.hdr.size = sizeof m;
    mg_dm_sync_reply_t r;
    if (link_send(coid, &m, sizeof m, &r, sizeof r) == -1) return -1;
    pthread_mutex_lock(&g_mtx);
    uint32_t keep = 0;
    for (uint32_t k = 0; k < C.pending_count; k++)       /* already persisted by DM */
        if (C.pending[k].id > r.highest_event_id) C.pending[keep++] = C.pending[k];
    C.pending_count = keep;
    if (C.next_event_id <= r.highest_event_id) C.next_event_id = r.highest_event_id + 1;
    g_ckpt_dirty = true;
    pthread_mutex_unlock(&g_mtx);
    return 0;
}

static void *link_thread(void *arg)
{
    (void)arg;
    struct sched_param sp = { .sched_priority = MG_SVC_INFO[MG_SVC_SENSOR].priority - 1 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    int coid = -1;
    uint32_t epoch = 0, seq = 0;
    uint64_t last_state_ms = 0;
    bool warned = false;

    for (;;) {
        pthread_mutex_lock(&g_mtx);
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_nsec += 100 * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        pthread_cond_timedwait(&g_cv, &g_mtx, &ts);
        uint64_t now = mg_now_ms();
        if (g_ckpt_dirty && now - g_ckpt_last_ms >= 500) ckpt_save_locked("periodic");
        pthread_mutex_unlock(&g_mtx);

        uint32_t dm_state = S->reg[MG_SVC_DEVMGR].state;
        uint32_t dm_epoch = S->reg[MG_SVC_DEVMGR].epoch;
        if (coid != -1 && dm_epoch != epoch) {               /* controller was replaced */
            name_close(coid);
            coid = -1;
        }
        if (coid == -1) {
            S->sensor.dm_connected = 0;
            /* reconnect ONLY after the supervisor verified the controller */
            if (dm_state != MG_ST_RUNNING || dm_epoch == 0) continue;
            coid = name_open(MG_SVC_INFO[MG_SVC_DEVMGR].attach_name, 0);
            if (coid == -1) continue;
            if (link_sync(coid) == -1) { name_close(coid); coid = -1; continue; }
            epoch = dm_epoch;
            warned = false;
            S->sensor.dm_connected = 1;
            S->sensor.dm_epoch_connected = epoch;
            mg_log(MG_INFO, "connected to Device Manager (epoch %u)", epoch);
            mg_trace("MG SENSOR RECONNECTED DM epoch %u", epoch);
            mg_pulse_sup(MG_PULSE_RECONNECTED, (int)epoch);
            last_state_ms = 0;
        }

        bool fail = false;
        /* 1. events first (oldest first); remove only when the DM persisted them */
        for (;;) {
            mg_dm_event_msg_t em;
            pthread_mutex_lock(&g_mtx);
            bool have = C.pending_count > 0;
            if (have) em.ev = C.pending[0];
            pthread_mutex_unlock(&g_mtx);
            if (!have) break;
            memset(&em.hdr, 0, sizeof em.hdr);
            em.hdr.type = MG_MSG_DM_EVENT;
            em.hdr.size = sizeof em;
            mg_dm_event_reply_t r;
            if (link_send(coid, &em, sizeof em, &r, sizeof r) == -1) { fail = true; break; }
            pthread_mutex_lock(&g_mtx);
            if (C.pending_count > 0 && C.pending[0].id == em.ev.id) {
                memmove(&C.pending[0], &C.pending[1], (C.pending_count - 1) * sizeof(mg_event_t));
                C.pending_count--;
                g_ckpt_dirty = true;
            }
            pthread_mutex_unlock(&g_mtx);
        }
        /* 2. absolute state: on change or every 100 ms (keep-alive) */
        now = mg_now_ms();
        if (!fail) {
            pthread_mutex_lock(&g_mtx);
            bool due = g_state_changed || now - last_state_ms >= 100;
            mg_dm_state_msg_t m = g_state;
            g_state_changed = false;
            pthread_mutex_unlock(&g_mtx);
            if (due) {
                m.hdr.type = MG_MSG_DM_STATE;
                m.hdr.size = sizeof m;
                m.sender = getpid();
                m.seq = ++seq;
                if (link_send(coid, &m, sizeof m, NULL, 0) == -1) {
                    if (errno == EINVAL) mg_log(MG_WARN, "controller rejected state as invalid");
                    else fail = true;
                } else {
                    last_state_ms = now;
                }
            }
        }
        if (fail) {
            if (!warned) mg_log(MG_WARN, "lost Device Manager (%s) - waiting for supervisor", strerror(errno));
            warned = true;
            name_close(coid);
            coid = -1;
            S->sensor.dm_connected = 0;
        }
    }
    return NULL;
}

/* ================================================================== */
/* Events                                                              */
/* ================================================================== */
static void create_event(uint32_t type, float value, float freq, float aux, uint32_t node_id)
{
    mg_event_t ev;
    memset(&ev, 0, sizeof ev);
    pthread_mutex_lock(&g_mtx);
    ev.id = C.next_event_id++;
    ev.type = type;
    ev.t_wall_ms = mg_wall_ms();
    ev.value = value;
    ev.freq_hz = freq;
    ev.aux = aux;
    ev.node_id = node_id;
    if (C.pending_count == MAX_PENDING) {
        memmove(&C.pending[0], &C.pending[1], (MAX_PENDING - 1) * sizeof(mg_event_t));
        C.pending_count--;
    }
    C.pending[C.pending_count++] = ev;
    ckpt_save_locked("event");                 /* write-ahead: persist before sending */
    pthread_cond_signal(&g_cv);
    pthread_mutex_unlock(&g_mtx);
    S->sensor.events_created++;
    S->sensor.last_event_id = ev.id;
    S->sensor.last_event_type = type;
    mg_trace("MG SENSOR EVENT %u %s", ev.id, mg_event_name(type));
    mg_evlog(MG_SVC_SENSOR, MG_WARN, "EVENT #%u %s from node %u: value %.2f, %.1f Hz, aux %.2f",
             ev.id, mg_event_name(type), node_id, value, freq, aux);
}

/* worst-first order for the health summary */
static int severity(uint32_t h)
{
    switch (h) {
    case MG_H_OK:         return 0;
    case MG_H_UNVERIFIED: return 1;
    case MG_H_DEGRADED:   return 2;
    case MG_H_FAULT:      return 3;
    default:              return 4;    /* OFFLINE */
    }
}

/* ================================================================== */
/* Main loop                                                           */
/* ================================================================== */
int main(void)
{
    const mg_svc_info_t *me = &MG_SVC_INFO[MG_SVC_SENSOR];
    mg_log_init("mg_sensor", MG_SVC_SENSOR);
    mg_set_rt(me->priority, me->cpu);
    S = mg_shm_attach(false);
    if (!S) { mg_log(MG_ERROR, "shared memory not found - start mg_supervisor"); return MG_EXIT_CONFIG; }
    mg_seq_repair(&S->sensor.lock);
    mg_ctl_start(MG_SVC_SENSOR);

    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_cv, &ca);

    pthread_mutex_lock(&g_mtx);
    ckpt_restore();
    register_expected();
    for (int k = 0; k < MG_MAX_NODES; k++)           /* nodes seen before the restart */
        if (C.seq[k].valid) node_find(C.seq[k].id, true);
    pthread_mutex_unlock(&g_mtx);

    const uint64_t node_timeout = (uint64_t)atoi(mg_env("MG_NODE_TIMEOUT_MS", "2000"));
    g_zone_ab = env_limit("MG_ZONE_AB", MG_ZONE_AB_DEFAULT, 0.1f, 100);
    g_zone_bc = env_limit("MG_ZONE_BC", MG_ZONE_BC_DEFAULT, 0.1f, 100);
    g_zone_cd = env_limit("MG_ZONE_CD", MG_ZONE_CD_DEFAULT, 0.1f, 100);
    if (!(g_zone_ab < g_zone_bc && g_zone_bc < g_zone_cd)) {
        mg_evlog(MG_SVC_SENSOR, MG_WARN, "zone limits %.1f/%.1f/%.1f not rising: using the ISO defaults",
                 g_zone_ab, g_zone_bc, g_zone_cd);
        g_zone_ab = MG_ZONE_AB_DEFAULT; g_zone_bc = MG_ZONE_BC_DEFAULT; g_zone_cd = MG_ZONE_CD_DEFAULT;
    }
    g_mount_deg = env_limit("MG_MOUNT_DEG", 10, 1, 90);
    float temp_warn = env_limit("MG_TEMP_WARN", 40, -20, 84);
    float temp_max = env_limit("MG_TEMP_MAX", 50, -19, 85);
    if (!(temp_max > temp_warn)) {
        mg_evlog(MG_SVC_SENSOR, MG_WARN, "MG_TEMP_MAX %.1f must be above MG_TEMP_WARN %.1f: using 40 / 50 C", temp_max, temp_warn);
        temp_warn = 40; temp_max = 50;
    }
    const char *pick = getenv("MG_MACHINE_NODE");    /* force which VIB node is the machine */
    const long machine_forced = pick ? atol(pick) : -1;
    mg_log(MG_INFO, "nodes expected: %s; ISO zones A<%.1f B<%.1f C<%.1f D mm/s; mount %.0f deg; temp warn %.1f max %.1f C",
           mg_env("MG_NODES", "1"), g_zone_ab, g_zone_bc, g_zone_cd, g_mount_deg, temp_warn, temp_max);

    pthread_t t1, t2;
    pthread_create(&t1, NULL, udp_thread, NULL);
    pthread_setname_np(t1, "udp");
    pthread_create(&t2, NULL, link_thread, NULL);
    pthread_setname_np(t2, "dm-link");

    int chid = ChannelCreate(0);
    int coid = ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, me->priority, MG_PULSE_TICK, 0);
    timer_t tid;
    timer_create(CLOCK_MONOTONIC, &ev, &tid);
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = MG_SENSOR_PERIOD_MS * 1000000L;
    its.it_interval.tv_nsec = MG_SENSOR_PERIOD_MS * 1000000L;
    timer_settime(tid, 0, &its, NULL);

    mg_ready(MG_SVC_SENSOR, g_restore_status);

    const uint64_t period_ns = (uint64_t)MG_SENSOR_PERIOD_MS * 1000000ull;
    const uint64_t start_ms = mg_now_ms();
    uint64_t prev_release = 0, cycles = 0;
    uint32_t misses = 0;
    float max_late = 0, max_exec = 0, last_exec = 0;

    /* machine + environment state */
    uint32_t mach_id = 0xFFFFFFFFu, mach_seen = 0, env_id = 0xFFFFFFFFu, env_seen = 0;
    float mv[MG_NODE_MAX_VALS] = { 0 }, ev3[3] = { 0, -1, 0 };
    uint32_t zone = 0, danger_n = 0, mount_n = 0, hot_n = 0, calm_n = 0;
    float peak60 = 0;
    uint64_t peak60_ms = 0;
    uint32_t last_warn = 0xFFFFFFFFu, last_zone = 0xFFFFFFFFu;
    static mg_node_pub_t snap[MG_MAX_NODES];

    for (;;) {
        struct _pulse p;
        if (MsgReceivePulse(chid, &p, sizeof p, NULL) == -1) continue;
        uint64_t release = mg_now_ns();
        uint64_t now = release / 1000000ull;

        /* deadline accounting: the loop must run every 10 ms and finish inside its period */
        if (prev_release) {
            uint64_t interval = release - prev_release;
            if (interval > period_ns) {
                float late = (float)(interval - period_ns) / 1e6f;
                if (late > max_late) max_late = late;
                if (interval >= 2 * period_ns) {
                    misses += (uint32_t)(interval / period_ns) - 1;
                    mg_trace("MG SENSOR DEADLINE MISS %.2f ms late", late);   /* only on a miss: rare */
                }
            }
        }
        prev_release = release;
        cycles++;

        mg_heartbeat(MG_SVC_SENSOR);
        mg_inject_poll(MG_SVC_SENSOR);

        /* ---- liveness, health summary, machine + environment node (one pass under the lock) ---- */
        mg_health_sum_t hs = { 0, 0, MG_H_OK, MG_H_OFFLINE };
        bool lost = false, fault = false;
        bool have_m = false, m_new = false, m_usable = false, have_e = false, e_new = false, e_usable = false;
        uint32_t new_mach = 0xFFFFFFFFu, count = 0;
        pthread_mutex_lock(&g_mtx);
        node_t *bm = NULL, *be = NULL;
        for (int k = 0; k < MG_MAX_NODES; k++) {
            node_t *n = &g_nodes[k];
            if (!n->p.used) continue;
            n->p.st.alive = n->p.st.last_rx_ms && now - n->p.st.last_rx_ms < node_timeout;
            if (!n->p.st.alive && n->p.st.last_rx_ms && n->p.health != MG_H_OFFLINE) {
                n->good = 0;
                node_set(n, MG_H_OFFLINE, "SILENT");
            }
            /* expected nodes always count; an extra node only while it is sending,
               so an extra node that goes silent is shown OFFLINE but does not
               degrade the system (list it in MG_NODES if it must be there) */
            if (n->p.expected || n->p.st.alive) {
                if (n->p.health == MG_H_OFFLINE || (n->p.expected && !n->p.st.last_rx_ms && now - start_ms > 5000))
                    lost = true;
                if (n->p.health == MG_H_FAULT || n->p.health == MG_H_DEGRADED) fault = true;
                hs.nodes++;
                if (n->p.health == MG_H_OK) hs.nodes_ok++;
                if (severity(n->p.health) > severity(hs.worst)) hs.worst = (uint8_t)n->p.health;
            }
            if (strcmp(n->p.kind, "VIB") == 0 && n->p.nvals >= 11 &&
                (machine_forced < 0 ? (!bm || n->p.id < bm->p.id) && n->p.st.alive : (long)n->p.id == machine_forced))
                bm = n;
            if (strcmp(n->p.kind, "ENV") == 0 && n->p.nvals >= 3 && n->p.st.alive && (!be || n->p.id < be->p.id))
                be = n;
            snap[count++] = n->p;
        }
        if (bm) {
            have_m = true;
            new_mach = bm->p.id;
            hs.machine = (uint8_t)bm->p.health;
            /* only verified data drives the machine state (invalid data does not propagate) */
            m_usable = bm->p.st.alive && (bm->p.health == MG_H_OK || bm->p.health == MG_H_DEGRADED);
            m_new = bm->samples != mach_seen || new_mach != mach_id;
            mach_seen = bm->samples;
            memcpy(mv, bm->p.v, sizeof mv);
        }
        if (be) {
            have_e = true;
            e_usable = be->p.health == MG_H_OK || be->p.health == MG_H_DEGRADED;
            e_new = be->samples != env_seen || be->p.id != env_id;
            env_seen = be->samples;
            env_id = be->p.id;
            memcpy(ev3, be->p.v, sizeof ev3);
        } else {
            env_id = 0xFFFFFFFFu;
        }
        if (have_m && new_mach != mach_id) {
            if (mach_id != 0xFFFFFFFFu) mg_evlog(MG_SVC_SENSOR, MG_WARN, "machine vibration node is now %u (was %u)", new_mach, mach_id);
            else mg_log(MG_INFO, "machine vibration node = %u", new_mach);
            mach_id = new_mach;
            danger_n = mount_n = 0;
        }
        uint32_t unknown = g_unknown_frames, relayed = g_relayed;
        bool danger_latched = C.danger_latched, mount_latched = C.mount_latched, temp_latched = C.temp_latched;
        pthread_mutex_unlock(&g_mtx);

        /* ---- machine condition: ISO zones, trip decision, mounting, data recorder ---- */
        if (have_m && m_new && m_usable) {
            zone = zone_of(mv[0]);
            if (mv[0] > peak60 || now - peak60_ms > 60000) { peak60 = mv[0]; peak60_ms = now; }
            uint32_t hd = S->edr.head;            /* ring in shared memory: survives a logger crash */
            S->edr.s[hd % MG_EDR_SAMPLES].t_ms = now;
            S->edr.s[hd % MG_EDR_SAMPLES].vel = mv[0];
            S->edr.s[hd % MG_EDR_SAMPLES].acc_rms = mv[4];
            S->edr.s[hd % MG_EDR_SAMPLES].acc_peak = mv[5];
            S->edr.s[hd % MG_EDR_SAMPLES].freq = mv[6];
            S->edr.s[hd % MG_EDR_SAMPLES].temp = mv[7];
            S->edr.s[hd % MG_EDR_SAMPLES].zone = zone;
            S->edr.head = hd + 1;
            if (zone != last_zone && last_zone != 0xFFFFFFFFu)
                mg_evlog(MG_SVC_SENSOR, zone >= 2 ? MG_WARN : MG_INFO, "machine vibration zone %s -> %s (%.2f mm/s, %.1f Hz)",
                         mg_zone_name(last_zone), mg_zone_name(zone), mv[0], mv[6]);
            last_zone = zone;

            /* zone D must persist for 2 frames (1 s): one spike does not stop a machine */
            danger_n = zone == 3 ? danger_n + 1 : 0;
            calm_n = zone <= 1 ? calm_n + 1 : 0;
            if (danger_n >= 2 && !danger_latched) {
                create_event(MG_EV_VIB_DANGER, mv[0], mv[6], mv[5], mach_id);
                pthread_mutex_lock(&g_mtx); C.danger_latched = 1; g_ckpt_dirty = true; pthread_mutex_unlock(&g_mtx);
            } else if (danger_latched && calm_n >= REARM_FRAMES) {
                /* one alarm per episode: re-armed only after 10 s back in zone A/B, so shaking
                   in bursts does not flood the alarm log with a new alarm every second */
                pthread_mutex_lock(&g_mtx); C.danger_latched = 0; g_ckpt_dirty = true; pthread_mutex_unlock(&g_mtx);
            }
            /* mount: the tilt only means something at rest; while shaking keep the count */
            if (mv[4] < STILL_G) mount_n = mv[10] >= g_mount_deg ? mount_n + 1 : 0;
            if (mount_n >= MOUNT_FRAMES && !mount_latched) {
                create_event(MG_EV_MOUNT_LOOSE, mv[10], 0.0f, mv[0], mach_id);
                pthread_mutex_lock(&g_mtx); C.mount_latched = 1; g_ckpt_dirty = true; pthread_mutex_unlock(&g_mtx);
            } else if (mount_latched && mv[4] < STILL_G && mv[10] < g_mount_deg / 2) {
                pthread_mutex_lock(&g_mtx); C.mount_latched = 0; g_ckpt_dirty = true; pthread_mutex_unlock(&g_mtx);
            }
        }
        if (!have_m || !m_usable) danger_n = mount_n = calm_n = 0;

        /* ---- environment limits ---- */
        if (have_e && e_new && e_usable) {
            hot_n = ev3[0] >= temp_max ? hot_n + 1 : 0;
            if (hot_n >= 2 && !temp_latched) {
                create_event(MG_EV_OVERTEMP, ev3[0], 0.0f, ev3[1], env_id);
                pthread_mutex_lock(&g_mtx); C.temp_latched = 1; g_ckpt_dirty = true; pthread_mutex_unlock(&g_mtx);
            } else if (temp_latched && ev3[0] < temp_warn) {
                pthread_mutex_lock(&g_mtx); C.temp_latched = 0; g_ckpt_dirty = true; pthread_mutex_unlock(&g_mtx);
            }
        }

        /* ---- warnings + absolute state for the Device Manager ---- */
        uint32_t warn = 0;
        if (have_m && m_usable && zone == 2) warn |= MG_WARN_VIB_ALERT;
        if (fault) warn |= MG_WARN_SENSOR_FAULT;
        if (lost) warn |= MG_WARN_NODE_LOST;
        if (have_m && m_usable && (mount_n >= MOUNT_FRAMES || (mount_latched && mv[4] < STILL_G && mv[10] >= g_mount_deg))) warn |= MG_WARN_MOUNT;
        if (have_e && e_usable && ev3[0] >= temp_warn) warn |= MG_WARN_ENV;
        bool all_ok = hs.nodes > 0 && hs.worst == MG_H_OK && have_m;
        if (last_warn != 0xFFFFFFFFu && (warn & MG_WARN_ENV) && !(last_warn & MG_WARN_ENV))
            mg_evlog(MG_SVC_SENSOR, MG_WARN, "environment temperature %.1f C (warn at %.1f C)", ev3[0], temp_warn);

        pthread_mutex_lock(&g_mtx);
        mg_dm_state_msg_t *st = &g_state;
        uint32_t mode_req = (all_ok && warn == 0) ? MG_MODE_NORMAL : MG_MODE_DEGRADED;
        uint32_t zone_out = have_m && m_usable ? zone : 0;
        bool changed = st->mode_req != mode_req || st->warnings != warn || memcmp(&st->hs, &hs, sizeof hs) != 0 ||
                       st->zone != zone_out;
        st->mode_req = mode_req;
        st->warnings = warn;
        st->hs = hs;
        st->vel_mm_s = have_m && m_usable && mv[0] <= 2000.0f ? mv[0] : 0.0f;
        st->zone = zone_out;
        st->running = have_m && m_usable && mv[9] == 1.0f;
        st->env_temp_c = have_e && e_usable ? ev3[0] : -100.0f;
        if (changed) { g_state_changed = true; pthread_cond_signal(&g_cv); }
        uint32_t pending = C.pending_count;
        pthread_mutex_unlock(&g_mtx);
        last_warn = warn;

        /* ---- publish (seqlock) ---- */
        uint64_t end = mg_now_ns();
        last_exec = (float)(end - release) / 1e6f;
        if (last_exec > max_exec) max_exec = last_exec;
        if (end - release > period_ns) misses++;

        mg_sensor_pub_t *pub = &S->sensor;
        mg_seq_write_begin(&pub->lock);
        pub->machine_node = have_m ? mach_id : 0xFFFFFFFFu;
        pub->vel_mm_s = mv[0];
        pub->vel_xyz[0] = mv[1]; pub->vel_xyz[1] = mv[2]; pub->vel_xyz[2] = mv[3];
        pub->acc_rms_g = mv[4];
        pub->acc_peak_g = mv[5];
        pub->crest = mv[4] > 0.001f ? mv[5] / mv[4] : 0.0f;
        pub->freq_hz = mv[6];
        pub->rpm = mv[6] * 60.0f;
        pub->chip_temp_c = mv[7];
        pub->node_zone = (uint32_t)mv[8];
        pub->zone = zone;
        pub->running = mv[9] == 1.0f;
        pub->mount_tilt_deg = mv[10];
        pub->peak_vel_60s = peak60;
        pub->env_node = have_e ? env_id : 0xFFFFFFFFu;
        pub->env_temp_c = ev3[0];
        pub->env_hum = ev3[1];
        pub->env_press_hpa = ev3[2];
        pub->warnings = warn;
        pub->hs = hs;
        pub->node_count = count;
        memcpy(pub->node, snap, count * sizeof snap[0]);
        if (count < MG_MAX_NODES) memset(&pub->node[count], 0, (MG_MAX_NODES - count) * sizeof snap[0]);
        pub->relayed = relayed;
        pub->unknown_frames = unknown;
        pub->cycles = cycles;
        pub->deadline_misses = misses;
        pub->max_late_ms = max_late;
        pub->last_exec_ms = last_exec;
        pub->max_exec_ms = max_exec;
        pub->events_pending = pending;
        pub->lim_zone_ab = g_zone_ab; pub->lim_zone_bc = g_zone_bc; pub->lim_zone_cd = g_zone_cd;
        pub->lim_mount_deg = g_mount_deg; pub->lim_temp_warn = temp_warn; pub->lim_temp_max = temp_max;
        pub->mach_ok = have_m && m_usable;
        pub->env_ok = have_e && e_usable;
        pub->slips = g_slips;
        pub->updated_ms = now;
        mg_seq_write_end(&pub->lock);
    }
    return 0;
}
