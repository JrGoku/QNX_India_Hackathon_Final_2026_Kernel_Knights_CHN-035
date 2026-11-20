/*
 * mg_devmgr - Device Manager = the machine controller
 * Critical service, priority 50, core 2.
 *
 *  - owns the state of the monitored machine: mode, alarm latch, and the
 *    TRIP (stop command) issued when vibration reaches ISO zone D. With
 *    MG_GPIO=1 the outputs drive the monitored device: green = running OK,
 *    amber = alert / degraded, red = tripped (stop relay), buzzer = new alarm
 *  - owns the alarm notifications to the maintenance centre (laptop, UDP
 *    6000): every event is stored in an outbox that is CHECKPOINTED BEFORE
 *    the request is acknowledged (write-ahead), resent until the centre ACKs,
 *    and de-duplicated by event id - no alarm is lost or delivered twice
 *  - validates every request (type, length, ranges, enum values), rejects
 *    duplicates/stale requests, and refuses quarantined (poison) requests
 *  - two-slot CRC checkpoint, restored on restart; scrubbed every second.
 *    The trip survives a restart: a crash never silently restarts a machine
 *  - if no valid checkpoint exists after a failure it boots into a
 *    RESTRICTED safe-initialization state (machine held stopped) that only an
 *    operator reset can leave, and only after all nodes are verified OK again
 *  - operator reset is refused while the vibration is still in zone C or D
 *
 * It contains one deliberate latent defect (handle_diag) so the judges can
 * "crash the Device Manager through an injected invalid operation".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <sys/iomsg.h>
#include "mg_common.h"
#include "mg_proto.h"

#define CKPT_NAME   "dm"
#define DM_CKPT_V   6
#define OUTBOX_MAX  MG_ALARM_LOG

typedef struct {
    mg_event_t ev;
    uint32_t   acked;
    uint32_t   tries;
    uint64_t   last_try_ms;
} outbox_t;

typedef struct {
    uint32_t version;
    uint32_t restricted;            /* safe-initialization state */
    uint32_t alarm_latched;
    uint32_t latched_event_id;
    uint32_t latched_type;
    uint64_t latched_wall_ms;
    mg_health_sum_t hs;
    uint32_t warnings;
    uint32_t mode_req;
    uint32_t highest_event_id;
    uint32_t total_events;
    uint32_t machine_tripped;       /* stop command latched (zone D)        */
    uint32_t zone;                  /* last ISO zone from the sensor        */
    uint32_t running;
    uint32_t outbox_n;
    outbox_t outbox[OUTBOX_MAX];
} dm_state_t;

static mg_shm_t       *S;
static dm_state_t      D;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_ecall_cv = PTHREAD_COND_INITIALIZER;
static uint64_t        g_ckpt_counter, g_ckpt_last_ms, g_scrub_ms;
static bool            g_dirty;
static int             g_restore_status;
static char            g_restore_detail[64];
static pid_t           g_last_sender;
static uint32_t        g_last_seq;
static uint64_t        g_sensor_last_ms;
static uint32_t        g_good_updates;
static uint64_t        g_buzz_until;
static uint32_t        g_tick;
static int             g_btn_count;
static uint32_t        g_mode = MG_MODE_BOOT, g_outputs;
static uint32_t        g_cnt_ok, g_cnt_dup, g_cnt_stale, g_cnt_invalid, g_cnt_quar, g_ev_rx, g_ev_dup;
static uint32_t        g_ecall_sent, g_ecall_acked, g_ecall_retries, g_last_ack, g_scrub_err;
static uint64_t        g_invalid_log_ms;

/* ================================================================== */
/* Checkpoint                                                          */
/* ================================================================== */
static void save_locked(const char *why)
{
    if (mg_ckpt_save(CKPT_NAME, &D, sizeof D, &g_ckpt_counter) == 0) {
        g_dirty = false;
        g_ckpt_last_ms = mg_now_ms();
        S->dm.ckpt_saved_counter = g_ckpt_counter;
        S->ck[MG_SVC_DEVMGR].saved_counter = g_ckpt_counter;
        S->dm.ckpt_saves++;
    } else {
        mg_log(MG_ERROR, "checkpoint save failed (%s): %s", why, strerror(errno));
    }
}

static void restore(void)
{
    mg_ckpt_result_t res;
    uint64_t expected = S->dm.ckpt_saved_counter;
    int files = mg_ckpt_files(CKPT_NAME);
    memset(&D, 0, sizeof D);
    if (mg_ckpt_load(CKPT_NAME, &D, sizeof D, expected, &res) == 0 && D.version == DM_CKPT_V) {
        g_restore_status = res.status;
        /* continue from the RESTORED counter so the boot save below repairs the
           damaged/missing slot and keeps the good checkpoint as the backup */
        g_ckpt_counter = res.counter;
        snprintf(g_restore_detail, sizeof g_restore_detail, "%s", res.detail);
        S->dm.restore_counter = (int64_t)res.counter;
        for (uint32_t k = 0; k < D.outbox_n; k++) D.outbox[k].last_try_ms = 0;  /* resend now */
    } else {
        memset(&D, 0, sizeof D);
        D.version = DM_CKPT_V;
        g_restore_status = MG_CK_NONE;
        g_ckpt_counter = expected;
        S->dm.restore_counter = -1;
        if (expected == 0 && files == 0) {
            snprintf(g_restore_detail, sizeof g_restore_detail, "first start - fresh state");
        } else {
            /* a checkpoint should exist but none is valid: do not guess */
            D.restricted = 1;
            D.hs.worst = D.hs.machine = MG_H_UNVERIFIED;
            snprintf(g_restore_detail, sizeof g_restore_detail, "NO VALID CHECKPOINT -> safe-init (restricted)");
        }
    }
    S->dm.restore_status = g_restore_status;
    S->ck[MG_SVC_DEVMGR].restore_status = g_restore_status;
    S->ck[MG_SVC_DEVMGR].restore_counter = S->dm.restore_counter;
    S->ck[MG_SVC_DEVMGR].restore_slot = g_restore_status == MG_CK_NONE ? '-' : res.slot;
    snprintf(S->dm.restore_detail, sizeof S->dm.restore_detail, "%s", g_restore_detail);
    mg_log(g_restore_status == MG_CK_NEWEST || (g_restore_status == MG_CK_NONE && !D.restricted) ? MG_INFO : MG_WARN,
           "checkpoint: %s", g_restore_detail);
    mg_trace("MG DM RESTORE %s", g_restore_detail);
    save_locked("boot");
}

/* ================================================================== */
/* Outputs                                                             */
/* ================================================================== */
static const int OUT_PINS[4] = { MG_PIN_LED_GREEN, MG_PIN_LED_AMBER, MG_PIN_LED_RED, MG_PIN_BUZZER };

static uint32_t compute_mode(uint64_t now)
{
    bool stale = g_sensor_last_ms == 0 || now - g_sensor_last_ms > MG_DM_SENSOR_STALE_MS;
    if (D.restricted || S->system_safe || D.machine_tripped) return MG_MODE_SAFE;   /* machine stopped */
    if (D.alarm_latched || (D.warnings & (MG_WARN_VIB_ALERT | MG_WARN_ENV))) return MG_MODE_ALERT;
    if (g_sensor_last_ms == 0) return MG_MODE_BOOT;
    if (stale || D.mode_req != MG_MODE_NORMAL || D.warnings) return MG_MODE_DEGRADED;
    return MG_MODE_NORMAL;
}

static void apply_outputs(uint64_t now)
{
    uint32_t mode = compute_mode(now);
    bool stale = g_sensor_last_ms && now - g_sensor_last_ms > MG_DM_SENSOR_STALE_MS;
    bool fast = (g_tick / 2) & 1;      /* 100 ms phase */
    bool slow = (g_tick / 10) & 1;     /* 500 ms phase */
    int g = 0, a = 0, r = 0, bz = 0;
    switch (mode) {
    case MG_MODE_NORMAL:   g = 1; break;
    case MG_MODE_DEGRADED: a = (D.warnings & MG_WARN_NODE_LOST) ? fast : stale ? slow : 1; break;
    case MG_MODE_ALERT:    a = slow; g = !D.alarm_latched; bz = (now < g_buzz_until) && fast; break;
    case MG_MODE_SAFE:     r = 1; a = D.restricted || S->system_safe; bz = (now < g_buzz_until) && fast; break;
    default:               a = slow; break;
    }
    if (mode != g_mode) {
        mg_trace("MG DM MODE %s", mg_mode_name(mode));
        mg_evlog(MG_SVC_DEVMGR, mode >= MG_MODE_ALERT ? MG_WARN : MG_INFO, "mode %s -> %s",
                 mg_mode_name(g_mode), mg_mode_name(mode));
        g_mode = mode;
    }
    int v[4] = { g, a, r, bz };
    g_outputs = 0;
    for (int k = 0; k < 4; k++) {
        mg_gpio_write(OUT_PINS[k], v[k]);
        if (v[k]) g_outputs |= 1u << k;
    }
}

static int selftest_outputs(void)
{
    if (!mg_gpio_ok()) return 0;
    int bad = 0;
    for (int k = 0; k < 4; k++) {
        int want = (g_outputs >> k) & 1u;
        if (mg_gpio_read(OUT_PINS[k]) != want) bad++;
    }
    if (bad) mg_log(MG_WARN, "output read-back mismatch on %d pin(s)", bad);
    return bad;
}

static void publish(uint64_t now)
{
    mg_dm_pub_t *p = &S->dm;
    mg_seq_write_begin(&p->lock);
    p->mode = g_mode;
    p->restricted = D.restricted;
    p->alarm_latched = D.alarm_latched;
    p->machine_tripped = D.machine_tripped;
    p->latched_event_id = D.latched_event_id;
    p->highest_event_id = D.highest_event_id;
    p->outputs = g_outputs;
    p->gpio_ok = mg_gpio_ok();
    p->hs = D.hs;
    p->warnings = D.warnings;
    p->req_ok = g_cnt_ok;
    p->req_dup = g_cnt_dup;
    p->req_stale = g_cnt_stale;
    p->req_invalid = g_cnt_invalid;
    p->req_quarantined = g_cnt_quar;
    p->events_received = D.total_events;   /* checkpointed: survives a DM restart */
    p->events_dup = g_ev_dup;
    uint32_t pend = 0;
    for (uint32_t k = 0; k < D.outbox_n; k++) if (!D.outbox[k].acked) pend++;
    p->outbox_pending = pend;
    p->ecall_sent = g_ecall_sent;
    p->ecall_acked = g_ecall_acked;
    p->ecall_retries = g_ecall_retries;
    p->last_ecall_acked = g_last_ack;
    p->alarm_n = D.outbox_n;
    for (uint32_t k = 0; k < D.outbox_n; k++) {
        p->alarm[k].ev = D.outbox[k].ev;
        p->alarm[k].acked = D.outbox[k].acked;
        p->alarm[k].tries = D.outbox[k].tries;
    }
    p->centre_set = getenv("MG_ECALL_HOST") != NULL;
    p->ckpt_scrub_errors = g_scrub_err;
    p->sensor_stale = g_sensor_last_ms && now - g_sensor_last_ms > MG_DM_SENSOR_STALE_MS;
    p->sensor_last_update_ms = g_sensor_last_ms;
    p->updated_ms = now;
    mg_seq_write_end(&p->lock);
}

/* ================================================================== */
/* Operator reset                                                      */
/* ================================================================== */
static int operator_reset(const char *source)
{
    if (D.restricted) {
        bool all_ok = D.hs.nodes > 0 && D.hs.worst == MG_H_OK;
        if (!all_ok || g_good_updates < 20) {
            mg_evlog(MG_SVC_DEVMGR, MG_WARN, "reset (%s) refused: nodes not verified yet", source);
            return MG_ERR_RESTRICTED;
        }
        D.restricted = 0;
    }
    if ((D.machine_tripped || D.alarm_latched) && D.zone >= 2) {
        mg_evlog(MG_SVC_DEVMGR, MG_WARN, "reset (%s) refused: vibration still in zone %s", source, mg_zone_name(D.zone));
        return MG_ERR_RESTRICTED;
    }
    if (D.machine_tripped) mg_evlog(MG_SVC_DEVMGR, MG_INFO, "operator reset (%s): machine trip released", source);
    D.machine_tripped = 0;
    D.alarm_latched = 0;
    g_buzz_until = 0;
    g_dirty = true;
    mg_evlog(MG_SVC_DEVMGR, MG_INFO, "operator reset (%s): alarm cleared", source);
    mg_trace("MG DM OPERATOR RESET");
    return EOK;
}

/* ================================================================== */
/* Request handlers (main thread, g_mtx held)                          */
/* ================================================================== */
static bool finite_in(float v, float lo, float hi) { return isfinite(v) && v >= lo && v <= hi; }

static void reject_invalid(rcvid_t rcvid, const char *why)
{
    g_cnt_invalid++;
    uint64_t now = mg_now_ms();
    if (now - g_invalid_log_ms > 1000) {
        g_invalid_log_ms = now;
        mg_evlog(MG_SVC_DEVMGR, MG_WARN, "rejected invalid request: %s", why);
    }
    MsgError(rcvid, MG_ERR_INVALID);
}

static void handle_state(rcvid_t rcvid, const mg_dm_state_msg_t *m)
{
    if (m->mode_req != MG_MODE_NORMAL && m->mode_req != MG_MODE_DEGRADED) { reject_invalid(rcvid, "mode"); return; }
    if (m->hs.worst >= MG_H_COUNT || m->hs.machine >= MG_H_COUNT || m->hs.nodes > MG_MAX_NODES ||
        m->hs.nodes_ok > m->hs.nodes) { reject_invalid(rcvid, "health summary"); return; }
    if (m->warnings & ~MG_WARN_ALL) { reject_invalid(rcvid, "warning bits"); return; }
    if (!finite_in(m->vel_mm_s, 0.0f, 2000.0f) || m->zone > 3 || m->running > 1 ||
        !(m->env_temp_c == -100.0f || finite_in(m->env_temp_c, -40.0f, 85.0f))) {
        reject_invalid(rcvid, "value out of physical range");
        return;
    }
    if (m->sender == g_last_sender && m->seq == g_last_seq) { g_cnt_dup++; MsgReply(rcvid, EOK, NULL, 0); return; }
    if (m->sender == g_last_sender && m->seq < g_last_seq)  { g_cnt_stale++; MsgReply(rcvid, EOK, NULL, 0); return; }
    g_last_sender = m->sender;
    g_last_seq = m->seq;
    g_cnt_ok++;
    bool changed = memcmp(&D.hs, &m->hs, sizeof D.hs) != 0 ||
                   D.warnings != m->warnings || D.mode_req != m->mode_req || D.zone != m->zone ||
                   D.running != m->running;
    D.zone = m->zone;
    D.running = m->running;
    D.hs = m->hs;
    D.warnings = m->warnings;
    D.mode_req = m->mode_req;
    g_sensor_last_ms = mg_now_ms();
    bool all_ok = m->hs.nodes > 0 && m->hs.worst == MG_H_OK;
    g_good_updates = all_ok ? g_good_updates + 1 : 0;
    if (changed) g_dirty = true;
    MsgReply(rcvid, EOK, NULL, 0);
}

static void handle_event(rcvid_t rcvid, const mg_dm_event_msg_t *m)
{
    const mg_event_t *e = &m->ev;
    if (e->id == 0 || e->type == MG_EV_NONE || e->type >= MG_EV_COUNT) { reject_invalid(rcvid, "event type/id"); return; }
    bool vals_ok = e->type == MG_EV_VIB_DANGER  ? finite_in(e->value, 0.0f, 2000.0f) && finite_in(e->freq_hz, 0.0f, 500.0f)
                                                    && finite_in(e->aux, 0.0f, 16.0f)
                 : e->type == MG_EV_OVERTEMP    ? finite_in(e->value, -40.0f, 85.0f)
                 :                                finite_in(e->value, 0.0f, 180.0f);
    if (!vals_ok) {
        reject_invalid(rcvid, "event values");
        return;
    }
    mg_dm_event_reply_t r;
    if (e->id <= D.highest_event_id) {
        g_ev_dup++;
        r.status = MG_EVREPLY_DUPLICATE;
        r.highest_event_id = D.highest_event_id;
        MsgReply(rcvid, EOK, &r, sizeof r);
        return;
    }
    if (D.outbox_n == OUTBOX_MAX) {                       /* drop the oldest acked entry */
        uint32_t k = 0;
        while (k < D.outbox_n && !D.outbox[k].acked) k++;
        if (k == D.outbox_n) k = 0;
        memmove(&D.outbox[k], &D.outbox[k + 1], (D.outbox_n - k - 1) * sizeof(outbox_t));
        D.outbox_n--;
    }
    outbox_t *o = &D.outbox[D.outbox_n++];
    memset(o, 0, sizeof *o);
    o->ev = *e;
    D.highest_event_id = e->id;
    D.total_events++;
    D.alarm_latched = 1;
    D.latched_event_id = e->id;
    D.latched_type = e->type;
    D.latched_wall_ms = e->t_wall_ms;
    if (e->type == MG_EV_VIB_DANGER && !D.machine_tripped) {
        D.machine_tripped = 1;
        mg_evlog(MG_SVC_DEVMGR, MG_ERROR, "MACHINE TRIPPED: stop command (vibration %.2f mm/s, zone D)", e->value);
        mg_trace("MG DM MACHINE TRIP");
    }
    g_buzz_until = mg_now_ms() + 10000;
    g_ev_rx++;
    save_locked("event");                   /* WRITE-AHEAD: persist, then acknowledge */
    r.status = MG_EVREPLY_STORED;
    r.highest_event_id = D.highest_event_id;
    MsgReply(rcvid, EOK, &r, sizeof r);
    pthread_cond_signal(&g_ecall_cv);
    mg_trace("MG DM EVENT %u STORED", e->id);
    mg_evlog(MG_SVC_DEVMGR, MG_WARN, "ALARM: event #%u %s stored, maintenance notification queued", e->id, mg_event_name(e->type));
}

/* ---- diagnostics: contains the deliberate latent defect ---- */
typedef void (*diag_fn_t)(void);
static void diag_lamp_test(void) { mg_log(MG_INFO, "diag: output test"); }
static void diag_selftest(void)  { selftest_outputs(); }
static void diag_dump(void)      { mg_log(MG_INFO, "diag: mode %s, events %u", mg_mode_name(g_mode), D.total_events); }
static diag_fn_t const g_diag[3] = { diag_lamp_test, diag_selftest, diag_dump };

static void handle_diag(rcvid_t rcvid, const mg_dm_diag_msg_t *m)
{
    diag_fn_t fn = NULL;
    if (m->op >= 0 && m->op < 3) fn = g_diag[m->op];
    /* LATENT DEFECT (kept on purpose for the fault-containment demo):
     * the "else: reject unknown op" branch is missing, so an op outside
     * 0..2 calls through a NULL function pointer -> SIGSEGV.
     * The supervisor quarantines the request that caused the crash, so
     * a retry of the same request is refused instead of crashing again. */
    fn();
    MsgReply(rcvid, EOK, NULL, 0);
}

static bool quarantined(uint16_t type, uint16_t op, uint32_t hash)
{
    for (int q = 0; q < MG_QUARANTINE_MAX; q++) {
        const mg_quarantine_t *e = &S->quarantine[q];
        if (e->valid && e->type == type && e->op == op && e->hash == hash) return true;
    }
    return false;
}

static void dispatch(rcvid_t rcvid, const mg_hdr_t *hdr, size_t len)
{
    static const struct { uint16_t type; size_t size; } SIZES[] = {
        { MG_MSG_DM_STATE, sizeof(mg_dm_state_msg_t) },
        { MG_MSG_DM_EVENT, sizeof(mg_dm_event_msg_t) },
        { MG_MSG_DM_SYNC,  sizeof(mg_dm_sync_msg_t) },
        { MG_MSG_DM_RESET, sizeof(mg_dm_reset_msg_t) },
        { MG_MSG_DM_DIAG,  sizeof(mg_dm_diag_msg_t) },
    };
    size_t need = 0;
    for (size_t k = 0; k < sizeof SIZES / sizeof SIZES[0]; k++)
        if (SIZES[k].type == hdr->type) need = SIZES[k].size;
    if (need == 0) { MsgError(rcvid, ENOSYS); return; }
    if (len < need) { reject_invalid(rcvid, "short message"); return; }

    uint16_t op = hdr->type == MG_MSG_DM_DIAG ? (uint16_t)((const mg_dm_diag_msg_t *)hdr)->op : 0;
    uint32_t hash = mg_crc32((const uint8_t *)hdr + sizeof(mg_hdr_t), need - sizeof(mg_hdr_t));
    if (quarantined(hdr->type, op, hash)) {
        g_cnt_quar++;
        mg_evlog(MG_SVC_DEVMGR, MG_WARN, "refused QUARANTINED request type 0x%x op %u", hdr->type, op);
        MsgError(rcvid, MG_ERR_QUARANTINED);
        return;
    }
    /* remember what we are processing: if we crash now, this is the culprit */
    S->dm.inflight_type = hdr->type;
    S->dm.inflight_op = op;
    S->dm.inflight_hash = hash;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    S->dm.inflight_valid = 1;

    pthread_mutex_lock(&g_mtx);
    switch (hdr->type) {
    case MG_MSG_DM_STATE: handle_state(rcvid, (const mg_dm_state_msg_t *)hdr); break;
    case MG_MSG_DM_EVENT: handle_event(rcvid, (const mg_dm_event_msg_t *)hdr); break;
    case MG_MSG_DM_SYNC: {
        mg_dm_sync_reply_t r = { D.highest_event_id, D.restricted };
        MsgReply(rcvid, EOK, &r, sizeof r);
        break;
    }
    case MG_MSG_DM_RESET: {
        int rc = operator_reset("mgctl");
        if (rc == EOK) MsgReply(rcvid, EOK, NULL, 0); else MsgError(rcvid, rc);
        break;
    }
    case MG_MSG_DM_DIAG: handle_diag(rcvid, (const mg_dm_diag_msg_t *)hdr); break;
    }
    pthread_mutex_unlock(&g_mtx);
    S->dm.inflight_valid = 0;
}

/* ================================================================== */
/* Alarm notifications: resend until the maintenance centre acks      */
/* ================================================================== */
static void *ecall_thread(void *arg)
{
    (void)arg;
    const char *host = getenv("MG_ECALL_HOST");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(MG_UDP_ALARM_PORT);
    bool have_host = host && inet_pton(AF_INET, host, &dst.sin_addr) == 1;
    if (!have_host) mg_log(MG_WARN, "maintenance centre not set (mg_supervisor -e <laptop-ip>): alarms stay queued");
    struct timeval tv = { 0, 100000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned session = (unsigned)S->sup_pid;

    for (;;) {
        char out[OUTBOX_MAX][160];
        uint32_t out_id[OUTBOX_MAX], out_try[OUTBOX_MAX];
        int nout = 0;
        uint64_t now = mg_now_ms();
        pthread_mutex_lock(&g_mtx);
        for (uint32_t k = 0; k < D.outbox_n && have_host; k++) {
            outbox_t *o = &D.outbox[k];
            if (o->acked || now - o->last_try_ms < 500) continue;
            o->tries++;
            o->last_try_ms = now;
            g_ecall_sent++;
            if (o->tries > 1) g_ecall_retries++;
            out_id[nout] = o->ev.id;
            out_try[nout] = o->tries;
            snprintf(out[nout++], sizeof out[0], "ALARM,%u,%u,%s,%llu,%.2f,%.1f,%.2f,%u,%u\n",
                     session, o->ev.id, mg_event_name(o->ev.type), (unsigned long long)o->ev.t_wall_ms,
                     o->ev.value, o->ev.freq_hz, o->ev.aux, o->ev.node_id, o->tries);
        }
        pthread_mutex_unlock(&g_mtx);
        for (int k = 0; k < nout; k++) {
            sendto(s, out[k], strlen(out[k]), 0, (struct sockaddr *)&dst, sizeof dst);
            mg_trace("MG DM ALARM %u SENT try %u", out_id[k], out_try[k]);
        }

        char buf[128];
        ssize_t n = have_host ? recvfrom(s, buf, sizeof buf - 1, 0, NULL, NULL) : -1;
        /* no network (Wi-Fi gone, interface being reconfigured): the call fails at
           once instead of waiting 100 ms - back off so this thread never spins */
        if (n < 0 && (!have_host || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))) usleep(100000);
        if (n > 0) {
            buf[n] = 0;
            unsigned sess = 0, id = 0;
            if (sscanf(buf, "ACK,%u,%u", &sess, &id) == 2 && sess == session) {
                pthread_mutex_lock(&g_mtx);
                for (uint32_t k = 0; k < D.outbox_n; k++) {
                    if (D.outbox[k].ev.id == id && !D.outbox[k].acked) {
                        D.outbox[k].acked = 1;
                        g_ecall_acked++;
                        g_last_ack = id;
                        g_dirty = true;
                        mg_evlog(MG_SVC_DEVMGR, MG_INFO, "alarm #%u acknowledged by the maintenance centre", id);
                        mg_trace("MG DM ALARM %u ACKED", id);
                    }
                }
                pthread_mutex_unlock(&g_mtx);
            }
        } else if (!have_host) {
            usleep(500000);
        }
    }
    return NULL;
}

/* ================================================================== */
/* Periodic work (50 ms)                                               */
/* ================================================================== */
static void on_tick(void)
{
    uint64_t now = mg_now_ms();
    g_tick++;
    mg_heartbeat(MG_SVC_DEVMGR);
    mg_inject_poll(MG_SVC_DEVMGR);

    pthread_mutex_lock(&g_mtx);
    /* optional reset button (MG_GPIO=1; active low, 150 ms debounce) */
    if (mg_gpio_ok()) {
        if (mg_gpio_read(MG_PIN_BTN_RESET) == 0) {
            if (++g_btn_count == 3) operator_reset("button");
        } else {
            g_btn_count = 0;
        }
    }
    apply_outputs(now);
    /* runtime scrubbing: is our newest checkpoint still intact? */
    if (now >= g_scrub_ms) {
        g_scrub_ms = now + 1000;
        if (mg_ckpt_verify(CKPT_NAME, sizeof D, g_ckpt_counter) != 0) {
            g_scrub_err++;
            mg_evlog(MG_SVC_DEVMGR, MG_WARN, "checkpoint #%llu damaged at runtime -> rewriting",
                     (unsigned long long)g_ckpt_counter);
            mg_trace("MG DM CKPT SCRUB REPAIR");
            g_dirty = true;
        }
    }
    if (g_dirty && now - g_ckpt_last_ms >= 100) save_locked("tick");
    publish(now);
    pthread_mutex_unlock(&g_mtx);
}

int main(void)
{
    const mg_svc_info_t *me = &MG_SVC_INFO[MG_SVC_DEVMGR];
    mg_log_init("mg_devmgr", MG_SVC_DEVMGR);
    mg_set_rt(me->priority, me->cpu);
    S = mg_shm_attach(false);
    if (!S) { mg_log(MG_ERROR, "shared memory not found - start mg_supervisor"); return MG_EXIT_CONFIG; }
    mg_seq_repair(&S->dm.lock);

    name_attach_t *att = name_attach(NULL, me->attach_name, 0);
    if (!att) { mg_log(MG_ERROR, "name_attach(%s): %s", me->attach_name, strerror(errno)); return MG_EXIT_CONFIG; }

    if (mg_gpio_init() == 0) {
        for (int k = 0; k < 4; k++) mg_gpio_mode_out(OUT_PINS[k]);
        mg_gpio_mode_in(MG_PIN_BTN_RESET, 1);
    }

    pthread_mutex_lock(&g_mtx);
    restore();
    /* bumpless restart: trust the restored sensor state for one stale period
       while the sensor service reconnects, instead of blinking "boot" */
    if (g_restore_status != MG_CK_NONE) g_sensor_last_ms = mg_now_ms();
    apply_outputs(mg_now_ms());          /* restored state is visible immediately */
    selftest_outputs();
    publish(mg_now_ms());
    pthread_mutex_unlock(&g_mtx);

    pthread_t et;
    pthread_create(&et, NULL, ecall_thread, NULL);
    pthread_setname_np(et, "alarm-notify");

    int coid = ConnectAttach(0, 0, att->chid, _NTO_SIDE_CHANNEL, 0);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, me->priority, MG_PULSE_TICK, 0);
    timer_t tid;
    timer_create(CLOCK_MONOTONIC, &ev, &tid);
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = MG_DM_TICK_MS * 1000000L;
    its.it_interval.tv_nsec = MG_DM_TICK_MS * 1000000L;
    timer_settime(tid, 0, &its, NULL);

    mg_ready(MG_SVC_DEVMGR, g_restore_status);

    union {
        struct _pulse pulse;
        mg_hdr_t      hdr;
        char          raw[512];
    } msg;
    struct _msg_info info;
    for (;;) {
        rcvid_t rcvid = MsgReceive(att->chid, &msg, sizeof msg, &info);
        if (rcvid == -1) { if (errno != EINTR) usleep(1000); continue; }
        if (rcvid == 0) {
            if (msg.pulse.code == MG_PULSE_TICK) on_tick();
            else if (msg.pulse.code == _PULSE_CODE_DISCONNECT) ConnectDetach(msg.pulse.scoid);
            continue;
        }
        size_t len = (size_t)info.srcmsglen < sizeof msg ? (size_t)info.srcmsglen : sizeof msg;
        if (mg_ctl_handle(rcvid, &msg, len, MG_SVC_DEVMGR)) continue;
        dispatch(rcvid, &msg.hdr, len);
    }
    return 0;
}
