/*
 * mg_logger - Data Logger (non-critical, priority 20, core 3)
 *
 * Writes three CSV files in MG_LOG_DIR (default /data/home/qnxuser/memguard/logs):
 *   readings.csv    one row per second: sensor values, health, modes, deadline stats
 *   events.csv      every system event (faults, recoveries, warnings, alarms)
 *   recoveries.csv  one row per recovery with all measured timings
 * and on every alarm event an edr_<id>.csv with the last 60 s of machine
 * data (vibration, frequency, zone). The ring lives in shared memory and is
 * filled by the sensor service, so the pre-alarm data survives even if this recorder
 * itself is restarted at that moment.
 *
 * Its operating state (how far it has written the event log, the recovery
 * table and the EDR dumps) is checkpointed 10 times a second, so a restarted
 * recorder continues exactly where it stopped: events that happened while it
 * was down are written afterwards instead of being lost. Without a valid
 * checkpoint it safe-initializes: starts at the current head and records the
 * gap as an event.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include "mg_common.h"
#include "mg_proto.h"

/* stage duration, or -1 when a stage never happened (e.g. restart refused: FAILED) */
static long long span(uint64_t a, uint64_t b) { return a && b && b >= a ? (long long)(b - a) : -1LL; }

static mg_shm_t *S;
static char      g_dir[200];

#define CKPT_NAME "logger"
#define LG_CKPT_V 1
typedef struct {
    uint32_t version;
    uint32_t ev_next;          /* next event-log entry to write   */
    uint32_t rec_next;         /* next recovery record to write   */
    uint32_t last_event;       /* last alarm event dumped to EDR   */
    uint32_t rows, edr_dumps, events_written;
    uint32_t reserved[4];
} lg_ckpt_t;
static lg_ckpt_t g_ck, g_ck_saved;
static uint64_t  g_ck_counter;

static void ckpt_save(void)
{
    if (!memcmp(&g_ck, &g_ck_saved, sizeof g_ck)) return;
    if (mg_ckpt_save(CKPT_NAME, &g_ck, sizeof g_ck, &g_ck_counter) == 0) {
        g_ck_saved = g_ck;
        S->ck[MG_SVC_LOGGER].saved_counter = g_ck_counter;
    }
}

static int ckpt_restore(void)
{
    mg_ckpt_result_t res;
    uint64_t expected = S->ck[MG_SVC_LOGGER].saved_counter;
    int files = mg_ckpt_files(CKPT_NAME);
    int status;
    if (mg_ckpt_load(CKPT_NAME, &g_ck, sizeof g_ck, expected, &res) == 0 && g_ck.version == LG_CKPT_V) {
        status = res.status;
        g_ck_counter = res.counter;
        S->ck[MG_SVC_LOGGER].restore_counter = (int64_t)res.counter;
        S->ck[MG_SVC_LOGGER].restore_slot = res.slot;
        mg_log(status == MG_CK_NEWEST ? MG_INFO : MG_WARN, "checkpoint: %s", res.detail);
    } else {
        /* safe-init: start from the current head, record the gap */
        memset(&g_ck, 0, sizeof g_ck);
        g_ck.version = LG_CKPT_V;
        g_ck.ev_next = S->evlog_head;
        g_ck.rec_next = S->rec_count;
        g_ck.last_event = S->sensor.last_event_id;
        g_ck_counter = expected;
        status = MG_CK_NONE;
        S->ck[MG_SVC_LOGGER].restore_counter = -1;
        S->ck[MG_SVC_LOGGER].restore_slot = '-';
        if (expected || files)
            mg_evlog(MG_SVC_LOGGER, MG_WARN, "recorder: no valid checkpoint -> safe-init at current position (gap possible)");
    }
    S->ck[MG_SVC_LOGGER].restore_status = status;
    S->logger.rows = g_ck.rows;
    S->logger.edr_dumps = g_ck.edr_dumps;
    S->logger.events_written = g_ck.events_written;
    g_ck_saved.version = 0;          /* force the boot save */
    ckpt_save();
    return status;
}

static FILE *open_csv(const char *name, const char *header)
{
    char path[300];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    bool fresh = access(path, F_OK) != 0;
    FILE *f = fopen(path, "a");
    if (f && fresh) { fputs(header, f); fflush(f); }
    if (!f) mg_log(MG_WARN, "cannot open %s: %s", path, strerror(errno));
    return f;
}

static void dump_edr(uint32_t event_id)
{
    char path[300];
    snprintf(path, sizeof path, "%s/edr_%u.csv", g_dir, event_id);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs("t_ms,vel_mm_s,acc_rms_g,acc_peak_g,freq_hz,temp_c,zone\n", f);
    uint32_t head = S->edr.head;
    uint32_t avail = head < MG_EDR_SAMPLES ? head : MG_EDR_SAMPLES;
    uint64_t newest = avail ? S->edr.s[(head - 1) % MG_EDR_SAMPLES].t_ms : 0;
    uint32_t n = 0;
    for (uint32_t k = head - avail; k != head; k++) {
        const typeof(S->edr.s[0]) *s = &S->edr.s[k % MG_EDR_SAMPLES];
        if (s->t_ms + 60000 < newest) continue;         /* last 60 s of machine data */
        fprintf(f, "%llu,%.3f,%.4f,%.4f,%.1f,%.1f,%s\n", (unsigned long long)s->t_ms, s->vel, s->acc_rms, s->acc_peak,
                s->freq, s->temp, mg_zone_name(s->zone));
        n++;
    }
    fclose(f);
    S->logger.edr_dumps++;
    g_ck.edr_dumps = S->logger.edr_dumps;
    mg_evlog(MG_SVC_LOGGER, MG_INFO, "recorder: saved %u samples before alarm #%u to edr_%u.csv", n, event_id, event_id);
}

int main(void)
{
    const mg_svc_info_t *me = &MG_SVC_INFO[MG_SVC_LOGGER];
    mg_log_init("mg_logger", MG_SVC_LOGGER);
    mg_set_rt(me->priority, me->cpu);
    S = mg_shm_attach(false);
    if (!S) { mg_log(MG_ERROR, "shared memory not found - start mg_supervisor"); return MG_EXIT_CONFIG; }
    mg_ctl_start(MG_SVC_LOGGER);

    snprintf(g_dir, sizeof g_dir, "%s", mg_env("MG_LOG_DIR", "/data/home/qnxuser/memguard/logs"));
    if (mg_mkdirs(g_dir) != 0) mg_log(MG_WARN, "cannot create %s: %s", g_dir, strerror(errno));

    FILE *fr = open_csv("readings.csv",
        "wall_ms,mode,tripped,machine_node,vel_mm_s,zone,running,freq_hz,mount_deg,env_temp_c,env_hum,env_hpa,"
        "nodes,nodes_ok,worst,warnings,cycles,deadline_misses,max_late_ms,max_exec_ms\n");
    FILE *fn = open_csv("nodes.csv", "wall_ms,node,kind,health,reason,rx,lost,dup,bad_crc,invalid,reboots,rssi,values\n");
    FILE *fe = open_csv("events.csv", "seq,t_ms,source,level,text\n");
    FILE *fv = open_csv("recoveries.csv",
        "id,service,cause,detect_ms,restart_ms,restore_ms,verify_ms,reconnect_ms,total_ms,ckpt_status,ckpt_restored,ckpt_expected,deadline_misses\n");

    /* continue exactly where the previous recorder stopped */
    int restore_status = ckpt_restore();
    uint32_t ev_next = g_ck.ev_next;
    uint32_t rec_next = g_ck.rec_next;
    uint32_t last_event = g_ck.last_event;
    uint64_t next_row = 0;

    mg_ready(MG_SVC_LOGGER, restore_status);
    for (;;) {
        usleep(100000);
        mg_heartbeat(MG_SVC_LOGGER);
        mg_inject_poll(MG_SVC_LOGGER);
        uint64_t now = mg_now_ms();

        /* events */
        uint32_t head = S->evlog_head;
        if (head - ev_next > MG_EVLOG_SIZE) {             /* ring overwrote them meanwhile */
            S->logger.events_missed += head - ev_next - MG_EVLOG_SIZE;
            ev_next = head - MG_EVLOG_SIZE;
        }
        for (; ev_next != head; ev_next++) {
            mg_evlog_entry_t e = S->evlog[ev_next % MG_EVLOG_SIZE];
            if (e.seq != ev_next + 1) break;              /* still being written */
            const char *src = e.svc < MG_SVC_COUNT ? MG_SVC_INFO[e.svc].key : "supervisor";
            if (fe) fprintf(fe, "%u,%llu,%s,%u,\"%s\"\n", e.seq, (unsigned long long)e.t_ms, src, e.level, e.text);
            S->logger.events_written++;
        }
        if (fe) fflush(fe);

        /* completed recoveries */
        while (rec_next < S->rec_count) {
            const mg_recovery_t *r = &S->rec[rec_next % MG_MAX_RECOVERIES];
            if (!r->complete) break;
            uint64_t t0 = r->t_inject_ms ? r->t_inject_ms : r->t_fail_ms;
            uint64_t tend = r->t_reconnect_ms ? r->t_reconnect_ms : r->t_healthy_ms;
            if (fv) fprintf(fv, "%u,%s,%s,%lld,%lld,%lld,%lld,%lld,%lld,%d,%lld,%lld,%u\n",
                            r->id, MG_SVC_INFO[r->svc].key, r->cause,
                            span(t0, r->t_detect_ms), span(r->t_detect_ms, r->t_spawn_ms),
                            span(r->t_spawn_ms, r->t_ready_ms), span(r->t_ready_ms, r->t_healthy_ms),
                            span(r->t_healthy_ms, r->t_reconnect_ms),
                            tend ? (long long)(tend - t0) : -1LL,
                            r->ckpt_status, (long long)r->ckpt_restored, (long long)r->ckpt_expected,
                            r->deadline_miss_during);
            rec_next++;
        }
        if (fv) fflush(fv);

        /* data-recorder snapshot on a new alarm event */
        if (S->sensor.last_event_id != last_event) {
            last_event = S->sensor.last_event_id;
            usleep(200000);                      /* keep 0.2 s after the impact too */
            dump_edr(last_event);
        }

        /* 1 Hz readings */
        if (now >= next_row && fr) {
            next_row = now + 1000;
            mg_sensor_pub_t sp;
            mg_dm_pub_t dp;
            mg_seq_read(&S->sensor.lock, &sp, &S->sensor, sizeof sp);
            mg_seq_read(&S->dm.lock, &dp, &S->dm, sizeof dp);
            unsigned long long wall = (unsigned long long)mg_wall_ms();
            fprintf(fr, "%llu,%s,%u,%d,%.3f,%s,%u,%.1f,%.1f,%.1f,%.0f,%.1f,%u,%u,%s,0x%02X,%llu,%u,%.2f,%.3f\n",
                    wall, mg_mode_name(dp.mode), dp.machine_tripped,
                    sp.machine_node == 0xFFFFFFFFu ? -1 : (int)sp.machine_node, sp.vel_mm_s, mg_zone_name(sp.zone),
                    sp.running, sp.freq_hz, sp.mount_tilt_deg, sp.env_temp_c, sp.env_hum, sp.env_press_hpa,
                    sp.hs.nodes, sp.hs.nodes_ok, mg_health_name(sp.hs.worst),
                    sp.warnings, (unsigned long long)sp.cycles, sp.deadline_misses, sp.max_late_ms, sp.max_exec_ms);
            fflush(fr);
            for (uint32_t k = 0; fn && k < sp.node_count && k < MG_MAX_NODES; k++) {
                const mg_node_pub_t *nd = &sp.node[k];
                fprintf(fn, "%llu,%u,%s,%s,\"%s\",%u,%u,%u,%u,%u,%u,%d,\"", wall, nd->id, nd->kind,
                        mg_health_name(nd->health), nd->reason, nd->st.rx, nd->st.lost, nd->st.dup,
                        nd->st.bad_crc, nd->st.invalid, nd->st.reboots, (int)nd->rssi_dbm);
                for (uint32_t i = 0; i < nd->nvals && i < MG_NODE_MAX_VALS; i++) fprintf(fn, "%s%.3f", i ? " " : "", nd->v[i]);
                fputs("\"\n", fn);
            }
            if (fn) fflush(fn);
            S->logger.rows++;
        }
        /* checkpoint the operating state (only when it changed) */
        g_ck.ev_next = ev_next;
        g_ck.rec_next = rec_next;
        g_ck.last_event = last_event;
        g_ck.rows = S->logger.rows;
        g_ck.events_written = S->logger.events_written;
        ckpt_save();
        S->logger.updated_ms = now;
    }
    return 0;
}
