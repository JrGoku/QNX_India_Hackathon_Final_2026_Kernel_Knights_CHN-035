/*
 * mg_statusfs - a QNX resource manager (non-critical, priority 12, core 3)
 *
 * Registers two read-only files in the path space:
 *     /dev/memguard/status    live state of every service and sensor
 *     /dev/memguard/metrics   every recovery with its measured timings
 * so anyone can type   cat /dev/memguard/status   on the target.
 *
 * It uses the standard QNX dispatch framework: iofunc defaults for
 * everything except io_read, plus a timer pulse (pulse_attach) that drives
 * the heartbeat from inside the dispatch loop - if the loop hangs, the
 * heartbeats stop and the supervisor restarts this process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include "mg_common.h"
#include "mg_proto.h"

static mg_shm_t                 *S;
static resmgr_connect_funcs_t    g_cfuncs;
static resmgr_io_funcs_t         g_iofuncs;
static iofunc_attr_t             g_attr_status, g_attr_metrics;
static char                      g_buf[8192];
static size_t                    g_len;

static size_t fmt_status(char *b, size_t n)
{
    size_t o = 0;
    mg_sensor_pub_t sp;
    mg_dm_pub_t dp;
    mg_seq_read(&S->sensor.lock, &sp, &S->sensor, sizeof sp);
    mg_seq_read(&S->dm.lock, &dp, &S->dm, sizeof dp);
    uint64_t now = mg_now_ms();
#define P(...) do { int w = snprintf(b + o, n - o, __VA_ARGS__); if (w > 0) o += (size_t)w < n - o ? (size_t)w : n - o - 1; } while (0)
    P("MemoryGuard %s  uptime %llu s  system-safe %s\n\n", MG_VERSION,
      (unsigned long long)((now - S->sup_start_ms) / 1000), S->system_safe ? "YES" : "no");
    P("%-9s %-11s %8s %8s %7s  %s\n", "SERVICE", "STATE", "PID", "RESTARTS", "HB AGE", "LAST CAUSE");
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        const mg_svc_reg_t *r = &S->reg[i];
        P("%-9s %-11s %8d %8u %5llums  %s\n", MG_SVC_INFO[i].key, mg_state_name(r->state), (int)r->pid,
          r->restarts, (unsigned long long)(now - r->last_hb_ms), r->last_cause);
    }
    char wbuf[80];
    P("\nMACHINE  mode %s%s  %s  alarm %s (event #%u)  warnings %s\n", mg_mode_name(dp.mode),
      dp.restricted ? " (RESTRICTED)" : "", dp.machine_tripped ? "TRIPPED" : "not-tripped",
      dp.alarm_latched ? "LATCHED" : "clear", dp.latched_event_id, mg_warn_names(sp.warnings, wbuf, sizeof wbuf));
    if (sp.machine_node != 0xFFFFFFFFu)
        P("VIB      node %u  %.2f mm/s  zone %s  %s  %.1f Hz  mount %.1f deg\n", sp.machine_node, sp.vel_mm_s,
          mg_zone_name(sp.zone), sp.running ? "running" : "idle", sp.freq_hz, sp.mount_tilt_deg);
    else
        P("VIB      none alive\n");
    if (sp.env_node != 0xFFFFFFFFu)
        P("ENV      node %u  %.1f C  %.0f %%  %.1f hPa\n", sp.env_node, sp.env_temp_c, sp.env_hum, sp.env_press_hpa);
    P("NODES    %u known  %u OK  worst %s  relayed %u  unknown %u\n", sp.hs.nodes, sp.hs.nodes_ok,
      mg_health_name(sp.hs.worst), sp.relayed, sp.unknown_frames);
    for (uint32_t k = 0; k < sp.node_count && k < MG_MAX_NODES; k++) {
        const mg_node_pub_t *ns = &sp.node[k];
        P("NODE %-3u %-4s %-10s %-18s rx %u lost %u dup %u reorder %u badcrc %u invalid %u reboots %u rssi %d %s\n",
          ns->id, ns->kind[0] ? ns->kind : "-", mg_health_name(ns->health), ns->reason[0] ? ns->reason : "-",
          ns->st.rx, ns->st.lost, ns->st.dup, ns->st.out_of_order, ns->st.bad_crc, ns->st.invalid,
          ns->st.reboots, (int)ns->rssi_dbm, ns->st.alive ? "alive" : "SILENT");
    }
    P("RT LOOP  %llu cycles @100 Hz  deadline misses %u  max late %.2f ms  exec %.3f/%.3f ms\n",
      (unsigned long long)sp.cycles, sp.deadline_misses, sp.max_late_ms, sp.last_exec_ms, sp.max_exec_ms);
    P("REQUESTS ok %u dup %u stale %u invalid %u quarantined %u | events %u dup %u\n",
      dp.req_ok, dp.req_dup, dp.req_stale, dp.req_invalid, dp.req_quarantined, dp.events_received, dp.events_dup);
    P("ALARMS   sent %u acked %u retries %u pending %u\n", dp.ecall_sent, dp.ecall_acked, dp.ecall_retries,
      dp.outbox_pending);
    P("CKPT     dm #%llu (%s) scrub-repairs %u | sensor #%llu\n",
      (unsigned long long)dp.ckpt_saved_counter, dp.restore_detail, dp.ckpt_scrub_errors,
      (unsigned long long)sp.ckpt_saved_counter);
    for (int q = 0; q < MG_QUARANTINE_MAX; q++)
        if (S->quarantine[q].valid)
            P("QUARANTINE type 0x%x op %u hash %08x\n", S->quarantine[q].type, S->quarantine[q].op,
              S->quarantine[q].hash);
    return o;
}

static size_t fmt_metrics(char *b, size_t n)
{
    size_t o = 0;
    P("%-3s %-8s %-22s %7s %7s %7s %7s %7s %7s  %-10s %s\n", "ID", "SERVICE", "CAUSE", "DETECT", "RESTART",
      "RESTORE", "VERIFY", "RECONN", "TOTAL", "CHECKPOINT", "MISSES");
    uint32_t total = S->rec_count;
    uint32_t start = total > MG_MAX_RECOVERIES ? total - MG_MAX_RECOVERIES : 0;
    for (uint32_t k = start; k < total; k++) {
        const mg_recovery_t *r = &S->rec[k % MG_MAX_RECOVERIES];
        uint64_t t0 = r->t_inject_ms ? r->t_inject_ms : r->t_fail_ms;
        uint64_t t1 = r->t_reconnect_ms ? r->t_reconnect_ms : r->t_healthy_ms;
        const char *ck = r->ckpt_status == MG_CK_NEWEST ? "exact" : r->ckpt_status == MG_CK_FALLBACK ? "fallback"
                       : r->ckpt_status == MG_CK_NONE ? "safe-init" : "n/a";
        P("%-3u %-8s %-22.22s %5lldms %5lldms %5lldms %5lldms %5lldms %5lldms  %-10s %u%s\n",
          r->id, MG_SVC_INFO[r->svc].key, r->cause,
          (long long)(r->t_detect_ms - t0),
          r->t_spawn_ms ? (long long)(r->t_spawn_ms - r->t_detect_ms) : -1LL,
          r->t_ready_ms ? (long long)(r->t_ready_ms - r->t_spawn_ms) : -1LL,
          r->t_healthy_ms ? (long long)(r->t_healthy_ms - r->t_ready_ms) : -1LL,
          r->t_reconnect_ms ? (long long)(r->t_reconnect_ms - r->t_healthy_ms) : -1LL,
          t1 ? (long long)(t1 - t0) : -1LL, ck, r->deadline_miss_during, r->complete ? "" : "  (in progress)");
    }
#undef P
    return o;
}

static int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb)
{
    int status = iofunc_read_verify(ctp, msg, ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    if (ocb->offset == 0)       /* take a fresh snapshot at the start of each read */
        g_len = ocb->attr == &g_attr_metrics ? fmt_metrics(g_buf, sizeof g_buf) : fmt_status(g_buf, sizeof g_buf);
    size_t nbytes = 0;
    if ((size_t)ocb->offset < g_len) {
        nbytes = g_len - (size_t)ocb->offset;
        if (nbytes > msg->i.nbytes) nbytes = msg->i.nbytes;
    }
    if (nbytes) {
        MsgReply(ctp->rcvid, (long)nbytes, g_buf + ocb->offset, nbytes);
        ocb->offset += (off_t)nbytes;
    } else {
        MsgReply(ctp->rcvid, 0, NULL, 0);
    }
    return _RESMGR_NOREPLY;
}

static int on_timer(message_context_t *ctp, int code, unsigned flags, void *handle)
{
    (void)ctp; (void)code; (void)flags; (void)handle;
    mg_heartbeat(MG_SVC_STATUSFS);
    mg_inject_poll(MG_SVC_STATUSFS);
    return 0;
}

int main(void)
{
    const mg_svc_info_t *me = &MG_SVC_INFO[MG_SVC_STATUSFS];
    mg_log_init("mg_statusfs", MG_SVC_STATUSFS);
    mg_set_rt(me->priority, me->cpu);
    S = mg_shm_attach(false);
    if (!S) { mg_log(MG_ERROR, "shared memory not found - start mg_supervisor"); return MG_EXIT_CONFIG; }
    mg_ctl_start(MG_SVC_STATUSFS);

    dispatch_t *dpp = dispatch_create();
    if (!dpp) { mg_log(MG_ERROR, "dispatch_create: %s", strerror(errno)); return 1; }
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &g_cfuncs, _RESMGR_IO_NFUNCS, &g_iofuncs);
    g_iofuncs.read = io_read;

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof rattr);
    rattr.nparts_max = 1;
    rattr.msg_max_size = 2048;

    iofunc_attr_init(&g_attr_status, S_IFREG | 0444, NULL, NULL);
    iofunc_attr_init(&g_attr_metrics, S_IFREG | 0444, NULL, NULL);
    if (resmgr_attach(dpp, &rattr, "/dev/memguard/status", _FTYPE_ANY, 0, &g_cfuncs, &g_iofuncs, &g_attr_status) == -1 ||
        resmgr_attach(dpp, &rattr, "/dev/memguard/metrics", _FTYPE_ANY, 0, &g_cfuncs, &g_iofuncs, &g_attr_metrics) == -1) {
        mg_log(MG_ERROR, "resmgr_attach: %s (needs root)", strerror(errno));
        return 1;
    }

    /* heartbeat timer delivered as a pulse into the same dispatch loop */
    int code = pulse_attach(dpp, MSG_FLAG_ALLOC_PULSE, 0, on_timer, NULL);
    int coid = message_connect(dpp, MSG_FLAG_SIDE_CHANNEL);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, me->priority, code, 0);
    timer_t tid;
    timer_create(CLOCK_MONOTONIC, &ev, &tid);
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = MG_HB_PERIOD_MS * 1000000L;
    its.it_interval.tv_nsec = MG_HB_PERIOD_MS * 1000000L;
    timer_settime(tid, 0, &its, NULL);

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    mg_log(MG_INFO, "serving /dev/memguard/status and /dev/memguard/metrics");
    mg_ready(MG_SVC_STATUSFS, 0);
    for (;;) {
        if ((ctp = dispatch_block(ctp)) == NULL) {
            mg_log(MG_ERROR, "dispatch_block: %s", strerror(errno));
            return 1;
        }
        dispatch_handler(ctp);
    }
    return 0;
}
