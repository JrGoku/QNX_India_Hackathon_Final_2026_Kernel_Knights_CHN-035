/*
 * MemoryGuard - mg_webui: browser dashboard (http://<pi-ip>:8080)
 *
 * A supervised NON-critical service, like the UI: it only READS the shared
 * memory and sends the same supervisor commands as mgctl. Killing it (or
 * the browser) never touches monitoring; the page shows "connection lost"
 * and reconnects by itself once the supervisor has restarted it.
 *
 *   GET  /              the dashboard page (embedded, index_html.h)
 *   GET  /api/state     one JSON snapshot of everything the page draws
 *   POST /api/action?do=<action>&svc=<key>&op=<op>&restart=1
 *                       fault injection / operator commands (whitelisted)
 *
 * Actions are accepted only from the maintenance laptop (MG_ECALL_HOST,
 * given to the supervisor with -e) and from the Pi itself; MG_WEB_ALLOW
 * adds addresses ("any" = everyone). Viewing is open to every client.
 *
 * Single-threaded on purpose: the work loop serves one short request at a
 * time with socket timeouts, then heartbeats, so a hang injection or a
 * stuck client really stops the heartbeats and the supervisor notices.
 * Priority 11 (above the stress load at 9) keeps the page live during the
 * CPU-load test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include "mg_common.h"
#include "mg_proto.h"
#include "index_html.h"

extern char **environ;

static mg_shm_t *S;
static pid_t     g_stress_pid;
static uint64_t  g_stress_until;
static uint64_t  g_last_action_ms;
static uint32_t  g_requests, g_actions;

/* ------------------------------------------------------------------ */
/* Output buffer + JSON helpers                                        */
/* ------------------------------------------------------------------ */
#define OUT_MAX (160 * 1024)
static char   g_out[OUT_MAX];
static size_t g_len;

static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out(const char *fmt, ...)
{
    if (g_len >= OUT_MAX - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(g_out + g_len, OUT_MAX - g_len, fmt, ap);
    va_end(ap);
    if (n > 0) g_len += (size_t)n < OUT_MAX - g_len ? (size_t)n : OUT_MAX - g_len - 1;
}

static void js(const char *s)          /* JSON string */
{
    out("\"");
    for (; s && *s && g_len < OUT_MAX - 8; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') out("\\%c", c);
        else if (c < 0x20 || c > 0x7e) out(" ");
        else g_out[g_len++] = (char)c;
    }
    g_out[g_len] = 0;
    out("\"");
}

static void jf(float v, int dec)         /* JSON number, null if not finite */
{
    if (!isfinite(v)) out("null");
    else out("%.*f", dec, (double)v);
}

static long long rel(uint64_t t, uint64_t now) { return t ? (long long)t - (long long)now : 0; }

/* ------------------------------------------------------------------ */
/* State snapshot                                                      */
/* ------------------------------------------------------------------ */
static const char *peer_kind(const char *src)
{
    const char *laptop = getenv("MG_ECALL_HOST");
    if (!src || !src[0]) return "";
    if (laptop && strcmp(src, laptop) == 0) return "node_sim (laptop)";
    if (strcmp(src, "127.0.0.1") == 0) return "local";
    return "Wi-Fi node";
}

static void build_state(void)
{
    static mg_sensor_pub_t sp;
    static mg_dm_pub_t dp;
    mg_seq_read(&S->sensor.lock, &sp, &S->sensor, sizeof sp);
    mg_seq_read(&S->dm.lock, &dp, &S->dm, sizeof dp);
    uint64_t now = mg_now_ms();
    char wbuf[96];

    g_len = 0;
    out("{\"v\":\"%s\",\"mono_ms\":%llu,\"uptime_ms\":%llu,\"wall_ms\":%llu,\"safe\":%u,", MG_VERSION,
        (unsigned long long)now,
        (unsigned long long)(S->sup_start_ms ? now - S->sup_start_ms : 0),
        (unsigned long long)mg_wall_ms(), S->system_safe);
    out("\"laptop\":"); js(mg_env("MG_ECALL_HOST", ""));

    /* supervisor + watchdog */
    out(",\"sup\":{\"pid\":%d,\"hb_age\":%lld,\"restarts\":%u,\"cause\":", (int)S->sup_pid,
        S->sup_hb_ms ? (long long)(now - S->sup_hb_ms) : -1LL, S->sup_restarts);
    js(S->sup_last_cause);
    out(",\"takeover_ms\":%llu,\"fail_mono\":%llu,\"adopted\":%u,\"detect_ms\":%lld}", (unsigned long long)S->sup_recovery_ms,
        (unsigned long long)S->sup_fail_ms, S->sup_adopted, S->sup_detect_ms && S->sup_fail_ms ? (long long)(S->sup_detect_ms - S->sup_fail_ms) : -1LL);
    out(",\"wd\":{\"pid\":%d,\"hb_age\":%lld,\"restarts\":%u}", (int)S->wd_pid,
        S->wd_hb_ms ? (long long)(now - S->wd_hb_ms) : -1LL, S->wd_restarts);

    /* services */
    out(",\"svc\":[");
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        const mg_svc_reg_t *r = &S->reg[i];
        const mg_svc_info_t *in = &MG_SVC_INFO[i];
        uint64_t life = r->first_start_ms ? now - r->first_start_ms : 0;
        if (i) out(",");
        out("{\"key\":\"%s\",\"title\":", in->key);
        js(in->title);
        out(",\"state\":\"%s\",\"pid\":%d,\"prio\":%d,\"cpu\":%d,\"crit\":%d,\"hb_age\":%lld,\"hb_limit\":%d,"
            "\"restarts\":%u,\"failed\":%u,\"avail\":",
            mg_state_name(r->state), (int)r->pid, in->priority, in->cpu, in->critical ? 1 : 0,
            r->last_hb_ms ? (long long)(now - r->last_hb_ms) : -1LL, in->hb_timeout_ms, r->restarts, r->failed_restarts);
        if (life) jf((float)(100.0 * (double)r->up_ms / (double)life), 3); else out("null");
        out(",\"lat_ms\":"); jf(r->ping_us / 1000.0f, 2);
        out(",\"lat_max_ms\":"); jf(r->ping_max_us / 1000.0f, 2);
        out(",\"ping_fail\":%u,\"adopted\":%u,\"cause\":", r->ping_fail, r->adopted);
        js(r->last_cause);
        if (i == MG_SVC_DEVMGR) {
            bool up = sp.dm_connected && sp.dm_epoch_connected == r->epoch && r->state == MG_ST_RUNNING;
            out(",\"clients\":\"%s\"", up ? "sensor: UP" : r->state == MG_ST_RUNNING ? "sensor: joining" : "sensor: HELD");
        } else {
            out(",\"clients\":\"shm readers\"");
        }
        const char *cn = mg_ckpt_name(i);
        if (cn) {
            char slot = '-';
            uint64_t cnt = 0, tw = 0;
            const mg_ckpt_pub_t *c = &S->ck[i];
            int act = mg_ckpt_active(cn, &slot, &cnt, &tw);
            out(",\"ck\":{\"name\":\"%s\",\"valid\":%d,\"slot\":\"%c\",\"counter\":%llu,\"age_ms\":%lld,"
                "\"files\":%d,\"saved\":%llu,\"restore\":\"%s\",\"restored\":%lld,\"rslot\":\"%c\"}",
                cn, act == 0, act == 0 ? slot : '-', (unsigned long long)cnt,
                act == 0 ? (long long)(mg_wall_ms() - tw) : -1LL, mg_ckpt_files(cn), (unsigned long long)c->saved_counter,
                c->restore_status == MG_CK_NEWEST ? "newest" : c->restore_status == MG_CK_FALLBACK ? "fallback" : "none",
                (long long)c->restore_counter, c->restore_slot ? c->restore_slot : '-');
        }
        out("}");
    }
    out("]");

    /* machine controller (Device Manager) */
    out(",\"dm\":{\"mode\":\"%s\",\"restricted\":%u,\"tripped\":%u,\"latched\":%u,\"latched_id\":%u,"
        "\"warnings\":", mg_mode_name(dp.mode), dp.restricted, dp.machine_tripped, dp.alarm_latched, dp.latched_event_id);
    js(mg_warn_names(dp.warnings, wbuf, sizeof wbuf));
    out(",\"outputs\":%u,\"gpio\":%u,\"req_ok\":%u,\"req_dup\":%u,\"req_stale\":%u,\"req_invalid\":%u,"
        "\"req_quar\":%u,\"ev_rx\":%u,\"ev_dup\":%u,\"pending\":%u,\"sent\":%u,\"acked\":%u,\"retries\":%u,"
        "\"centre\":%u,\"sensor_stale\":%u,\"scrub\":%u,\"restore\":",
        dp.outputs, dp.gpio_ok, dp.req_ok, dp.req_dup, dp.req_stale, dp.req_invalid, dp.req_quarantined,
        dp.events_received, dp.events_dup, dp.outbox_pending, dp.ecall_sent, dp.ecall_acked, dp.ecall_retries,
        dp.centre_set, dp.sensor_stale, dp.ckpt_scrub_errors);
    js(dp.restore_detail);
    out("}");

    /* alarm log (DM outbox: checkpointed, exactly-once delivery) */
    out(",\"alarms\":[");
    for (uint32_t k = 0; k < dp.alarm_n && k < MG_ALARM_LOG; k++) {
        const mg_event_t *e = &dp.alarm[k].ev;
        if (k) out(",");
        out("{\"id\":%u,\"type\":\"%s\",\"wall\":%llu,\"value\":", e->id, mg_event_name(e->type),
            (unsigned long long)e->t_wall_ms);
        jf(e->value, 2); out(",\"freq\":"); jf(e->freq_hz, 1); out(",\"aux\":"); jf(e->aux, 2);
        out(",\"node\":%u,\"acked\":%u,\"tries\":%u}", e->node_id, dp.alarm[k].acked, dp.alarm[k].tries);
    }
    out("]");

    /* machine + environment */
    bool mach = sp.machine_node != 0xFFFFFFFFu, env = sp.env_node != 0xFFFFFFFFu;
    out(",\"machine\":{\"node\":%d,\"vel\":", mach ? (int)sp.machine_node : -1); jf(sp.vel_mm_s, 2);
    out(",\"vx\":"); jf(sp.vel_xyz[0], 2); out(",\"vy\":"); jf(sp.vel_xyz[1], 2); out(",\"vz\":"); jf(sp.vel_xyz[2], 2);
    out(",\"acc_rms\":"); jf(sp.acc_rms_g, 3); out(",\"acc_peak\":"); jf(sp.acc_peak_g, 3);
    out(",\"crest\":"); jf(sp.crest, 1); out(",\"freq\":"); jf(sp.freq_hz, 1); out(",\"rpm\":"); jf(sp.rpm, 0);
    out(",\"chip_temp\":"); jf(sp.chip_temp_c, 1); out(",\"tilt\":"); jf(sp.mount_tilt_deg, 1);
    out(",\"zone\":\"%s\",\"node_zone\":\"%s\",\"running\":%u,\"peak60\":", mg_zone_name(sp.zone),
        mg_zone_name(sp.node_zone), sp.running);
    jf(sp.peak_vel_60s, 2);
    out(",\"env_node\":%d,\"env_temp\":", env ? (int)sp.env_node : -1); jf(env && sp.env_ok ? sp.env_temp_c : NAN, 1);
    out(",\"env_hum\":"); jf(sp.env_hum, 0); out(",\"env_press\":"); jf(sp.env_press_hpa, 1);
    out(",\"warnings\":"); js(mg_warn_names(sp.warnings, wbuf, sizeof wbuf));
    /* limits as the sensor service applies them (validated there); defaults until it publishes */
    bool lim = sp.lim_temp_max > sp.lim_temp_warn && sp.lim_zone_cd > 0;
    out(",\"zone_ab\":"); jf(lim ? sp.lim_zone_ab : MG_ZONE_AB_DEFAULT, 2);
    out(",\"zone_bc\":"); jf(lim ? sp.lim_zone_bc : MG_ZONE_BC_DEFAULT, 2);
    out(",\"zone_cd\":"); jf(lim ? sp.lim_zone_cd : MG_ZONE_CD_DEFAULT, 2);
    out(",\"mount_deg\":"); jf(lim ? sp.lim_mount_deg : 10.0f, 1);
    out(",\"temp_warn\":"); jf(lim ? sp.lim_temp_warn : 40.0f, 1);
    out(",\"temp_max\":"); jf(lim ? sp.lim_temp_max : 50.0f, 1);
    out(",\"mach_ok\":%u,\"env_ok\":%u,\"slips\":%u", sp.mach_ok, sp.env_ok, sp.slips);
    out(",\"cycles\":%llu,\"misses\":%u,\"max_late\":", (unsigned long long)sp.cycles, sp.deadline_misses);
    jf(sp.max_late_ms, 2); out(",\"exec_ms\":"); jf(sp.last_exec_ms, 3); out(",\"max_exec\":"); jf(sp.max_exec_ms, 3);
    long lost = (long)sp.events_created - (long)dp.events_received - (long)sp.events_pending;
    out(",\"dm_link\":%u,\"ev_created\":%u,\"ev_pending\":%u,\"lost\":%ld,\"relayed\":%u,\"unknown\":%u}",
        sp.dm_connected, sp.events_created, sp.events_pending, lost < 0 ? 0 : lost, sp.relayed, sp.unknown_frames);

    /* nodes: identical for node_sim and real nodes - only the sender differs */
    out(",\"nodes\":[");
    for (uint32_t k = 0; k < sp.node_count && k < MG_MAX_NODES; k++) {
        const mg_node_pub_t *n = &sp.node[k];
        if (k) out(",");
        out("{\"id\":%u,\"kind\":", n->id); js(n->kind);
        out(",\"expected\":%u,\"health\":\"%s\",\"reason\":", n->expected, mg_health_name(n->health)); js(n->reason);
        out(",\"src\":"); js(n->src); out(",\"via\":"); js(peer_kind(n->src));
        out(",\"rssi\":%d,\"flags\":%u,\"alive\":%u,\"age_ms\":%lld,\"rx\":%u,\"lost\":%u,\"dup\":%u,\"ooo\":%u,"
            "\"crc\":%u,\"invalid\":%u,\"reboots\":%u,\"st\":%u,\"seq\":%u,\"v\":[",
            (int)n->rssi_dbm, n->flags, n->st.alive, n->st.last_rx_ms ? (long long)(now - n->st.last_rx_ms) : -1LL,
            n->st.rx, n->st.lost, n->st.dup, n->st.out_of_order, n->st.bad_crc, n->st.invalid, n->st.reboots,
            n->st.status_frames, n->st.last_seq);
        for (uint32_t i = 0; i < n->nvals && i < MG_NODE_MAX_VALS; i++) { if (i) out(","); jf(n->v[i], 3); }
        out("]}");
    }
    out("]");

    /* machine history (EDR ring, written by the sensor service): last 2 minutes */
    out(",\"edr\":[");
    {
        uint32_t head = S->edr.head, n = head < 240 ? head : 240, first = 1;
        for (uint32_t k = head - n; k != head; k++) {
            const typeof(S->edr.s[0]) *e = &S->edr.s[k % MG_EDR_SAMPLES];
            if (!e->t_ms || now - e->t_ms > 125000) continue;
            if (!first) out(",");
            first = 0;
            out("[%lld,", rel(e->t_ms, now)); jf(e->vel, 2); out(","); jf(e->temp, 1); out(",%u]", e->zone);
        }
    }
    out("]");

    /* recoveries */
    out(",\"rec_count\":%u,\"rec\":[", S->rec_count);
    {
        uint32_t total = S->rec_count, n = total < 12 ? total : 12;
        for (uint32_t k = total - n; k < total; k++) {
            const mg_recovery_t *r = &S->rec[k % MG_MAX_RECOVERIES];
            if (k != total - n) out(",");
            out("{\"id\":%u,\"svc\":\"%s\",\"cause\":", r->id, r->svc < MG_SVC_COUNT ? MG_SVC_INFO[r->svc].key : "?");
            js(r->cause);
            uint64_t t0 = r->t_inject_ms ? r->t_inject_ms : r->t_fail_ms;
            out(",\"ago_ms\":%lld,\"inject\":%d,\"fail\":%llu,\"detect\":%llu,\"spawn\":%llu,\"ready\":%llu,"
                "\"healthy\":%llu,\"reconnect\":%llu,\"t0\":%llu,\"ck_exp\":%lld,\"ck_res\":%lld,\"ck\":%d,\"miss\":%u,"
                "\"complete\":%u}",
                t0 ? (long long)(now - t0) : -1LL, r->t_inject_ms ? 1 : 0,
                (unsigned long long)r->t_fail_ms, (unsigned long long)r->t_detect_ms, (unsigned long long)r->t_spawn_ms,
                (unsigned long long)r->t_ready_ms, (unsigned long long)r->t_healthy_ms,
                (unsigned long long)r->t_reconnect_ms, (unsigned long long)t0, (long long)r->ckpt_expected,
                (long long)r->ckpt_restored, r->ckpt_status, r->deadline_miss_during, r->complete);
        }
    }
    out("]");

    /* event log (supervisor, watchdog, DM, every service) */
    out(",\"log\":[");
    {
        uint32_t head = S->evlog_head, n = head < MG_EVLOG_SIZE ? head : MG_EVLOG_SIZE, first = 1;
        for (uint32_t k = head - n; k != head; k++) {
            const mg_evlog_entry_t *e = &S->evlog[k % MG_EVLOG_SIZE];
            if (e->seq != k + 1) continue;
            if (!first) out(",");
            first = 0;
            out("{\"seq\":%u,\"t\":%lld,\"src\":\"%s\",\"lvl\":%u,\"text\":", e->seq, rel(e->t_ms, now),
                e->svc < MG_SVC_COUNT ? MG_SVC_INFO[e->svc].key : "supervisor", e->level);
            js(e->text);
            out("}");
        }
    }
    out("]");

    out(",\"quar\":[");
    for (int q = 0, first = 1; q < MG_QUARANTINE_MAX; q++) {
        if (!S->quarantine[q].valid) continue;
        if (!first) out(",");
        first = 0;
        out("{\"type\":%u,\"op\":%u,\"hash\":\"%08x\"}", S->quarantine[q].type, S->quarantine[q].op, S->quarantine[q].hash);
    }
    out("]");

    out(",\"logger\":{\"rows\":%u,\"edr_dumps\":%u,\"events\":%u,\"missed\":%u},\"ui_frames\":%u",
        S->logger.rows, S->logger.edr_dumps, S->logger.events_written, S->logger.events_missed, S->ui.frames);
    out(",\"stress\":%lld,\"web_requests\":%u}",
        g_stress_pid > 0 && g_stress_until > now ? (long long)(g_stress_until - now) : 0LL, g_requests);
}

/* ------------------------------------------------------------------ */
/* Actions (same supervisor commands as mgctl)                         */
/* ------------------------------------------------------------------ */
static char g_msg[256];

static int sup_cmd(uint32_t cmd, int svc, uint32_t arg, uint32_t flags)
{
    int coid = name_open(MG_SUP_NAME, 0);
    if (coid == -1) { snprintf(g_msg, sizeof g_msg, "supervisor not reachable (%s)", strerror(errno)); return 1; }
    mg_sup_cmd_t c;
    memset(&c, 0, sizeof c);
    c.hdr.type = MG_MSG_SUP_CMD;
    c.hdr.size = sizeof c;
    c.cmd = cmd;
    c.svc = svc;
    c.arg = arg;
    c.flags = flags;
    mg_sup_reply_t r;
    memset(&r, 0, sizeof r);
    uint64_t ns = 800ull * 1000000ull;          /* below our own heartbeat budget */
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &ns, NULL);
    int rc = MsgSend(coid, &c, sizeof c, &r, sizeof r);
    name_close(coid);
    if (rc == -1) { snprintf(g_msg, sizeof g_msg, "supervisor did not answer (%s)", strerror(errno)); return 1; }
    r.text[sizeof r.text - 1] = 0;
    snprintf(g_msg, sizeof g_msg, "%s", r.text);
    return r.status == 0 ? 0 : 1;
}

static bool param(const char *q, const char *key, char *val, size_t len)
{
    size_t kl = strlen(key);
    for (const char *p = q; p && *p; ) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') {
            p += kl + 1;
            size_t n = 0;
            while (*p && *p != '&' && n + 1 < len) {
                char c = *p++;
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
                val[n++] = c;
            }
            val[n] = 0;
            return n > 0;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return false;
}

static void reap(void)
{
    if (g_stress_pid > 0 && waitpid(g_stress_pid, NULL, WNOHANG) == g_stress_pid) g_stress_pid = 0;
}

static int start_stress(void)
{
    reap();
    if (g_stress_pid > 0) { snprintf(g_msg, sizeof g_msg, "CPU load test already running"); return 1; }
    char path[160];
    snprintf(path, sizeof path, "%.150s/mgctl", mg_env("MG_BIN_DIR", "."));
    char *argv[] = { "mgctl", "stress", "20", "4", NULL };
    int rc = posix_spawn(&g_stress_pid, path, NULL, NULL, argv, environ);
    if (rc != 0) { g_stress_pid = 0; snprintf(g_msg, sizeof g_msg, "cannot start %s: %s", path, strerror(rc)); return 1; }
    g_stress_until = mg_now_ms() + 20000;
    snprintf(g_msg, sizeof g_msg, "CPU load: 4 busy threads at priority %d on all cores for 20 s (pid %d)",
             MG_STRESS_PRIORITY, (int)g_stress_pid);
    return 0;
}

static int do_action(const char *q)
{
    char a[24] = "", sv[16] = "", op[16] = "", rs[4] = "";
    if (!param(q, "do", a, sizeof a)) { snprintf(g_msg, sizeof g_msg, "missing action"); return 1; }
    param(q, "svc", sv, sizeof sv);
    param(q, "op", op, sizeof op);
    bool restart = param(q, "restart", rs, sizeof rs) && rs[0] == '1';
    int svc = sv[0] ? mg_svc_by_key(sv) : -1;

    if (!strcmp(a, "reset"))  return sup_cmd(MG_CMD_RESET, -1, 0, 0);
    if (!strcmp(a, "qclear")) return sup_cmd(MG_CMD_QCLEAR, -1, 0, 0);
    if (!strcmp(a, "stress")) return start_stress();
    if (!strcmp(a, "suphang")) return sup_cmd(MG_CMD_SUP_HANG, -1, 0, 0);
    if (!strcmp(a, "supkill")) {
        pid_t p = S->sup_pid;
        if (p <= 0 || kill(p, SIGKILL) != 0) { snprintf(g_msg, sizeof g_msg, "supervisor not running"); return 1; }
        snprintf(g_msg, sizeof g_msg, "SIGKILL sent to the supervisor (pid %d) - the watchdog must take over", (int)p);
        return 0;
    }
    if (!strcmp(a, "wdkill")) {
        pid_t p = S->wd_pid;
        if (p <= 0 || kill(p, SIGKILL) != 0) { snprintf(g_msg, sizeof g_msg, "watchdog not running"); return 1; }
        snprintf(g_msg, sizeof g_msg, "SIGKILL sent to the watchdog (pid %d) - the supervisor restarts it", (int)p);
        return 0;
    }
    if (!strcmp(a, "multi")) {
        int rc = sup_cmd(MG_CMD_KILL, MG_SVC_UI, 0, 0);
        rc |= sup_cmd(MG_CMD_KILL, MG_SVC_LOGGER, 0, 0);
        rc |= sup_cmd(MG_CMD_DM_INVALID_OP, MG_SVC_DEVMGR, 0, 0);
        snprintf(g_msg, sizeof g_msg, rc ? "multiple failure: at least one injection was refused"
                                         : "3 simultaneous failures: UI killed, logger killed, DM invalid operation");
        return rc;
    }
    if (svc < 0) { snprintf(g_msg, sizeof g_msg, "unknown service '%s'", sv); return 1; }
    if (!strcmp(a, "kill"))    return sup_cmd(MG_CMD_KILL, svc, 0, 0);
    if (!strcmp(a, "restart")) return sup_cmd(MG_CMD_RESTART, svc, 0, 0);
    if (!strcmp(a, "segv"))    return sup_cmd(MG_CMD_INJECT, svc, MG_INJ_SEGV, 0);
    if (!strcmp(a, "hang"))    return sup_cmd(MG_CMD_INJECT, svc, MG_INJ_HANG, 0);
    if (!strcmp(a, "leak"))    return sup_cmd(MG_CMD_INJECT, svc, MG_INJ_LEAK, 0);
    if (!strcmp(a, "invalid")) {
        if (svc != MG_SVC_DEVMGR) { snprintf(g_msg, sizeof g_msg, "invalid-op is a Device Manager fault"); return 1; }
        return sup_cmd(MG_CMD_DM_INVALID_OP, svc, 0, 0);
    }
    if (!strcmp(a, "ckpt")) {
        uint32_t t = !strcmp(op, "corrupt") ? MG_CKT_CORRUPT : !strcmp(op, "withhold") ? MG_CKT_WITHHOLD
                   : !strcmp(op, "restore") ? MG_CKT_RESTORE : !strcmp(op, "corrupt-both") ? MG_CKT_CORRUPT_BOTH
                   : !strcmp(op, "clear") ? MG_CKT_CLEAR : 0;
        if (!t || !mg_ckpt_name(svc)) { snprintf(g_msg, sizeof g_msg, "no such checkpoint action"); return 1; }
        return sup_cmd(MG_CMD_CKPT, svc, t, restart ? 1u : 0u);
    }
    snprintf(g_msg, sizeof g_msg, "unknown action '%s'", a);
    return 1;
}

static bool may_act(const char *ip)
{
    if (!strcmp(ip, "127.0.0.1")) return true;
    const char *laptop = getenv("MG_ECALL_HOST");
    if (laptop && !strcmp(ip, laptop)) return true;
    const char *allow = getenv("MG_WEB_ALLOW");
    if (!allow) return false;
    if (!strcmp(allow, "any")) return true;
    char buf[256];
    snprintf(buf, sizeof buf, "%s", allow);
    for (char *t = strtok(buf, ", "); t; t = strtok(NULL, ", "))
        if (!strcmp(t, ip)) return true;
    return false;
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */
static void send_all(int fd, const char *p, size_t n)
{
    while (n) {
        ssize_t w = send(fd, p, n, 0);
        if (w <= 0) return;                    /* timeout / client gone: drop it */
        p += w;
        n -= (size_t)w;
    }
}

static void reply(int fd, int code, const char *type, const char *body, size_t len)
{
    char h[256];
    int n = snprintf(h, sizeof h,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
                     code, code == 200 ? "OK" : code == 403 ? "Forbidden" : code == 404 ? "Not Found" : "Bad Request",
                     type, len);
    send_all(fd, h, (size_t)n);
    send_all(fd, body, len);
}

static void handle(int fd, const char *ip)
{
    char req[2048];
    size_t got = 0;
    while (got < sizeof req - 1) {
        ssize_t n = recv(fd, req + got, sizeof req - 1 - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
        req[got] = 0;
        if (strstr(req, "\r\n\r\n")) break;
    }
    req[got] = 0;
    char method[8] = "", path[512] = "";
    if (sscanf(req, "%7s %511s", method, path) != 2) return;
    g_requests++;
    char *query = strchr(path, '?');
    if (query) *query++ = 0;

    if (!strcmp(method, "GET") && (!strcmp(path, "/") || !strcmp(path, "/index.html"))) {
        reply(fd, 200, "text/html; charset=utf-8", MG_INDEX_HTML, sizeof MG_INDEX_HTML - 1);
    } else if (!strcmp(method, "GET") && !strcmp(path, "/api/state")) {
        build_state();
        reply(fd, 200, "application/json", g_out, g_len);
    } else if (!strcmp(method, "POST") && !strcmp(path, "/api/action")) {
        int rc;
        uint64_t now = mg_now_ms();
        if (!may_act(ip)) {
            snprintf(g_msg, sizeof g_msg, "refused: commands only from the maintenance laptop (%s) or the Pi",
                     mg_env("MG_ECALL_HOST", "-e not set"));
            rc = 2;
        } else if (now - g_last_action_ms < 600) {
            snprintf(g_msg, sizeof g_msg, "busy: one command at a time");
            rc = 1;
        } else {
            g_last_action_ms = now;
            g_actions++;
            mg_evlog(MG_SVC_WEBUI, MG_INFO, "web command from %s: %s", ip, query ? query : "");
            rc = do_action(query ? query : "");
        }
        g_len = 0;
        out("{\"ok\":%s,\"text\":", rc == 0 ? "true" : "false");
        js(g_msg);
        out("}");
        reply(fd, rc == 2 ? 403 : 200, "application/json", g_out, g_len);
    } else if (!strcmp(path, "/favicon.ico")) {
        reply(fd, 404, "text/plain", "", 0);
    } else {
        reply(fd, 404, "text/plain", "not found\n", 10);
    }
}

int main(void)
{
    const mg_svc_info_t *me = &MG_SVC_INFO[MG_SVC_WEBUI];
    mg_log_init("mg_webui", MG_SVC_WEBUI);
    mg_set_rt(me->priority, me->cpu);
    signal(SIGPIPE, SIG_IGN);
    S = mg_shm_attach(false);
    if (!S) { mg_log(MG_ERROR, "shared memory not found - start mg_supervisor"); return MG_EXIT_CONFIG; }
    mg_ctl_start(MG_SVC_WEBUI);

    int port = atoi(mg_env("MG_WEB_PORT", "8080"));
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);   /* rebind at once after a restart */
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    int tries = 0;
    while (bind(ls, (struct sockaddr *)&a, sizeof a) != 0) {
        if (++tries > 20) { mg_log(MG_ERROR, "bind :%d: %s", port, strerror(errno)); return MG_EXIT_CONFIG; }
        mg_heartbeat(MG_SVC_WEBUI);
        usleep(50000);
    }
    listen(ls, 8);
    mg_log(MG_INFO, "dashboard on http://<pi-ip>:%d/  (commands from %s)", port, mg_env("MG_ECALL_HOST", "the Pi only"));
    mg_ready(MG_SVC_WEBUI, 0);

    for (;;) {
        mg_heartbeat(MG_SVC_WEBUI);
        mg_inject_poll(MG_SVC_WEBUI);
        reap();
        struct pollfd p = { .fd = ls, .events = POLLIN };
        if (poll(&p, 1, 40) <= 0) continue;
        struct sockaddr_in peer;
        socklen_t pl = sizeof peer;
        int fd = accept(ls, (struct sockaddr *)&peer, &pl);
        if (fd < 0) { usleep(20000); continue; }
        struct timeval tv = { 0, 300000 };     /* a slow client never blocks the heartbeat for long */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        char ip[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
        handle(fd, ip);
        close(fd);
    }
}
