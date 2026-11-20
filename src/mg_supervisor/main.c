/*
 * mg_supervisor - MemoryGuard Recovery Supervisor ("Health Monitor")
 *
 *  - starts every service as its own child process (posix_spawn)
 *  - detects crashes instantly (reaper thread blocked in waitpid())
 *  - detects hangs by heartbeat loss (pulses every 50 ms)
 *  - restarts the failed service only (never reboots, never touches the rest)
 *  - verifies health before declaring recovery: READY pulse after the
 *    checkpoint is restored, N heartbeats, then a PING round-trip
 *  - lets dependent clients reconnect only after verification
 *  - quarantines the request a Device Manager crashed on (poison request)
 *  - stops a restart storm and drives the safe state if a critical
 *    service keeps failing
 *  - records detection / restore / verification / reconnection times
 *  - measures response latency (PING round trip) and availability per service
 *  - keeps mg_watchdog alive, and is itself restarted by it: a restarted
 *    supervisor (-r) ADOPTS the services that are still running instead of
 *    restarting them, so critical monitoring never stops
 *
 * Runs at priority 63 on core 1. Usage:
 *   mg_supervisor [-e <maintenance-centre-ip>] [-d <bin-dir>] [-k] [-r]
 *     -k  keep checkpoints from the previous run (default: start fresh)
 *     -r  recovery start by mg_watchdog: adopt the running services
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <spawn.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include "mg_common.h"
#include "mg_proto.h"

extern char **environ;

typedef struct {
    int      state;                /* mirrors S->reg[i].state                 */
    pid_t    pid;
    uint64_t t_spawn_ms, t_ready_ms, verify_deadline_ms;
    int      hb_after_ready;
    int      rec_id;               /* recovery record being filled, or -1     */
    bool     initial;              /* first start, not a recovery              */
    bool     awaiting_exit;        /* we sent SIGKILL/SIGTERM, waiting reaper  */
    bool     operator_stop;
    char     pending_cause[32];
    uint64_t pending_fail_ms, pending_detect_ms;
    uint64_t hist[MG_RESTART_MAX + 1];
    int      nhist;
    bool     reached_running;      /* this process instance became healthy    */
    bool     adopted;              /* not our child: exit found by polling     */
    uint64_t last_acct_ms;         /* availability accounting                  */
    uint64_t hb_grace_until;       /* adopted: time to find the new supervisor */
} svc_rt_t;

static mg_shm_t      *S;
static svc_rt_t       R[MG_SVC_COUNT];
static name_attach_t *g_att;
static int            g_self_coid = -1;
static char           g_bindir[PATH_MAX];
static volatile sig_atomic_t g_quit;
static int            g_dm_wait_rec = -1;   /* DM recovery waiting for client reconnect */
static uint32_t       g_nonce = 1;
static uint64_t       g_verify_min_ms = MG_VERIFY_MIN_MS;
static uint64_t       g_wd_grace_until;     /* new watchdog: give it time to start */
static uint64_t       g_last_tick_ms;       /* stall guard (see tick)               */
static uint64_t       g_stall_grace_until;
static int            g_ping_next;
static uint64_t       g_ping_due;

typedef struct { pid_t pid; int status; uint64_t t_ms; } exit_rec_t;
static exit_rec_t      g_exitq[64];
static unsigned        g_exit_head, g_exit_tail;
static pthread_mutex_t g_exit_mtx = PTHREAD_MUTEX_INITIALIZER;

#define REC(id) (&S->rec[(uint32_t)(id) % MG_MAX_RECOVERIES])

/* ------------------------------------------------------------------ */
static void on_signal(int sig) { (void)sig; g_quit = 1; }

static void *reaper_thread(void *arg)
{
    (void)arg;
    for (;;) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, 0);
        if (pid == -1) {
            if (errno == EINTR) continue;
            usleep(20000);                 /* ECHILD: no children right now */
            continue;
        }
        pthread_mutex_lock(&g_exit_mtx);
        if (g_exit_head - g_exit_tail < 64) {
            exit_rec_t *e = &g_exitq[g_exit_head % 64];
            e->pid = pid;
            e->status = status;
            e->t_ms = mg_now_ms();
            g_exit_head++;
        }
        pthread_mutex_unlock(&g_exit_mtx);
        MsgSendPulse(g_self_coid, MG_SUP_PRIORITY, MG_PULSE_CHILD, 0);
    }
    return NULL;
}

static int find_by_pid(pid_t pid)
{
    for (int i = 0; i < MG_SVC_COUNT; i++)
        if (R[i].pid == pid) return i;
    return -1;
}

static void resolve_bindir(const char *argv0, const char *opt)
{
    char tmp[PATH_MAX];
    if (opt) { snprintf(g_bindir, sizeof g_bindir, "%s", opt); return; }
    const char *env = getenv("MG_BIN_DIR");
    if (env && *env) { snprintf(g_bindir, sizeof g_bindir, "%s", env); return; }
    if (strchr(argv0, '/') && realpath(argv0, tmp)) {
        snprintf(g_bindir, sizeof g_bindir, "%s", dirname(tmp));
        return;
    }
    int fd = open("/proc/self/exefile", O_RDONLY);
    if (fd != -1) {
        ssize_t n = read(fd, tmp, sizeof tmp - 1);
        close(fd);
        if (n > 0) {
            tmp[n] = 0;
            snprintf(g_bindir, sizeof g_bindir, "%s", dirname(tmp));
            return;
        }
    }
    snprintf(g_bindir, sizeof g_bindir, ".");
}

/* kill processes left over from a previous supervisor that was SIGKILLed */
static void kill_leftovers(void)
{
    mg_shm_t *old = mg_shm_attach(false);
    if (!old) return;
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        pid_t p = old->reg[i].pid;
        if (p <= 0 || p == getpid()) continue;
        char path[64], exe[256] = "";
        snprintf(path, sizeof path, "/proc/%d/exefile", (int)p);
        int fd = open(path, O_RDONLY);
        if (fd == -1) continue;
        ssize_t n = read(fd, exe, sizeof exe - 1);
        close(fd);
        if (n > 0) exe[n] = 0;
        if (strstr(exe, MG_SVC_INFO[i].binary)) {
            printf("supervisor: killing leftover %s (pid %d)\n", MG_SVC_INFO[i].binary, (int)p);
            kill(p, SIGKILL);
        }
    }
    /* and a watchdog left over from that run */
    if (old->wd_pid > 0 && old->wd_pid != getppid()) {
        char path[64], exe[256] = "";
        snprintf(path, sizeof path, "/proc/%d/exefile", (int)old->wd_pid);
        int fd = open(path, O_RDONLY);
        if (fd != -1) {
            ssize_t n = read(fd, exe, sizeof exe - 1);
            close(fd);
            if (n > 0) exe[n] = 0;
            if (strstr(exe, "mg_watchdog")) kill(old->wd_pid, SIGKILL);
        }
    }
    munmap(old, sizeof *old);
    usleep(100000);
}

/* ------------------------------------------------------------------ */
/* Recovery records                                                    */
/* ------------------------------------------------------------------ */
static int rec_new(int svc, const char *cause, uint64_t t_fail, uint64_t t_detect)
{
    uint32_t id = S->rec_count;
    mg_recovery_t *r = REC(id);
    memset(r, 0, sizeof *r);
    r->id = id + 1;
    r->svc = (uint32_t)svc;
    snprintf(r->cause, sizeof r->cause, "%s", cause);
    r->t_fail_ms = t_fail;
    r->t_detect_ms = t_detect;
    r->ckpt_status = -1;
    r->ckpt_expected = -1;
    r->ckpt_restored = -1;
    if (mg_ckpt_name(svc)) r->ckpt_expected = (int64_t)S->ck[svc].saved_counter;
    r->sensor_miss_at_fail = S->sensor.deadline_misses;
    if (S->last_inject.svc == (uint32_t)svc && S->last_inject.t_ms &&
        t_detect >= S->last_inject.t_ms && t_detect - S->last_inject.t_ms < 15000) {
        r->t_inject_ms = S->last_inject.t_ms;
        S->last_inject.t_ms = 0;
        S->last_inject.svc = MG_SVC_COUNT;
    }
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    S->rec_count = id + 1;
    return (int)id;
}

static long d(uint64_t a, uint64_t b) { return (a && b && a >= b) ? (long)(a - b) : -1; }

static void rec_print(const mg_recovery_t *r)
{
    uint64_t t0 = r->t_inject_ms ? r->t_inject_ms : r->t_fail_ms;
    char ck[64] = "n/a";
    if (r->ckpt_status == MG_CK_NEWEST)
        snprintf(ck, sizeof ck, "exact (#%lld)", (long long)r->ckpt_restored);
    else if (r->ckpt_status == MG_CK_FALLBACK)
        snprintf(ck, sizeof ck, "fallback #%lld (expected #%lld)",
                 (long long)r->ckpt_restored, (long long)r->ckpt_expected);
    else if (r->ckpt_status == MG_CK_NONE)
        snprintf(ck, sizeof ck, "none -> safe-init");
    printf("\n[RECOVERY #%u] %s: %s\n"
           "   detect %ld ms | restart %ld ms | restore %ld ms | verify %ld ms | reconnect %ld ms"
           " | TOTAL %ld ms\n   checkpoint: %s | critical deadline misses during recovery: %u\n\n",
           r->id, MG_SVC_INFO[r->svc].key, r->cause,
           d(r->t_detect_ms, t0), d(r->t_spawn_ms, r->t_detect_ms), d(r->t_ready_ms, r->t_spawn_ms),
           d(r->t_healthy_ms, r->t_ready_ms), d(r->t_reconnect_ms, r->t_healthy_ms),
           d(r->t_reconnect_ms ? r->t_reconnect_ms : r->t_healthy_ms, t0),
           ck, r->deadline_miss_during);
    fflush(stdout);
    mg_evlog(MG_SVC_COUNT, MG_INFO, "recovered %s (%s) in %ld ms, ckpt %s",
             MG_SVC_INFO[r->svc].key, r->cause,
             d(r->t_reconnect_ms ? r->t_reconnect_ms : r->t_healthy_ms, t0), ck);
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */
static void set_state(int i, int st)
{
    R[i].state = st;
    S->reg[i].state = (uint32_t)st;
}

static int spawn_svc(int i)
{
    char path[PATH_MAX + 64];
    snprintf(path, sizeof path, "%s/%s", g_bindir, MG_SVC_INFO[i].binary);
    char *argv[2] = { (char *)MG_SVC_INFO[i].binary, NULL };
    pid_t pid = -1;
    int rc = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    uint64_t now = mg_now_ms();
    if (rc != 0) {
        mg_evlog(MG_SVC_COUNT, MG_ERROR, "spawn %s failed: %s", path, strerror(rc));
        set_state(i, MG_ST_FAILED);
        R[i].pid = 0;
        S->reg[i].failed_restarts++;
        return -1;
    }
    R[i].pid = pid;
    R[i].reached_running = false;
    R[i].adopted = false;
    S->reg[i].adopted = 0;
    if (!S->reg[i].first_start_ms) S->reg[i].first_start_ms = now;
    R[i].t_spawn_ms = now;
    R[i].t_ready_ms = 0;
    R[i].hb_after_ready = 0;
    R[i].verify_deadline_ms = now + MG_VERIFY_TIMEOUT_MS;
    R[i].awaiting_exit = false;
    R[i].operator_stop = false;
    S->reg[i].pid = pid;
    S->reg[i].started_ms = now;
    S->reg[i].last_hb_ms = now;
    set_state(i, R[i].initial ? MG_ST_STARTING : MG_ST_RECOVERING);
    if (R[i].rec_id >= 0) REC(R[i].rec_id)->t_spawn_ms = now;
    mg_trace("MG SUP spawn %s pid %d", MG_SVC_INFO[i].key, (int)pid);
    printf("supervisor: started %-8s pid %-7d prio %d core %d\n",
           MG_SVC_INFO[i].key, (int)pid, MG_SVC_INFO[i].priority, MG_SVC_INFO[i].cpu);
    fflush(stdout);
    return 0;
}

static bool restart_allowed(int i, uint64_t now)
{
    int n = 0;
    for (int k = 0; k < R[i].nhist; k++)
        if (now - R[i].hist[k] < MG_RESTART_WINDOW_MS) R[i].hist[n++] = R[i].hist[k];
    R[i].nhist = n;
    if (n >= MG_RESTART_MAX) return false;
    R[i].hist[R[i].nhist++] = now;
    return true;
}

static void enter_system_safe(int failed_svc)
{
    S->system_safe = 1;
    mg_evlog(MG_SVC_COUNT, MG_ERROR, "SYSTEM SAFE STATE: %s failed permanently",
             MG_SVC_INFO[failed_svc].key);
    mg_trace("MG SUP SYSTEM SAFE");
    if (failed_svc == MG_SVC_DEVMGR && mg_gpio_init() == 0) {
        /* the machine controller is gone for good: the supervisor holds the
           monitored device in its safe state (stopped) itself */
        int pins[] = { MG_PIN_LED_GREEN, MG_PIN_LED_AMBER, MG_PIN_LED_RED, MG_PIN_BUZZER };
        for (int k = 0; k < 4; k++) mg_gpio_mode_out(pins[k]);
        mg_gpio_write(MG_PIN_LED_GREEN, 0);
        mg_gpio_write(MG_PIN_LED_AMBER, 1);
        mg_gpio_write(MG_PIN_LED_RED, 1);
        mg_gpio_write(MG_PIN_BUZZER, 0);
    }
}

static void request_kill(int i, const char *cause, uint64_t t_fail, int sig)
{
    if (R[i].pid <= 0 || R[i].awaiting_exit) return;
    uint64_t now = mg_now_ms();
    R[i].awaiting_exit = true;
    snprintf(R[i].pending_cause, sizeof R[i].pending_cause, "%s", cause);
    R[i].pending_fail_ms = t_fail;
    R[i].pending_detect_ms = now;
    set_state(i, MG_ST_RECOVERING);
    kill(R[i].pid, sig);
}

static void classify(int status, char *cause, size_t n)
{
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGSEGV || sig == SIGBUS) snprintf(cause, n, "invalid memory access");
        else if (sig == SIGKILL)  snprintf(cause, n, "process termination");
        else if (sig == SIGTERM)  snprintf(cause, n, "terminated");
        else if (sig == SIGABRT)  snprintf(cause, n, "abort");
        else if (sig == SIGILL)   snprintf(cause, n, "illegal instruction");
        else                      snprintf(cause, n, "signal %d", sig);
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == MG_EXIT_RESOURCE) snprintf(cause, n, "resource exhaustion");
        else                          snprintf(cause, n, "exited with code %d", code);
    } else {
        snprintf(cause, n, "unknown exit");
    }
}

static void handle_exit(pid_t pid, int status, uint64_t t_exit)
{
    int i = find_by_pid(pid);
    if (i < 0) return;
    uint64_t now = mg_now_ms();
    char cause[32];
    uint64_t t_fail = t_exit, t_detect = now;

    if (R[i].operator_stop) {
        snprintf(cause, sizeof cause, "operator restart");
    } else if (R[i].awaiting_exit) {
        snprintf(cause, sizeof cause, "%s", R[i].pending_cause);
        t_fail = R[i].pending_fail_ms;
        t_detect = R[i].pending_detect_ms;
        /* it had already crashed when its heartbeat stopped (the kernel was
           still tearing it down): report the real cause */
        if (strcmp(R[i].pending_cause, "heartbeat loss") == 0 && WIFSIGNALED(status) && WTERMSIG(status) != SIGKILL)
            classify(status, cause, sizeof cause);
    } else if (R[i].adopted) {
        snprintf(cause, sizeof cause, "process termination");   /* exit status not visible */
    } else {
        classify(status, cause, sizeof cause);
    }
    /* a restart attempt that died before it passed verification = unsuccessful */
    if (!R[i].reached_running && !R[i].operator_stop) S->reg[i].failed_restarts++;
    S->reg[i].pid = 0;
    S->reg[i].last_exit_status = status;
    snprintf(S->reg[i].last_cause, sizeof S->reg[i].last_cause, "%s", cause);
    R[i].pid = 0;
    if (g_quit) { set_state(i, MG_ST_STOPPED); return; }

    mg_trace("MG SUP FAULT %s: %s", MG_SVC_INFO[i].key, cause);
    mg_evlog(MG_SVC_COUNT, MG_WARN, "FAULT %s: %s (pid %d)", MG_SVC_INFO[i].key, cause, (int)pid);
    printf("supervisor: FAULT in %s -> %s\n", MG_SVC_INFO[i].key, cause);
    fflush(stdout);

    /* a CRASH (not a kill) while the DM was processing a request:
       quarantine that exact request so a retry cannot crash it again */
    bool crash_sig = WIFSIGNALED(status) &&
        (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS || WTERMSIG(status) == SIGILL ||
         WTERMSIG(status) == SIGFPE || WTERMSIG(status) == SIGABRT);
    /* ... or it stopped responding in the middle of a request (hang or a crash
       that was detected through the heartbeat first): same treatment */
    bool hb_kill = R[i].awaiting_exit && strcmp(R[i].pending_cause, "heartbeat loss") == 0;
    if (i == MG_SVC_DEVMGR && (crash_sig || hb_kill) && !R[i].operator_stop &&
        (!R[i].awaiting_exit || hb_kill) && S->dm.inflight_valid) {
        for (int q = 0; q < MG_QUARANTINE_MAX; q++) {
            if (!S->quarantine[q].valid) {
                S->quarantine[q].type = S->dm.inflight_type;
                S->quarantine[q].op = S->dm.inflight_op;
                S->quarantine[q].hash = S->dm.inflight_hash;
                S->quarantine[q].t_ms = now;
                S->quarantine[q].valid = 1;
                mg_evlog(MG_SVC_COUNT, MG_WARN, "quarantined poison request type 0x%x op %u hash %08x",
                         S->dm.inflight_type, S->dm.inflight_op, S->dm.inflight_hash);
                break;
            }
        }
    }
    if (i == MG_SVC_DEVMGR) S->dm.inflight_valid = 0;

    int rid = rec_new(i, cause, t_fail, t_detect);
    S->reg[i].restarts++;
    if (g_dm_wait_rec >= 0 && i == MG_SVC_DEVMGR) {   /* crashed again before clients reconnected */
        REC(g_dm_wait_rec)->complete = 1;
        g_dm_wait_rec = -1;
    }

    if (!restart_allowed(i, now)) {
        set_state(i, MG_ST_FAILED);
        REC(rid)->complete = 1;
        mg_evlog(MG_SVC_COUNT, MG_ERROR, "%s exceeded %d restarts in %d s -> FAILED",
                 MG_SVC_INFO[i].key, MG_RESTART_MAX, MG_RESTART_WINDOW_MS / 1000);
        if (MG_SVC_INFO[i].critical) enter_system_safe(i);
        return;
    }
    R[i].rec_id = rid;
    R[i].initial = false;
    spawn_svc(i);
}

static bool ping_svc(int i, uint32_t *rtt_us)
{
    uint64_t t0 = mg_now_ns();
    int coid = name_open(MG_SVC_INFO[i].attach_name, 0);
    if (coid == -1) return false;
    mg_ping_t p;
    memset(&p, 0, sizeof p);
    p.hdr.type = MG_MSG_PING;
    p.hdr.size = sizeof p;
    p.nonce = g_nonce++;
    mg_ping_reply_t r;
    memset(&r, 0, sizeof r);
    uint64_t timeout_ns = 30ull * 1000000ull;
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &timeout_ns, NULL);
    int rc = MsgSend(coid, &p, sizeof p, &r, sizeof r);
    if (rtt_us) *rtt_us = (uint32_t)((mg_now_ns() - t0) / 1000u);
    name_close(coid);
    return rc != -1 && r.nonce == p.nonce && r.pid == R[i].pid;
}

static void become_healthy(int i)
{
    uint64_t now = mg_now_ms();
    set_state(i, MG_ST_RUNNING);
    R[i].reached_running = true;
    R[i].last_acct_ms = now;
    S->reg[i].epoch++;
    mg_trace("MG SUP %s HEALTHY epoch %u", MG_SVC_INFO[i].key, S->reg[i].epoch);
    if (R[i].initial) {
        printf("supervisor: %-8s healthy after %ld ms (startup)\n", MG_SVC_INFO[i].key,
               (long)(now - R[i].t_spawn_ms));
        fflush(stdout);
        return;
    }
    if (R[i].rec_id < 0) return;
    mg_recovery_t *r = REC(R[i].rec_id);
    r->t_healthy_ms = now;
    r->deadline_miss_during = S->sensor.deadline_misses - r->sensor_miss_at_fail;
    if (i == MG_SVC_DEVMGR) {
        g_dm_wait_rec = R[i].rec_id;          /* wait for the sensor to reconnect */
    } else {
        r->t_reconnect_ms = now;              /* no clients hold a connection */
        r->complete = 1;
        rec_print(r);
    }
    R[i].rec_id = -1;
}

static void on_ready(int i, int status)
{
    if (i < 0 || i >= MG_SVC_COUNT) return;
    if (R[i].state != MG_ST_STARTING && R[i].state != MG_ST_RECOVERING) return;
    uint64_t now = mg_now_ms();
    R[i].t_ready_ms = now;
    R[i].hb_after_ready = 0;
    set_state(i, MG_ST_VERIFYING);
    if (R[i].rec_id >= 0) {
        mg_recovery_t *r = REC(R[i].rec_id);
        r->t_ready_ms = now;
        if (mg_ckpt_name(i)) {
            r->ckpt_status = S->ck[i].restore_status;
            r->ckpt_restored = S->ck[i].restore_counter;
        }
        (void)status;
    }
}

static void spawn_watchdog(void)
{
    char path[PATH_MAX + 64];
    snprintf(path, sizeof path, "%s/mg_watchdog", g_bindir);
    char *argv[2] = { "mg_watchdog", NULL };
    pid_t pid = -1;
    int rc = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (rc != 0) {
        mg_evlog(MG_SVC_COUNT, MG_ERROR, "spawn %s failed: %s", path, strerror(rc));
        g_wd_grace_until = mg_now_ms() + 5000;      /* retry later, not every tick */
        return;
    }
    S->wd_pid = pid;
    S->wd_hb_ms = mg_now_ms();
    g_wd_grace_until = mg_now_ms() + 1000;
    printf("supervisor: started watchdog pid %d (prio %d core %d)\n", (int)pid, MG_WD_PRIORITY, MG_WD_CPU);
    fflush(stdout);
}

/* the watchdog watches us; we keep the watchdog alive */
static void check_watchdog(uint64_t now)
{
    if (now < g_wd_grace_until) return;
    pid_t p = S->wd_pid;
    bool alive = p > 0 && kill(p, 0) == 0;
    if (alive && now - S->wd_hb_ms <= MG_WD_HB_TIMEOUT_MS) return;
    if (p > 0) {
        mg_evlog(MG_SVC_COUNT, MG_WARN, "watchdog %s -> restarting it", alive ? "hung" : "gone");
        if (alive) kill(p, SIGKILL);
        S->wd_restarts++;
    }
    spawn_watchdog();
}

static void account_and_ping(uint64_t now)
{
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        if (R[i].state == MG_ST_RUNNING && R[i].last_acct_ms) S->reg[i].up_ms += now - R[i].last_acct_ms;
        R[i].last_acct_ms = R[i].state == MG_ST_RUNNING ? now : 0;
    }
    /* response latency: one running service per 200 ms, so each once a second */
    if (now < g_ping_due) return;
    g_ping_due = now + MG_PING_PERIOD_MS / MG_SVC_COUNT;
    int i = g_ping_next;
    g_ping_next = (g_ping_next + 1) % MG_SVC_COUNT;
    if (R[i].state != MG_ST_RUNNING || R[i].pid <= 0 || R[i].awaiting_exit) return;
    uint32_t us = 0;
    if (ping_svc(i, &us)) {
        S->reg[i].ping_us = us;
        if (us > S->reg[i].ping_max_us) S->reg[i].ping_max_us = us;
    } else {
        S->reg[i].ping_fail++;
    }
}

static void tick(void)
{
    uint64_t now = mg_now_ms();
    S->sup_hb_ms = now;
    /* if this loop itself was held up, the services' heartbeat pulses are
       still queued behind our timer pulses: give them time to be read before
       judging anyone (otherwise a supervisor delay looks like a service hang) */
    if (g_last_tick_ms && now - g_last_tick_ms > 5 * MG_SUP_TICK_MS) g_stall_grace_until = now + 50;
    g_last_tick_ms = now;
    /* services adopted from a previous supervisor are not our children:
       waitpid() cannot see them die, so poll for their existence */
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        if (R[i].adopted && R[i].pid > 0 && kill(R[i].pid, 0) == -1 && errno == ESRCH)
            handle_exit(R[i].pid, 0, now);
    }
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        if (R[i].pid <= 0 || R[i].awaiting_exit) continue;
        switch (R[i].state) {
        case MG_ST_RUNNING:
            if (now < R[i].hb_grace_until || now < g_stall_grace_until) break;
            if (now - S->reg[i].last_hb_ms > (uint64_t)MG_SVC_INFO[i].hb_timeout_ms) {
                mg_trace("MG SUP %s HEARTBEAT LOSS", MG_SVC_INFO[i].key);
                printf("supervisor: heartbeat loss in %s (%ld ms silent) -> kill + restart\n",
                       MG_SVC_INFO[i].key, (long)(now - S->reg[i].last_hb_ms));
                request_kill(i, "heartbeat loss", S->reg[i].last_hb_ms, SIGKILL);
            }
            break;
        case MG_ST_STARTING:
        case MG_ST_RECOVERING:
        case MG_ST_VERIFYING:
            if (now > R[i].verify_deadline_ms) {
                printf("supervisor: %s failed health verification -> retry\n", MG_SVC_INFO[i].key);
                request_kill(i, "verification timeout", now, SIGKILL);
                break;
            }
            /* defined health-verification period: READY, then at least
               g_verify_min_ms of on-time heartbeats (>= MG_VERIFY_HEARTBEATS),
               then a correct PING answer. Only then are clients let back in. */
            if (R[i].state == MG_ST_VERIFYING && R[i].hb_after_ready >= MG_VERIFY_HEARTBEATS &&
                now - R[i].t_ready_ms >= g_verify_min_ms &&
                now - S->reg[i].last_hb_ms <= (uint64_t)MG_SVC_INFO[i].hb_timeout_ms) {
                uint32_t us = 0;
                if (ping_svc(i, &us)) { S->reg[i].ping_us = us; become_healthy(i); }
            }
            break;
        default:
            break;
        }
    }
    account_and_ping(now);
    check_watchdog(now);
    /* DM recovered but the sensor never reconnected */
    if (g_dm_wait_rec >= 0) {
        mg_recovery_t *r = REC(g_dm_wait_rec);
        if (now - r->t_healthy_ms > 3000) {
            r->complete = 1;
            rec_print(r);
            g_dm_wait_rec = -1;
        }
    }
}

/* ------------------------------------------------------------------ */
/* mgctl commands                                                      */
/* ------------------------------------------------------------------ */
static void note_inject(int svc, const char *kind)
{
    S->last_inject.t_ms = mg_now_ms();
    S->last_inject.svc = (uint32_t)svc;
    snprintf(S->last_inject.kind, sizeof S->last_inject.kind, "%s", kind);
    mg_trace("MG INJECT %s %s", svc >= 0 && svc < MG_SVC_COUNT ? MG_SVC_INFO[svc].key : "?", kind);
}

static int send_to(const char *name, void *msg, size_t len, void *reply, size_t rlen, uint64_t ms)
{
    int coid = name_open(name, 0);
    if (coid == -1) return -1;
    uint64_t ns = ms * 1000000ull;
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &ns, NULL);
    int rc = MsgSend(coid, msg, len, reply, rlen);
    int err = errno;
    name_close(coid);
    errno = err;
    return rc;
}

/* Commands that need an answer from the Device Manager run in a short-lived
   worker thread that replies to mgctl / the web dashboard itself. The DM may
   be crashing or hung (that is the point of the invalid-op test): the
   supervisor's own loop must keep reading heartbeats meanwhile. */
typedef struct { rcvid_t rcvid; uint32_t cmd; int restarted; } dm_job_t;

static void *dm_job(void *arg)
{
    dm_job_t *j = arg;
    mg_sup_reply_t rep;
    memset(&rep, 0, sizeof rep);
    if (j->cmd == MG_CMD_DM_INVALID_OP) {
        mg_dm_diag_msg_t m;
        memset(&m, 0, sizeof m);
        m.hdr.type = MG_MSG_DM_DIAG;
        m.hdr.size = sizeof m;
        m.op = 99;                                   /* outside the diagnostic table */
        int rc = send_to(MG_SVC_INFO[MG_SVC_DEVMGR].attach_name, &m, sizeof m, NULL, 0, 300);
        if (rc == -1 && errno == MG_ERR_QUARANTINED) {
            S->last_inject.t_ms = 0;
            mg_evlog(MG_SVC_COUNT, MG_INFO, "invalid op refused by the DM: request is quarantined");
            snprintf(rep.text, sizeof rep.text, "REJECTED: request is quarantined (it crashed the DM before) - no fault");
        } else if (rc == -1) {
            snprintf(rep.text, sizeof rep.text, "invalid op delivered; DM did not reply (%s) -> watch recovery", strerror(errno));
        } else {
            snprintf(rep.text, sizeof rep.text, "DM handled the op without crashing");
        }
    } else {
        mg_dm_reset_msg_t m;
        memset(&m, 0, sizeof m);
        m.hdr.type = MG_MSG_DM_RESET;
        m.hdr.size = sizeof m;
        int rc = send_to(MG_SVC_INFO[MG_SVC_DEVMGR].attach_name, &m, sizeof m, NULL, 0, 300);
        if (rc == -1 && errno == MG_ERR_RESTRICTED)
            snprintf(rep.text, sizeof rep.text, "reset refused by the Device Manager: nodes not verified yet, or vibration still in zone C/D (mgctl events)");
        else if (rc == -1)
            snprintf(rep.text, sizeof rep.text, "reset: DM unreachable (%s); restarted %d failed service(s)", strerror(errno), j->restarted);
        else
            snprintf(rep.text, sizeof rep.text, "operator reset accepted; restarted %d failed service(s)", j->restarted);
    }
    MsgReply(j->rcvid, EOK, &rep, sizeof rep);
    free(j);
    return NULL;
}

static bool start_dm_job(rcvid_t rcvid, uint32_t cmd, int restarted)
{
    dm_job_t *j = malloc(sizeof *j);
    if (!j) return false;
    j->rcvid = rcvid;
    j->cmd = cmd;
    j->restarted = restarted;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    int rc = pthread_create(&t, &at, dm_job, j);
    pthread_attr_destroy(&at);
    if (rc != 0) { free(j); return false; }
    return true;
}

static void handle_cmd(rcvid_t rcvid, const mg_sup_cmd_t *c)
{
    mg_sup_reply_t rep;
    memset(&rep, 0, sizeof rep);
    int svc = c->svc;
    bool svc_ok = svc >= 0 && svc < MG_SVC_COUNT;

    switch (c->cmd) {
    case MG_CMD_KILL:
        if (!svc_ok || R[svc].pid <= 0) { rep.status = -1; snprintf(rep.text, sizeof rep.text, "service not running"); break; }
        note_inject(svc, "process termination");
        kill(R[svc].pid, SIGKILL);
        snprintf(rep.text, sizeof rep.text, "sent SIGKILL to %s (pid %d)", MG_SVC_INFO[svc].key, (int)R[svc].pid);
        break;

    case MG_CMD_INJECT: {
        if (!svc_ok || R[svc].pid <= 0 || c->arg <= MG_INJ_NONE || c->arg >= MG_INJ_COUNT) {
            rep.status = -1;
            snprintf(rep.text, sizeof rep.text, "bad service or fault kind");
            break;
        }
        mg_inject_msg_t m;
        memset(&m, 0, sizeof m);
        m.hdr.type = MG_MSG_INJECT;
        m.hdr.size = sizeof m;
        m.kind = c->arg;
        note_inject(svc, mg_inject_name(c->arg));
        if (send_to(MG_SVC_INFO[svc].attach_name, &m, sizeof m, NULL, 0, 200) == -1) {
            rep.status = -1;
            snprintf(rep.text, sizeof rep.text, "inject failed: %s", strerror(errno));
        } else {
            snprintf(rep.text, sizeof rep.text, "injected '%s' into %s", mg_inject_name(c->arg), MG_SVC_INFO[svc].key);
        }
        break;
    }

    case MG_CMD_DM_INVALID_OP:
        if (R[MG_SVC_DEVMGR].state != MG_ST_RUNNING) {
            rep.status = -1;
            snprintf(rep.text, sizeof rep.text, "Device Manager is %s - wait until it is RUNNING",
                     mg_state_name(R[MG_SVC_DEVMGR].state));
            break;
        }
        note_inject(MG_SVC_DEVMGR, "invalid operation");
        if (start_dm_job(rcvid, c->cmd, 0)) return;            /* the worker replies */
        rep.status = -1;
        snprintf(rep.text, sizeof rep.text, "could not start the request thread");
        break;

    case MG_CMD_CKPT: {
        const char *name = svc_ok ? mg_ckpt_name(svc) : NULL;
        if (!name) {
            rep.status = -1;
            snprintf(rep.text, sizeof rep.text, "checkpoints exist for sensor, dm, logger and ui");
            break;
        }
        char msg[160];
        int rc = mg_ckpt_tamper(name, (int)c->arg, msg, sizeof msg);
        if (rc == 0 && (c->flags & 1u) && R[svc].pid > 0) {
            note_inject(svc, c->arg == MG_CKT_WITHHOLD ? "checkpoint withheld" : "checkpoint corrupted");
            request_kill(svc, c->arg == MG_CKT_WITHHOLD ? "checkpoint withheld" : "checkpoint corrupted",
                         mg_now_ms(), SIGKILL);
            snprintf(rep.text, sizeof rep.text, "%s; restarting %s to restore", msg, name);
        } else {
            rep.status = rc;
            snprintf(rep.text, sizeof rep.text, "%s", msg);
        }
        break;
    }

    case MG_CMD_RESET: {
        int restarted = 0;
        uint64_t now = mg_now_ms();
        for (int i = 0; i < MG_SVC_COUNT; i++) {
            if (R[i].state == MG_ST_FAILED && R[i].pid <= 0) {
                /* same as "mgctl restart": recorded as a recovery, logged */
                R[i].nhist = 0;
                R[i].initial = false;
                R[i].rec_id = rec_new(i, "operator restart after FAILED", now, now);
                S->reg[i].restarts++;
                mg_evlog(MG_SVC_COUNT, MG_WARN, "operator reset restarts %s (was FAILED)", MG_SVC_INFO[i].key);
                if (spawn_svc(i) == 0) restarted++;
            }
        }
        S->system_safe = 0;
        if (start_dm_job(rcvid, c->cmd, restarted)) return;    /* the worker replies */
        snprintf(rep.text, sizeof rep.text, "restarted %d failed service(s); DM reset not sent", restarted);
        break;
    }

    case MG_CMD_RESTART:
        if (svc_ok && R[svc].pid <= 0 && R[svc].state == MG_ST_FAILED) {
            /* operator brings back a service the restart-storm guard gave up on */
            uint64_t now = mg_now_ms();
            R[svc].nhist = 0;
            R[svc].initial = false;
            R[svc].rec_id = rec_new(svc, "operator restart after FAILED", now, now);
            S->reg[svc].restarts++;
            mg_evlog(MG_SVC_COUNT, MG_WARN, "operator restarts %s (was FAILED)", MG_SVC_INFO[svc].key);
            spawn_svc(svc);
            snprintf(rep.text, sizeof rep.text, "restarting %s (was FAILED)", MG_SVC_INFO[svc].key);
            break;
        }
        if (!svc_ok || R[svc].pid <= 0) { rep.status = -1; snprintf(rep.text, sizeof rep.text, "service not running"); break; }
        R[svc].operator_stop = true;
        request_kill(svc, "operator restart", mg_now_ms(), SIGTERM);
        snprintf(rep.text, sizeof rep.text, "restarting %s", MG_SVC_INFO[svc].key);
        break;

    case MG_CMD_SUP_HANG:
        /* watchdog demo: this supervisor stops scheduling for good. The
           reply goes out first so mgctl does not wait. */
        snprintf(rep.text, sizeof rep.text, "supervisor %d now hangs - mg_watchdog must take over", (int)getpid());
        MsgReply(rcvid, EOK, &rep, sizeof rep);
        mg_evlog(MG_SVC_COUNT, MG_ERROR, "INJECTED: supervisor hang (no more supervisor heartbeats)");
        mg_trace("MG SUP INJECT HANG");
        for (;;) pause();

    case MG_CMD_QCLEAR:
        memset(S->quarantine, 0, sizeof S->quarantine);
        snprintf(rep.text, sizeof rep.text, "quarantine cleared");
        break;

    default:
        rep.status = -1;
        snprintf(rep.text, sizeof rep.text, "unknown command");
        break;
    }
    MsgReply(rcvid, EOK, &rep, sizeof rep);
}

/* ------------------------------------------------------------------ */
static void shutdown_all(void)
{
    printf("supervisor: shutting down services\n");
    S->shutting_down = 1;                         /* the watchdog must not restart us */
    if (S->wd_pid > 0) kill(S->wd_pid, SIGTERM);
    for (int i = 0; i < MG_SVC_COUNT; i++)
        if (R[i].pid > 0) kill(R[i].pid, SIGTERM);
    usleep(300000);
    for (int i = 0; i < MG_SVC_COUNT; i++)
        if (R[i].pid > 0) kill(R[i].pid, SIGKILL);
}

/* is pid still the expected service binary? */
static bool pid_is(pid_t p, const char *binary)
{
    if (p <= 0 || kill(p, 0) == -1) return false;
    char path[64], exe[256] = "";
    snprintf(path, sizeof path, "/proc/%d/exefile", (int)p);
    int fd = open(path, O_RDONLY);
    if (fd == -1) return false;
    ssize_t n = read(fd, exe, sizeof exe - 1);
    close(fd);
    if (n <= 0) return false;
    exe[n] = 0;
    return strstr(exe, binary) != NULL;
}

int main(int argc, char **argv)
{
    const char *bindir_opt = NULL;
    bool keep_ckpt = false, adopt = false;
    int opt;
    while ((opt = getopt(argc, argv, "e:d:kr")) != -1) {
        switch (opt) {
        case 'e': setenv("MG_ECALL_HOST", optarg, 1); break;
        case 'd': bindir_opt = optarg; break;
        case 'k': keep_ckpt = true; break;
        case 'r': adopt = true; keep_ckpt = true; break;
        default:
            fprintf(stderr, "usage: %s [-e maintenance-centre-ip] [-d bin-dir] [-k] [-r]\n", argv[0]);
            return 1;
        }
    }
    resolve_bindir(argv[0], bindir_opt);
    setenv("MG_BIN_DIR", g_bindir, 1);
    const char *vm = getenv("MG_VERIFY_MS");
    if (vm && atoi(vm) > 0) g_verify_min_ms = (uint64_t)atoi(vm);

    mg_log_init("mg_supervisor", MG_SVC_COUNT);
    mg_set_rt(MG_SUP_PRIORITY, MG_SUP_CPU);

    g_att = name_attach(NULL, MG_SUP_NAME, 0);
    if (!g_att) {
        fprintf(stderr, "supervisor: name_attach(%s) failed: %s (already running?)\n",
                MG_SUP_NAME, strerror(errno));
        return 1;
    }

    /* recovery start: keep the shared memory (metrics, checkpoint counters,
       quarantine, event log) and take over whatever still runs */
    if (adopt) {
        S = mg_shm_attach(false);
        if (!S || S->magic != MG_SHM_MAGIC || S->version != MG_SHM_VERSION) {
            fprintf(stderr, "supervisor: -r but no usable shared memory - normal start\n");
            if (S) munmap(S, sizeof *S);
            S = NULL;
            adopt = false;
        }
    }
    if (!adopt) {
        kill_leftovers();
        S = mg_shm_attach(true);
        if (!S) { perror("supervisor: shared memory"); return 1; }
        memset(S, 0, sizeof *S);
        S->magic = MG_SHM_MAGIC;
        S->version = MG_SHM_VERSION;
        S->sup_start_ms = mg_now_ms();
        S->last_inject.svc = MG_SVC_COUNT;
    }
    S->sup_pid = getpid();
    S->sup_hb_ms = mg_now_ms();
    S->shutting_down = 0;

    if (!keep_ckpt) {
        char msg[128];
        for (int i = 0; i < MG_SVC_COUNT; i++)
            if (mg_ckpt_name(i)) mg_ckpt_tamper(mg_ckpt_name(i), MG_CKT_CLEAR, msg, sizeof msg);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    g_self_coid = ConnectAttach(0, 0, g_att->chid, _NTO_SIDE_CHANNEL, 0);
    pthread_t rt;
    pthread_create(&rt, NULL, reaper_thread, NULL);
    pthread_setname_np(rt, "reaper");

    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, g_self_coid, MG_SUP_PRIORITY, MG_PULSE_TICK, 0);
    timer_t tid;
    timer_create(CLOCK_MONOTONIC, &ev, &tid);
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = MG_SUP_TICK_MS * 1000000L;
    its.it_interval.tv_nsec = MG_SUP_TICK_MS * 1000000L;
    timer_settime(tid, 0, &its, NULL);

    printf("\n=== MemoryGuard Auto %s - Recovery Supervisor (pid %d, prio %d, core %d)%s ===\n"
           "binaries: %s\ncheckpoints: %s%s\nmaintenance centre: %s\nhealth verification: READY + >= %d heartbeats + %llu ms + PING\n\n",
           MG_VERSION, (int)getpid(), MG_SUP_PRIORITY, MG_SUP_CPU, adopt ? " - RECOVERY START" : "", g_bindir,
           mg_ckpt_dir(), keep_ckpt ? " (kept from last run)" : " (fresh)", mg_env("MG_ECALL_HOST", "(not set, use -e)"),
           MG_VERIFY_HEARTBEATS, (unsigned long long)g_verify_min_ms);
    fflush(stdout);

    if (adopt) {
        int adopted = 0, restarted = 0;
        uint64_t now = mg_now_ms();
        for (int i = 0; i < MG_SVC_COUNT; i++) {
            R[i].rec_id = -1;
            pid_t p = S->reg[i].pid;
            if (pid_is(p, MG_SVC_INFO[i].binary) && S->reg[i].state == MG_ST_RUNNING) {
                R[i].pid = p;
                R[i].adopted = true;
                R[i].reached_running = true;
                R[i].initial = false;
                R[i].last_acct_ms = now;
                R[i].state = MG_ST_RUNNING;
                S->reg[i].adopted = 1;
                S->reg[i].last_hb_ms = now;        /* fresh heartbeat budget */
                R[i].hb_grace_until = now + 1000;  /* it must first reconnect to us */
                adopted++;
                printf("supervisor: adopted %-8s pid %d (still running, not restarted)\n", MG_SVC_INFO[i].key, (int)p);
            } else {
                /* gone, or caught in the middle of its own recovery: restart it */
                if (p > 0 && pid_is(p, MG_SVC_INFO[i].binary)) kill(p, SIGKILL);
                R[i].initial = false;
                R[i].rec_id = rec_new(i, "restart after supervisor loss", now, now);
                S->reg[i].restarts++;
                spawn_svc(i);
                restarted++;
            }
        }
        S->sup_restarts++;
        S->sup_adopted = (uint32_t)adopted;
        S->sup_recovery_ms = S->sup_fail_ms ? now - S->sup_fail_ms : 0;
        mg_evlog(MG_SVC_COUNT, MG_WARN, "SUPERVISOR RECOVERED by watchdog in %llu ms: %d adopted, %d restarted",
                 (unsigned long long)S->sup_recovery_ms, adopted, restarted);
        mg_trace("MG SUP RECOVERED adopted %d", adopted);
        printf("\n[SUPERVISOR RECOVERY] %s: detect %lld ms | takeover TOTAL %llu ms | %d adopted, %d restarted\n\n",
               S->sup_last_cause[0] ? S->sup_last_cause : "supervisor lost",
               S->sup_detect_ms && S->sup_fail_ms ? (long long)(S->sup_detect_ms - S->sup_fail_ms) : -1LL,
               (unsigned long long)S->sup_recovery_ms, adopted, restarted);
        fflush(stdout);
        /* keep the existing watchdog (it started us) */
        g_wd_grace_until = now + 1000;
    } else {
        mg_evlog(MG_SVC_COUNT, MG_INFO, "supervisor started");
        /* start order: recorder first so it sees everything, then the controller,
           then the sensor (connects to the controller), then the non-critical ones */
        const int order[] = { MG_SVC_LOGGER, MG_SVC_DEVMGR, MG_SVC_SENSOR, MG_SVC_UI, MG_SVC_STATUSFS, MG_SVC_WEBUI };
        _Static_assert(sizeof order / sizeof order[0] == MG_SVC_COUNT, "start order");
        for (int k = 0; k < MG_SVC_COUNT; k++) {
            int i = order[k];
            R[i].rec_id = -1;
            R[i].initial = true;
            spawn_svc(i);
            usleep(50000);
        }
        spawn_watchdog();
    }

    union {
        struct _pulse pulse;
        mg_hdr_t      hdr;
        mg_sup_cmd_t  cmd;
        char          raw[512];
    } msg;

    while (!g_quit) {
        rcvid_t rcvid = MsgReceive(g_att->chid, &msg, sizeof msg, NULL);
        if (rcvid == -1) {
            if (errno == EINTR) continue;
            usleep(1000);
            continue;
        }
        if (rcvid == 0) {
            int v = msg.pulse.value.sival_int;
            switch (msg.pulse.code) {
            case MG_PULSE_HB:
                if (v >= 0 && v < MG_SVC_COUNT) {
                    S->reg[v].last_hb_ms = mg_now_ms();
                    S->reg[v].hb_count++;
                    if (R[v].state == MG_ST_VERIFYING) R[v].hb_after_ready++;
                }
                break;
            case MG_PULSE_READY:
                on_ready(v & 0xFF, (v >> 8) & 0xFF);
                break;
            case MG_PULSE_CHILD:
                for (;;) {
                    exit_rec_t e;
                    pthread_mutex_lock(&g_exit_mtx);
                    bool have = g_exit_tail != g_exit_head;
                    if (have) e = g_exitq[g_exit_tail++ % 64];
                    pthread_mutex_unlock(&g_exit_mtx);
                    if (!have) break;
                    handle_exit(e.pid, e.status, e.t_ms);
                }
                break;
            case MG_PULSE_RECONNECTED:
                if (g_dm_wait_rec >= 0) {
                    mg_recovery_t *r = REC(g_dm_wait_rec);
                    r->t_reconnect_ms = mg_now_ms();
                    r->complete = 1;
                    rec_print(r);
                    g_dm_wait_rec = -1;
                }
                break;
            case MG_PULSE_TICK:
                tick();
                break;
            case _PULSE_CODE_DISCONNECT:
                ConnectDetach(msg.pulse.scoid);
                break;
            default:
                break;
            }
            continue;
        }
        if (msg.hdr.type == _IO_CONNECT) { MsgReply(rcvid, EOK, NULL, 0); continue; }
        if (msg.hdr.type > _IO_BASE && msg.hdr.type <= _IO_MAX) { MsgError(rcvid, ENOSYS); continue; }
        if (msg.hdr.type == MG_MSG_SUP_CMD) handle_cmd(rcvid, &msg.cmd);
        else MsgError(rcvid, ENOSYS);
    }

    shutdown_all();
    name_detach(g_att, 0);
    shm_unlink(MG_SHM_NAME);
    printf("supervisor: stopped\n");
    return 0;
}
