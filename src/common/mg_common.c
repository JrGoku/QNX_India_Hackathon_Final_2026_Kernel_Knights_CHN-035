/*
 * MemoryGuard Auto - common helpers
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>
#include <sys/dispatch.h>
#include <sys/trace.h>
#include <sys/slog2.h>
#include "mg_common.h"
#include "mg_proto.h"

/* ------------------------------------------------------------------ */
/* Service table: priorities, cores and heartbeat budgets              */
/* Core 0 is left for the OS drivers (i2c, network, gpio).             */
/* Core 1: supervisor.  Core 2: critical services.  Core 3: the rest.  */
/* ------------------------------------------------------------------ */
const mg_svc_info_t MG_SVC_INFO[MG_SVC_COUNT] = {
    /* key       binary          attach        title                  prio cpu crit  hb  */
    { "sensor",  "mg_sensor",   "mg_sensor",   "Sensor Service",       55, 2, true,  150 },
    { "dm",      "mg_devmgr",   "mg_dm",       "Device Manager",       50, 2, true,  150 },
    { "logger",  "mg_logger",   "mg_logger",   "Data Logger",          20, 3, false, 1000 },
    { "ui",      "mg_ui",       "mg_ui",       "User Interface",       10, 3, false, 1000 },
    { "statusfs","mg_statusfs", "mg_statusfs", "Status resource mgr",  12, 3, false, 1000 },
    { "webui",   "mg_webui",    "mg_webui",    "Web dashboard",        11, 3, false, 1500 },
};

/* ------------------------------------------------------------------ */
/* Time                                                                */
/* ------------------------------------------------------------------ */
uint64_t mg_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

uint64_t mg_now_ms(void) { return mg_now_ns() / 1000000ull; }

uint64_t mg_wall_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

const char *mg_env(const char *name, const char *def)
{
    const char *v = getenv(name);
    return (v && *v) ? v : def;
}

int mg_mkdirs(const char *path)
{
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0777) == -1 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0777) == -1 && errno != EEXIST) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Shared memory + seqlock                                             */
/* ------------------------------------------------------------------ */
mg_shm_t *mg_shm_attach(bool create)
{
    int fd = shm_open(MG_SHM_NAME, create ? (O_RDWR | O_CREAT) : O_RDWR, 0666);
    if (fd == -1) return NULL;
    if (create) {
        fchmod(fd, 0666);
        if (ftruncate(fd, sizeof(mg_shm_t)) == -1) { close(fd); return NULL; }
    }
    void *p = mmap(NULL, sizeof(mg_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return NULL;
    mg_shm_t *s = (mg_shm_t *)p;
    if (!create && (s->magic != MG_SHM_MAGIC || s->version != MG_SHM_VERSION)) {
        munmap(p, sizeof(mg_shm_t));
        errno = EPROTO;
        return NULL;
    }
    return s;
}

void mg_seq_write_begin(mg_seqlock_t *l)
{
    __atomic_add_fetch(&l->seq, 1, __ATOMIC_ACQ_REL);   /* odd = writing */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

void mg_seq_write_end(mg_seqlock_t *l)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    __atomic_add_fetch(&l->seq, 1, __ATOMIC_ACQ_REL);   /* even = stable */
}

/* A writer that crashed mid-update leaves the counter odd; the
 * restarted writer calls this once to make the section readable again. */
void mg_seq_repair(mg_seqlock_t *l)
{
    if (__atomic_load_n(&l->seq, __ATOMIC_ACQUIRE) & 1u)
        __atomic_add_fetch(&l->seq, 1, __ATOMIC_ACQ_REL);
}

bool mg_seq_read(const mg_seqlock_t *l, void *dst, const void *src, size_t n)
{
    for (int tries = 0; tries < 200; tries++) {
        uint32_t s1 = __atomic_load_n(&l->seq, __ATOMIC_ACQUIRE);
        if (s1 & 1u) { sched_yield(); continue; }
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        memcpy(dst, src, n);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (__atomic_load_n(&l->seq, __ATOMIC_ACQUIRE) == s1) return true;
    }
    memcpy(dst, src, n);     /* writer died mid-update: give best effort */
    return false;
}

/* ------------------------------------------------------------------ */
/* Real-time setup: priority + processor affinity (runmask)            */
/* ------------------------------------------------------------------ */
int mg_set_rt(int priority, int cpu)
{
    int rc = 0;
    struct sched_param sp;
    memset(&sp, 0, sizeof sp);
    sp.sched_priority = priority;
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) != EOK) {
        mg_log(MG_WARN, "could not set priority %d", priority);
        rc = -1;
    }
    if (cpu >= 0 && getenv("MG_NO_PIN") == NULL) {
        int ncpu = _syspage_ptr->num_cpu;
        if (cpu >= ncpu) {
            mg_log(MG_WARN, "cpu %d not present (%d cpus); not pinning", cpu, ncpu);
            return -1;
        }
        int nelem = RMSK_SIZE(ncpu);
        size_t sz = sizeof(int) + 2u * (size_t)nelem * sizeof(unsigned);
        void *data = calloc(1, sz);
        if (!data) return -1;
        int *rsizep = (int *)data;
        unsigned *rmaskp = (unsigned *)(rsizep + 1);
        unsigned *imaskp = rmaskp + nelem;
        *rsizep = nelem;
        RMSK_SET(cpu, rmaskp);   /* where this thread may run         */
        RMSK_SET(cpu, imaskp);   /* inherited by threads created later */
        if (ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT, data) == -1) {
            mg_log(MG_WARN, "runmask to cpu %d failed: %s", cpu, strerror(errno));
            rc = -1;
        }
        free(data);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Logging: slog2 (visible in Momentics "Target System Log" view and   */
/* with `slog2info` on the target) + stderr + shared event log         */
/* ------------------------------------------------------------------ */
static slog2_buffer_t g_slog;
static int            g_slog_ok;
static char           g_logname[32] = "memguard";
static mg_svc_t       g_self = MG_SVC_COUNT;
static mg_shm_t      *g_log_shm;

void mg_log_init(const char *name, mg_svc_t self)
{
    snprintf(g_logname, sizeof g_logname, "%s", name);
    g_self = self;
    slog2_buffer_set_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.num_buffers = 1;
    cfg.buffer_set_name = g_logname;
    cfg.verbosity_level = SLOG2_INFO;
    cfg.buffer_config[0].buffer_name = "main";
    cfg.buffer_config[0].num_pages = 8;
    g_slog_ok = (slog2_register(&cfg, &g_slog, 0) == 0);
    if (self < MG_SVC_COUNT) mg_apply_limits();
}

/* Resource management: every service gets a kernel-enforced address-space
   limit. A leak then makes malloc() fail inside that one process (which
   fail-stops with MG_EXIT_RESOURCE) instead of starving the whole Pi.
   MG_MEM_LIMIT_MB=0 turns it off. */
void mg_apply_limits(void)
{
    /* No core files: while the dumper writes one, a crashed service stays half
       alive (its channel blocks callers, the supervisor cannot reap it) and the
       crash is seen late, as a heartbeat loss. MG_CORE_DUMPS=1 keeps them. */
    if (strcmp(mg_env("MG_CORE_DUMPS", "0"), "1") != 0) {
        struct rlimit core = { 0, 0 };
        setrlimit(RLIMIT_CORE, &core);
    }
    long mb = strtol(mg_env("MG_MEM_LIMIT_MB", ""), NULL, 10);
    if (!*mg_env("MG_MEM_LIMIT_MB", "")) mb = MG_MEM_LIMIT_MB_DEFAULT;
    if (mb <= 0) return;
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = (rlim_t)mb << 20;
    if (setrlimit(RLIMIT_AS, &rl) != 0)
        mg_log(MG_WARN, "memory limit %ld MiB not applied: %s", mb, strerror(errno));
}

static void evlog_write(mg_shm_t *s, mg_svc_t svc, int level, const char *text)
{
    if (!s) return;
    uint32_t n = __atomic_fetch_add(&s->evlog_head, 1, __ATOMIC_ACQ_REL);
    mg_evlog_entry_t *e = &s->evlog[n % MG_EVLOG_SIZE];
    e->seq = 0;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    e->t_ms = mg_now_ms();
    e->svc = (uint32_t)svc;
    e->level = (uint32_t)level;
    snprintf(e->text, sizeof e->text, "%s", text);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    e->seq = n + 1;
}

void mg_log(int level, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (g_slog_ok) {
        uint8_t sev = level >= MG_ERROR ? SLOG2_ERROR : level == MG_WARN ? SLOG2_WARNING : SLOG2_INFO;
        slog2f(g_slog, 0, sev, "%s", buf);
    }
    fprintf(stderr, "[%s] %s%s\n", g_logname,
            level >= MG_ERROR ? "ERROR: " : level == MG_WARN ? "WARN: " : "", buf);
    if (level >= MG_WARN) {
        if (!g_log_shm) g_log_shm = mg_shm_attach(false);
        evlog_write(g_log_shm, g_self, level, buf);
    }
}

void mg_evlog(mg_svc_t svc, int level, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (g_slog_ok) {
        uint8_t sev = level >= MG_ERROR ? SLOG2_ERROR : level == MG_WARN ? SLOG2_WARNING : SLOG2_INFO;
        slog2f(g_slog, 0, sev, "%s", buf);
    }
    fprintf(stderr, "[%s] %s\n", g_logname, buf);
    if (!g_log_shm) g_log_shm = mg_shm_attach(false);
    evlog_write(g_log_shm, svc, level, buf);
}

/* User string events show up in the System Profiler timeline. */
void mg_trace(const char *fmt, ...)
{
    char buf[128];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    (void)TraceEvent(_NTO_TRACE_INSERTUSRSTREVENT, 100, buf);
}

/* ------------------------------------------------------------------ */
/* Pulses to the supervisor                                            */
/* ------------------------------------------------------------------ */
static int      g_sup_coid = -1;
static uint64_t g_sup_retry_ms;
static uint64_t g_last_hb_ms;

void mg_pulse_sup(int code, int value)
{
    uint64_t now = mg_now_ms();
    if (g_sup_coid == -1) {
        if (now < g_sup_retry_ms) return;
        g_sup_coid = name_open(MG_SUP_NAME, 0);
        if (g_sup_coid == -1) { g_sup_retry_ms = now + 100; return; }
    }
    if (MsgSendPulse(g_sup_coid, -1, code, value) == -1) {
        name_close(g_sup_coid);
        g_sup_coid = -1;
        g_sup_retry_ms = now + 100;
    }
}

void mg_heartbeat(mg_svc_t self)
{
    uint64_t now = mg_now_ms();
    if (now - g_last_hb_ms < MG_HB_PERIOD_MS - 10) return;   /* tolerate timer jitter */
    g_last_hb_ms = now;
    mg_pulse_sup(MG_PULSE_HB, (int)self);
}

void mg_ready(mg_svc_t self, int status)
{
    mg_log(MG_INFO, "READY (restore status %d)", status);
    mg_trace("MG %s READY", MG_SVC_INFO[self].key);
    g_last_hb_ms = 0;
    mg_pulse_sup(MG_PULSE_READY, (int)self | (status << 8));
    mg_heartbeat(self);
}

/* ------------------------------------------------------------------ */
/* Names and small utilities                                           */
/* ------------------------------------------------------------------ */
const char *mg_mode_name(uint32_t m)
{
    static const char *n[] = { "BOOT", "NORMAL", "DEGRADED", "ALERT", "SAFE" };
    return m < MG_MODE_COUNT ? n[m] : "?";
}

const char *mg_health_name(uint32_t h)
{
    static const char *n[] = { "UNVERIFIED", "OK", "DEGRADED", "FAULT", "OFFLINE" };
    return h < MG_H_COUNT ? n[h] : "?";
}

const char *mg_state_name(uint32_t s)
{
    static const char *n[] = { "STOPPED", "STARTING", "RUNNING", "RECOVERING", "VERIFYING", "FAILED" };
    return s <= MG_ST_FAILED ? n[s] : "?";
}

const char *mg_event_name(uint32_t e)
{
    static const char *n[] = { "NONE", "VIBRATION_DANGER", "OVER_TEMPERATURE", "SENSOR_MOUNT_LOOSE" };
    return e < MG_EV_COUNT ? n[e] : "?";
}

const char *mg_zone_name(uint32_t z)
{
    static const char *n[] = { "A", "B", "C", "D" };
    return z < 4 ? n[z] : "?";
}

/* "VIB-ALERT NODE-LOST" or "none" */
const char *mg_warn_names(uint32_t w, char *buf, size_t len)
{
    static const char *n[] = { "VIB-ALERT", "SENSOR-FAULT", "NODE-LOST", "MOUNT-MOVED", "ENV-TEMP" };
    size_t o = 0;
    buf[0] = 0;
    for (unsigned k = 0; k < 5; k++)
        if (w & (1u << k)) {
            int r = snprintf(buf + o, len - o, "%s%s", o ? " " : "", n[k]);
            if (r < 0 || (size_t)r >= len - o) break;
            o += (size_t)r;
        }
    if (!o) snprintf(buf, len, "none");
    return buf;
}

const char *mg_inject_name(uint32_t k)
{
    static const char *n[] = { "none", "invalid memory access", "heartbeat loss", "resource exhaustion" };
    return k < MG_INJ_COUNT ? n[k] : "?";
}

int mg_svc_by_key(const char *key)
{
    if (!key) return -1;
    for (int i = 0; i < MG_SVC_COUNT; i++)
        if (strcmp(key, MG_SVC_INFO[i].key) == 0 || strcmp(key, MG_SVC_INFO[i].binary) == 0)
            return i;
    if (strcmp(key, "devmgr") == 0 || strcmp(key, "vc") == 0) return MG_SVC_DEVMGR;
    return -1;
}

uint32_t mg_crc32(const void *data, size_t len)
{
    static uint32_t table[256];
    static int init;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = 1;
    }
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}
