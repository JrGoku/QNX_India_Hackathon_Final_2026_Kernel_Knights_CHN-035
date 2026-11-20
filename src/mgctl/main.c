/*
 * mgctl - MemoryGuard command-line tool (status + fault injection)
 *
 * Works from an SSH shell on the Pi, or from a Momentics launch
 * configuration whose argument is ${string_prompt} (the whole command
 * typed as one string is split on spaces).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <signal.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>
#include <stdint.h>
#include <sys/dispatch.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>
#include "mg_common.h"
#include "mg_proto.h"

static mg_shm_t *S;

static void usage(void)
{
    puts("mgctl - MemoryGuard control tool\n"
         "\n"
         "  status                         services, machine, nodes, real-time stats\n"
         "  watch                          status every second (Ctrl+C to stop)\n"
         "  metrics                        every recovery with measured timings\n"
         "  events [n]                     last n system events (default 20)\n"
         "\n"
         "  fault injection (the problem statement's five kinds):\n"
         "  kill   <svc>                   process termination (SIGKILL)\n"
         "  inject <svc> segv              invalid memory access\n"
         "  inject <svc> hang              heartbeat loss (main loop blocks)\n"
         "  inject <svc> leak              resource exhaustion (memory leak)\n"
         "  inject dm invalid-op           crash the Device Manager with a bad request\n"
         "  ckpt <svc> corrupt|withhold|corrupt-both [--restart]   (svc: sensor, dm, logger, ui)\n"
         "  ckpt <svc> restore|clear\n"
         "  stress <seconds> [threads]     CPU load at priority 9 on all cores\n"
         "\n"
         "  System Profiler (kernel event trace, needs root):\n"
         "  trace <seconds> [command...]   record a trace; after 1 s run the command, e.g.\n"
         "                                 trace 8 inject dm invalid-op   |   trace 10 stress 5\n"
         "                                 file: /dev/shmem/memguard_<time>.kev (RAM; MG_TRACE_DIR=dir for a disk\n"
         "                                 file, MG_TRACE_IRQ=1 to keep interrupt events)\n"
         "\n"
         "  supervisor / watchdog:\n"
         "  kill supervisor                 terminate the supervisor (watchdog takes over)\n"
         "  inject supervisor hang          supervisor stops beating (watchdog takes over)\n"
         "  kill watchdog                   terminate the watchdog (supervisor restarts it)\n"
         "\n"
         "  multi                          several simultaneous failures: kill ui + kill logger\n"
         "                                 + dm invalid-op, all at once\n"
         "\n"
         "  reset                          operator acknowledge (clears alarm / safe state)\n"
         "  restart <svc>                  graceful restart\n"
         "  qclear                         clear the poison-request quarantine\n"
         "\n"
         "  <svc> = sensor | dm | logger | ui | statusfs");
}

static int sup_cmd(uint32_t cmd, int svc, uint32_t arg, uint32_t flags)
{
    int coid = name_open(MG_SUP_NAME, 0);
    if (coid == -1) { fprintf(stderr, "supervisor not running (%s)\n", strerror(errno)); return 1; }
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
    uint64_t ns = 2000ull * 1000000ull;
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &ns, NULL);
    int rc = MsgSend(coid, &c, sizeof c, &r, sizeof r);
    name_close(coid);
    if (rc == -1) { fprintf(stderr, "supervisor did not answer: %s\n", strerror(errno)); return 1; }
    printf("%s\n", r.text);
    return r.status == 0 ? 0 : 1;
}

static void print_status(void)
{
    mg_sensor_pub_t sp;
    mg_dm_pub_t dp;
    mg_seq_read(&S->sensor.lock, &sp, &S->sensor, sizeof sp);
    mg_seq_read(&S->dm.lock, &dp, &S->dm, sizeof dp);
    uint64_t now = mg_now_ms();
    printf("MemoryGuard %s   uptime %llu s   system safe state: %s\n\n", MG_VERSION,
           (unsigned long long)((now - S->sup_start_ms) / 1000), S->system_safe ? "YES" : "no");
    printf("Supervisor   : pid %d   restarts by watchdog %u (last: %s, takeover %llu ms, %u services adopted)\n",
           (int)S->sup_pid, S->sup_restarts, S->sup_last_cause[0] ? S->sup_last_cause : "-",
           (unsigned long long)S->sup_recovery_ms, S->sup_adopted);
    printf("Watchdog     : pid %d   heartbeat age %llu ms   restarts %u\n\n", (int)S->wd_pid,
           (unsigned long long)(S->wd_hb_ms ? now - S->wd_hb_ms : 0), S->wd_restarts);
    printf("%-8s %-11s %7s %4s %4s %7s %6s %6s %7s %9s %-14s %s\n", "SERVICE", "STATE", "PID", "PRIO", "CORE",
           "HB AGE", "RESTRT", "FAILED", "AVAIL", "LATENCY", "CLIENTS", "LAST FAILURE");
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        const mg_svc_reg_t *r = &S->reg[i];
        uint64_t life = r->first_start_ms ? now - r->first_start_ms : 0;
        char avail[16] = "-", lat[24] = "-", clients[24] = "-";
        if (life) snprintf(avail, sizeof avail, "%.2f%%", 100.0 * (double)r->up_ms / (double)life);
        if (r->ping_us) snprintf(lat, sizeof lat, "%.2fms", r->ping_us / 1000.0);
        if (i == MG_SVC_DEVMGR) {
            /* the sensor service is the DM's client; it may only reconnect after verification */
            bool up = sp.dm_connected && sp.dm_epoch_connected == r->epoch && r->state == MG_ST_RUNNING;
            snprintf(clients, sizeof clients, "%s", up ? "sensor: UP" : r->state == MG_ST_RUNNING ? "sensor: joining" : "sensor: HELD");
        } else {
            snprintf(clients, sizeof clients, "shm readers");
        }
        printf("%-8s %-11s %7d %4d %4d %5llums %6u %6u %7s %9s %-14s %s%s\n", MG_SVC_INFO[i].key,
               mg_state_name(r->state), (int)r->pid, MG_SVC_INFO[i].priority, MG_SVC_INFO[i].cpu,
               (unsigned long long)(now - r->last_hb_ms), r->restarts, r->failed_restarts, avail, lat, clients,
               r->last_cause[0] ? r->last_cause : "-", r->adopted ? "  [adopted]" : "");
    }
    printf("  (FAILED = restart attempts that never passed verification; LATENCY = PING round trip, max");
    for (int i = 0; i < MG_SVC_COUNT; i++) printf(" %s %.1f", MG_SVC_INFO[i].key, S->reg[i].ping_max_us / 1000.0);
    printf(" ms)\n");
    printf("\nCheckpoints (active = newest valid copy on disk):\n");
    for (int i = 0; i < MG_SVC_COUNT; i++) {
        const char *cn = mg_ckpt_name(i);
        if (!cn) continue;
        char slot = '-';
        uint64_t cnt = 0, tw = 0;
        const mg_ckpt_pub_t *c = &S->ck[i];
        const char *rs = c->restore_status == MG_CK_NEWEST ? "newest" : c->restore_status == MG_CK_FALLBACK ? "FALLBACK"
                       : "NONE (safe-init)";
        if (mg_ckpt_active(cn, &slot, &cnt, &tw) == 0)
            printf("  %-7s active slot %c #%-6llu (%5.1f s old)   last start restored: %s #%lld slot %c\n", cn, slot,
                   (unsigned long long)cnt, (double)(mg_wall_ms() - tw) / 1000.0, rs, (long long)c->restore_counter,
                   c->restore_slot ? c->restore_slot : '-');
        else
            printf("  %-7s NO VALID CHECKPOINT ON DISK   last start restored: %s\n", cn, rs);
    }
    printf("\nMachine      : mode %s%s   %s   alarm: %s", mg_mode_name(dp.mode),
           dp.restricted ? " (RESTRICTED safe-init)" : "", dp.machine_tripped ? "TRIPPED (stop command)" : "not tripped",
           dp.alarm_latched ? "LATCHED" : "clear");
    if (dp.gpio_ok)
        printf("   LEDs G%u A%u R%u buzzer %u", dp.outputs & 1u, (dp.outputs >> 1) & 1u, (dp.outputs >> 2) & 1u,
               (dp.outputs >> 3) & 1u);
    printf("\n");
    char wbuf[80];
    if (sp.machine_node != 0xFFFFFFFFu)
        printf("Vibration    : node %u  %.2f mm/s RMS (x %.2f y %.2f z %.2f, 60 s peak %.2f)  ISO zone %s (node says %s)\n"
               "               %s  %.1f Hz = %.0f rpm  acc %.3f g RMS / %.3f g peak (crest %.1f)  mount moved %.1f deg\n",
               sp.machine_node, sp.vel_mm_s, sp.vel_xyz[0], sp.vel_xyz[1], sp.vel_xyz[2], sp.peak_vel_60s,
               mg_zone_name(sp.zone), mg_zone_name(sp.node_zone), sp.running ? "RUNNING" : "IDLE", sp.freq_hz, sp.rpm,
               sp.acc_rms_g, sp.acc_peak_g, sp.crest, sp.mount_tilt_deg);
    else
        printf("Vibration    : no vibration node alive (machine protection inactive)\n");
    if (sp.env_node != 0xFFFFFFFFu) {
        char hum[16] = "n/a";
        if (sp.env_hum >= 0) snprintf(hum, sizeof hum, "%.0f %%", sp.env_hum);
        printf("Environment  : node %u  %.1f C  humidity %s  %.1f hPa\n", sp.env_node, sp.env_temp_c, hum, sp.env_press_hpa);
    } else {
        printf("Environment  : no environment node alive\n");
    }
    printf("Warnings     : %s\n", mg_warn_names(sp.warnings, wbuf, sizeof wbuf));
    printf("Nodes        : %u known, %u OK, worst %s   (relayed %u frames to UDP %u, %u unknown/invalid)\n",
           sp.hs.nodes, sp.hs.nodes_ok, mg_health_name(sp.hs.worst), sp.relayed, sp.relay_port, sp.unknown_frames);
    printf("  %-4s %-5s %-10s %-20s %-15s %6s %6s %5s %5s %5s %5s %5s %6s\n", "ID", "KIND", "HEALTH", "REASON", "FROM",
           "RX", "LOST", "DUP", "REORD", "CRC", "INVAL", "REBOOT", "RSSI");
    for (uint32_t k = 0; k < sp.node_count && k < MG_MAX_NODES; k++) {
        const mg_node_pub_t *n = &sp.node[k];
        char age[16];
        if (n->st.last_rx_ms) snprintf(age, sizeof age, "%s", n->st.alive ? "" : " SILENT");
        else snprintf(age, sizeof age, "%s", n->expected ? " never seen" : "");
        printf("  %-4u %-5s %-10s %-20s %-15s %6u %6u %5u %5u %5u %5u %5u %4d dBm%s\n", n->id,
               n->kind[0] ? n->kind : "-", mg_health_name(n->health), n->reason[0] ? n->reason : "-",
               n->src[0] ? n->src : "-", n->st.rx, n->st.lost, n->st.dup, n->st.out_of_order, n->st.bad_crc,
               n->st.invalid, n->st.reboots, (int)n->rssi_dbm, age);
        if (n->nvals) {
            printf("       values:");
            for (uint32_t i = 0; i < n->nvals && i < MG_NODE_MAX_VALS; i++) printf(" %.3g", n->v[i]);
            printf("\n");
        }
    }
    printf("100 Hz loop  : %llu cycles, deadline misses %u, max lateness %.2f ms, exec %.3f ms (max %.3f)\n",
           (unsigned long long)sp.cycles, sp.deadline_misses, sp.max_late_ms, sp.last_exec_ms, sp.max_exec_ms);
    printf("Controller   : link %s | requests ok %u, duplicate %u, stale %u, invalid %u, quarantined %u\n",
           sp.dm_connected ? "UP" : "DOWN", dp.req_ok, dp.req_dup, dp.req_stale, dp.req_invalid, dp.req_quarantined);
    {
        /* every alarm event is a request that must arrive exactly once */
        long lost = (long)sp.events_created - (long)dp.events_received - (long)sp.events_pending;
        printf("Requests     : events created %u = delivered %u + in flight %u -> LOST %ld | duplicates rejected %u"
               " | recorder missed %u log lines\n",
               sp.events_created, dp.events_received, sp.events_pending, lost < 0 ? 0 : lost, dp.events_dup + dp.req_dup,
               S->logger.events_missed);
    }
    printf("Alarms       : created %u, pending at sensor %u | DM stored %u (dup %u) | notifications sent %u, acked %u, retries %u, queued %u\n",
           sp.events_created, sp.events_pending, dp.events_received, dp.events_dup, dp.ecall_sent, dp.ecall_acked,
           dp.ecall_retries, dp.outbox_pending);
    printf("Checkpoints  : dir %s, DM scrub repairs %u, last DM restore: %s\n", mg_ckpt_dir(),
           dp.ckpt_scrub_errors, dp.restore_detail);
    for (int q = 0; q < MG_QUARANTINE_MAX; q++)
        if (S->quarantine[q].valid)
            printf("Quarantine   : request type 0x%x op %u (hash %08x)\n", S->quarantine[q].type,
                   S->quarantine[q].op, S->quarantine[q].hash);
    printf("Recorder     : %u rows, %u events, %u EDR dumps | UI frames %u%s\n",
           S->logger.rows, S->logger.events_written, S->logger.edr_dumps, S->ui.frames, S->ui.oled_ok ? ", OLED ok" : "");
}

static long dd(uint64_t a, uint64_t b) { return (a && b && a >= b) ? (long)(a - b) : -1; }

static void print_metrics(void)
{
    uint32_t total = S->rec_count;
    if (!total) { puts("no recoveries yet - inject a fault first"); return; }
    printf("%-3s %-8s %-22s %7s %7s %7s %7s %7s %7s  %-24s %s\n", "#", "SERVICE", "CAUSE", "DETECT", "RESTART",
           "RESTORE", "VERIFY", "RECONN", "TOTAL", "CHECKPOINT", "MISSES");
    long sum = 0, worst = 0;
    int n = 0;
    uint32_t start = total > MG_MAX_RECOVERIES ? total - MG_MAX_RECOVERIES : 0;
    for (uint32_t k = start; k < total; k++) {
        const mg_recovery_t *r = &S->rec[k % MG_MAX_RECOVERIES];
        uint64_t t0 = r->t_inject_ms ? r->t_inject_ms : r->t_fail_ms;
        uint64_t t1 = r->t_reconnect_ms ? r->t_reconnect_ms : r->t_healthy_ms;
        char ck[40] = "n/a";
        if (r->ckpt_status == MG_CK_NEWEST) snprintf(ck, sizeof ck, "exact #%lld", (long long)r->ckpt_restored);
        else if (r->ckpt_status == MG_CK_FALLBACK)
            snprintf(ck, sizeof ck, "fallback #%lld (exp #%lld)", (long long)r->ckpt_restored, (long long)r->ckpt_expected);
        else if (r->ckpt_status == MG_CK_NONE) snprintf(ck, sizeof ck, "none -> safe-init");
        long tot = dd(t1, t0);
        printf("%-3u %-8s %-22.22s %5ldms %5ldms %5ldms %5ldms %5ldms %5ldms  %-24s %u%s\n", r->id,
               MG_SVC_INFO[r->svc].key, r->cause, dd(r->t_detect_ms, t0), dd(r->t_spawn_ms, r->t_detect_ms),
               dd(r->t_ready_ms, r->t_spawn_ms), dd(r->t_healthy_ms, r->t_ready_ms),
               dd(r->t_reconnect_ms, r->t_healthy_ms), tot, ck, r->deadline_miss_during,
               r->complete ? "" : "  (in progress)");
        if (r->complete && tot >= 0) { sum += tot; if (tot > worst) worst = tot; n++; }
    }
    if (n) printf("\n%d completed recoveries: average %ld ms, worst %ld ms. No reboots.\n", n, sum / n, worst);
    {
        int exact = 0, fb = 0, none = 0, ck = 0;
        uint32_t misses = 0, failed = 0;
        for (uint32_t k = start; k < total; k++) {
            const mg_recovery_t *r = &S->rec[k % MG_MAX_RECOVERIES];
            if (r->ckpt_status >= 0) ck++;
            if (r->ckpt_status == MG_CK_NEWEST) exact++;
            else if (r->ckpt_status == MG_CK_FALLBACK) fb++;
            else if (r->ckpt_status == MG_CK_NONE) none++;
            misses += r->deadline_miss_during;
        }
        for (int i = 0; i < MG_SVC_COUNT; i++) failed += S->reg[i].failed_restarts;
        printf("Checkpoint restoration: %d of %d exact newest, %d fell back to the previous valid copy, %d safe-init\n",
               exact, ck, fb, none);
        printf("Critical deadline misses during recoveries: %u | unsuccessful restart attempts: %u"
               " | supervisor takeovers: %u\n", misses, failed, S->sup_restarts);
    }
    printf("Timings: DETECT = fault -> supervisor noticed, RESTART = new process created,\n"
           "RESTORE = checkpoint loaded + READY, VERIFY = heartbeats + ping, RECONN = clients reconnected.\n");
}

static void print_events(int count)
{
    uint32_t head = S->evlog_head;
    uint32_t n = head < (uint32_t)count ? head : (uint32_t)count;
    if (n > MG_EVLOG_SIZE) n = MG_EVLOG_SIZE;
    for (uint32_t k = head - n; k != head; k++) {
        const mg_evlog_entry_t *e = &S->evlog[k % MG_EVLOG_SIZE];
        if (e->seq != k + 1) continue;
        printf("%8.3f s  %-10s %-5s %s\n", (double)(e->t_ms - S->sup_start_ms) / 1000.0,
               e->svc < MG_SVC_COUNT ? MG_SVC_INFO[e->svc].key : "supervisor",
               e->level >= MG_ERROR ? "ERROR" : e->level == MG_WARN ? "WARN" : "info", e->text);
    }
}

static volatile int g_stress_run = 1;
/* Each load thread pins itself to one CPU (thread k -> CPU k mod ncpu). Without this the threads
   inherit the runmask of whoever started mgctl: from the web dashboard (pinned to core 3) all four
   ran on core 3 only, so the "all cores" load never reached the critical core 2. */
static void *spin(void *a)
{
    int ncpu = _syspage_ptr->num_cpu;
    int cpu = (int)(intptr_t)a % (ncpu > 0 ? ncpu : 1);
    if (ncpu > 0 && ncpu <= 32 && ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)(1u << cpu)) == -1)
        fprintf(stderr, "stress: could not pin a thread to cpu %d: %s\n", cpu, strerror(errno));
    volatile unsigned long x = 0;
    while (g_stress_run) x++;
    return NULL;
}

static int stress(int seconds, int threads)
{
    struct sched_param sp = { .sched_priority = MG_STRESS_PRIORITY };
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setinheritsched(&at, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&at, SCHED_RR);
    pthread_attr_setschedparam(&at, &sp);
    pthread_t t[16];
    if (threads < 1) threads = 4;
    if (threads > 16) threads = 16;
    uint32_t miss0 = S->sensor.deadline_misses;
    printf("stress: %d busy threads at priority %d for %d s (all cores)...\n", threads, MG_STRESS_PRIORITY, seconds);
    fflush(stdout);
    mg_trace("MG STRESS START");
    for (int k = 0; k < threads; k++) pthread_create(&t[k], &at, spin, (void *)(intptr_t)k);
    sleep((unsigned)seconds);
    g_stress_run = 0;
    for (int k = 0; k < threads; k++) pthread_join(t[k], NULL);
    mg_trace("MG STRESS END");
    printf("stress done: critical-loop deadline misses during load: %u (max lateness so far %.2f ms)\n",
           S->sensor.deadline_misses - miss0, S->sensor.max_late_ms);
    return 0;
}

extern char **environ;
static int run(int ac, char **av);

/* Kernel event trace for the Momentics System Profiler: tracelogger runs for <seconds>; after 1 s a
   "MG TRACE START" marker is written and the optional mgctl command runs, so the fault and everything
   it causes are inside the trace. MemoryGuard's own markers (MG INJECT, MG SUP FAULT, MG SUP spawn,
   MG <svc> READY, MG SUP <svc> HEALTHY, MG DM ALARM ... SENT / ACKED, MG SENSOR DEADLINE MISS ...)
   appear as user events on the timeline. */
static int trace_cmd(int seconds, int nargs, char **args)
{
    if (seconds < 2) seconds = 2;
    if (seconds > 60) seconds = 60;
    char path[192], stamp[32], secs[16], fpath[192];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(stamp, sizeof stamp, "%Y%m%d_%H%M%S", &tm);
    /* The Pi's event rate (4 cores, 1 kHz timers, Wi-Fi interrupts) is ~8 MB/s in wide mode: writing
       that to the SD card made tracelogger drop thousands of buffers. So by default the trace goes to
       RAM (-M: a shared memory object under /dev/shmem, no file writes while tracing), with bigger
       kernel (-k, per CPU) and tracelogger (-b) buffers, and the Interrupt class left out (-F 2: not
       needed to show scheduling, IPC and the markers, and the biggest share of the events). */
    const char *dir = mg_env("MG_TRACE_DIR", "/dev/shmem");
    bool shm = !strcmp(dir, "/dev/shmem");
    snprintf(path, sizeof path, "%s/memguard_%s.kev", dir, stamp);
    snprintf(fpath, sizeof fpath, shm ? "/memguard_%s.kev" : "%s", shm ? stamp : path);  /* -M adds /dev/shmem */
    snprintf(secs, sizeof secs, "%d", seconds);
    char *targv[24];
    int a = 0;
    targv[a++] = "tracelogger";
    targv[a++] = "-w";
    targv[a++] = "-k"; targv[a++] = "64";
    targv[a++] = "-b"; targv[a++] = "1024";
    if (!getenv("MG_TRACE_IRQ")) { targv[a++] = "-F"; targv[a++] = "2"; }
    if (getenv("MG_TRACE_LIGHT")) { targv[a++] = "-F"; targv[a++] = "1"; }   /* no kernel calls: ~4x smaller */
    targv[a++] = "-n"; targv[a++] = "0";
    targv[a++] = "-s"; targv[a++] = secs;
    if (shm) { targv[a++] = "-M"; targv[a++] = "-S"; targv[a++] = (char *)mg_env("MG_TRACE_MAX", "400M"); }
    targv[a++] = "-f"; targv[a++] = fpath;
    targv[a] = NULL;
    pid_t tp;
    int err = posix_spawnp(&tp, "tracelogger", NULL, NULL, targv, environ);
    if (err) { fprintf(stderr, "can't start tracelogger: %s\n", strerror(err)); return 1; }
    printf("tracing %d s into %s\n", seconds, path);
    fflush(stdout);
    sleep(1);                                      /* let tracelogger arm the kernel buffers */
    int st;
    if (waitpid(tp, &st, WNOHANG) == tp) {
        fprintf(stderr, "tracelogger stopped at once (exit %d). It needs root: run  su -c \"mgctl trace ...\"\n"
                        "or let Momentics capture the trace (Target Navigator > Kernel Events Tracing).\n",
                WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return 1;
    }
    mg_trace("MG TRACE START %s", nargs ? args[0] : "observe");
    int rc = 0;
    if (nargs) {
        char *sub[16];
        int n = 0;
        sub[n++] = "mgctl";
        for (int k = 0; k < nargs && n < 15; k++) sub[n++] = args[k];
        sub[n] = NULL;
        printf("running: mgctl");
        for (int k = 1; k < n; k++) printf(" %s", sub[k]);
        printf("\n");
        fflush(stdout);
        rc = run(n, sub);
    }
    if (waitpid(tp, &st, 0) != tp || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
        fprintf(stderr, "tracelogger ended with an error - the file may be incomplete\n");
    struct stat sb;
    if (stat(path, &sb) == 0)
        printf("trace done: %s (%lld KB)\n"
               "Momentics: Target File System Navigator > %s > drag the file to a project > open it\n"
               "(System Profiler). Filter the timeline on user events \"MG ...\" to find the fault.\n"
               "%s",
               path, (long long)sb.st_size / 1024, dir,
               shm ? "The file is in RAM: it is gone after a reboot and uses memory until you delete it\n"
                     "(sudo rm /dev/shmem/memguard_*.kev). Keep a copy: cp it to ~/memguard/traces/.\n" : "");
    else
        fprintf(stderr, "no trace file at %s\n", path);
    return rc;
}

static int run(int ac, char **av)
{
    const char *cmd = ac > 1 ? av[1] : "status";
    if (!strcmp(cmd, "trace")) return trace_cmd(ac > 2 ? atoi(av[2]) : 10, ac > 3 ? ac - 3 : 0, av + 3);
    if (!strcmp(cmd, "status")) { print_status(); return 0; }
    if (!strcmp(cmd, "metrics")) { print_metrics(); return 0; }
    if (!strcmp(cmd, "events")) { print_events(ac > 2 ? atoi(av[2]) : 20); return 0; }
    if (!strcmp(cmd, "watch")) {
        for (;;) { printf("\033[2J\033[H"); print_status(); fflush(stdout); sleep(1); }
    }
    if (!strcmp(cmd, "stress")) return stress(ac > 2 ? atoi(av[2]) : 10, ac > 3 ? atoi(av[3]) : 4);
    if (!strcmp(cmd, "reset")) return sup_cmd(MG_CMD_RESET, -1, 0, 0);
    if (!strcmp(cmd, "qclear")) return sup_cmd(MG_CMD_QCLEAR, -1, 0, 0);

    if (ac > 2 && !strcmp(av[2], "watchdog") && !strcmp(cmd, "kill")) {
        if (S->wd_pid <= 0 || kill(S->wd_pid, SIGKILL) != 0) { fprintf(stderr, "watchdog not running\n"); return 1; }
        printf("sent SIGKILL to the watchdog (pid %d) - the supervisor restarts it\n", (int)S->wd_pid);
        return 0;
    }
    if (ac > 2 && (!strcmp(av[2], "supervisor") || !strcmp(av[2], "sup"))) {
        if (!strcmp(cmd, "kill")) {
            pid_t p = S->sup_pid;
            if (p <= 0 || kill(p, SIGKILL) != 0) { fprintf(stderr, "supervisor not running\n"); return 1; }
            printf("sent SIGKILL to the supervisor (pid %d) - the watchdog must take over\n", (int)p);
            return 0;
        }
        if (!strcmp(cmd, "inject") && ac > 3 && !strcmp(av[3], "hang")) return sup_cmd(MG_CMD_SUP_HANG, -1, 0, 0);
        usage();
        return 1;
    }
    if (!strcmp(cmd, "multi")) {
        /* stretch goal: several simultaneous failures, one critical */
        int rc = 0;
        rc |= sup_cmd(MG_CMD_KILL, MG_SVC_UI, 0, 0);
        rc |= sup_cmd(MG_CMD_KILL, MG_SVC_LOGGER, 0, 0);
        rc |= sup_cmd(MG_CMD_DM_INVALID_OP, MG_SVC_DEVMGR, 0, 0);
        puts("three failures injected at once - see 'mgctl metrics'");
        return rc;
    }

    int svc = ac > 2 ? mg_svc_by_key(av[2]) : -1;
    if (!strcmp(cmd, "kill") || !strcmp(cmd, "restart")) {
        if (svc < 0) { usage(); return 1; }
        return sup_cmd(!strcmp(cmd, "kill") ? MG_CMD_KILL : MG_CMD_RESTART, svc, 0, 0);
    }
    if (!strcmp(cmd, "inject")) {
        const char *kind = ac > 3 ? av[3] : "";
        if (svc == MG_SVC_DEVMGR && (!strcmp(kind, "invalid-op") || !strcmp(kind, "invalid")))
            return sup_cmd(MG_CMD_DM_INVALID_OP, svc, 0, 0);
        uint32_t k = !strcmp(kind, "segv") ? MG_INJ_SEGV : !strcmp(kind, "hang") ? MG_INJ_HANG
                   : !strcmp(kind, "leak") ? MG_INJ_LEAK : MG_INJ_NONE;
        if (svc < 0 || k == MG_INJ_NONE) { usage(); return 1; }
        return sup_cmd(MG_CMD_INJECT, svc, k, 0);
    }
    if (!strcmp(cmd, "ckpt")) {
        const char *act = ac > 3 ? av[3] : "";
        uint32_t a = !strcmp(act, "corrupt") ? MG_CKT_CORRUPT : !strcmp(act, "withhold") ? MG_CKT_WITHHOLD
                   : !strcmp(act, "restore") ? MG_CKT_RESTORE : !strcmp(act, "corrupt-both") ? MG_CKT_CORRUPT_BOTH
                   : !strcmp(act, "clear") ? MG_CKT_CLEAR : 0;
        bool restart = ac > 4 && !strcmp(av[4], "--restart");
        if (svc < 0 || a == 0) { usage(); return 1; }
        return sup_cmd(MG_CMD_CKPT, svc, a, restart ? 1u : 0u);
    }
    usage();
    return 1;
}

int main(int argc, char **argv)
{
    /* Momentics ${string_prompt} delivers "inject dm segv" as ONE argument: split it */
    char *av[16];
    int ac = 0;
    char joined[256] = "";
    if (argc == 2 && strchr(argv[1], ' ')) {
        snprintf(joined, sizeof joined, "%s", argv[1]);
        av[ac++] = argv[0];
        for (char *tok = strtok(joined, " "); tok && ac < 15; tok = strtok(NULL, " ")) av[ac++] = tok;
    } else {
        for (int k = 0; k < argc && k < 15; k++) av[ac++] = argv[k];
    }
    av[ac] = NULL;

    const char *cmd = ac > 1 ? av[1] : "status";
    if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) { usage(); return 0; }

    S = mg_shm_attach(false);
    if (!S) { fprintf(stderr, "MemoryGuard is not running (no shared memory). Start mg_supervisor first.\n"); return 1; }

    return run(ac, av);
}

