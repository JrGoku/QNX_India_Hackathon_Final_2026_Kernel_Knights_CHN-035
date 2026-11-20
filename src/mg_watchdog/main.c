/*
 * mg_watchdog - watches the Recovery Supervisor (priority 62, core 0)
 *
 * The supervisor restarts every other service; this small process makes sure
 * the supervisor itself cannot become a single point of failure.
 *
 *  - the supervisor writes a heartbeat time into shared memory every 10 ms;
 *    the watchdog reads it every 20 ms
 *  - supervisor gone (process no longer exists) or silent for more than
 *    MG_SUP_HB_TIMEOUT_MS (hung): the watchdog kills what is left of it and
 *    starts a new one with -r. The new supervisor ADOPTS the services that are
 *    still running, so the sensor service and the Device Manager are never
 *    interrupted, and restarts only what died in the meantime
 *  - the watchdog publishes its own heartbeat; the supervisor restarts the
 *    watchdog if it dies or hangs (they watch each other)
 *  - it runs on core 0, away from the supervisor's core 1, so a core-1
 *    overload cannot hide a hung supervisor
 *
 * Started by mg_supervisor; not meant to be started by hand.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <unistd.h>
#include <limits.h>
#include <sys/wait.h>
#include "mg_common.h"

extern char **environ;

static volatile sig_atomic_t g_quit;
static void on_signal(int sig) { (void)sig; g_quit = 1; }

static pid_t start_supervisor(const char *bindir)
{
    char path[PATH_MAX + 32];
    snprintf(path, sizeof path, "%s/mg_supervisor", bindir);
    char *argv[] = { "mg_supervisor", "-r", "-d", (char *)bindir, NULL };
    pid_t pid = -1;
    int rc = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (rc != 0) {
        fprintf(stderr, "watchdog: cannot start %s: %s\n", path, strerror(rc));
        return -1;
    }
    return pid;
}

int main(void)
{
    mg_log_init("mg_watchdog", MG_SVC_COUNT);
    mg_set_rt(MG_WD_PRIORITY, MG_WD_CPU);
    mg_shm_t *S = mg_shm_attach(false);
    if (!S) { fprintf(stderr, "watchdog: no shared memory - start mg_supervisor\n"); return 1; }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    const char *bindir = mg_env("MG_BIN_DIR", ".");
    uint64_t grace_until = mg_now_ms() + 1000;
    mg_log(MG_INFO, "watching supervisor pid %d (timeout %d ms)", (int)S->sup_pid, MG_SUP_HB_TIMEOUT_MS);

    while (!g_quit) {
        usleep(MG_WD_PERIOD_MS * 1000);
        uint64_t now = mg_now_ms();
        S->wd_hb_ms = now;
        while (waitpid(-1, NULL, WNOHANG) > 0) { }     /* reap supervisors we started */
        if (S->shutting_down || now < grace_until) continue;

        pid_t sup = S->sup_pid;
        bool exists = sup > 0 && (kill(sup, 0) == 0 || errno != ESRCH);
        uint64_t last = S->sup_hb_ms;
        bool silent = now > last && now - last > MG_SUP_HB_TIMEOUT_MS;
        if (exists && !silent) continue;
        if (S->shutting_down) continue;

        /* the supervisor is gone or hung */
        S->sup_fail_ms = last;
        S->sup_detect_ms = now;
        snprintf(S->sup_last_cause, sizeof S->sup_last_cause, "%s",
                 exists ? "supervisor hang (no heartbeat)" : "supervisor termination");
        mg_evlog(MG_SVC_COUNT, MG_ERROR, "WATCHDOG: %s after %llu ms silence -> starting a new supervisor",
                 S->sup_last_cause, (unsigned long long)(now - last));
        mg_trace("MG WD SUPERVISOR LOST");
        printf("watchdog: %s (pid %d, %llu ms silent) -> new supervisor\n", S->sup_last_cause, (int)sup,
               (unsigned long long)(now - last));
        fflush(stdout);
        if (exists) {
            kill(sup, SIGKILL);
            for (int k = 0; k < 50 && kill(sup, 0) == 0; k++) usleep(2000);   /* frees its name */
        }
        pid_t np = start_supervisor(bindir);
        if (np > 0) S->sup_pid = np;        /* the new one overwrites this too */
        S->sup_hb_ms = mg_now_ms();
        grace_until = mg_now_ms() + 1000;    /* let it start before judging it */
    }
    return 0;
}
