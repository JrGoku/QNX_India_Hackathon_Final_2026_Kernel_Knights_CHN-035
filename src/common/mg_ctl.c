/*
 * MemoryGuard Auto - control channel and fault-injection hooks
 *
 * Every service attaches a name (MG_SVC_INFO[].attach_name) so the
 * supervisor can PING it during health verification and deliver
 * INJECT requests. The injected fault is executed by the service's
 * MAIN loop (mg_inject_poll), not by the control thread, so that a
 * "hang" really stops the work loop and its heartbeats.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include "mg_common.h"
#include "mg_proto.h"

static volatile int   g_inject_kind;
static int            g_leaking;
static size_t         g_leaked;
static uint64_t       g_leak_last_ms;
static name_attach_t *g_ctl_att;
static mg_svc_t       g_ctl_self;
static volatile uintptr_t g_bad_addr = 0x10;   /* an address no process may touch */

#define MG_LEAK_STEP   (1u << 20)        /* 1 MiB per step                 */
#define MG_LEAK_PERIOD 100               /* ms between steps -> visible     */
#define MG_LEAK_BUDGET (64u << 20)       /* own resource guard: 64 MiB      */

void mg_inject_request(int kind)
{
    if (kind > MG_INJ_NONE && kind < MG_INJ_COUNT) g_inject_kind = kind;
}

/* Handles PING / INJECT and the system messages a name_attach() channel
 * receives. Returns 1 if the message was consumed. Used by mg_ctl's own
 * thread and directly by the Device Manager's main loop. */
int mg_ctl_handle(rcvid_t rcvid, const void *msg, size_t len, mg_svc_t self)
{
    const mg_hdr_t *hdr = (const mg_hdr_t *)msg;
    if (len < sizeof(uint16_t)) return 0;

    if (hdr->type == _IO_CONNECT) {               /* client did name_open() */
        MsgReply(rcvid, EOK, NULL, 0);
        return 1;
    }
    if (hdr->type > _IO_BASE && hdr->type <= _IO_MAX) {
        MsgError(rcvid, ENOSYS);
        return 1;
    }
    if (hdr->type == MG_MSG_PING) {
        const mg_ping_t *p = (const mg_ping_t *)msg;
        mg_ping_reply_t r = { p->nonce, (uint32_t)self, 0, getpid() };
        MsgReply(rcvid, EOK, &r, sizeof r);
        return 1;
    }
    if (hdr->type == MG_MSG_INJECT) {
        const mg_inject_msg_t *m = (const mg_inject_msg_t *)msg;
        if (m->kind <= MG_INJ_NONE || m->kind >= MG_INJ_COUNT) {
            MsgError(rcvid, EINVAL);
            return 1;
        }
        mg_log(MG_WARN, "fault injection requested: %s", mg_inject_name(m->kind));
        mg_inject_request((int)m->kind);
        MsgReply(rcvid, EOK, NULL, 0);
        return 1;
    }
    return 0;
}

static void *ctl_thread(void *arg)
{
    (void)arg;
    union {
        struct _pulse pulse;
        mg_hdr_t      hdr;
        char          raw[512];
    } msg;
    for (;;) {
        rcvid_t rcvid = MsgReceive(g_ctl_att->chid, &msg, sizeof msg, NULL);
        if (rcvid == -1) {
            if (errno == EINTR) continue;
            usleep(10000);
            continue;
        }
        if (rcvid == 0) {
            if (msg.pulse.code == _PULSE_CODE_DISCONNECT) ConnectDetach(msg.pulse.scoid);
            continue;
        }
        if (!mg_ctl_handle(rcvid, &msg, sizeof msg, g_ctl_self))
            MsgError(rcvid, ENOSYS);
    }
    return NULL;
}

int mg_ctl_start(mg_svc_t self)
{
    g_ctl_self = self;
    g_ctl_att = name_attach(NULL, MG_SVC_INFO[self].attach_name, 0);
    if (!g_ctl_att) {
        mg_log(MG_ERROR, "name_attach(%s) failed: %s", MG_SVC_INFO[self].attach_name, strerror(errno));
        return -1;
    }
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, ctl_thread, NULL) != EOK) return -1;
    pthread_setname_np(tid, "ctl");
    return 0;
}

/* Called from each service's main loop every iteration. */
void mg_inject_poll(mg_svc_t self)
{
    int kind = g_inject_kind;
    if (kind != MG_INJ_NONE) {
        g_inject_kind = MG_INJ_NONE;
        mg_trace("MG %s INJECT %s", MG_SVC_INFO[self].key, mg_inject_name((uint32_t)kind));
        switch (kind) {
        case MG_INJ_SEGV: {
            mg_log(MG_ERROR, "INJECTED: dereferencing an invalid pointer");
            volatile int *bad = (volatile int *)g_bad_addr;
            *bad = 0xDEAD;                       /* -> SIGSEGV */
            break;
        }
        case MG_INJ_HANG:
            mg_log(MG_ERROR, "INJECTED: main loop blocked forever (no more heartbeats)");
            for (;;) pause();                    /* deadlock-like: blocked, not spinning */
            break;
        case MG_INJ_LEAK:
            mg_log(MG_ERROR, "INJECTED: memory leak started (1 MiB / 100 ms)");
            g_leaking = 1;
            break;
        default:
            break;
        }
    }
    if (g_leaking) {
        uint64_t now = mg_now_ms();
        if (now - g_leak_last_ms >= MG_LEAK_PERIOD) {
            g_leak_last_ms = now;
            char *p = (char *)malloc(MG_LEAK_STEP);
            if (p) {
                memset(p, 0xA5, MG_LEAK_STEP);   /* touch pages so RAM is really used */
                g_leaked += MG_LEAK_STEP;
            }
            if (!p || g_leaked >= MG_LEAK_BUDGET) {
                mg_log(MG_ERROR, "resource guard: %zu MiB leaked, budget exceeded -> fail-stop",
                       g_leaked >> 20);
                mg_trace("MG %s RESOURCE EXHAUSTED", MG_SVC_INFO[self].key);
                exit(MG_EXIT_RESOURCE);
            }
        }
    }
}
