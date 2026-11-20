/*
 * mg_ui - User Interface (NON-critical, priority 10, core 3)
 *
 * 5 Hz display service. Nothing critical depends on this process.
 *
 *  - MG_UI_CONSOLE=1 prints a text status screen once per second.
 *  - MG_DASH_FEED=1 sends a MemoryGuard status frame to the HDMI dashboard
 *    5 times a second: $ND,99,<seq>,MG,<mode>,<nodes ok>,<nodes>,<misses>,0,<flags>*CK
 *    It shows up in the dashboard's Nodes list as "Node 99" (MG_DASH_ID changes
 *    the id): kill the UI and that row goes STALE, then LIVE after the restart.
 *    MG_DASH_PORT (default 5006) / MG_DASH_HOST (default 127.0.0.1).
 *  - MG_OLED=1 drives a 128x64 SSD1306 OLED at 0x3C on the Pi's I2C bus.
 *    The final hardware has no OLED on the Pi (Node 1 has its own).
 *
 * Configuration (which outputs are on, dashboard id) and operating state
 * (frame counter, dashboard sequence number) are checkpointed once a second.
 * A restarted UI restores them before it draws or sends anything, so the
 * dashboard sees the same id and a continuing sequence, not a new device.
 * Without a valid checkpoint it safe-initializes from the environment.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mg_common.h"
#include "mg_proto.h"

static mg_shm_t *S;

#define CKPT_NAME "ui"
#define UI_CKPT_V 1
typedef struct {
    uint32_t version;
    uint32_t console, want_oled, dash_feed, dash_id;   /* configuration   */
    uint32_t frames, dash_seq;                         /* operating state */
    uint32_t reserved[4];
} ui_ckpt_t;
static ui_ckpt_t g_ck;
static uint64_t  g_ck_counter;

static void ckpt_save(void)
{
    if (mg_ckpt_save(CKPT_NAME, &g_ck, sizeof g_ck, &g_ck_counter) == 0)
        S->ck[MG_SVC_UI].saved_counter = g_ck_counter;
}

static char svc_char(uint32_t st)
{
    switch (st) {
    case MG_ST_RUNNING:    return '+';
    case MG_ST_STARTING:
    case MG_ST_RECOVERING:
    case MG_ST_VERIFYING:  return 'R';
    case MG_ST_FAILED:     return 'X';
    default:               return '-';
    }
}

static const char *h3(uint8_t h)
{
    static const char *n[] = { "...", "OK", "DEG", "FLT", "OFF" };
    return h < MG_H_COUNT ? n[h] : "?";
}

/* ---- HDMI dashboard feed: MemoryGuard itself as a node ---- */
static int g_dash = -1;
static struct sockaddr_in g_dash_addr;
static uint32_t g_dash_seq;

static unsigned g_dash_id = 99;

static void dash_open(void)
{
    if (!g_ck.dash_feed) return;
    g_dash_id = g_ck.dash_id;
    int port = atoi(mg_env("MG_DASH_PORT", "5006"));
    const char *host = mg_env("MG_DASH_HOST", "127.0.0.1");
    if (port <= 0 || port > 65535) return;
    memset(&g_dash_addr, 0, sizeof g_dash_addr);
    g_dash_addr.sin_family = AF_INET;
    g_dash_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &g_dash_addr.sin_addr) != 1) {
        mg_log(MG_WARN, "MG_DASH_HOST '%s' is not an IPv4 address - dashboard feed off", host);
        return;
    }
    g_dash = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_dash < 0) { mg_log(MG_WARN, "dashboard socket: %s", strerror(errno)); return; }
    fcntl(g_dash, F_SETFL, fcntl(g_dash, F_GETFL) | O_NONBLOCK);   /* never block the UI loop */
    mg_log(MG_INFO, "sending MemoryGuard status to the HDMI dashboard at %s:%d (node %u)", host, port, g_dash_id);
}

static void dash_send(const mg_sensor_pub_t *sp, const mg_dm_pub_t *dp)
{
    if (g_dash < 0) return;
    unsigned flags = (dp->mode == MG_MODE_SAFE || S->system_safe) ? 1u : 0u;
    char body[96], pkt[112];
    int n = snprintf(body, sizeof body, "ND,%u,%u,MG,%u,%u,%u,%u,0,%u", g_dash_id, (unsigned)g_dash_seq++,
                     dp->mode, sp->hs.nodes_ok, sp->hs.nodes, sp->deadline_misses, flags);
    if (n <= 0 || n >= (int)sizeof body) return;
    uint8_t cs = 0;
    for (int i = 0; i < n; i++) cs ^= (uint8_t)body[i];
    int len = snprintf(pkt, sizeof pkt, "$%s*%02X", body, cs);
    (void)sendto(g_dash, pkt, (size_t)len, 0, (struct sockaddr *)&g_dash_addr, sizeof g_dash_addr);
}

int main(void)
{
    const mg_svc_info_t *me = &MG_SVC_INFO[MG_SVC_UI];
    mg_log_init("mg_ui", MG_SVC_UI);
    mg_set_rt(me->priority, me->cpu);
    S = mg_shm_attach(false);
    if (!S) { mg_log(MG_ERROR, "shared memory not found - start mg_supervisor"); return MG_EXIT_CONFIG; }
    mg_ctl_start(MG_SVC_UI);

    /* restore configuration + operating state before drawing anything */
    mg_ckpt_result_t res;
    uint64_t expected = S->ck[MG_SVC_UI].saved_counter;
    int files = mg_ckpt_files(CKPT_NAME);
    int restore_status;
    if (mg_ckpt_load(CKPT_NAME, &g_ck, sizeof g_ck, expected, &res) == 0 && g_ck.version == UI_CKPT_V) {
        restore_status = res.status;
        g_ck_counter = res.counter;
        S->ck[MG_SVC_UI].restore_counter = (int64_t)res.counter;
        S->ck[MG_SVC_UI].restore_slot = res.slot;
        mg_log(res.status == MG_CK_NEWEST ? MG_INFO : MG_WARN, "checkpoint: %s", res.detail);
    } else {
        memset(&g_ck, 0, sizeof g_ck);           /* safe-init: configuration from the environment */
        g_ck.version = UI_CKPT_V;
        g_ck.console = getenv("MG_UI_CONSOLE") != NULL;
        g_ck.want_oled = getenv("MG_OLED") != NULL && getenv("MG_NO_OLED") == NULL;
        g_ck.dash_feed = getenv("MG_DASH_FEED") != NULL;
        g_ck.dash_id = (uint32_t)atoi(mg_env("MG_DASH_ID", "99"));
        g_ck_counter = expected;
        restore_status = MG_CK_NONE;
        S->ck[MG_SVC_UI].restore_counter = -1;
        S->ck[MG_SVC_UI].restore_slot = '-';
        if (expected || files) mg_evlog(MG_SVC_UI, MG_WARN, "UI: no valid checkpoint -> safe-init from environment");
    }
    S->ck[MG_SVC_UI].restore_status = restore_status;
    ckpt_save();

    bool console = g_ck.console;
    bool want_oled = g_ck.want_oled;
    bool oled_warned = false;
    int fd = -1;
    bool oled = false;
    g_dash_seq = g_ck.dash_seq;
    dash_open();
    uint64_t retry_ms = 0, next_console = 0, next_ckpt = 0;
    uint32_t frame = g_ck.frames;
    mg_ready(MG_SVC_UI, restore_status);

    for (;;) {
        usleep(200000);
        mg_heartbeat(MG_SVC_UI);
        mg_inject_poll(MG_SVC_UI);
        uint64_t now = mg_now_ms();

        if (want_oled && !oled && now >= retry_ms) {
            retry_ms = now + 5000;
            if (fd < 0) fd = mg_i2c_open(mg_env("MG_I2C_DEV", MG_I2C_DEV_DEFAULT), 0);
            oled = fd >= 0 && mg_oled_init(fd) == 0;
            if (oled) {
                mg_log(MG_INFO, "OLED found at 0x%02X", MG_OLED_ADDR);
                oled_warned = false;
            } else if (!oled_warned) {
                mg_log(MG_WARN, "MG_OLED set but no OLED answers at 0x%02X - retrying every 5 s", MG_OLED_ADDR);
                oled_warned = true;
            }
        }

        mg_sensor_pub_t sp;
        mg_dm_pub_t dp;
        mg_seq_read(&S->sensor.lock, &sp, &S->sensor, sizeof sp);
        mg_seq_read(&S->dm.lock, &dp, &S->dm, sizeof dp);
        dash_send(&sp, &dp);

        char l[MG_OLED_ROWS][32];
        snprintf(l[0], sizeof l[0], "MEMGUARD %-9s %c", mg_mode_name(dp.mode), (frame & 1) ? '\x7f' : ' ');
        if (sp.machine_node != 0xFFFFFFFFu)
            snprintf(l[1], sizeof l[1], "VIB N%u %-3s %5.2f Z%s %s", sp.machine_node, h3(sp.hs.machine), sp.vel_mm_s,
                     mg_zone_name(sp.zone), dp.machine_tripped ? "TRIP" : sp.running ? "RUN" : "IDLE");
        else
            snprintf(l[1], sizeof l[1], "VIB NONE ALIVE");
        snprintf(l[2], sizeof l[2], "NODES %u/%u OK %s", sp.hs.nodes_ok, sp.hs.nodes, h3(sp.hs.worst));
        {
            int o = snprintf(l[3], sizeof l[3], "N");
            for (uint32_t k = 0; k < sp.node_count && k < MG_MAX_NODES && o < (int)sizeof l[3] - 6; k++)
                o += snprintf(l[3] + o, sizeof l[3] - (size_t)o, " %u%c", sp.node[k].id,
                              sp.node[k].health == MG_H_OK ? '+' : sp.node[k].health == MG_H_OFFLINE ? 'X' : '!');
        }
        snprintf(l[4], sizeof l[4], "SVC S%c D%c L%c U%c F%c",
                 svc_char(S->reg[MG_SVC_SENSOR].state), svc_char(S->reg[MG_SVC_DEVMGR].state),
                 svc_char(S->reg[MG_SVC_LOGGER].state), svc_char(S->reg[MG_SVC_UI].state),
                 svc_char(S->reg[MG_SVC_STATUSFS].state));
        uint32_t nrec = S->rec_count;
        const mg_recovery_t *r = nrec ? &S->rec[(nrec - 1) % MG_MAX_RECOVERIES] : NULL;
        if (r && r->complete) {
            uint64_t t0 = r->t_inject_ms ? r->t_inject_ms : r->t_fail_ms;
            uint64_t t1 = r->t_reconnect_ms ? r->t_reconnect_ms : r->t_healthy_ms;
            snprintf(l[5], sizeof l[5], "LAST %s %lldMS", MG_SVC_INFO[r->svc].key, t1 ? (long long)(t1 - t0) : -1LL);
        } else if (r) {
            snprintf(l[5], sizeof l[5], "RECOVERING %s", MG_SVC_INFO[r->svc].key);
        } else {
            snprintf(l[5], sizeof l[5], "NO FAULTS YET");
        }
        snprintf(l[6], sizeof l[6], "ALARM %u/%u Q%u", dp.ecall_acked, dp.highest_event_id, dp.outbox_pending);
        snprintf(l[7], sizeof l[7], "MISS %u LATE %.1fMS", sp.deadline_misses, sp.max_late_ms);

        if (oled) {
            for (int k = 0; k < MG_OLED_ROWS; k++) mg_oled_text(k, l[k]);
            /* one page at a time so the shared I2C bus is never held for long */
            for (int p = 0; p < MG_OLED_ROWS && oled; p++) {
                if (mg_oled_flush_page(fd, p) != 0) { oled = false; mg_log(MG_WARN, "OLED write failed"); }
                usleep(2000);
            }
        }
        if (console && now >= next_console) {
            next_console = now + 1000;
            printf("----\n");
            for (int k = 0; k < MG_OLED_ROWS; k++) printf("%s\n", l[k]);
            fflush(stdout);
        }
        frame++;
        if (now >= next_ckpt) {
            next_ckpt = now + 1000;
            g_ck.frames = frame;
            g_ck.dash_seq = g_dash_seq;
            ckpt_save();
        }
        S->ui.frames = frame;
        S->ui.oled_ok = oled;
        S->ui.updated_ms = now;
    }
    return 0;
}
