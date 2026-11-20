/*
 * mg_selftest - hour-zero bring-up test. Run this FIRST from Momentics.
 *
 * Checks, one by one, everything the real system depends on and prints
 * PASS / WARN / FAIL with a hint:
 *   privileges, cores + pinning, shared memory, checkpoint directory,
 *   frames from every Wi-Fi node (UDP 5005), slog2 + trace events.
 *   Only if enabled: GPIO LEDs/buzzer/button (MG_GPIO=1), a local MPU6050
 *   (MG_LOCAL_IMU=1), an OLED on the Pi (MG_OLED=1).
 *
 * Usage: mg_selftest [-q]     (-q = skip the 5 s waits)
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syspage.h>
#include "mg_common.h"

static int g_pass, g_warn, g_fail;

static void result(int level, const char *what, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    const char *tag = level == 0 ? "PASS" : level == 1 ? "WARN" : "FAIL";
    if (level == 0) g_pass++; else if (level == 1) g_warn++; else g_fail++;
    printf("[%s] %-22s %s\n", tag, what, buf);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    bool quick = argc > 1 && !strcmp(argv[1], "-q");
    mg_log_init("mg_selftest", MG_SVC_COUNT);
    printf("\n=== MemoryGuard self-test ===\n\n");

    /* 1. privileges */
    if (geteuid() == 0) result(0, "privileges", "running as root");
    else result(1, "privileges", "not root: GPIO and /dev/memguard need root (launch from Momentics/qconn or su root)");

    /* 2. cores and pinning */
    int ncpu = _syspage_ptr->num_cpu;
    result(ncpu >= 4 ? 0 : 1, "cpu cores", "%d cores%s", ncpu, ncpu >= 4 ? "" : " (layout expects 4: core1 supervisor, core2 critical, core3 others)");
    if (mg_set_rt(20, ncpu > 2 ? 2 : 0) == 0) result(0, "priority + pinning", "SCHED_FIFO 20 pinned to core %d", ncpu > 2 ? 2 : 0);
    else result(1, "priority + pinning", "could not pin (set MG_NO_PIN=1 to run unpinned)");

    /* 3. shared memory */
    int fd = shm_open("/mg_selftest", O_RDWR | O_CREAT, 0666);
    if (fd != -1 && ftruncate(fd, 4096) == 0) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        result(p != MAP_FAILED ? 0 : 2, "shared memory", p != MAP_FAILED ? "shm_open + mmap ok" : "mmap failed");
        if (p != MAP_FAILED) munmap(p, 4096);
    } else {
        result(2, "shared memory", "shm_open failed: %s", strerror(errno));
    }
    if (fd != -1) close(fd);
    shm_unlink("/mg_selftest");

    /* 4. checkpoints */
    {
        struct { uint32_t a, b; char pad[200]; } x = { 1, 2, "" }, y;
        uint64_t c = 0;
        char msg[160];
        mg_ckpt_result_t res;
        int ok = mg_ckpt_save("selftest", &x, sizeof x, &c) == 0;
        x.a = 7;
        ok = ok && mg_ckpt_save("selftest", &x, sizeof x, &c) == 0;
        ok = ok && mg_ckpt_load("selftest", &y, sizeof y, c, &res) == 0 && y.a == 7 && res.status == MG_CK_NEWEST;
        mg_ckpt_tamper("selftest", MG_CKT_CORRUPT, msg, sizeof msg);
        ok = ok && mg_ckpt_load("selftest", &y, sizeof y, c, &res) == 0 && y.a == 1 && res.status == MG_CK_FALLBACK;
        mg_ckpt_tamper("selftest", MG_CKT_CLEAR, msg, sizeof msg);
        if (ok) result(0, "checkpoint A/B + CRC", "save, restore, corruption fallback ok in %s", mg_ckpt_dir());
        else result(2, "checkpoint A/B + CRC", "failed in %s (%s) - try MG_CKPT_DIR=/data/home/qnxuser/memguard", mg_ckpt_dir(), strerror(errno));
    }

    /* 5. optional wired extras (not part of the final hardware) */
    if (!getenv("MG_GPIO")) {
        result(0, "gpio", "skipped: no LEDs/buzzer/button on the Pi in this build (MG_GPIO=1 to test them)");
    } else if (mg_gpio_init() == 0) {
        int pins[4] = { MG_PIN_LED_GREEN, MG_PIN_LED_AMBER, MG_PIN_LED_RED, MG_PIN_BUZZER };
        const char *nm[4] = { "green LED (GPIO22)", "amber LED (GPIO23)", "red LED (GPIO24)", "buzzer (GPIO25)" };
        for (int k = 0; k < 4; k++) mg_gpio_mode_out(pins[k]);
        for (int k = 0; k < 4; k++) {
            printf("       -> %s ON for 0.5 s\n", nm[k]);
            fflush(stdout);
            mg_gpio_write(pins[k], 1);
            int rb = mg_gpio_read(pins[k]);
            usleep(500000);
            mg_gpio_write(pins[k], 0);
            result(rb == 1 ? 0 : 2, "gpio output", "%s read-back %s", nm[k], rb == 1 ? "ok" : "WRONG");
        }
        mg_gpio_mode_in(MG_PIN_BTN_RESET, 1);
        if (!quick) {
            printf("       -> press the RESET button (GPIO27) within 5 s...\n");
            fflush(stdout);
            int seen = 0;
            for (int t = 0; t < 100 && !seen; t++) { if (mg_gpio_read(MG_PIN_BTN_RESET) == 0) seen = 1; usleep(50000); }
            result(seen ? 0 : 1, "reset button", seen ? "press detected" : "no press seen (check wiring to GND)");
        }
    } else {
        result(2, "gpio", "cannot map GPIO registers (need root)");
    }

    if (getenv("MG_LOCAL_IMU") || getenv("MG_OLED")) {
        const char *dev = mg_env("MG_I2C_DEV", MG_I2C_DEV_DEFAULT);
        int i2c = mg_i2c_open(dev, MG_I2C_SPEED);
        if (i2c < 0) {
            result(2, "i2c bus", "cannot open %s: %s (is i2c-bcm2711 running?)", dev, strerror(errno));
        } else {
            result(0, "i2c bus", "%s open at %d Hz", dev, MG_I2C_SPEED);
            uint8_t who = 0;
            if (!getenv("MG_LOCAL_IMU")) {
                /* only the OLED was asked for */
            } else if (mg_i2c_read_reg(i2c, MG_MPU_ADDR, 0x75, &who, 1) == 0 && who != 0 && who != 0xFF) {
                result(who == 0x68 ? 0 : 1, "local MPU6050", "WHO_AM_I = 0x%02X%s", who, who == 0x68 ? "" : " (clone, accepted)");
            } else {
                result(2, "local MPU6050", "no answer at 0x68 (check SDA=GPIO2, SCL=GPIO3, 3.3 V, AD0 to GND)");
            }
            if (getenv("MG_OLED")) {
                if (mg_oled_init(i2c) == 0) {
                    mg_oled_text(0, "MEMGUARD SELFTEST");
                    mg_oled_text(2, "OLED OK");
                    mg_oled_flush(i2c);
                    result(0, "OLED", "SSD1306 at 0x3C initialised (shifted image: MG_OLED_SH1106=1)");
                } else {
                    result(2, "OLED", "no answer at 0x3C");
                }
            }
            close(i2c);
        }
    } else {
        result(0, "i2c", "skipped: no sensors on the Pi's I2C in this build (all sensors are Wi-Fi nodes)");
    }

    /* 6. frames from the Wi-Fi nodes */
    if (!quick) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(MG_UDP_NODE_PORT);
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (s == -1 || bind(s, (struct sockaddr *)&a, sizeof a) == -1) {
            result(2, "udp nodes", "cannot bind UDP %d: %s (stop MemoryGuard, and run node_dashboard.py with "
                   "--udp-port %d)", MG_UDP_NODE_PORT, strerror(errno), MG_UDP_RELAY_PORT);
        } else {
            struct timeval tv = { 0, 200000 };
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            printf("       -> listening 5 s for node frames on UDP %d...\n", MG_UDP_NODE_PORT);
            fflush(stdout);
            struct { unsigned id; int cnt; char last[128]; } seen[MG_MAX_NODES];
            int nseen = 0, badcs = 0, other = 0;
            uint64_t end = mg_now_ms() + 5000;
            while (mg_now_ms() < end) {
                char buf[512];
                ssize_t n = recvfrom(s, buf, sizeof buf - 1, 0, NULL, NULL);
                if (n <= 0) continue;
                buf[n] = 0;
                char *nl = strpbrk(buf, "\r\n");
                if (nl) *nl = 0;
                char *star = strrchr(buf, '*');
                uint8_t cs = 0;
                for (char *p = buf + 1; star && p < star; p++) cs ^= (uint8_t)*p;
                unsigned want = 0x100;
                if (star) sscanf(star + 1, "%2x", &want);
                if (buf[0] != '$' || !star || want != cs) { badcs++; continue; }
                unsigned id = 0;
                if (sscanf(buf, "$ND,%u,", &id) != 1 && sscanf(buf, "$MG,%u,", &id) != 1) { other++; continue; }
                int k = 0;
                while (k < nseen && seen[k].id != id) k++;
                if (k == nseen) {
                    if (nseen == MG_MAX_NODES) continue;
                    seen[k].id = id;
                    seen[k].cnt = 0;
                    nseen++;
                }
                seen[k].cnt++;
                snprintf(seen[k].last, sizeof seen[k].last, "%.120s", buf);
            }
            /* every expected node must be there */
            char want_list[128];
            snprintf(want_list, sizeof want_list, "%s", mg_env("MG_NODES", "1"));
            char *save = NULL;
            for (char *t = strtok_r(want_list, ", ", &save); t; t = strtok_r(NULL, ", ", &save)) {
                unsigned id = (unsigned)atoi(t);
                int k = 0;
                while (k < nseen && seen[k].id != id) k++;
                char what[32];
                snprintf(what, sizeof what, "node %u", id);
                if (k < nseen) result(0, what, "%d frames in 5 s, last: %.80s", seen[k].cnt, seen[k].last);
                else result(2, what, "no frames (give it Wi-Fi from the dashboard; check it sends to this Pi's IP)");
            }
            for (int k = 0; k < nseen; k++) {
                char what[32];
                snprintf(what, sizeof what, "node %u", seen[k].id);
                bool listed = false;
                char list2[128];
                snprintf(list2, sizeof list2, "%s", mg_env("MG_NODES", "1"));
                char *sv = NULL;
                for (char *t = strtok_r(list2, ", ", &sv); t; t = strtok_r(NULL, ", ", &sv))
                    if ((unsigned)atoi(t) == seen[k].id) listed = true;
                if (!listed)
                    result(0, what, "extra node, %d frames (add it to MG_NODES if it must always be there)", seen[k].cnt);
            }
            if (badcs) result(1, "udp checksum", "%d frames with a bad checksum", badcs);
            if (other) result(1, "udp frames", "%d frames of an unknown format", other);
        }
        if (s != -1) close(s);
    }

    /* 8. logging + tracing */
    mg_log(MG_INFO, "self-test log line (look for it with: slog2info -b mg_selftest)");
    mg_trace("MG SELFTEST trace marker");
    result(0, "slog2 + trace", "wrote a slog2 line and a trace marker");

    printf("\n=== %d PASS, %d WARN, %d FAIL ===\n\n", g_pass, g_warn, g_fail);
    return g_fail ? 1 : 0;
}
