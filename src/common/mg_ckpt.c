/*
 * MemoryGuard Auto - two-slot (A/B) checkpoints with CRC32
 *
 * Files:  <dir>/mg_ckpt_<name>_a  and  <dir>/mg_ckpt_<name>_b
 * Each save increments a 64-bit counter and writes slot (counter & 1),
 * i.e. always the OLDER slot. A crash in the middle of a write can only
 * damage the slot being written; the other slot still holds the previous
 * good checkpoint. On load the newest slot that passes magic/version/
 * length/CRC checks wins.
 *
 * Default dir is /dev/shmem (RAM): survives process crashes, cleared on
 * reboot. Set MG_CKPT_DIR=/data/... to make checkpoints persistent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "mg_common.h"

#define CK_MAGIC   0x4D47434Bu   /* 'MGCK' */
#define CK_VERSION 1
#define CK_MAX     8192

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t counter;
    uint32_t len;
    uint32_t crc;          /* CRC32 of payload */
    uint64_t t_wall_ms;
} ck_hdr_t;

const char *mg_ckpt_dir(void) { return mg_env("MG_CKPT_DIR", "/dev/shmem"); }

static void ck_path(char *buf, size_t n, const char *name, char slot, const char *suffix)
{
    snprintf(buf, n, "%s/mg_ckpt_%s_%c%s", mg_ckpt_dir(), name, slot, suffix ? suffix : "");
}

int mg_ckpt_save(const char *name, const void *payload, uint32_t len, uint64_t *counter)
{
    if (len > CK_MAX) return -1;
    uint64_t c = *counter + 1;
    char slot = (c & 1u) ? 'b' : 'a';
    char path[256];
    ck_path(path, sizeof path, name, slot, NULL);

    struct { ck_hdr_t h; uint8_t data[CK_MAX]; } buf;
    buf.h.magic = CK_MAGIC;
    buf.h.version = CK_VERSION;
    buf.h.counter = c;
    buf.h.len = len;
    buf.h.crc = mg_crc32(payload, len);
    buf.h.t_wall_ms = mg_wall_ms();
    memcpy(buf.data, payload, len);

    int fd = open(path, O_WRONLY | O_CREAT, 0666);
    if (fd == -1) return -1;
    ssize_t want = (ssize_t)(sizeof(ck_hdr_t) + len);
    ssize_t n = pwrite(fd, &buf, (size_t)want, 0);
    close(fd);
    if (n != want) return -1;
    *counter = c;
    return 0;
}

/* returns 1 = valid, 0 = missing, -1 = present but invalid (detail filled) */
static int ck_read_slot(const char *name, char slot, void *payload, uint32_t len,
                        uint64_t *counter, char *why, size_t whylen)
{
    char path[256];
    ck_path(path, sizeof path, name, slot, NULL);
    int fd = open(path, O_RDONLY);
    if (fd == -1) { snprintf(why, whylen, "missing"); return 0; }
    struct { ck_hdr_t h; uint8_t data[CK_MAX]; } buf;
    ssize_t n = read(fd, &buf, sizeof buf);
    close(fd);
    *counter = 0;
    if (n < (ssize_t)sizeof(ck_hdr_t)) { snprintf(why, whylen, "truncated"); return -1; }
    *counter = buf.h.counter;
    if (buf.h.magic != CK_MAGIC)      { snprintf(why, whylen, "bad magic"); return -1; }
    if (buf.h.version != CK_VERSION)  { snprintf(why, whylen, "bad version"); return -1; }
    if (buf.h.len != len)             { snprintf(why, whylen, "bad length"); return -1; }
    if (n < (ssize_t)(sizeof(ck_hdr_t) + len)) { snprintf(why, whylen, "truncated"); return -1; }
    if (mg_crc32(buf.data, len) != buf.h.crc)  { snprintf(why, whylen, "CRC mismatch"); return -1; }
    if (payload) memcpy(payload, buf.data, len);
    snprintf(why, whylen, "ok");
    return 1;
}

int mg_ckpt_load(const char *name, void *payload, uint32_t len,
                 uint64_t expected_counter, mg_ckpt_result_t *res)
{
    static uint8_t tmp[2][CK_MAX];
    char why[2][32];
    uint64_t cnt[2];
    int st[2];
    st[0] = ck_read_slot(name, 'a', tmp[0], len, &cnt[0], why[0], sizeof why[0]);
    st[1] = ck_read_slot(name, 'b', tmp[1], len, &cnt[1], why[1], sizeof why[1]);

    memset(res, 0, sizeof *res);
    int best = -1;
    for (int i = 0; i < 2; i++)
        if (st[i] == 1 && (best == -1 || cnt[i] > cnt[best])) best = i;

    if (best == -1) {
        res->status = MG_CK_NONE;
        res->counter = 0;
        res->slot = '-';
        snprintf(res->detail, sizeof res->detail, "no valid checkpoint (A: %.16s, B: %.16s)", why[0], why[1]);
        return -1;
    }
    memcpy(payload, tmp[best], len);
    res->counter = cnt[best];
    res->slot = best ? 'B' : 'A';

    /* Is this the newest checkpoint that was ever written? */
    int other = 1 - best;
    bool newer_invalid = (st[other] == -1 && cnt[other] > cnt[best]);
    bool behind_expected = (expected_counter > cnt[best]);
    if (newer_invalid || behind_expected) {
        res->status = MG_CK_FALLBACK;
        snprintf(res->detail, sizeof res->detail, "fell back to slot %c #%llu (newest: %.16s)",
                 res->slot, (unsigned long long)cnt[best],
                 newer_invalid ? why[other] : "unavailable");
    } else {
        res->status = MG_CK_NEWEST;
        snprintf(res->detail, sizeof res->detail, "restored newest slot %c #%llu",
                 res->slot, (unsigned long long)cnt[best]);
    }
    return 0;
}

/* Runtime scrubbing: is the checkpoint we wrote last still intact? */
int mg_ckpt_verify(const char *name, uint32_t len, uint64_t counter)
{
    char why[32];
    uint64_t c = 0;
    char slot = (counter & 1u) ? 'b' : 'a';
    int st = ck_read_slot(name, slot, NULL, len, &c, why, sizeof why);
    return (st == 1 && c == counter) ? 0 : -1;
}

/* newest slot that is valid on disk right now, whatever its payload size */
int mg_ckpt_active(const char *name, char *slot, uint64_t *counter, uint64_t *t_wall_ms)
{
    int best = -1;
    uint64_t best_cnt = 0, best_t = 0;
    for (int i = 0; i < 2; i++) {
        char path[256];
        ck_path(path, sizeof path, name, i ? 'b' : 'a', NULL);
        int fd = open(path, O_RDONLY);
        if (fd == -1) continue;
        static struct { ck_hdr_t h; uint8_t data[CK_MAX]; } buf;
        ssize_t n = read(fd, &buf, sizeof buf);
        close(fd);
        if (n < (ssize_t)sizeof(ck_hdr_t) || buf.h.magic != CK_MAGIC || buf.h.version != CK_VERSION ||
            buf.h.len > CK_MAX || n < (ssize_t)(sizeof(ck_hdr_t) + buf.h.len) ||
            mg_crc32(buf.data, buf.h.len) != buf.h.crc)
            continue;
        if (best == -1 || buf.h.counter > best_cnt) { best = i; best_cnt = buf.h.counter; best_t = buf.h.t_wall_ms; }
    }
    if (best == -1) { if (slot) *slot = '-'; return -1; }
    if (slot) *slot = best ? 'B' : 'A';
    if (counter) *counter = best_cnt;
    if (t_wall_ms) *t_wall_ms = best_t;
    return 0;
}

const char *mg_ckpt_name(int svc)
{
    switch (svc) {
    case MG_SVC_SENSOR: return "sensor";
    case MG_SVC_DEVMGR: return "dm";
    case MG_SVC_LOGGER: return "logger";
    case MG_SVC_UI:     return "ui";
    default:            return NULL;
    }
}

int mg_ckpt_files(const char *name)
{
    char path[256];
    int n = 0;
    for (char sl = 'a'; sl <= 'b'; sl++) {
        ck_path(path, sizeof path, name, sl, NULL);
        if (access(path, F_OK) == 0) n++;
    }
    return n;
}

static int copy_file(const char *from, const char *to)
{
    int in = open(from, O_RDONLY);
    if (in == -1) return -1;
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out == -1) { close(in); return -1; }
    char buf[4096];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, (size_t)n) != n) { rc = -1; break; }
    close(in);
    close(out);
    return rc;
}

static int corrupt_slot(const char *name, char slot)
{
    char path[256];
    ck_path(path, sizeof path, name, slot, NULL);
    int fd = open(path, O_RDWR);
    if (fd == -1) return -1;
    uint8_t junk[16];
    off_t off = (off_t)sizeof(ck_hdr_t) + 4;
    if (pread(fd, junk, sizeof junk, off) != (ssize_t)sizeof junk) { close(fd); return -1; }
    /* add, not XOR: corrupting twice must never turn the bytes back into valid data */
    for (size_t i = 0; i < sizeof junk; i++) junk[i] = (uint8_t)(junk[i] + 0x37u);
    ssize_t n = pwrite(fd, junk, sizeof junk, off);
    close(fd);
    return n == (ssize_t)sizeof junk ? 0 : -1;
}

/* newest slot by header counter, even if its CRC is bad */
static char newest_slot(const char *name)
{
    uint64_t ca = 0, cb = 0;
    char why[32];
    int a = ck_read_slot(name, 'a', NULL, 0, &ca, why, sizeof why);
    int b = ck_read_slot(name, 'b', NULL, 0, &cb, why, sizeof why);
    if (a == 0 && b == 0) return 0;
    if (a == 0) return 'b';
    if (b == 0) return 'a';
    return cb > ca ? 'b' : 'a';
}

int mg_ckpt_tamper(const char *name, int action, char *msg, size_t msglen)
{
    char path[256], held[256];
    char s = newest_slot(name);
    switch (action) {
    case MG_CKT_CORRUPT:
        if (!s) { snprintf(msg, msglen, "no checkpoint files for %s", name); return -1; }
        if (corrupt_slot(name, s)) { snprintf(msg, msglen, "corrupt failed: %s", strerror(errno)); return -1; }
        snprintf(msg, msglen, "corrupted newest checkpoint %s slot %c", name, s - 32);
        return 0;
    case MG_CKT_CORRUPT_BOTH: {
        int a = corrupt_slot(name, 'a'), b = corrupt_slot(name, 'b');
        snprintf(msg, msglen, "corrupted %s slots: A %s, B %s", name, a ? "-" : "yes", b ? "-" : "yes");
        return (a && b) ? -1 : 0;
    }
    case MG_CKT_WITHHOLD:
        if (!s) { snprintf(msg, msglen, "no checkpoint files for %s", name); return -1; }
        ck_path(path, sizeof path, name, s, NULL);
        ck_path(held, sizeof held, name, s, ".withheld");
        if (copy_file(path, held) || unlink(path)) {
            snprintf(msg, msglen, "withhold failed: %s", strerror(errno));
            return -1;
        }
        snprintf(msg, msglen, "withheld newest checkpoint %s slot %c", name, s - 32);
        return 0;
    case MG_CKT_RESTORE: {
        int restored = 0;
        for (char sl = 'a'; sl <= 'b'; sl++) {
            ck_path(path, sizeof path, name, sl, NULL);
            ck_path(held, sizeof held, name, sl, ".withheld");
            if (access(held, F_OK) != 0) continue;
            /* never overwrite a checkpoint written after the withhold */
            if (access(path, F_OK) == 0) { unlink(held); continue; }
            if (copy_file(held, path) == 0) { unlink(held); restored++; }
        }
        snprintf(msg, msglen, "restored %d withheld file(s) for %s", restored, name);
        return 0;
    }
    case MG_CKT_CLEAR:
        for (char sl = 'a'; sl <= 'b'; sl++) {
            ck_path(path, sizeof path, name, sl, NULL);
            unlink(path);
            ck_path(held, sizeof held, name, sl, ".withheld");
            unlink(held);
        }
        snprintf(msg, msglen, "cleared all checkpoints for %s", name);
        return 0;
    default:
        snprintf(msg, msglen, "unknown checkpoint action");
        return -1;
    }
}
