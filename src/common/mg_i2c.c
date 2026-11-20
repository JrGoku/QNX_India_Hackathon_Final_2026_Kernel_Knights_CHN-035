/*
 * MemoryGuard Auto - I2C through the QNX i2c resource manager
 *
 * The i2c-bcm2711 driver is a resource manager that exposes /dev/i2c1.
 * Transactions are devctl() calls (DCMD_I2C_SEND / DCMD_I2C_SENDRECV)
 * with an i2c_send_t / i2c_sendrecv_t header followed by the data.
 * Because QNX message passing carries the client's priority, a request
 * from the 100 Hz sensor loop (prio 55) is served ahead of one from the
 * UI (prio 10) that shares the same bus.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <devctl.h>
#include <hw/i2c.h>
#include "mg_common.h"

#define MG_I2C_MAX 160

int mg_i2c_open(const char *dev, uint32_t speed_hz)
{
    int fd = open(dev, O_RDWR);
    if (fd == -1) return -1;
    if (speed_hz) {
        uint32_t speed = speed_hz;
        int rc = devctl(fd, DCMD_I2C_SET_BUS_SPEED, &speed, sizeof speed, NULL);
        if (rc != EOK) mg_log(MG_WARN, "I2C set speed %u failed: %s", speed_hz, strerror(rc));
    }
    return fd;
}

int mg_i2c_write(int fd, uint8_t addr, const uint8_t *data, uint32_t len)
{
    if (fd < 0 || len > MG_I2C_MAX) return -EINVAL;
    struct {
        i2c_send_t hdr;
        uint8_t    buf[MG_I2C_MAX];
    } msg;
    memset(&msg.hdr, 0, sizeof msg.hdr);
    msg.hdr.slave.addr = addr;
    msg.hdr.slave.fmt = I2C_ADDRFMT_7BIT;
    msg.hdr.len = len;
    msg.hdr.stop = 1;
    memcpy(msg.buf, data, len);
    int rc = devctl(fd, DCMD_I2C_SEND, &msg, sizeof(i2c_send_t) + len, NULL);
    return rc == EOK ? 0 : -rc;
}

int mg_i2c_read_reg(int fd, uint8_t addr, uint8_t reg, uint8_t *out, uint32_t len)
{
    if (fd < 0 || len == 0 || len > MG_I2C_MAX) return -EINVAL;
    struct {
        i2c_sendrecv_t hdr;
        uint8_t        buf[MG_I2C_MAX];
    } msg;
    memset(&msg.hdr, 0, sizeof msg.hdr);
    msg.hdr.slave.addr = addr;
    msg.hdr.slave.fmt = I2C_ADDRFMT_7BIT;
    msg.hdr.send_len = 1;
    msg.hdr.recv_len = len;
    msg.hdr.stop = 1;
    msg.buf[0] = reg;
    int rc = devctl(fd, DCMD_I2C_SENDRECV, &msg, sizeof(i2c_sendrecv_t) + len, NULL);
    if (rc != EOK) return -rc;
    memcpy(out, msg.buf, len);
    return 0;
}
