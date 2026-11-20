/*
 * MemoryGuard Auto - 128x64 OLED (SSD1306, or SH1106 with MG_OLED_SH1106=1)
 *
 * Text mode only: 8 rows x 21 columns with the 5x7 font in mg_font5x7.h.
 * The frame buffer is sent one 128-byte page per I2C transaction so the
 * shared bus is never blocked for long (the MPU6050 lives on it too).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "mg_common.h"
#include "mg_font5x7.h"

static uint8_t g_fb[MG_OLED_ROWS][128];
static int     g_col_offset;   /* 2 for SH1106 panels */

static int oled_cmds(int fd, const uint8_t *cmds, uint32_t n)
{
    uint8_t buf[32];
    if (n > sizeof buf - 1) return -1;
    buf[0] = 0x00;                       /* control byte: command stream */
    memcpy(buf + 1, cmds, n);
    return mg_i2c_write(fd, MG_OLED_ADDR, buf, n + 1);
}

int mg_oled_init(int fd)
{
    g_col_offset = getenv("MG_OLED_SH1106") ? 2 : 0;
    static const uint8_t init[] = {
        0xAE,             /* display off                 */
        0xD5, 0x80,       /* clock divide                */
        0xA8, 0x3F,       /* multiplex 64                */
        0xD3, 0x00,       /* display offset 0            */
        0x40,             /* start line 0                */
        0x8D, 0x14,       /* charge pump on              */
        0x20, 0x02,       /* page addressing mode        */
        0xA1,             /* segment remap               */
        0xC8,             /* COM scan direction          */
        0xDA, 0x12,       /* COM pins                    */
        0x81, 0xCF,       /* contrast                    */
        0xD9, 0xF1,       /* pre-charge                  */
        0xDB, 0x40,       /* VCOMH                       */
        0xA4,             /* follow RAM                  */
        0xA6,             /* normal (not inverted)       */
        0xAF              /* display on                  */
    };
    if (oled_cmds(fd, init, sizeof init) != 0) return -1;
    mg_oled_clear();
    return mg_oled_flush(fd);
}

void mg_oled_clear(void) { memset(g_fb, 0, sizeof g_fb); }

void mg_oled_text(int row, const char *text)
{
    if (row < 0 || row >= MG_OLED_ROWS) return;
    memset(g_fb[row], 0, sizeof g_fb[row]);
    for (int i = 0; i < MG_OLED_COLS && text[i]; i++) {
        int c = toupper((unsigned char)text[i]);
        if (c < 32 || c > 127) c = '?';
        const uint8_t *glyph = mg_font5x7[c - 32];
        for (int x = 0; x < 5; x++) g_fb[row][i * 6 + x] = glyph[x];
    }
}

int mg_oled_flush_page(int fd, int page)
{
    uint8_t col_lo = (uint8_t)(g_col_offset & 0x0F);
    uint8_t col_hi = (uint8_t)(0x10 | ((g_col_offset >> 4) & 0x0F));
    uint8_t cmds[3] = { (uint8_t)(0xB0 | (page & 7)), col_lo, col_hi };
    if (oled_cmds(fd, cmds, 3) != 0) return -1;
    uint8_t data[129];
    data[0] = 0x40;                      /* control byte: data stream */
    memcpy(data + 1, g_fb[page], 128);
    return mg_i2c_write(fd, MG_OLED_ADDR, data, sizeof data);
}

int mg_oled_flush(int fd)
{
    for (int p = 0; p < MG_OLED_ROWS; p++)
        if (mg_oled_flush_page(fd, p) != 0) return -1;
    return 0;
}
