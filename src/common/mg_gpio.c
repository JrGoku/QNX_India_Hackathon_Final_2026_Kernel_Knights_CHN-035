/*
 * MemoryGuard Auto - GPIO for Raspberry Pi 4 (BCM2711)
 *
 * The Device Manager is the only MemoryGuard process that drives GPIO.
 * We map the GPIO register block with mmap_device_memory() (needs root,
 * which is how programs launched from Momentics through qconn run).
 * We only touch pins nobody else uses; SET/CLR registers are write-1
 * atomic, so we never disturb other pins.
 *
 * If mapping fails (not root, different board) the functions become
 * no-ops and mg_gpio_ok() returns false, so the system still runs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include "mg_common.h"

/* The Pi 4 exposes its peripherals at one of two physical addresses
 * ("low" or "high peripheral" mode). Try both, like uart_bridge.py does,
 * and prefer the one where GPIO2/GPIO3 are already in ALT0 (the I2C1
 * function the i2c-bcm2711 driver set up): that proves we mapped the real
 * GPIO block and not something else. MG_GPIO_BASE=0x... forces one. */
static const uint64_t GPIO_BASES[] = { 0xFE200000ull, 0x47E200000ull };
#define GPFSEL0   (0x00 / 4)
#define GPSET0    (0x1C / 4)
#define GPCLR0    (0x28 / 4)
#define GPLEV0    (0x34 / 4)
#define GPPUPPDN0 (0xE4 / 4)     /* BCM2711 pull-up/down control */

static volatile uint32_t *g_gpio;

static bool i2c_pins_alt0(volatile uint32_t *regs)
{
    uint32_t v = regs[GPFSEL0];
    return ((v >> 6) & 7u) == 4u && ((v >> 9) & 7u) == 4u;   /* GPIO2, GPIO3 = ALT0 */
}

int mg_gpio_init(void)
{
    if (g_gpio) return 0;
    /* the final hardware has no LEDs/buzzer/button on the Pi: GPIO is opt-in */
    if (!getenv("MG_GPIO") || getenv("MG_NO_GPIO")) return -1;

    uint64_t bases[2] = { GPIO_BASES[0], GPIO_BASES[1] };
    int nbases = 2;
    const char *force = getenv("MG_GPIO_BASE");
    if (force && *force) { bases[0] = strtoull(force, NULL, 16); nbases = 1; }

    volatile uint32_t *fallback = NULL;
    uint64_t fallback_base = 0;
    int err = 0;
    for (int k = 0; k < nbases; k++) {
        void *p = mmap_device_memory(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_NOCACHE, 0, bases[k]);
        if (p == MAP_FAILED) { err = errno; continue; }
        volatile uint32_t *regs = (volatile uint32_t *)p;
        if (i2c_pins_alt0(regs) || nbases == 1) {
            g_gpio = regs;
            if (fallback) munmap((void *)fallback, 0x1000);
            mg_log(MG_INFO, "GPIO registers at 0x%llX", (unsigned long long)bases[k]);
            return 0;
        }
        if (!fallback) { fallback = regs; fallback_base = bases[k]; }
        else munmap(p, 0x1000);
    }
    if (fallback) {
        g_gpio = fallback;
        mg_log(MG_WARN, "GPIO registers at 0x%llX (I2C pins not in ALT0 - is the I2C driver running?)",
               (unsigned long long)fallback_base);
        return 0;
    }
    mg_log(MG_WARN, "GPIO map failed (%s) - running without LEDs (are you root?)", strerror(err));
    return -1;
}

bool mg_gpio_ok(void) { return g_gpio != NULL; }

static void set_fsel(int pin, uint32_t fn)
{
    uint32_t reg = GPFSEL0 + (uint32_t)pin / 10u;
    uint32_t sh = ((uint32_t)pin % 10u) * 3u;
    uint32_t v = g_gpio[reg];
    v &= ~(7u << sh);
    v |= (fn & 7u) << sh;
    g_gpio[reg] = v;
}

void mg_gpio_mode_out(int pin)
{
    if (!g_gpio || pin < 0 || pin > 53) return;
    set_fsel(pin, 1u);
}

void mg_gpio_mode_in(int pin, int pull)
{
    if (!g_gpio || pin < 0 || pin > 53) return;
    set_fsel(pin, 0u);
    uint32_t reg = GPPUPPDN0 + (uint32_t)pin / 16u;
    uint32_t sh = ((uint32_t)pin % 16u) * 2u;
    uint32_t code = pull == 1 ? 1u : pull == 2 ? 2u : 0u;   /* 01 up, 10 down */
    uint32_t v = g_gpio[reg];
    v &= ~(3u << sh);
    v |= code << sh;
    g_gpio[reg] = v;
}

void mg_gpio_write(int pin, int value)
{
    if (!g_gpio || pin < 0 || pin > 53) return;
    uint32_t bit = 1u << ((uint32_t)pin % 32u);
    if (value) g_gpio[GPSET0 + (uint32_t)pin / 32u] = bit;
    else       g_gpio[GPCLR0 + (uint32_t)pin / 32u] = bit;
}

int mg_gpio_read(int pin)
{
    if (!g_gpio || pin < 0 || pin > 53) return -1;
    return (int)((g_gpio[GPLEV0 + (uint32_t)pin / 32u] >> ((uint32_t)pin % 32u)) & 1u);
}
