/*
 * MemoryGuard - shared definitions
 *
 * Domain: an industrial machine-condition monitor. Wi-Fi nodes measure the
 * monitored machine (Node 1: vibration, ISO 10816-3 zones) and its
 * environment (Node 2: temperature / humidity / pressure). The Device
 * Manager is the machine controller: it raises alarms and trips (stops) the
 * machine on dangerous vibration.
 *
 * Everything that more than one process needs to agree on lives here:
 * service table, timing budgets, the shared-memory layout, and the
 * helper API (time, logging, tracing, heartbeats, checkpoints, GPIO, I2C).
 */
#ifndef MG_COMMON_H
#define MG_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#define MG_VERSION "1.3"

/* ------------------------------------------------------------------ */
/* Services supervised by mg_supervisor                                */
/* ------------------------------------------------------------------ */
typedef enum {
    MG_SVC_SENSOR = 0,   /* Sensor Service     (critical)                  */
    MG_SVC_DEVMGR,       /* Device Manager = machine controller (critical) */
    MG_SVC_LOGGER,       /* Data Logger                                    */
    MG_SVC_UI,           /* User Interface (non-critical)                 */
    MG_SVC_STATUSFS,     /* /dev/memguard resource manager (non-critical) */
    MG_SVC_WEBUI,        /* browser dashboard, HTTP :8080 (non-critical)  */
    MG_SVC_COUNT
} mg_svc_t;

typedef struct {
    const char *key;          /* short name used by mgctl: sensor, dm, ...  */
    const char *binary;       /* executable file name                       */
    const char *attach_name;  /* name_attach() name for PING / INJECT       */
    const char *title;        /* human readable                             */
    int  priority;            /* SCHED_FIFO priority (1..63 unprivileged)   */
    int  cpu;                 /* core to pin to (-1 = any)                  */
    bool critical;            /* failure of a critical service matters more */
    int  hb_timeout_ms;       /* heartbeat-loss detection threshold         */
} mg_svc_info_t;

extern const mg_svc_info_t MG_SVC_INFO[MG_SVC_COUNT];

#define MG_SUP_NAME        "mg_sup"
#define MG_SUP_PRIORITY    63
#define MG_SUP_CPU         1
#define MG_WD_PRIORITY     62     /* mg_watchdog: watches the supervisor       */
#define MG_WD_CPU          0
#define MG_WD_PERIOD_MS    20
#define MG_SUP_HB_TIMEOUT_MS 300  /* supervisor silent this long -> watchdog acts */
#define MG_WD_HB_TIMEOUT_MS  500  /* watchdog silent this long -> supervisor respawns it */
#define MG_STRESS_PRIORITY 9

/* ------------------------------------------------------------------ */
/* Timing budgets                                                      */
/* ------------------------------------------------------------------ */
#define MG_HB_PERIOD_MS          50    /* every service beats this often      */
#define MG_SUP_TICK_MS           10    /* supervisor scan period              */
#define MG_VERIFY_HEARTBEATS     3     /* beats needed after READY            */
#define MG_VERIFY_MIN_MS         500   /* defined health-verification period  */
#define MG_VERIFY_TIMEOUT_MS     3000  /* give up on a restart after this     */
#define MG_PING_PERIOD_MS        1000  /* each running service is pinged once a second */
#define MG_MEM_LIMIT_MB_DEFAULT  256   /* kernel address-space limit per service */
#define MG_RESTART_WINDOW_MS     30000 /* restart-storm window                */
#define MG_RESTART_MAX           4     /* max restarts inside the window      */
#define MG_SENSOR_PERIOD_MS      10    /* 100 Hz acquisition loop             */
#define MG_NODE_TIMEOUT_MS       2000  /* nodes send every 0.5 s: 4 missed frames = silent */
#define MG_DM_TICK_MS            50
#define MG_DM_SENSOR_STALE_MS    500   /* DM: no sensor updates for this long */

/* ------------------------------------------------------------------ */
/* Pins (BCM numbering) and buses                                      */
/* All sensors are Wi-Fi nodes. Optional wired extras on the Pi:       */
/* MG_GPIO=1 = outputs that represent the monitored machine (green    */
/* running, amber alert, red trip/stop relay, buzzer) + reset button;  */
/* MG_OLED=1 = status OLED on the Pi's I2C.                            */
/* ------------------------------------------------------------------ */
#define MG_PIN_LED_GREEN   22
#define MG_PIN_LED_AMBER   23
#define MG_PIN_LED_RED     24
#define MG_PIN_BUZZER      25
#define MG_PIN_BTN_RESET   27
#define MG_I2C_DEV_DEFAULT "/dev/i2c1"
#define MG_I2C_SPEED       400000
#define MG_MPU_ADDR        0x68
#define MG_OLED_ADDR       0x3C
#define MG_UDP_NODE_PORT   5005   /* nodes -> mg_sensor                       */
#define MG_UDP_RELAY_PORT  5006   /* mg_sensor -> node_dashboard.py (relay)    */
#define MG_UDP_ALARM_PORT  6000   /* mg_devmgr -> maintenance centre (laptop)  */
#define MG_WEB_PORT        8080   /* mg_webui browser dashboard                */

/* ------------------------------------------------------------------ */
/* Domain enums                                                        */
/* ------------------------------------------------------------------ */
typedef enum { MG_MODE_BOOT = 0, MG_MODE_NORMAL, MG_MODE_DEGRADED,
               MG_MODE_ALERT, MG_MODE_SAFE, MG_MODE_COUNT } mg_mode_t;

typedef enum { MG_H_UNVERIFIED = 0, MG_H_OK, MG_H_DEGRADED,
               MG_H_FAULT, MG_H_OFFLINE, MG_H_COUNT } mg_health_t;

/* Wireless nodes. Any node that sends a valid $ND frame is registered
   automatically (up to MG_MAX_NODES); MG_NODES lists the ones that MUST be
   there (default "1"), so a missing expected node degrades the system.   */
#define MG_MAX_NODES      8
#define MG_NODE_MAX_VALS  12
#define MG_NODE_KIND_LEN  8
#define MG_NODE_ID_LOCAL  0    /* the optional MPU on the Pi's own I2C bus */

#define MG_WARN_VIB_ALERT      0x01u  /* vibration in ISO zone C (alert)     */
#define MG_WARN_SENSOR_FAULT   0x02u  /* a node reports or shows a fault     */
#define MG_WARN_NODE_LOST      0x04u  /* a node stopped sending              */
#define MG_WARN_MOUNT          0x08u  /* vibration sensor mounting moved     */
#define MG_WARN_ENV            0x10u  /* environment temperature high        */
#define MG_WARN_ALL            0x1Fu

/* ISO 10816-3 group 2 (medium machines, rigid mounting): zone limits in
   mm/s RMS. Must match ZONE_AB/BC/CD in node1.ino; MG_ZONE_AB/BC/CD override. */
#define MG_ZONE_AB_DEFAULT  1.4f
#define MG_ZONE_BC_DEFAULT  2.8f
#define MG_ZONE_CD_DEFAULT  4.5f

/* health summary the sensor service sends to the Device Manager */
typedef struct {
    uint8_t nodes;      /* nodes known (expected + discovered)      */
    uint8_t nodes_ok;   /* of those, how many are OK                */
    uint8_t worst;      /* worst health of any known node           */
    uint8_t machine;    /* health of the machine's vibration node   */
} mg_health_sum_t;

/* events need an operator's attention and are delivered exactly once */
typedef enum { MG_EV_NONE = 0,
               MG_EV_VIB_DANGER,    /* zone D for >= 2 frames -> machine TRIPPED  */
               MG_EV_OVERTEMP,      /* environment above MG_TEMP_MAX              */
               MG_EV_MOUNT_LOOSE,   /* vibration sensor moved >= MG_MOUNT_DEG     */
               MG_EV_COUNT } mg_event_type_t;

typedef enum { MG_INJ_NONE = 0, MG_INJ_SEGV, MG_INJ_HANG, MG_INJ_LEAK,
               MG_INJ_COUNT } mg_inject_t;

typedef enum { MG_ST_STOPPED = 0, MG_ST_STARTING, MG_ST_RUNNING,
               MG_ST_RECOVERING, MG_ST_VERIFYING, MG_ST_FAILED } mg_svc_state_t;

/* exit codes a service uses to tell the supervisor *why* it stopped */
#define MG_EXIT_RESOURCE  42   /* resource exhaustion detected by own guard */
#define MG_EXIT_CONFIG    43

/* ------------------------------------------------------------------ */
/* Event record - travels sensor -> DM -> maintenance centre          */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t id;          /* monotonic, never reused (checkpointed)   */
    uint32_t type;        /* mg_event_type_t                           */
    uint64_t t_wall_ms;   /* wall clock, for the emergency centre      */
    float    value;       /* mm/s (vibration), C (temperature), deg (mount) */
    float    freq_hz;     /* dominant vibration frequency, 0 if n/a    */
    float    aux;         /* acceleration peak in g, or humidity %     */
    uint32_t node_id;     /* node that saw it                          */
} mg_event_t;

/* ------------------------------------------------------------------ */
/* Shared memory "/memguard" (created by the supervisor)               */
/* Each section has exactly ONE writer; readers use the seqlock.       */
/* ------------------------------------------------------------------ */
#ifndef MG_SHM_NAME
#define MG_SHM_NAME     "/memguard"
#endif
#define MG_SHM_MAGIC    0x4D475244u   /* 'MGRD' */
#define MG_SHM_VERSION  9
#define MG_MAX_RECOVERIES 32
#define MG_EVLOG_SIZE     64
#define MG_EDR_SAMPLES    500         /* machine samples (250 s at 2 Hz) */
#define MG_QUARANTINE_MAX 8
#define MG_ALARM_LOG      8           /* = DM outbox size */

typedef struct { volatile uint32_t seq; } mg_seqlock_t;

typedef struct {
    pid_t    pid;
    uint32_t state;            /* mg_svc_state_t                     */
    uint32_t restarts;
    uint32_t epoch;            /* +1 every time it becomes healthy  */
    uint64_t last_hb_ms;
    uint64_t started_ms;
    uint32_t hb_count;
    int32_t  last_exit_status;
    char     last_cause[32];
    /* CLI metrics (written by the supervisor) */
    uint32_t failed_restarts;  /* restart attempts that never became healthy */
    uint64_t first_start_ms;   /* for availability                         */
    uint64_t up_ms;            /* time spent RUNNING                       */
    uint32_t ping_us, ping_max_us, ping_fail;   /* response latency      */
    uint32_t adopted;          /* taken over by a restarted supervisor     */
} mg_svc_reg_t;

/* checkpoint bookkeeping every checkpointing service publishes */
typedef struct {
    uint64_t saved_counter;    /* newest checkpoint written                */
    int32_t  restore_status;   /* mg_ckpt_status_t of the last start       */
    int64_t  restore_counter;  /* counter restored (-1 = none)             */
    char     restore_slot;     /* 'A' / 'B' / '-'                          */
} mg_ckpt_pub_t;

typedef struct {
    uint32_t id;
    uint32_t svc;
    char     cause[32];
    uint64_t t_inject_ms;      /* when mgctl injected the fault (0 = organic) */
    uint64_t t_fail_ms;        /* when the failure became real                */
    uint64_t t_detect_ms;      /* when the supervisor noticed                 */
    uint64_t t_spawn_ms;       /* replacement process created                 */
    uint64_t t_ready_ms;       /* replacement restored state, said READY      */
    uint64_t t_healthy_ms;     /* passed health verification                  */
    uint64_t t_reconnect_ms;   /* dependent clients reconnected               */
    int64_t  ckpt_expected;    /* last checkpoint counter written before fault*/
    int64_t  ckpt_restored;    /* counter actually restored (-1 = none)       */
    int32_t  ckpt_status;      /* 0 newest, 1 fallback, 2 none, -1 n/a        */
    uint32_t sensor_miss_at_fail;
    uint32_t deadline_miss_during;
    uint32_t complete;
} mg_recovery_t;

typedef struct {
    uint32_t valid;
    uint16_t type;
    uint16_t op;
    uint32_t hash;             /* CRC32 of the message body */
    uint64_t t_ms;
} mg_quarantine_t;

typedef struct {
    uint32_t seq;              /* slot written completely when seq == index+1 */
    uint64_t t_ms;
    uint32_t svc;              /* MG_SVC_COUNT = supervisor/other */
    uint32_t level;            /* 0 info, 1 warn, 2 error */
    char     text[100];
} mg_evlog_entry_t;

typedef struct {
    uint32_t rx, lost, dup, out_of_order, bad_crc, invalid, reboots;
    uint32_t status_frames;     /* $ST Wi-Fi status reports (not data) */
    uint32_t alive;
    uint32_t last_seq;
    uint64_t last_rx_ms;
} mg_node_stats_t;

typedef struct {
    uint32_t used;
    uint32_t id;
    uint32_t expected;          /* listed in MG_NODES                     */
    char     kind[MG_NODE_KIND_LEN];   /* "VIB", "ENV", ...             */
    uint32_t nvals;
    float    v[MG_NODE_MAX_VALS];      /* last values, as sent          */
    int32_t  rssi_dbm;
    uint32_t flags;
    uint32_t health;            /* mg_health_t                            */
    char     reason[28];
    char     src[16];           /* sender IP                              */
    mg_node_stats_t st;
} mg_node_pub_t;

typedef struct {
    mg_seqlock_t lock;
    /* the monitored machine (vibration node) */
    uint32_t machine_node;      /* VIB node used, or -1u                      */
    float    vel_mm_s, vel_xyz[3], acc_rms_g, acc_peak_g, crest, freq_hz, rpm;
    float    chip_temp_c, mount_tilt_deg;
    uint32_t zone;              /* 0..3 = A..D, computed on the Pi            */
    uint32_t node_zone;         /* what the node reported                     */
    uint32_t running;
    float    peak_vel_60s;
    /* environment (ENV node) */
    uint32_t env_node;          /* or -1u                                     */
    float    env_temp_c, env_hum, env_press_hpa;
    uint32_t warnings;
    mg_health_sum_t hs;
    /* all nodes */
    uint32_t node_count;
    mg_node_pub_t node[MG_MAX_NODES];
    uint32_t relay_port, relayed, unknown_frames;
    /* real-time loop statistics */
    uint64_t cycles;
    uint32_t deadline_misses;
    float    max_late_ms, last_exec_ms, max_exec_ms;
    /* link to the Device Manager */
    uint32_t dm_connected;
    uint32_t dm_epoch_connected;
    uint32_t events_created, events_pending, last_event_id, last_event_type;
    /* restore info */
    int32_t  restore_status;
    int64_t  restore_counter;
    uint64_t ckpt_saved_counter;
    /* limits in force (after validation), so displays never re-parse the env */
    float    lim_zone_ab, lim_zone_bc, lim_zone_cd, lim_mount_deg, lim_temp_warn, lim_temp_max;
    uint32_t mach_ok, env_ok;   /* the machine / environment values above are verified data */
    uint32_t slips;             /* vibration frames dropped as FIFO axis slips */
    uint64_t updated_ms;
} mg_sensor_pub_t;

typedef struct {
    mg_seqlock_t lock;
    uint32_t mode;
    uint32_t restricted;          /* safe-initialization state active  */
    uint32_t alarm_latched, latched_event_id, highest_event_id;
    uint32_t outputs;             /* bit0 G, bit1 A, bit2 R, bit3 buzzer */
    uint32_t gpio_ok;
    mg_health_sum_t hs;
    uint32_t warnings;
    uint32_t req_ok, req_dup, req_stale, req_invalid, req_quarantined;
    uint32_t events_received, events_dup;
    uint32_t machine_tripped;     /* stop command latched (zone D event)  */
    uint32_t outbox_pending, ecall_sent, ecall_acked, ecall_retries, last_ecall_acked;
    /* alarm log: copy of the (checkpointed) alarm outbox, oldest first */
    uint32_t alarm_n;
    struct { mg_event_t ev; uint32_t acked, tries; } alarm[MG_ALARM_LOG];
    uint32_t centre_set;          /* -e <laptop-ip> given                  */
    uint64_t ckpt_saved_counter;
    uint32_t ckpt_saves, ckpt_scrub_errors;
    int32_t  restore_status;
    int64_t  restore_counter;
    char     restore_detail[64];
    uint32_t sensor_stale;
    uint64_t sensor_last_update_ms;
    /* the request being processed right now (for poison-request quarantine) */
    volatile uint32_t inflight_valid;
    volatile uint16_t inflight_type;
    volatile uint16_t inflight_op;
    volatile uint32_t inflight_hash;
    uint64_t updated_ms;
} mg_dm_pub_t;

typedef struct {
    volatile uint32_t head;       /* next write index (monotonic) */
    struct { uint64_t t_ms; float vel, acc_rms, acc_peak, freq, temp; uint32_t zone; } s[MG_EDR_SAMPLES];
} mg_edr_ring_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    pid_t    sup_pid;
    uint64_t sup_start_ms;
    uint32_t system_safe;         /* supervisor-level safe state (critical svc FAILED) */
    mg_svc_reg_t    reg[MG_SVC_COUNT];
    uint32_t        rec_count;    /* total recoveries; ring index = n % MAX */
    mg_recovery_t   rec[MG_MAX_RECOVERIES];
    mg_quarantine_t quarantine[MG_QUARANTINE_MAX];
    struct { uint64_t t_ms; uint32_t svc; char kind[32]; } last_inject;
    volatile uint32_t evlog_head;
    mg_evlog_entry_t  evlog[MG_EVLOG_SIZE];
    mg_sensor_pub_t sensor;
    mg_dm_pub_t     dm;
    mg_edr_ring_t   edr;
    struct { uint32_t rows, edr_dumps, events_written, events_missed; uint64_t updated_ms; } logger;
    struct { uint32_t frames, oled_ok; uint64_t updated_ms; } ui;
    mg_ckpt_pub_t   ck[MG_SVC_COUNT]; /* per service; dm/sensor mirror their own fields */
    /* watchdog <-> supervisor */
    volatile uint64_t sup_hb_ms;
    volatile pid_t    wd_pid;
    volatile uint64_t wd_hb_ms;
    volatile uint32_t shutting_down;  /* orderly stop: the watchdog must not act */
    uint32_t sup_restarts;
    uint32_t wd_restarts;
    char     sup_last_cause[32];
    uint64_t sup_fail_ms;              /* watchdog: last supervisor heartbeat seen */
    uint64_t sup_detect_ms;            /* watchdog: when it acted                  */
    uint64_t sup_recovery_ms;          /* last supervisor takeover, total ms       */
    uint32_t sup_adopted;              /* services taken over without a restart    */
} mg_shm_t;

/* ------------------------------------------------------------------ */
/* Helper API (mg_common.c)                                            */
/* ------------------------------------------------------------------ */
uint64_t mg_now_ms(void);           /* CLOCK_MONOTONIC */
uint64_t mg_now_ns(void);
uint64_t mg_wall_ms(void);          /* CLOCK_REALTIME  */

mg_shm_t *mg_shm_attach(bool create);
void      mg_seq_write_begin(mg_seqlock_t *l);
void      mg_seq_write_end(mg_seqlock_t *l);
void      mg_seq_repair(mg_seqlock_t *l);   /* call once at writer start-up */
bool      mg_seq_read(const mg_seqlock_t *l, void *dst, const void *src, size_t n);

int  mg_set_rt(int priority, int cpu);     /* priority + core pinning */
void mg_apply_limits(void);                 /* kernel memory limit (MG_MEM_LIMIT_MB) */
void mg_log_init(const char *name, mg_svc_t self);
void mg_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define MG_INFO  0
#define MG_WARN  1
#define MG_ERROR 2
void mg_evlog(mg_svc_t svc, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void mg_trace(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* heartbeats & lifecycle pulses to the supervisor */
void mg_heartbeat(mg_svc_t self);
void mg_ready(mg_svc_t self, int status);
void mg_pulse_sup(int code, int value);

/* control channel (PING / INJECT) + fault injection hooks (mg_ctl.c) */
int  mg_ctl_start(mg_svc_t self);
void mg_inject_request(int kind);
void mg_inject_poll(mg_svc_t self);

/* names */
const char *mg_mode_name(uint32_t m);
const char *mg_health_name(uint32_t h);
const char *mg_state_name(uint32_t s);
const char *mg_event_name(uint32_t e);
const char *mg_inject_name(uint32_t k);
const char *mg_warn_names(uint32_t w, char *buf, size_t len);
const char *mg_zone_name(uint32_t z);       /* "A".."D" */
int         mg_svc_by_key(const char *key);
uint32_t    mg_crc32(const void *data, size_t len);
const char *mg_env(const char *name, const char *def);
int         mg_mkdirs(const char *path);

/* checkpoints (mg_ckpt.c) */
typedef enum { MG_CK_NEWEST = 0, MG_CK_FALLBACK = 1, MG_CK_NONE = 2 } mg_ckpt_status_t;
typedef struct {
    int      status;
    uint64_t counter;
    char     slot;
    char     detail[64];
} mg_ckpt_result_t;
typedef enum { MG_CKT_CORRUPT = 1, MG_CKT_WITHHOLD, MG_CKT_RESTORE,
               MG_CKT_CORRUPT_BOTH, MG_CKT_CLEAR } mg_ckpt_tamper_t;

int  mg_ckpt_save(const char *name, const void *payload, uint32_t len, uint64_t *counter);
int  mg_ckpt_load(const char *name, void *payload, uint32_t len,
                  uint64_t expected_counter, mg_ckpt_result_t *res);
int  mg_ckpt_verify(const char *name, uint32_t len, uint64_t counter);
int  mg_ckpt_tamper(const char *name, int action, char *msg, size_t msglen);
int  mg_ckpt_files(const char *name);      /* how many slot files exist (0..2) */
/* newest valid slot on disk right now: 0 ok (slot, counter, age filled), -1 none */
int  mg_ckpt_active(const char *name, char *slot, uint64_t *counter, uint64_t *t_wall_ms);
const char *mg_ckpt_name(int svc);           /* "sensor", "dm", "logger", "ui" or NULL */
const char *mg_ckpt_dir(void);

/* GPIO (mg_gpio.c) - BCM2711 registers, Raspberry Pi 4 */
int  mg_gpio_init(void);
bool mg_gpio_ok(void);
void mg_gpio_mode_out(int pin);
void mg_gpio_mode_in(int pin, int pull);   /* pull: 0 none, 1 up, 2 down */
void mg_gpio_write(int pin, int value);
int  mg_gpio_read(int pin);

/* I2C (mg_i2c.c) - QNX i2c resource manager via devctl() */
int  mg_i2c_open(const char *dev, uint32_t speed_hz);
int  mg_i2c_write(int fd, uint8_t addr, const uint8_t *data, uint32_t len);
int  mg_i2c_read_reg(int fd, uint8_t addr, uint8_t reg, uint8_t *out, uint32_t len);

/* OLED SSD1306 / SH1106 (mg_oled.c) */
#define MG_OLED_COLS 21
#define MG_OLED_ROWS 8
int  mg_oled_init(int fd);
void mg_oled_clear(void);
void mg_oled_text(int row, const char *text);         /* uppercase 5x7 font */
int  mg_oled_flush_page(int fd, int page);            /* one 128-byte page  */
int  mg_oled_flush(int fd);

#endif /* MG_COMMON_H */
