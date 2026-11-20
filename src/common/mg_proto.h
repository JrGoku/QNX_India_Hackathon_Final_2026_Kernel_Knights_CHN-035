/*
 * MemoryGuard Auto - QNX message-passing protocol
 *
 * All private messages start with mg_hdr_t. Their type values sit far
 * above _IO_MAX so they can never be confused with resource-manager
 * (_IO_*) messages that the kernel/libc may send to a name_attach()
 * channel (for example _IO_CONNECT when a client calls name_open()).
 */
#ifndef MG_PROTO_H
#define MG_PROTO_H

#include <stdint.h>
#include <sys/neutrino.h>
#include "mg_common.h"

#define MG_MSG_BASE 0x4D00

enum {
    MG_MSG_PING = MG_MSG_BASE + 1,  /* supervisor -> any service     */
    MG_MSG_INJECT,                  /* supervisor -> any service     */
    MG_MSG_DM_STATE,                /* sensor -> DM (absolute state) */
    MG_MSG_DM_EVENT,                /* sensor -> DM (alarm event)    */
    MG_MSG_DM_SYNC,                 /* sensor -> DM (resync ids)     */
    MG_MSG_DM_RESET,                /* operator acknowledge          */
    MG_MSG_DM_DIAG,                 /* diagnostic op (fault target)  */
    MG_MSG_SUP_CMD                  /* mgctl -> supervisor           */
};

/* pulse codes */
#define MG_PULSE_HB          (_PULSE_CODE_MINAVAIL + 1)  /* value = svc            */
#define MG_PULSE_READY       (_PULSE_CODE_MINAVAIL + 2)  /* value = svc | st << 8  */
#define MG_PULSE_CHILD       (_PULSE_CODE_MINAVAIL + 3)  /* reaper thread          */
#define MG_PULSE_TICK        (_PULSE_CODE_MINAVAIL + 4)  /* periodic timer         */
#define MG_PULSE_RECONNECTED (_PULSE_CODE_MINAVAIL + 5)  /* value = DM epoch       */
#define MG_PULSE_WAKE        (_PULSE_CODE_MINAVAIL + 6)  /* generic wake-up        */

typedef struct {
    uint16_t type;
    uint16_t subtype;
    uint32_t size;
} mg_hdr_t;

/* ---------------- generic ---------------- */
typedef struct { mg_hdr_t hdr; uint32_t nonce; } mg_ping_t;
typedef struct { uint32_t nonce; uint32_t svc; uint32_t status; pid_t pid; } mg_ping_reply_t;

typedef struct { mg_hdr_t hdr; uint32_t kind; } mg_inject_msg_t;

/* ---------------- sensor -> device manager ---------------- */
typedef struct {
    mg_hdr_t hdr;
    pid_t    sender;
    uint32_t seq;                       /* per-sender, duplicate detection */
    uint32_t mode_req;                  /* NORMAL or DEGRADED              */
    mg_health_sum_t hs;
    uint32_t warnings;
    float    vel_mm_s;          /* machine vibration velocity RMS       */
    uint32_t zone;              /* 0..3 = ISO zone A..D (Pi computed)   */
    uint32_t running;
    float    env_temp_c;        /* -100 = no environment node           */
} mg_dm_state_msg_t;

typedef struct { mg_hdr_t hdr; mg_event_t ev; } mg_dm_event_msg_t;
typedef struct { int32_t status; uint32_t highest_event_id; } mg_dm_event_reply_t;
#define MG_EVREPLY_STORED    0
#define MG_EVREPLY_DUPLICATE 1

typedef struct { mg_hdr_t hdr; } mg_dm_sync_msg_t;
typedef struct { uint32_t highest_event_id; uint32_t restricted; } mg_dm_sync_reply_t;

typedef struct { mg_hdr_t hdr; } mg_dm_reset_msg_t;
typedef struct { mg_hdr_t hdr; int32_t op; } mg_dm_diag_msg_t;

/* status codes DM returns through MsgError()/MsgReply() */
#define MG_ERR_QUARANTINED  EACCES
#define MG_ERR_INVALID      EINVAL
#define MG_ERR_RESTRICTED   EBUSY

/* ---------------- mgctl -> supervisor ---------------- */
enum {
    MG_CMD_KILL = 1,       /* svc                    : process termination   */
    MG_CMD_INJECT,         /* svc, arg = mg_inject_t : segv / hang / leak    */
    MG_CMD_DM_INVALID_OP,  /*                        : crash DM via bad op   */
    MG_CMD_CKPT,           /* svc, arg = tamper, flags bit0 = restart after  */
    MG_CMD_RESET,          /* operator acknowledge                         */
    MG_CMD_RESTART,        /* graceful restart of svc                      */
    MG_CMD_QCLEAR,         /* clear the poison-request quarantine          */
    MG_CMD_SUP_HANG        /* the supervisor itself stops (watchdog demo)  */
};

typedef struct {
    mg_hdr_t hdr;
    uint32_t cmd;
    int32_t  svc;
    uint32_t arg;
    uint32_t flags;
} mg_sup_cmd_t;

typedef struct {
    int32_t status;        /* 0 = OK */
    char    text[200];
} mg_sup_reply_t;

/* PING / INJECT / _IO_CONNECT handling shared by every service (mg_ctl.c) */
int mg_ctl_handle(rcvid_t rcvid, const void *msg, size_t len, mg_svc_t self);

#endif /* MG_PROTO_H */
