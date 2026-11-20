# MemoryGuard - QNX fault containment & service recovery

Industrial machine-condition monitor for the QNX hackathon (MemoryGuard problem
statement), Raspberry Pi 4 + QNX SDP 8.0, built with the QNX Momentics IDE.

Wi-Fi nodes measure the monitored machine: Node 1 its vibration (ISO 10816-3
zones A-D), Node 2 its environment (temperature, humidity, pressure). The
Device Manager is the machine controller: alarms, and a TRIP (stop command)
when vibration stays in zone D. The point of the project is that this keeps
working while its own services crash, hang, leak or lose their checkpoints.

## Layout

    Makefile               builds all programs (Momentics "QNX Executable" project)
    src/common/            shared library: IPC protocol, shared memory, checkpoints,
                           logging, fault hooks; optional GPIO / I2C / OLED drivers
    src/mg_supervisor/     Recovery Supervisor (prio 63, core 1)
    src/mg_watchdog/       watchdog for the supervisor (prio 62, core 0); a
                           restarted supervisor adopts the running services
    src/mg_sensor/         Sensor Service - Wi-Fi nodes, plausibility checks, ISO zones,
                           alarm events, relay to the dashboard (prio 55, core 2)
    src/mg_devmgr/         Device Manager - machine state, trip, alarm notifications (prio 50, core 2)
    src/mg_logger/         Data Logger + pre-alarm data recorder (prio 20, core 3)
    src/mg_ui/             User Interface, non-critical (prio 10, core 3)
    src/mg_statusfs/       resource manager: /dev/memguard/status, /dev/memguard/metrics
    src/mg_webui/          browser dashboard http://<pi-ip>:8080 (prio 11, core 3, non-critical):
                           live charts, process timeline, recovery breakdown, alarm and
                           event logs, fault-injection menu. Page source: www/index.html
    src/mgctl/             CLI: status, metrics, events, fault injection
    src/mg_selftest/       hour-zero check
    tools/alarm_center.py  laptop "maintenance centre" that receives the alarms (UDP 6000)
    tools/gen_font.py      regenerates src/common/mg_font5x7.h
    tools/gen_webui.py     regenerates src/mg_webui/index_html.h after editing www/index.html

The node sketches (node1.ino) and the HDMI dashboard (node_dashboard.py + uart_bridge.py)
are in the project docs; the hardware chat owns them.

## Quick reference (on the Pi, in /data/home/qnxuser/memguard)

    ./mg_selftest                      check the nodes first (MemoryGuard stopped)
    ./mg_supervisor -e <laptop-ip>     start everything (Momentics launches this)
    ./mgctl status | watch | metrics | events
    ./mgctl kill ui
    ./mgctl inject dm invalid-op
    ./mgctl inject <svc> segv|hang|leak
    ./mgctl ckpt dm corrupt|withhold|corrupt-both --restart
    ./mgctl stress 20
    sudo ./mgctl trace 8 inject dm invalid-op   kernel trace for the Momentics System Profiler
                                                (/dev/shmem/memguard_<time>.kev in RAM, MG ... user events)
    ./mgctl kill supervisor | inject supervisor hang | kill watchdog
    ./mgctl multi                      ui + logger killed and DM crashed at once
    ./mgctl ckpt logger|ui corrupt --restart
    ./mgctl reset
    cat /dev/memguard/status
    browser on the laptop: http://<pi-ip>:8080/   (commands only from the -e laptop or the Pi;
                           MG_WEB_ALLOW=any or a list of IPs to allow more)

## Hardware (final build)

    Pi 4 + QNX: nothing wired; HDMI for node_dashboard.py. Optional: MG_GPIO=1 outputs that
                represent the machine (green running, amber alert, red trip, buzzer).
    Node 1:     XIAO ESP32C3 + MPU6050 + OLED, VIB frames every 0.5 s (vibration mm/s, zone).
    Node 2:     GLYPH C6 + BME280/BMP280 + OLED, ENV frames every 0.5 s.
    Firmware:   firmware/node1/node1.ino, firmware/node2/node2.ino (Arduino IDE).

## Provisioning key (kept out of the repository)

    The nodes only accept Wi-Fi details signed with a shared 64-hex-character key.
    Pi:    tools/prov_key.txt (one line, the key), or MG_PROV_KEY=..., or --key
    Nodes: firmware/nodeN/secrets.h (copy secrets.example.h, put the key in it)
    New key: python3 tools/node_dashboard.py --genkey, then re-flash both nodes.
    prov_key.txt and secrets.h are in .gitignore: never commit them.

## Ports

    UDP 5005  nodes -> mg_sensor
    UDP 5006  mg_sensor relays every checked frame -> node_dashboard.py
    UDP 6000  mg_devmgr -> maintenance centre (tools/alarm_center.py)
    TCP 8080  mg_webui browser dashboard (MG_WEB_PORT to change)

Both MemoryGuard and the dashboard want the nodes' port, and only one program can
receive on it. So MemoryGuard keeps 5005 and the dashboard listens on the relay:

    sudo on -C 0 python3 node_dashboard.py --udp-port 5006

`on -C 0` keeps the dashboard on core 0; MemoryGuard uses cores 1-3.

## Node frame (every node, UDP 5005)

    $ND,<id>,<seq>,<KIND>,<v1>,...,<vn>,<rssi dBm>,<flags>*<XOR checksum, 2 hex>

  - VIB: vel vx vy vz (mm/s RMS), acc rms, acc peak (g), freq (Hz), chip temp (C),
         zone 0-3, running 0/1, mount tilt (deg); flags bit0 MPU failed, bit1 samples lost
  - ENV: temp (C), humidity (% or -1 on a BMP280), pressure (hPa);
         flags bit0 read failed, bit1 no humidity sensor (not a fault)
  - any other KIND: up to 12 values, generic check (fault flag, finite values)

## Machine logic

    zone C (2.8-4.5 mm/s)                  VIB-ALERT warning, mode ALERT
    zone D (>= 4.5) for 2 frames (1 s)     VIBRATION_DANGER alarm -> machine TRIPPED (mode SAFE);
                                           reset refused while still in zone C/D
    sensor mount moved >= 10 deg           SENSOR_MOUNT_LOOSE alarm, node DEGRADED
    environment >= 40 C / >= 50 C x2       ENV-TEMP warning / OVER_TEMPERATURE alarm
    Data from a node is used only when it passed its checks: values out of physical
    range, a zone that does not match the velocity, impossible jumps, frozen output
    are counted and dropped.

## Adding a node

  1. Flash it with a new id and its own KIND; give it Wi-Fi from the dashboard.
     MemoryGuard registers it automatically ("new node N discovered"): liveness,
     loss/duplicate/reorder/reboot counters, fault flag and finite-value checks,
     and it appears in mgctl status, /dev/memguard/status and logs/nodes.csv.
  2. If the system must not run without it, add its id to MG_NODES
     (supervisor Environment tab, e.g. MG_NODES=1,2). Default: MG_NODES=1.
  3. Optional: plausibility rules for the new KIND = one check function and one
     line in the KINDS[] table at the top of src/mg_sensor/main.c.
  Up to 8 nodes (MG_MAX_NODES in src/common/mg_common.h).

## Environment switches

    MG_NODES=1,2          nodes that must be present (default 1; set 1,2 when Node 2 is used)
    MG_MACHINE_NODE=1     force which VIB node is the machine (default: lowest id alive)
    MG_NODE_TIMEOUT_MS    silence before a node is OFFLINE (default 2000 = 4 frames)
    MG_ZONE_AB / BC / CD  ISO zone limits in mm/s (1.4 / 2.8 / 4.5, as in node1.ino)
    MG_MOUNT_DEG          mount movement alarm (10)
    MG_TEMP_WARN / MG_TEMP_MAX   environment temperature warning / alarm (40 / 50 C)
                          plain numbers only, e.g. MG_TEMP_WARN=34 MG_TEMP_MAX=37. A value that
                          is not a number, out of range, or MAX <= WARN is replaced by the default
                          and logged ("MG_TEMP_WARN=... is not a number"). The web page shows the
                          limits the sensor service actually uses.
    MG_VERIFY_MS          health-verification period after READY (500)
    MG_MEM_LIMIT_MB       kernel memory limit per service (256, 0 = off)
    MG_RELAY_PORT=0       no relay to the dashboard (default 5006), MG_RELAY_HOST
    MG_UI_CONSOLE=1       UI prints its status screen to the Console
    MG_DASH_FEED=1        UI shows MemoryGuard as "Node 99" in the dashboard's node list
    MG_CKPT_DIR, MG_LOG_DIR
    MG_GPIO=1             outputs for the monitored machine: LEDs 22/23/24 (green, amber,
                          red = trip), buzzer 25, reset button 27

## Problem statement -> implementation

    Separate processes, clear interfaces    one binary per service, QNX message passing + pulses,
                                            one shared-memory status area (one writer per section)
    Recovery Supervisor (high priority)     mg_supervisor prio 63 core 1; crash = waitpid(),
                                            hang = heartbeat pulses every 50 ms
    Watchdog components                     mg_watchdog watches the supervisor (and vice versa);
                                            a new supervisor ADOPTS still-running services
    Prevent invalid requests propagating    DM validates every request; the request that crashed
                                            it is quarantined; nodes' frames are checked
    Restart without reboot, bounded time    only the failed process; 3 s verification budget;
                                            > 4 failures in 30 s -> FAILED (+ system safe state)
    Restore last validated checkpoint       A/B slots + CRC32 for sensor, dm, logger and ui;
                                            newest valid wins, else the other slot
    Verify before reconnecting clients      READY + >= 3 heartbeats + 500 ms (MG_VERIFY_MS) + PING;
                                            the sensor reconnects to a new DM only after that
    No valid checkpoint                     DM: RESTRICTED safe-init until operator reset with healthy
                                            nodes; sensor: recalibrate; logger/ui: start from now/env
    Resource management                     /dev/memguard resource manager; per-service kernel memory
                                            limit (MG_MEM_LIMIT_MB, default 256) + 64 MiB own guard
    Metrics                                 mgctl metrics: detect / restore / verify / reconnect times,
                                            deadline misses, checkpoint accuracy, failed restarts;
                                            mgctl status: lost / duplicate requests
    Mandatory CLI fields                    mgctl status: health, heartbeat age, failure source,
                                            restart attempts, active checkpoint, recovery state,
                                            availability, response latency, deadline misses, clients
