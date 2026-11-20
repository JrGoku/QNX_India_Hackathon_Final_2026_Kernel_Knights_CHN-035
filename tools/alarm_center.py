#!/usr/bin/env python3
"""MemoryGuard maintenance centre - run on the laptop (plays the plant's SCADA /
maintenance desk that receives machine alarms).

    python3 alarm_center.py                  # listen on UDP 6000
    python3 alarm_center.py --ack-loss 0.5   # drop half of the ACKs on purpose

The Device Manager sends every alarm as
    ALARM,<session>,<id>,<type>,<wall ms>,<value>,<freq Hz>,<aux>,<node>,<attempt>
and resends it until it gets "ACK,<session>,<id>" back, also after it was
restarted from its checkpoint. Duplicates are recognised by (session, id) and
shown as "duplicate suppressed": each alarm is handled exactly once.
--ack-loss shows that the Device Manager keeps retrying until it gets through.
"""
import argparse
import random
import socket
import time

UNITS = {
    "VIBRATION_DANGER": lambda v, f, a: f"vibration {v} mm/s RMS (ISO zone D) at {f} Hz, acc peak {a} g -> MACHINE TRIPPED",
    "OVER_TEMPERATURE": lambda v, f, a: f"environment {v} C (humidity {a} %)",
    "SENSOR_MOUNT_LOOSE": lambda v, f, a: f"vibration sensor moved {v} deg - readings not trustworthy, check the mounting",
}

p = argparse.ArgumentParser()
p.add_argument("--port", type=int, default=6000)
p.add_argument("--ack-loss", type=float, default=0.0, help="probability of dropping an ACK (0..1)")
args = p.parse_args()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", args.port))
print(f"maintenance centre listening on UDP {args.port} (ack loss {args.ack_loss:.0%})")

seen = {}
dups = 0
while True:
    data, addr = s.recvfrom(512)
    line = data.decode(errors="replace").strip()
    f = line.split(",")
    if len(f) < 10 or f[0] != "ALARM":
        print("ignored:", line)
        continue
    session, eid, etype, t_wall, value, freq, aux, node, tries = f[1:10]
    key = (session, eid)
    now = time.strftime("%H:%M:%S")
    if key in seen:
        dups += 1
        print(f"{now}  duplicate suppressed: alarm #{eid} (attempt {tries}, {dups} duplicates so far)")
    else:
        seen[key] = time.time()
        when = time.strftime("%H:%M:%S", time.localtime(int(t_wall) / 1000))
        what = UNITS.get(etype, lambda v, fr, a: f"value {v}, {fr} Hz, aux {a}")(value, freq, aux)
        print("\n" + "=" * 72)
        print(f"  MACHINE ALARM #{eid}  {etype}   from {addr[0]}")
        print(f"  {what}")
        print(f"  seen by node {node} at {when}, received {now} (attempt {tries})")
        print("=" * 72 + "\n")
    if random.random() >= args.ack_loss:
        s.sendto(f"ACK,{session},{eid}\n".encode(), addr)
    else:
        print(f"{now}  (ACK for #{eid} dropped on purpose)")
