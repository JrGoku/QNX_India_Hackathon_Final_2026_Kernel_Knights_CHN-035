#!/usr/bin/env python3
"""
node_sim.py - pretend to be a Wi-Fi sensor node, from the laptop.

Sends the same frame a real node sends, to the Pi's UDP 5005:
    $ND,<id>,<seq>,<KIND>,<v1>,...,<vn>,<rssi>,<flags>*<XOR checksum>

Use it to rehearse "a new node joins", or to send bad frames without
touching the real nodes.

    python3 tools/node_sim.py <pi-ip>                      node 2, kind ENV (like node2.ino)
    python3 tools/node_sim.py <pi-ip> --id 1 --kind VIB    a running machine (like node1.ino 3.0)
    python3 tools/node_sim.py <pi-ip> --id 3 --kind GAS    any other kind (generic check)

Both real kinds send 2 frames/s (--rate changes it). Run it while the real
node with the same id is off, or use a new id.

While it runs, type a letter + Enter to inject a fault into the stream:
    c  next frame has a bad checksum        d  next frame is sent twice
    g  next frame has a garbage value       j  skip 5 sequence numbers
    r  restart the sequence (node reboot)   f  toggle the fault flag (bit0)
    s  toggle silence (stop sending)        q  quit
    VIB only: a b c4 d4 = vibration in ISO zone A / B / C / D (use "c4", "d4"
              because c and d are taken), i = machine idle, m = sensor mount moved
    ENV only: h = heat up to 55 C (over-temperature), n = back to normal
Only standard-library Python 3.
"""
import argparse
import math
import random
import select
import socket
import sys
import time


def frame(body):
    x = 0
    for ch in body.encode():
        x ^= ch
    return "$%s*%02X\n" % (body, x)


STATE = {"vel": 2.0, "running": 1, "tilt": 0.3, "temp": 24.0}
ZONES = (1.4, 2.8, 4.5)


def zone(v):
    return 0 if v < ZONES[0] else 1 if v < ZONES[1] else 2 if v < ZONES[2] else 3


def values(kind, t):
    n = lambda s: random.gauss(0, s)
    if kind == "VIB":            # vel vx vy vz (mm/s), acc rms/peak (g), freq, temp, zone, running, tilt
        if STATE["running"]:
            vel = max(0.0, STATE["vel"] * (1 + n(0.02)))
            freq = 49.6 + n(0.05)
        else:
            vel, freq = abs(0.16 + n(0.02)), 0.0
        acc = vel * 0.012 + abs(n(0.002))
        return [vel, vel * 0.5, vel * 0.95, vel * 0.3, acc, acc * 3.1, freq, 31.0 + n(0.05),
                zone(vel), STATE["running"], STATE["tilt"] + abs(n(0.05))]
    if kind == "ENV":            # temp, humidity, pressure (BME280)
        STATE["temp"] += (STATE.get("target", 24.0) - STATE["temp"]) * 0.05
        return [STATE["temp"] + n(0.05), 55.0 + n(0.3), 1006.5 + n(0.05)]
    return [24.0 + 0.5 * math.sin(t / 20) + n(0.05), 55.0 + n(0.3)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pi", help="the Pi's IP address")
    ap.add_argument("--port", type=int, default=5005)
    ap.add_argument("--id", type=int, default=2)
    ap.add_argument("--kind", default="ENV", help="1-7 letters/digits, e.g. VIB, ENV, GAS")
    ap.add_argument("--rate", type=float, default=2.0, help="frames per second")
    ap.add_argument("--count", type=int, default=0, help="stop after this many frames (0 = run until q)")
    a = ap.parse_args()
    if not (a.kind.isalnum() and 1 <= len(a.kind) <= 7):
        sys.exit("--kind must be 1-7 letters/digits")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = (a.pi, a.port)
    seq, sent, fault, silent = 0, 0, 0, False
    once = set()
    period = 1.0 / a.rate
    print("node %d (%s) -> %s:%d at %.0f/s. Keys: c d g j r f s q + Enter" % (a.id, a.kind, a.pi, a.port, a.rate))
    t0 = time.monotonic()
    nxt = t0
    while a.count == 0 or sent < a.count:
        if select.select([sys.stdin], [], [], 0)[0]:
            line = sys.stdin.readline().strip().lower()
            levels = {"a": 0.8, "b": 2.0, "c4": 3.5, "d4": 6.0}
            if line in levels and a.kind == "VIB":
                STATE.update(vel=levels[line], running=1)
                print("vibration -> %.1f mm/s (zone %s)" % (levels[line], "ABCD"[zone(levels[line])]))
                continue
            if a.kind == "VIB" and line in ("i", "m"):
                if line == "i":
                    STATE["running"] ^= 1
                    print("machine", "running" if STATE["running"] else "idle")
                else:
                    STATE["tilt"] = 0.3 if STATE["tilt"] > 5 else 14.0
                    print("sensor mount moved %.0f deg" % STATE["tilt"])
                continue
            if a.kind == "ENV" and line in ("h", "n"):
                STATE["target"] = 56.0 if line == "h" else 24.0
                print("environment heating up to 56 C" if line == "h" else "environment back to 24 C")
                continue
            for key in line:
                if key == "q":
                    return
                if key == "f":
                    fault ^= 1
                    print("fault flag", "ON" if fault else "off")
                elif key == "s":
                    silent = not silent
                    print("silent" if silent else "sending again")
                elif key == "j":
                    seq += 5
                    print("skipped 5 sequence numbers")
                elif key == "r":
                    seq = 0
                    print("sequence restarted (reboot)")
                elif key in "cdg":
                    once.add(key)
                    print({"c": "bad checksum", "d": "duplicate", "g": "garbage value"}[key], "on the next frame")
        now = time.monotonic()
        if now < nxt:
            time.sleep(min(0.01, nxt - now))
            continue
        nxt += period
        if silent:
            continue
        v = values(a.kind, now - t0)
        if "g" in once:
            v[0] = float("nan") if a.kind not in ("VIB", "ENV") else 999.0
            once.discard("g")
        if a.kind == "VIB":
            vals = ",".join(["%.2f" % x for x in v[:4]] + ["%.4f" % v[4], "%.4f" % v[5], "%.1f" % v[6],
                             "%.1f" % v[7], "%d" % v[8], "%d" % v[9], "%.1f" % v[10]])
        else:
            vals = ",".join("%.2f" % x for x in v)
        pkt = frame("ND,%d,%d,%s,%s,%d,%d" % (a.id, seq + 1, a.kind, vals, -55 - random.randint(0, 8), fault))
        if "c" in once:
            pkt = pkt[:-3] + ("%02X" % (int(pkt[-3:-1], 16) ^ 0x5A)) + "\n"
            once.discard("c")
        copies = 2 if "d" in once else 1
        once.discard("d")
        for _ in range(copies):
            s.sendto(pkt.encode(), dst)
        seq += 1
        sent += 1


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
