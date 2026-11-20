#!/usr/bin/env python3
"""
node_dashboard.py - QNX monitoring dashboard for the Wi-Fi sensor nodes, on the Pi's HDMI screen
(QNX 8.0 on Raspberry Pi 4, plain Python + SDL2 through ctypes, like cam_uart_view.py). No wires to the nodes.

The Raspberry Pi is the monitoring system:
  - Nodes send their data over Wi-Fi (UDP port 5005) and the dashboard shows it live.
    Node 1 = XIAO ESP32C3 + MPU6050: machine vibration (ISO 10816 velocity, zone, frequency, running/idle).
    Node 2 = PCBCupid GLYPH C6 + GY-BME/PM 280: temperature, pressure (and humidity with a BME280).
  - Only this Pi can give a node its Wi-Fi: a node with no Wi-Fi details opens its own setup hotspot
    "QNX-NODE-<id>" (password derived from the shared key). The dashboard finds it, the Pi's Wi-Fi joins it
    for a few seconds, sends the Wi-Fi name, password and this Pi's IP signed with the shared key, then
    rejoins its normal network. The node then joins that network and starts sending data.

The Pi's Wi-Fi is switched through wpa_supplicant: with wpa_cli if the image has it, otherwise directly over
wpa_supplicant's control socket (e.g. /var/run/wpa_supplicant/bcm0). If neither works, use --manual:
join the node's hotspot yourself (--setup-pass prints its password), then press Enter.

Run (root is usually needed for wpa_cli):
    sudo python3 node_dashboard.py               fullscreen on HDMI
    sudo python3 node_dashboard.py --window      in a window
Without the screen:
    sudo python3 node_dashboard.py --scan                                   nodes in setup mode
    sudo python3 node_dashboard.py --diagnose                               check every step of the setup path
    sudo python3 node_dashboard.py --set "MyHotspot" [--node QNX-NODE-1]     asks for the password
    python3 node_dashboard.py --status [--node-ip IP]                       Wi-Fi status reports
    python3 node_dashboard.py --forget --node-ip IP                         node back to setup mode
    python3 node_dashboard.py --listen                                      print the nodes' packets
    python3 node_dashboard.py --setup-pass [QNX-NODE-1]                     hotspot password (manual join)
    python3 node_dashboard.py --genkey                                      new shared key (prov_key.txt AND the nodes' secrets.h)
Logs:    every run writes logs/node_dashboard_<date>_<time>.log next to this file (passwords are never written).
         --debug adds every Wi-Fi command, node message and key press; --log FILE picks the file.
Options: --wpa-ctrl /var/run/wpa_supplicant/bcm0  --wpa-cli PATH  --wifi-iface IFACE  --manual  --host PI_IP  --password PW
         --udp-port 5005  --ctrl-port 7000  --setup-ip 192.168.4.1
         --no-scan  never scan for setup hotspots on its own (F5 still scans); use it beside MemoryGuard

Keys: Tab / Shift+Tab next / previous field, type to edit, Backspace, Ctrl+U clear field,
      Enter = send to the selected node in setup mode, F2 next node in setup mode, F5 scan,
      F1 show / hide password, F8 twice = reset the node (erase its Wi-Fi details), F12 screenshot (.bmp),
      Esc twice = quit. The mouse works too (click a field or a button) if the Pi has one.
"""
import base64
import collections
import ctypes
import getpass
import hashlib
import hmac
import math
import os
import secrets
import shlex
import shutil
import socket
import struct
import sys
import subprocess
import threading
import time
import traceback
import zlib
from ctypes import POINTER, byref, c_char_p, c_int, c_uint8, c_uint32, c_void_p

# ======================= settings =======================
# Shared provisioning key: the same 64 hex characters as PROV_KEY_HEX in the nodes' secrets.h.
# It is a secret, so it is not in this file: it is read from prov_key.txt next to this file
# (not committed to git), or from the MG_PROV_KEY environment variable, or given with --key.
PROV_KEY = ""
PROV_KEY_FILE = "prov_key.txt"
NODE_PORT = 5005                # nodes send their packets here (PI_PORT in the node sketch)
CTRL_PORT = 7000                # the node listens here, on its setup hotspot and on the normal Wi-Fi
SETUP_IP = "192.168.4.1"        # the node's address on its own setup hotspot
WPA_CLI = "wpa_cli"             # how to reach the Pi's wpa_supplicant (e.g. "wpa_cli -p /var/run/wpa_supplicant")
NODE_INFO = {                   # id: board and sensor, shown on the dashboard
    1: "XIAO ESP32C3  ·  MPU6050  ·  machine vibration",
    2: "PCBCupid GLYPH C6  ·  GY-BME/PM 280",
}
NODE_KIND = {1: "VIB", 2: "ENV"}  # what a node sends, used before its first packet arrives
SEA_LEVEL_HPA = 1013.25         # sea-level pressure for the altitude estimate (use your local value)
ISO_ZONES = (1.4, 2.8, 4.5)     # vibration zone limits A/B, B/C, C/D in mm/s RMS (same as ZONE_* in node1.ino;
                                # ISO 10816-3 group 2, rigid mounting)
# =========================================================

ERR_TEXT = {
    "AUTH": "Node rejected the signature: PROV_KEY differs between this file and the node sketch",
    "NONCE": "The node's challenge expired. Try again",
    "BUSY": "Node is locked for 3 s after a bad signature. Try again",
    "BADDATA": "Node refused the name, password or IP address",
    "NOKEY": "Node has no valid key (check PROV_KEY_HEX in the node sketch)",
    "UNKNOWN": "Node did not understand the command (old firmware?)",
    "FORMAT": "Node could not read the message",
}


class LinkError(Exception):
    pass


# ---------------------------------------------------------------- log file
class Log:
    """Everything the dashboard does goes to logs/node_dashboard_<date>_<time>.log next to this file.
    Passwords are never written: Wi-Fi passwords and keys are replaced by ***."""
    path = None
    debug = False
    _lock = threading.Lock()
    _f = None
    _seen = {}

    @classmethod
    def open(cls, path=None, debug=False):
        cls.debug = debug
        if path is None:
            d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            try:
                os.makedirs(d, exist_ok=True)
            except OSError:
                d = "/tmp"
            path = os.path.join(d, "node_dashboard_%s.log" % time.strftime("%Y%m%d_%H%M%S"))
        try:
            cls._f = open(path, "a", buffering=1)
            cls.path = path
        except OSError as e:
            print("Can't write the log file %s (%s)" % (path, e))
            return
        cls.write("INFO", "=" * 70)
        cls.write("INFO", "node_dashboard started: %s" % " ".join(sys.argv[1:]))
        cls.write("INFO", "python %s, pid %d, uid %d" % (sys.version.split()[0], os.getpid(), os.getuid()))

    @classmethod
    def write(cls, level, text):
        if cls._f is None or (level == "DEBUG" and not cls.debug):
            return
        t = time.time()
        stamp = time.strftime("%H:%M:%S", time.localtime(t)) + ".%03d" % int((t % 1) * 1000)
        name = threading.current_thread().name
        with cls._lock:
            try:
                for line in str(text).splitlines() or [""]:
                    cls._f.write("%s %-5s [%s] %s\n" % (stamp, level, name, line))
            except (OSError, ValueError):
                pass

    @classmethod
    def info(cls, text):
        cls.write("INFO", text)

    @classmethod
    def dbg(cls, text):
        cls.write("DEBUG", text)

    @classmethod
    def error(cls, text, once_key=None):
        """Logs an error with its traceback. With once_key, the same error is only logged once a minute."""
        if once_key is not None:
            now = time.monotonic()
            if now - cls._seen.get(once_key, -999) < 60:
                return
            cls._seen[once_key] = now
        cls.write("ERROR", text)
        tb = traceback.format_exc()
        if tb and not tb.startswith("NoneType: None"):
            cls.write("ERROR", tb.rstrip())

    @staticmethod
    def hide(line):
        """Masks secrets in a command line before it is logged."""
        parts = line.split(" ")
        if len(parts) >= 3 and parts[0].upper() == "SET_NETWORK" and parts[2] in ("psk", "password", "wep_key0"):
            return " ".join(parts[:3] + ['"***"'])
        if line.startswith("$SET,"):
            f = line.split(",")
            if len(f) == 5:
                ssid = bytes.fromhex(f[1]).decode("utf-8", "replace") if all(c in "0123456789abcdef" for c in f[1]) else "?"
                return "$SET,<ssid %r>,<encrypted password, %d bytes>,%s,<signature>" % (ssid, len(f[2]) // 2, f[3])
        if line.startswith("$FORGET,"):
            return "$FORGET,<signature>"
        return line


def _log_uncaught(kind, exc_type, exc, tb):
    Log.write("ERROR", "Uncaught %s: %s" % (kind, "".join(traceback.format_exception(exc_type, exc, tb)).rstrip()))


sys.excepthook = (lambda t, e, tb: (_log_uncaught("exception", t, e, tb), sys.__excepthook__(t, e, tb)))
if hasattr(threading, "excepthook"):
    _old_thread_hook = threading.excepthook
    threading.excepthook = (lambda a: (_log_uncaught("exception in thread %s" % (a.thread.name if a.thread else "?"),
                                                     a.exc_type, a.exc_value, a.exc_traceback),
                                       _old_thread_hook(a)))


# ---------------------------------------------------------------- protocol helpers
def load_prov_key():
    """The shared key: MG_PROV_KEY, else prov_key.txt next to this file, else PROV_KEY."""
    k = os.environ.get("MG_PROV_KEY", "").strip()
    if k:
        return k
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), PROV_KEY_FILE)
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return PROV_KEY


def key_bytes(hexkey):
    try:
        k = bytes.fromhex(hexkey)
    except ValueError:
        k = b""
    if len(k) != 32:
        sys.exit("No valid provisioning key: put the nodes' 64 hex characters in %s next to node_dashboard.py "
                 "(or set MG_PROV_KEY, or pass --key). Make a new one with --genkey." % PROV_KEY_FILE)
    return k


def sign(key, text):
    return hmac.new(key, text.encode(), hashlib.sha256).hexdigest()


def keystream_xor(key, nonce, data):
    out = bytearray(data)
    block = b""
    for i in range(len(out)):
        if i % 32 == 0:
            block = hmac.new(key, b"ENC" + nonce + bytes([i // 32]), hashlib.sha256).digest()
        out[i] ^= block[i % 32]
    return bytes(out)


def valid_ipv4(s):
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts)


def check_credentials(ssid, password, host):
    """Returns an error message, or None if the node will accept these."""
    if not ssid:
        return "Type the Wi-Fi name (SSID)"
    if len(ssid.encode()) > 32:
        return "Wi-Fi name is longer than 32 bytes"
    n = len(password)
    hexkey = n == 64 and all(c in "0123456789abcdefABCDEF" for c in password)
    if not (n == 0 or 8 <= n <= 63 or hexkey):
        return "Password must be 8-63 characters (or empty for an open network)"
    if not valid_ipv4(host):
        return "Type this Pi's IP address on that Wi-Fi network, e.g. 192.168.43.10"
    return None


def guess_pi_ip():
    for target in ("10.255.255.255", "192.168.255.255", "172.31.255.255", "8.8.8.8"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 1))
            ip = s.getsockname()[0]
            if ip and not ip.startswith(("127.", "0.")):
                return ip
        except OSError:
            pass
        finally:
            s.close()
    return ""


class NodeStatus:
    def __init__(self, fields):
        self.node, self.mac, self.state, ssid_hex, self.ip, rssi, self.reason, self.host = fields
        try:
            self.ssid = bytes.fromhex(ssid_hex).decode("utf-8", "replace")
        except ValueError:
            self.ssid = "?"
        self.rssi = int(rssi) if rssi.lstrip("-").isdigit() else 0


def parse_st(data):
    """'$ST,<status fields>*CK' over UDP -> NodeStatus, or None."""
    try:
        s = data.decode("ascii").strip()
        body, chk = s[1:].rsplit("*", 1)
        x = 0
        for c in body.encode():
            x ^= c
        if int(chk[:2], 16) != x:
            return None
        return parse_status("$" + body)
    except (ValueError, UnicodeDecodeError):
        return None


def parse_status(line):
    f = line[1:].split(",")
    if len(f) != 9:
        return None
    return NodeStatus(f[1:])


def reason_text(token):
    return {"none": "", "wrong_password": "wrong password?", "no_network": "network not found (2.4 GHz only)",
            "timeout": "no answer from the access point",
            "ap_lost": "access point out of range"}.get(token, token.replace("_", " "))


def parse_nd(data):
    """'$ND,id,seq,kind,v1,...,vn,rssi,flags*CK' -> (id, seq, kind, [v...], rssi, flags). ValueError if bad."""
    s = data.decode("ascii", "strict").strip()
    if not s.startswith("$") or "*" not in s:
        raise ValueError("not a packet")
    body, chk = s[1:].rsplit("*", 1)
    x = 0
    for c in body.encode():
        x ^= c
    if int(chk[:2], 16) != x:
        raise ValueError("bad checksum")
    p = body.split(",")
    if len(p) < 6 or p[0] != "ND":
        raise ValueError("not a node packet")
    return int(p[1]), int(p[2]), p[3], [float(v) for v in p[4:-2]], int(p[-2]), int(p[-1])


def node_name(node_id):
    return "Node %s" % node_id


def imu_angles(v):
    """(pitch, roll) in degrees from ax, ay, az."""
    ax, ay, az = v[0], v[1], v[2]
    return (math.degrees(math.atan2(-ax, math.sqrt(ay * ay + az * az))), math.degrees(math.atan2(ay, az)))


# ---------------------------------------------------------------- talking to a node (TCP port 7000)
class NodeClient:
    """One short TCP conversation with a node: on its setup hotspot (192.168.4.1) or on the normal Wi-Fi."""

    def __init__(self, key, port):
        self.key, self.port = key, port

    def _open(self, ip, timeout=4):
        try:
            s = socket.create_connection((ip, self.port), timeout=timeout)
        except OSError as e:
            Log.info("node: can't connect to %s:%d (%s)" % (ip, self.port, e))
            raise LinkError("can't reach the node at %s:%d (%s)" % (ip, self.port, e.strerror or e))
        Log.dbg("node: connected to %s:%d" % (ip, self.port))
        s.settimeout(0.3)
        return s

    @staticmethod
    def _ask(s, buf, line, want, timeout=3):
        Log.dbg("node <- %s" % Log.hide(line))
        s.sendall((line + "\n").encode())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while b"\n" in buf:
                i = buf.index(b"\n")
                text = bytes(buf[:i]).decode("ascii", "replace").strip()
                del buf[:i + 1]
                Log.dbg("node -> %s" % text)
                if text.startswith(want) or text.startswith("$ERR,"):
                    return text
            try:
                data = s.recv(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
        Log.info("node: no %s reply to %s within %.0f s" % (want, line.split(",")[0], timeout))
        return None

    def _challenge(self, s, buf):
        for _ in range(3):
            r = self._ask(s, buf, "$NONCE", "$NONCE,", 2)
            if r is None:
                continue
            if r.startswith("$ERR,"):
                return None, ERR_TEXT.get(r[5:], r[5:])
            n = r[7:]
            if len(n) == 32 and all(c in "0123456789abcdef" for c in n):
                return n, None
        return None, "The node did not answer"

    def status(self, ip):
        s = self._open(ip)
        try:
            r = self._ask(s, bytearray(), "$STATUS", "$STATUS,", 3)
        finally:
            s.close()
        return parse_status(r) if r else None

    def provision(self, ip, ssid, password, host):
        try:
            s = self._open(ip)
        except LinkError as e:
            return False, str(e)
        buf = bytearray()
        try:
            n, err = self._challenge(s, buf)
            if err:
                return False, err
            enc = keystream_xor(self.key, bytes.fromhex(n), password.encode())
            s_hex, p_hex = ssid.encode().hex(), enc.hex()
            mac = sign(self.key, "SET,%s,%s,%s,%s" % (s_hex, p_hex, host, n))
            r = self._ask(s, buf, "$SET,%s,%s,%s,%s" % (s_hex, p_hex, host, mac), "$OK,", 4)
        except OSError as e:
            return False, "Connection to the node broke (%s)" % e
        finally:
            s.close()
        if r is None:
            return False, "The node did not answer"
        if r == "$OK,SET":
            return True, "The node accepted the details"
        return False, ERR_TEXT.get(r[5:], r[5:])

    def forget(self, ip):
        try:
            s = self._open(ip)
        except LinkError as e:
            return False, str(e)
        buf = bytearray()
        try:
            n, err = self._challenge(s, buf)
            if err:
                return False, err
            r = self._ask(s, buf, "$FORGET,%s" % sign(self.key, "FORGET,%s" % n), "$OK,", 3)
        except OSError as e:
            return False, "Connection to the node broke (%s)" % e
        finally:
            s.close()
        if r == "$OK,FORGET":
            return True, "The node erased its Wi-Fi details and opened its setup hotspot"
        return False, "The node did not answer" if r is None else ERR_TEXT.get(r[5:], r[5:])


def setup_password(key, ap_ssid):
    """The node's setup-hotspot password: first 16 hex of HMAC(key, 'SETUP-AP,<hotspot name>')."""
    return sign(key, "SETUP-AP," + ap_ssid)[:16]


# ---------------------------------------------------------------- the Pi's own Wi-Fi (wpa_cli)
class WifiError(Exception):
    pass


CTRL_DIRS = ("/var/run/wpa_supplicant", "/run/wpa_supplicant", "/data/var/run/wpa_supplicant",
             "/tmp/wpa_supplicant")
TOOL_DIRS = ("/usr/sbin", "/sbin", "/usr/bin", "/bin", "/proc/boot", "/system/bin", "/system/xbin",
             "/usr/local/sbin", "/usr/local/bin")


def find_tool(name):
    """Full path of a program, also looking where sudo's PATH may not."""
    if "/" in name or shutil.which(name):
        return name
    for d in TOOL_DIRS:
        if os.path.exists(os.path.join(d, name)):
            return os.path.join(d, name)
    for d in TOOL_DIRS:                                   # QNX names some tools like wpa_cli-2.11
        try:
            hits = sorted(n for n in os.listdir(d) if n.startswith(name + "-"))
        except OSError:
            continue
        if hits:
            return os.path.join(d, hits[-1])
    return name


class WifiCtl:
    """Drives the Pi's Wi-Fi (wpa_supplicant) to hop onto a node's setup hotspot and back.
    Uses the wpa_cli program if the image has it, otherwise talks to wpa_supplicant's control socket
    directly (the same thing wpa_cli does), so no extra program is needed."""

    def __init__(self, cli, iface, ctrl=None):
        self.iface = iface
        self.sock_path = None
        self.error = None
        parts = shlex.split(cli)
        if parts:
            parts[0] = find_tool(parts[0])
        if parts and (os.path.exists(parts[0]) or shutil.which(parts[0])) and not ctrl:
            self.base = parts + (["-i", iface] if iface else [])
            self.how = "wpa_cli " + parts[0]
        else:
            self.sock_path = self._find_socket(ctrl, iface)
            if not self.sock_path:
                self.error = ("no wpa_cli and no wpa_supplicant control socket in %s (use --wpa-ctrl DIR)"
                              % ", ".join(([ctrl] if ctrl else []) + list(CTRL_DIRS)))
                return
            self.iface = self.iface or os.path.basename(self.sock_path)
            self.how = "control socket " + self.sock_path
        try:
            self.status()
        except WifiError as e:
            self.error = str(e)

    @staticmethod
    def _find_socket(ctrl, iface):
        dirs = [ctrl] if ctrl else list(CTRL_DIRS)
        for d in dirs:
            if ctrl and not os.path.isdir(d) and os.path.exists(d):
                return d                                   # a socket path was given directly
            if not os.path.isdir(d):
                continue
            names = sorted(os.listdir(d))
            if iface and iface in names:
                return os.path.join(d, iface)
            for pick in ("bcm0", "wlan0"):
                if pick in names:
                    return os.path.join(d, pick)
            names = [n for n in names if "p2p" not in n]
            if names:
                return os.path.join(d, names[0])
        return None

    LOCAL_DIRS = ("/tmp", "/var/tmp", "/data/var/tmp", "/dev/shm", "/var/run")

    def _local_socket(self):
        """Our own reply address. wpa_supplicant answers to it, so it must be a real path we can create."""
        tried = []
        dirs = ([self._local_dir] if getattr(self, "_local_dir", None) else []) + \
            [d for d in self.LOCAL_DIRS if os.path.isdir(d)] + [os.path.expanduser("~"), os.getcwd()]
        for d in dirs:
            path = os.path.join(d, "nd_wpa_%d_%d" % (os.getpid(), threading.get_ident() % 100000))
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                if os.path.exists(path):
                    os.unlink(path)
                s.bind(path)
                os.chmod(path, 0o777)
                self._local_dir = d
                return s, path
            except OSError as e:
                s.close()
                tried.append("%s (%s)" % (d, e.strerror))
        raise WifiError("can't create a reply socket in: " + ", ".join(tried))

    def _sock_cmd(self, cmd, timeout):
        s, local = self._local_socket()
        stage = "connect to"
        try:
            s.settimeout(timeout)
            s.connect(self.sock_path)
            stage = "send to"
            s.send(cmd.encode())
            stage = "read the reply from"
            while True:
                reply = s.recv(8192).decode("utf-8", "replace")
                if not reply.startswith("<"):              # skip unsolicited event messages
                    return reply
        except socket.timeout:
            raise WifiError("wpa_supplicant did not answer %s (reply socket %s)" % (cmd.split()[0], local))
        except OSError as e:
            raise WifiError("can't %s %s: %s (reply socket %s)" % (stage, self.sock_path, e.strerror or e, local))
        finally:
            s.close()
            try:
                os.unlink(local)
            except OSError:
                pass

    def run(self, *args, timeout=10):
        if self.sock_path:
            cmd = " ".join([args[0].upper()] + list(args[1:]))
            try:
                out = self._sock_cmd(cmd, timeout).strip()
            except WifiError as e:
                Log.info("wpa: %s -> ERROR %s" % (Log.hide(cmd), e))
                raise
            if args[0] in ("status", "scan_results"):
                Log.dbg("wpa: %s ->\n%s" % (cmd, out))
            else:
                Log.dbg("wpa: %s -> %s" % (Log.hide(cmd), out[:200]))
            if out.startswith("FAIL") and not out.startswith("FAIL-BUSY"):
                Log.info("wpa: %s -> %s" % (Log.hide(cmd), out[:200]))
                raise WifiError("wpa_supplicant %s failed: %s" % (args[0], out[:120]))
            return out
        try:
            p = subprocess.run(self.base + list(args), capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise WifiError("wpa_cli not found (use --wpa-cli PATH)")
        except subprocess.TimeoutExpired:
            raise WifiError("wpa_cli %s timed out" % args[0])
        out = p.stdout.strip()
        if p.returncode != 0 or out.endswith("FAIL") or "Failed to connect" in out:
            raise WifiError("wpa_cli %s failed: %s" % (args[0], (out or p.stderr.strip())[:120]))
        return out

    def status(self):
        d = {}
        for line in self.run("status").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
            elif line.startswith("Selected interface") and "'" in line:
                d["_iface"] = line.split("'")[1]          # wpa_cli names the interface it picked
        if d.get("_iface") and not getattr(self, "iface", None):
            self.iface = d["_iface"]
        return d

    def add_ip(self, ip):
        """Give the Wi-Fi interface an extra address (used when the hotspot's DHCP gives the Pi none)."""
        iface = getattr(self, "iface", None)
        if not iface:
            return False
        p = subprocess.run([find_tool("ifconfig"), iface, "alias", ip, "netmask", "255.255.255.0"],
                           capture_output=True, text=True)
        return p.returncode == 0

    def del_ip(self, ip):
        iface = getattr(self, "iface", None)
        if iface:
            subprocess.run([find_tool("ifconfig"), iface, "-alias", ip], capture_output=True, text=True)

    def scan(self):
        """[(ssid, signal dBm)] of nodes in setup mode, strongest first."""
        found = {}
        self.ap_info = getattr(self, "ap_info", {})
        try:
            self.run("bss_flush", "0")                  # forget old scan results (a node that already left
        except WifiError:                               # setup mode must not stay in the list)
            pass
        for attempt in range(2):                        # the Broadcom chip can take ~5 s per scan
            for _ in range(3):
                if not self.run("scan").startswith("FAIL-BUSY"):
                    break
                time.sleep(1)
            end = time.monotonic() + 8
            while time.monotonic() < end:
                time.sleep(1.5)
                for line in self.run("scan_results").splitlines()[1:]:
                    f = line.split("\t")
                    if len(f) >= 5 and f[4].startswith("QNX-NODE-"):
                        sig = int(f[2]) if f[2].lstrip("-").isdigit() else -100
                        found[f[4]] = max(sig, found.get(f[4], -999))
                        self.ap_info[f[4]] = {"freq": f[1], "flags": f[3], "bssid": f[0]}
                if found and time.monotonic() > end - 5:  # give other nodes a moment to show up too
                    break
            if found:
                break
        Log.info("scan: %s" % (", ".join("%s %d dBm %s" % (a, v, self.ap_info.get(a, {}).get("flags", ""))
                                          for a, v in found.items()) or "no QNX-NODE hotspot"))
        return sorted(found.items(), key=lambda kv: -kv[1])

    def watch(self, stop, out):
        """Collects wpa_supplicant's event messages (why a join fails) until stop is set."""
        if not self.sock_path:
            return
        try:
            s, local = self._local_socket()
        except WifiError:
            return
        try:
            s.settimeout(0.5)
            s.connect(self.sock_path)
            s.send(b"ATTACH")
            while not stop.is_set():
                try:
                    msg = s.recv(4096).decode("utf-8", "replace").strip()
                except socket.timeout:
                    continue
                if msg.startswith("<"):
                    out.append(msg.split(">", 1)[-1])
                    Log.info("wpa event: " + out[-1])
            try:
                s.send(b"DETACH")
            except OSError:
                pass
        except OSError:
            pass
        finally:
            s.close()
            try:
                os.unlink(local)
            except OSError:
                pass

    def join(self, ssid, psk):
        nid = self.run("add_network").splitlines()[-1].strip()
        if not nid.isdigit():
            raise WifiError("wpa_cli add_network gave %r" % nid)
        flags = getattr(self, "ap_info", {}).get(ssid, {}).get("flags", "[WPA2-PSK-CCMP]")
        try:
            self.run("set_network", nid, "ssid", '"%s"' % ssid)
            self.run("set_network", nid, "scan_ssid", "1")
            if "WPA" in flags or "RSN" in flags:          # spell out WPA2-PSK / CCMP, like the ESP32 uses
                self.run("set_network", nid, "key_mgmt", "WPA-PSK")
                self.run("set_network", nid, "proto", "RSN")
                self.run("set_network", nid, "pairwise", "CCMP")
                self.run("set_network", nid, "group", "CCMP")
                self.run("set_network", nid, "ieee80211w", "0")
                self.run("set_network", nid, "psk", '"%s"' % psk)
            else:                                         # node built with an open setup hotspot
                self.run("set_network", nid, "key_mgmt", "NONE")
            self.run("select_network", nid)            # leaves the normal network for now
        except WifiError:
            self.restore(nid, None)
            raise
        return nid

    def restore(self, nid, prev_id):
        Log.info("wifi: removing temporary network %s, back to network id %s" % (nid, prev_id))
        for args in (("remove_network", nid), ("enable_network", "all")):
            try:
                self.run(*args)
            except WifiError:
                pass
        try:
            if prev_id and prev_id.isdigit():
                self.run("select_network", prev_id)
                self.run("enable_network", "all")
            self.run("reassociate")
        except WifiError:
            pass

    def wait_for(self, ssid, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                st = self.status()
                if st.get("wpa_state") == "COMPLETED" and st.get("ssid") == ssid and st.get("ip_address"):
                    return st
            except WifiError:
                pass
            time.sleep(1)
        return None


def wait_reachable(ip, port, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            socket.create_connection((ip, port), timeout=2).close()
            return True
        except OSError:
            time.sleep(1)
    return False


STATIC_SETUP_IP = "192.168.4.200"     # the Pi's own address on a node hotspot if DHCP gives none


def join_node_hotspot(wifi, client, args, node_ap, say):
    """Join the node's hotspot and make sure 192.168.4.1:7000 answers.
    Returns (net_id, extra_ip or None, error text or None). net_id must be given to wifi.restore()."""
    events, stop = [], threading.Event()
    watcher = threading.Thread(target=wifi.watch, args=(stop, events), daemon=True)
    watcher.start()
    time.sleep(0.3)
    try:
        nid = wifi.join(node_ap, setup_password(client.key, node_ap))
    except WifiError:
        stop.set()
        raise
    # a) Wi-Fi link to the hotspot
    st, end = {}, time.monotonic() + 30
    while time.monotonic() < end:
        try:
            st = wifi.status()
        except WifiError:
            st = {}
        if st.get("wpa_state") == "COMPLETED" and st.get("ssid") == node_ap:
            break
        time.sleep(1)
    else:
        stop.set()
        watcher.join(1)
        wifi.last_events = list(events)
        state = st.get("wpa_state", "unknown")
        why = {"4WAY_HANDSHAKE": "wrong hotspot password - PROV_KEY differs between node1.ino and node_dashboard.py?",
               "SCANNING": "hotspot not seen - is the OLED showing SETUP, and is the node close to the Pi?",
               "DISCONNECTED": "hotspot not seen - is the OLED showing SETUP?",
               "ASSOCIATING": "the hotspot did not accept the Pi",
               "INACTIVE": "wpa_supplicant did not start joining"}.get(state, "")
        hint = [e for e in events if any(k in e for k in ("REJECT", "TEMP-DISABLED", "DISCONNECTED", "TIMEOUT",
                                                              "WRONG_KEY", "AUTH", "FAIL"))]
        if any("WRONG_KEY" in e for e in events):
            why = "wrong hotspot password - PROV_KEY differs between node1.ino and node_dashboard.py?"
        return nid, None, "Pi could not join %s (Wi-Fi state %s). %s%s" % (
            node_ap, state, why, (" Last event: " + hint[-1]) if hint else "")
    stop.set()
    wifi.last_events = list(events)
    say("Joined %s, Pi address %s" % (node_ap, st.get("ip_address") or "none yet"))
    # b) IP route to the node
    if wait_reachable(args.setup_ip, client.port, 10):
        return nid, None, None
    extra = None
    if not (st.get("ip_address") or "").startswith("192.168.4."):
        say("No address from the hotspot's DHCP - giving the Pi %s by hand" % STATIC_SETUP_IP)
        if wifi.add_ip(STATIC_SETUP_IP):
            extra = STATIC_SETUP_IP
            if wait_reachable(args.setup_ip, client.port, 8):
                return nid, extra, None
    try:
        st = wifi.status()
    except WifiError:
        pass
    return nid, extra, ("Joined %s but %s:%d does not answer (Pi address: %s). Is the node's firmware 2.0?"
                        % (node_ap, args.setup_ip, client.port, st.get("ip_address") or "none"))


def provision_over_air(wifi, client, args, node_ap, ssid, password, host, progress):
    """Hop onto the node's setup hotspot, send the signed details, hop back. Returns (ok, message)."""
    if wifi is None or wifi.error:                     # manual mode: the Pi is already on the hotspot
        progress("Sending to %s at %s..." % (node_ap, args.setup_ip))
        return client.provision(args.setup_ip, ssid, password, host)
    try:
        before = wifi.status()
    except WifiError as e:
        return False, str(e)
    prev_ssid, prev_id = before.get("ssid", ""), before.get("id")
    progress("1/4  Joining %s..." % node_ap)
    try:
        nid, extra, err = join_node_hotspot(wifi, client, args, node_ap, lambda t: progress("1/4  " + t))
    except WifiError as e:
        return False, str(e)
    try:
        if err:
            result = (False, err)
        else:
            progress("2/4  Sending signed Wi-Fi details to %s..." % node_ap)
            result = client.provision(args.setup_ip, ssid, password, host)
    finally:
        progress("3/4  Back to %s..." % (prev_ssid or "the normal network"))
        if extra:
            wifi.del_ip(extra)
        wifi.restore(nid, prev_id)
        if prev_ssid and not wifi.wait_for(prev_ssid, 30):
            result = (result[0], result[1] + ". The Pi has not rejoined %s yet - check its Wi-Fi" % prev_ssid)
    return result


def cli_diagnose(args, key):
    """Step-by-step check of the wireless setup path, printing everything it sees."""
    print("1. Pi Wi-Fi control")
    w = WifiCtl(args.wpa_cli, args.wifi_iface, args.wpa_ctrl)
    if w.error:
        print("   FAIL: %s\n   -> try --wpa-ctrl /var/run/wpa_supplicant/bcm0, or --manual" % w.error)
        return 1
    print("   using " + w.how)
    st = w.status()
    print("   OK  interface %s, on \"%s\", state %s, IP %s" % (w.iface or "?", st.get("ssid"), st.get("wpa_state"),
                                                          st.get("ip_address")))
    print("2. Scanning for nodes in setup mode...")
    aps = w.scan()
    print("   " + (", ".join("%s (%d dBm)" % a for a in aps) if aps else "none found - is the OLED showing SETUP?"))
    ap = args.node if args.node_given or not aps else aps[0][0]
    info = getattr(w, "ap_info", {}).get(ap, {})
    print("3. Hotspot %s, password %s  (channel freq %s MHz, security %s)" % (
        ap, setup_password(key, ap), info.get("freq", "?"), info.get("flags", "?")))
    prev_ssid, prev_id = st.get("ssid", ""), st.get("id")
    client = NodeClient(key, args.ctrl_port)
    nid, extra, err = join_node_hotspot(w, client, args, ap, lambda t: print("   " + t))
    try:
        if err:
            print("   FAIL: " + err)
            ev = getattr(w, "last_events", [])
            if ev:
                print("   wpa_supplicant said:")
                for e in ev[-15:]:
                    print("     " + e)
        else:
            print("4. Talking to the node at %s:%d" % (args.setup_ip, args.ctrl_port))
            s = client.status(args.setup_ip)
            print("   OK  node says: %s" % (s.state if s else "no answer"))
    finally:
        print("5. Back to \"%s\"..." % prev_ssid)
        if extra:
            w.del_ip(extra)
        w.restore(nid, prev_id)
        back = w.wait_for(prev_ssid, 30) if prev_ssid else None
        print("   " + ("OK  IP %s" % back.get("ip_address") if back else "not back yet - check the Pi's Wi-Fi"))
    return 0 if not err else 1


# ---------------------------------------------------------------- UDP packets from the nodes
class NodeData:
    def __init__(self, node_id):
        self.id = node_id
        self.kind = ""
        self.vals = []
        self.rssi = 0
        self.flags = 0
        self.seq = None
        self.count = self.lost = 0
        self.last = 0.0
        self.src = ""
        self.hist = collections.deque()          # (time, values) for the graphs
        self.times = collections.deque()         # arrival times in the last second
        self.recent = collections.deque()        # (time, packets lost before this one), last 30 s

    def rate(self, now):
        while self.times and now - self.times[0] > 1.0:
            self.times.popleft()
        return len(self.times)

    def loss(self, now=None):
        """Lost packets in % over the last 30 s (gaps while the Pi was away on a setup hotspot age out)."""
        now = time.monotonic() if now is None else now
        while self.recent and now - self.recent[0][0] > 30:
            self.recent.popleft()
        got = len(self.recent)
        lost = sum(g for _, g in self.recent)
        return 100.0 * lost / (got + lost) if got + lost else 0.0


class UdpListener(threading.Thread):
    def __init__(self, port, log, on_packet=None, on_status=None):
        super().__init__(daemon=True)
        self.port, self.log, self.on_packet, self.on_status = port, log, on_packet, on_status
        self.nodes = {}
        self.status = {}                         # node id (text) -> (NodeStatus, time, ip)
        self.bad = 0
        self.error = None
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("", port))
        except OSError as e:
            self.error = "UDP port %d: %s" % (port, e.strerror)
        self.sock.settimeout(0.5)

    def run(self):
        if self.error:
            self.log(self.error, "bad")
            return
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.5)
                continue
            now = time.monotonic()
            if data.startswith(b"$ST,"):
                st = parse_st(data)
                if st is None:
                    self.bad += 1
                    continue
                with self.lock:
                    old = self.status.get(st.node)
                    self.status[st.node] = (st, now, addr[0])
                if old is None or old[0].state != st.state or old[0].ip != st.ip:
                    Log.info("udp: %s status %s on \"%s\" ip %s rssi %d reason %s (from %s)" % (
                        node_name(st.node), st.state, st.ssid, st.ip, st.rssi, st.reason, addr[0]))
                if self.on_status:
                    self.on_status(st, old[0] if old else None, addr[0])
                continue
            try:
                node, seq, kind, vals, rssi, flags = parse_nd(data)
            except (ValueError, UnicodeDecodeError) as e:
                self.bad += 1
                Log.write("WARN", "udp: bad packet from %s (%s): %r" % (addr[0], e, data[:80]))
                continue
            with self.lock:
                nd = self.nodes.get(node)
                if nd is None:
                    nd = self.nodes[node] = NodeData(node)
                    self.log("%s is sending %s data from %s" % (node_name(node), kind, addr[0]), "good")
                gap = 0
                if nd.seq is not None:
                    gap = seq - nd.seq - 1
                    if 0 < gap < 10000:
                        nd.lost += gap
                    else:
                        if seq < nd.seq - 100:
                            self.log("%s restarted" % node_name(node), "warn")
                        gap = 0
                nd.seq, nd.kind, nd.vals, nd.rssi, nd.flags = seq, kind, vals, rssi, flags
                nd.count += 1
                nd.last = now
                nd.src = addr[0]
                nd.times.append(now)
                nd.recent.append((now, gap))
                if not flags & 1:
                    nd.hist.append((now, vals))
                keep = 60 if kind == "IMU" else 300
                while nd.hist and now - nd.hist[0][0] > keep:
                    nd.hist.popleft()
            if self.on_packet:
                self.on_packet(node, seq, kind, vals, rssi, flags, addr[0])


# ---- Embedded fonts: Inter by Rasmus Andersson, SIL Open Font License 1.1 (generated) ----
FONT_ATLAS_W = 1024
FONT_DATA = {
    'small': (44, 19, 24, '32,0,0,5,0,0,19,51;33,6,0,6,14,0,5,58;34,13,0,9,14,0,5,94;35,23,0,12,14,0,5,121;36,36,0,12,18,0,3,123;37,49,0,19,15,0,5,189;38,69,0,13,14,0,5,124;39,83,0,6,14,0,5,60;40,90,0,7,18,0,4,70;41,98,0,7,18,0,4,70;42,106,0,10,14,0,5,99;43,117,0,13,10,0,9,127;44,131,0,6,6,0,17,58;45,138,0,9,7,0,12,88;46,148,0,6,3,0,16,58;47,155,0,7,17,0,4,70;48,163,0,12,14,0,5,123;49,176,0,8,14,0,5,79;50,185,0,12,14,0,5,117;51,198,0,12,14,0,5,119;52,211,0,12,14,0,5,125;53,224,0,12,14,0,5,118;54,237,0,12,14,0,5,120;55,250,0,11,14,0,5,109;56,262,0,12,14,0,5,120;57,275,0,12,15,0,4,120;58,288,0,6,10,0,9,58;59,295,0,6,14,0,9,60;60,302,0,13,11,0,8,127;61,316,0,13,9,0,10,127;62,330,0,13,11,0,8,127;63,344,0,10,14,0,5,100;64,355,0,19,18,0,5,187;65,375,0,13,14,0,5,135;66,389,0,12,14,0,5,125;67,402,0,14,14,0,5,139;68,417,0,14,14,0,5,137;69,432,0,11,14,0,5,115;70,444,0,11,14,0,5,112;71,456,0,14,14,0,5,142;72,471,0,14,14,0,5,141;73,486,0,5,14,0,5,52;74,492,0,11,14,0,5,109;75,504,0,13,14,0,5,131;76,518,0,11,14,0,5,108;77,530,0,17,14,0,5,173;78,548,0,14,14,0,5,144;79,563,0,15,14,0,5,146;80,579,0,12,14,0,5,122;81,592,0,15,16,0,5,146;82,608,0,12,14,0,5,123;83,621,0,12,14,0,5,123;84,634,0,12,14,0,5,124;85,647,0,14,14,0,5,141;86,662,0,13,14,0,5,135;87,676,0,19,14,0,5,191;88,696,0,13,14,0,5,133;89,710,0,13,14,0,5,132;90,724,0,12,14,0,5,122;91,737,0,7,18,0,4,70;92,745,0,7,17,0,4,70;93,753,0,7,18,0,4,70;94,761,0,9,14,0,5,91;95,771,0,9,2,0,19,88;96,781,0,6,15,0,4,64;97,788,0,11,11,0,8,108;98,800,0,12,14,0,5,118;99,813,0,11,11,0,8,110;100,825,0,12,14,0,5,118;101,838,0,11,11,0,8,112;102,850,0,7,15,0,4,72;103,858,0,12,15,0,8,118;104,871,0,11,14,0,5,114;105,883,0,5,15,0,4,48;106,889,0,6,19,-1,4,48;107,896,0,11,14,0,5,106;108,908,0,5,14,0,5,48;109,914,0,17,11,0,8,169;110,932,0,11,11,0,8,114;111,944,0,11,11,0,8,115;112,956,0,12,15,0,8,118;113,969,0,12,15,0,8,118;114,982,0,7,11,0,8,73;115,990,0,10,11,0,8,102;116,1001,0,7,14,0,5,65;117,1009,0,11,11,0,8,114;118,0,20,11,11,0,8,109;119,12,20,16,11,0,8,158;120,29,20,11,11,0,8,106;121,41,20,11,15,0,8,109;122,53,20,11,11,0,8,106;123,65,20,8,18,0,4,84;124,74,20,7,23,0,1,66;125,82,20,8,18,0,4,84;126,91,20,13,8,0,11,127;176,105,20,9,14,0,5,87;183,115,20,6,8,0,11,58;8212,122,20,19,7,0,12,190;8230,142,20,17,3,0,16,173;8226,160,20,10,9,0,10,101',
        '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'),
    'body': (55, 24, 30, '32,0,0,7,0,0,24,68;33,8,0,7,18,0,6,69;34,16,0,11,18,0,6,112;35,28,0,15,18,0,6,152;36,44,0,15,24,0,3,154;37,60,0,24,19,0,6,236;38,85,0,16,18,0,6,155;39,102,0,7,18,0,6,72;40,110,0,9,22,0,5,88;41,120,0,9,22,0,5,88;42,130,0,12,18,0,6,120;43,143,0,16,13,0,11,159;44,160,0,7,7,0,21,69;45,168,0,11,8,0,16,110;46,180,0,7,4,0,20,69;47,188,0,9,21,0,6,87;48,198,0,15,18,0,6,151;49,214,0,10,18,0,6,98;50,225,0,15,18,0,6,146;51,241,0,15,18,0,6,148;52,257,0,16,18,0,6,155;53,274,0,15,18,0,6,146;54,290,0,15,18,0,6,149;55,306,0,14,18,0,6,136;56,321,0,15,18,0,6,148;57,337,0,15,19,0,5,149;58,353,0,7,13,0,11,69;59,361,0,7,17,0,11,72;60,369,0,16,13,0,11,159;61,386,0,16,10,0,14,159;62,403,0,16,13,0,11,159;63,420,0,12,18,0,6,123;64,433,0,23,22,0,7,232;65,457,0,17,18,0,6,166;66,475,0,16,18,0,6,157;67,492,0,18,18,0,6,175;68,511,0,17,18,0,6,173;69,529,0,14,18,0,6,144;70,544,0,14,18,0,6,142;71,559,0,18,18,0,6,179;72,578,0,18,18,0,6,178;73,597,0,6,18,0,6,65;74,604,0,14,18,0,6,137;75,619,0,16,18,0,6,161;76,636,0,14,18,0,6,136;77,651,0,22,18,0,6,217;78,674,0,18,18,0,6,181;79,693,0,18,18,0,6,184;80,712,0,15,18,0,6,153;81,728,0,18,20,0,6,184;82,747,0,15,18,0,6,155;83,763,0,15,18,0,6,154;84,779,0,16,18,0,6,155;85,796,0,18,18,0,6,179;86,815,0,17,18,0,6,166;87,833,0,24,18,0,6,237;88,858,0,16,18,0,6,164;89,875,0,16,18,0,6,163;90,892,0,15,18,0,6,151;91,908,0,9,22,0,5,88;92,918,0,9,21,0,6,87;93,928,0,9,22,0,5,88;94,938,0,11,17,0,7,113;95,950,0,11,2,0,24,110;96,962,0,8,19,0,5,78;97,971,0,13,13,0,11,135;98,985,0,15,18,0,6,147;99,1001,0,14,13,0,11,137;100,0,25,15,18,0,6,147;101,16,25,14,13,0,11,140;102,31,25,9,18,0,6,89;103,41,25,15,18,0,11,147;104,57,25,14,18,0,6,142;105,72,25,6,18,0,6,58;106,79,25,7,23,-1,6,58;107,87,25,13,18,0,6,132;108,101,25,6,18,0,6,58;109,108,25,21,13,0,11,210;110,130,25,14,13,0,11,142;111,145,25,14,13,0,11,144;112,160,25,15,18,0,11,147;113,176,25,15,18,0,11,147;114,192,25,9,13,0,11,90;115,202,25,13,13,0,11,127;116,216,25,8,17,0,7,79;117,225,25,14,13,0,11,142;118,240,25,13,13,0,11,135;119,254,25,20,13,0,11,196;120,275,25,13,13,0,11,131;121,289,25,13,18,0,11,135;122,303,25,13,13,0,11,132;123,317,25,10,22,0,5,102;124,328,25,8,29,0,1,80;125,337,25,10,22,0,5,102;126,348,25,16,9,0,15,159;176,365,25,11,18,0,6,109;183,377,25,7,10,0,14,69;8212,385,25,24,8,0,16,240;8230,410,25,21,4,0,20,208;8226,432,25,14,11,0,13,135',
        'eNrtXQd8VMXWn02yIT00IZTQywOpoaqoFBFQmrQ8sYAFRUFBURFBEFAQEeTJQzoBAkQBQSkqBog0A6GEIoSaRgJJCGmbZJNt55t6'
        'y+5NgeD3VO75QXbv7Nx7Z+49/5nT5gxCgqJgHf2cC7vRfPiRl1ayHSQfiTekeoahDaTvyOfrxMwfxPFyeEH+ZdCB26m7O0mH5Kqc'
        'ph9/Hv9ddPwpuTI6d1ZxgLwXfy4fDA+fT68HjEJpYaD0s2e+yUi/1FuSUJSyrpUor7wdIJx/f2Tblbyj8wKkc7psvpB/JqyR8pbo'
        'CYAo8f0WvxcM5QW+H5/LT/65Pzu4AhKNYyUdt1zMP72iHtKmLvNYo+p+OVr9Q8iOmvTzOfmCj9CCrmsbO11jxP60zANvuskFHT45'
        'kFCQd3nna9VV9R4F+EE+uk6vWXBqXTO5LGjmidu5x1a1UtfJPr/kIXUJoSj1YQSvEDzndHbWkaXN5RPEc0Iz4GfnIkzhsFhdWv0y'
        'JNV2qUZuNUk+OgHwFS/OrcXLeoFZ/FxzxvHbhVdXdVM3+/bhb+qj0qtk/b6yiShpuuJ4bmrUVD/nF8v5TNG+qfRpdAaQuX8pHECo'
        'J5grscP/AnRg316FVPx3DaQINp0O2bVRg0KYKr16O8HKYsX9aFf7RGN6DL9uWC1qTiRFVfnByrhTtKnyadkI+U2YUFNwxerEoluR'
        'I+j35mBy5sQRW67lnZ5VQ5tN98Ia+jkNtqBPpHfdClYQmDv2S/Xc4RX5pO3wS5gl2ZsjaKf8wwcAabfA3k8ck6tyBjQXB+GPoXBS'
        '/PYAQkeP0g9OgXBLvtJG1q7+Jkb0hUQ4FomfH4ddDOPZADYAM39hXRJAwv98B4AF4EY7fsp/8E/FAIWhit57XZXx7wNQZKb0DCuo'
        'hznDQQBgIEfnzZwE/qfj3wrxP4lXnvw2Lu/3+UF8gMqAi/TLOoD2iju2+wGAvbdQk0QMhI+AdY1qdNqCUZwHcNAo3srP+Han9uyP'
        's0PuZHdFxaVgs1RV4MmCm2nHvZUG5tF5jG/sq42KOhZS9K2v8ixCe9SH69nvYwvYJayLPe4S/z7HIPNfSBP/f0gHD4KMf4kdZfy/'
        'mMsREO6laHYRLsh/pcwq5vGs4GMre7EZ3aQXawEH7exwTfzjMeIDCQjp8DqeIAvhMXZ8HuA90d+1hIuvwyp23NYCz1MMFPA5wvA7'
        'kGn1K/ZcC3KzAGZJM8EghKrZk8VdviJFHN8tHXyAlBkmBR+thwXs9/FWcNzEnDhNE/++4fi15wCkt9fE/x5YST/fxXLAB9L4Mwze'
        'IcMVLNHEf0OIRmgejCTf/ZOya0s/PFCMaxlmQLwoeJdLFxiNDJbuydCXz7ymt9327Xcbn9dHE/8n4d/OTfW2Qqb4/ilMoDNKJhzs'
        'ZuywDcwtyOEEC+xaw/E/BMwTq7q3j4ILbJwaD8WTH0ANNkCePFOgz6BAwv+/nJ6c8Syc7RdQ7Y18+ERZXM8KXeig7XB8UhXV3wC5'
        'DLPuS4FyVWZXxDt6knfcJosIbbc5wPzfStpD8QMbbWBdJU80uMUjDYYn0mEGOx6SD4eeojxdY3w67PKVW5pZFEaYUjUxe7bZDnl1'
        'WckrAOff6FjviY12yqKijqHhIDw6RXsiTVCqDtEEgHOvt2/Q70fgDHPH+PfYBQVdtW9VAJLIOB/yJfxb4Ukn/L8EcOHNjo1GRADs'
        'UbbCv8suKG5ZahW/Tj+CtQ2Dm23Bv4yBfY9ChvRmnoMrmn3n+P8ETiFpLLJUwx+RMJ0JG2AWMu51CnfUF1izjadhO5WlL4tJcDRY'
        'Wys7/jzcrMJuHiFkn+byr7cE/sPhbfMNV56pcjOfNAR1ssHCasgw0kb50gX/8yFnuD9q8iPc8NZiup9gKRve8ed4/sLImNWXtosP'
        'mFg0TYKCg7O4YNMP5iA0AGa6SP994DyZVB0ghI2x/OrI7Sb04ojbyEq6n4FjZ85Gw9memvg3Oaq7tHVW6gTx9RjQt70A/iBt8twH'
        'W8lhgn2agQ806DQbsn3j+cu8CmNpQ2LgY3myseR+JOH/Sdp4mcZBbGXyORKyPRXF38Cv9PN7WE6vdxQ+osfvgGN+U+/HjsNN1vDG'
        'b9VhgsBwSehuvdUBuXNLEMToOcuLwLJCjE+/w2zGJXFM5LHZxsuy0l74Xjp4GiKfpjOLmn3dz8Bb9EvV2xDuw9QzK7ykZvHhefB5'
        'OfDfphg2sEu8AfDyXeF/NVifQtq32g7fiGnmJvwg4T8Mrnip8F8lEzawYW+UGUaor/UbQ1lpVfazZ/YHTGbyyFk2ZZYD/01BQuZy'
        'Ju9OBiYbh8ImWx6ViBoDsJlwFST5E26FWzU5KuAJ+s7SYaFqJsnh95HwPxfGu+K/kS0Rzy1vuHLLYCY9BL31IT2MoIB0xn8zC5uu'
        'PE6f6KzFcjvhv0xqwtLEyzCPl24AwoSzOWbRfDuTqNJ7cPx/JvCvkv5xi4jBoBmAv5DFhIzyOGQxsbET5HGxzDDiEsCVfxs05f+6'
        'cByVQlVsqZRbMuA5etwNLGQkjeklCRqVLFCH62eUvwMiIwM5r26TbBqH4c1REv5f5Uws6CwMZkPX1Bl15dLaRVzwSwBmGPiYXa+G'
        'iY03nqfIw9GiBzc74NbUyqhUqv2lCSxLg2nrNm5pw/jKTsafgDR4TVHR8yKMlnWlid6Fjvou7DsPlnHN54K7ZJA55MTi70NB1bLx'
        'vxkuikus46/mDvE/G2AUKgH/oyHbSwxlx5dK+O91lYteAv+LIE60YjYkeKmuNQKulVUlFK4SE5EDuF1hcPh75cQ/nm/YdI88bsGz'
        '1PjDDQDL4LVzDGEvCy0mIJl0vLUFhvOLbIULRtq0G/6Kbhv2C06U8N9TMsAp8L8M3kZN7AkeqAxaQAUzZ/y/B7/wkVX7rB/gP/Rz'
        'KB5MQlknX1AaRLZT8dEyszG83ft3yAxmHHmY4Gykk/SPUWuHR1HAQYgUBUPZEEVYkKuRhhSOG+Q3FevuOR+zR7LmypUr8WDHf6/M'
        'YlaFT0vr61Amx7aDQmbDMSQR/QlVlhUNr1587PoavlSdOk8IIAi9BkfdZPzPZhO6rOTc0HpkX4mJ9gI8wzWRDcxQeYOp1r0hTbPJ'
        'WPZOnuCjKHCx/zGq+sltKFYOIb0hn3x8yCweI77ZOaPpgKl1sJh5jbOETz40RTtgigv7rmBdr2yFgeK3BlH7K6tZ3PsGUx1KxX8V'
        'GwwR31scOhR05/gfC7IK7XKrkHih7W2GKSsl/PcZBkXNFPivbKFvmZJ/BhNDpGs9BFZDmVVsuIq/g+FVRWXh/20uhJG3QV+iWxab'
        'By5B2xVAJ+D1sEiSJO1dDcfgW3GR4Hyiv7eyspFD5r7sWk74r1SY6+GM/9pFWb7EFPRiKXCo2/et+butEMbx3+e3rMQtXM1eoxB3'
        'teh7PkO3jxiMOkZQPnkt+hjkEvtjcXF0NJG44/EIRPR/rzN8PP4RdoVZkrydpH9Ma+Fq53OQLOmw5KqUYrjcSbiCMfeQDFh7JHoN'
        '3KKj5M8yGJYy3fex0lq9jM37A+AoL/hOkpzmS/Z/NjJc4CICJ7+r0jRaMxvrgzL+18FnHxxOO/wVfylD8CjWe9vV2JUqZqlRAL3Z'
        't8VM3qx0gfVsGuzgN3BAY60mmyG7p6rAxf4nWvysBc7Jh4HH2DRxHXAtv23kCeVeIBy8B5g0hp4listoWXsR7PtAGsNCf1eTsJLF'
        'l7IBrFT894d8QymXKAv/Q1Bvm4QOjVt1+JzPUlWKoNFqCf+DsVC/V4F/VUdWsxlFMblfKavKMMggH8fhTP07xX8NK7Rhtnj2tAhw'
        'CLBqQ777C8zQkCwmNlLp8HOQJiuwkyErEFsMopR3rJPL9SgF/tEviqmA438BnQk7Q5xbSWAYFEPcPTFHBP5DsZaJTVFMrdsHr5aK'
        '/83whWthQ9hEJIbiGHpUDeABZv8bxAUmvyVJmT/Wd5b+CbMm4aYkN3G5oGcRCC14IjfLtLvcC0X9hnpe6qCp/5dO1yCI6aJCXvoa'
        'PtfG/yuQpjCdBPSIhuPiOIKoOzL+fwOm5WQyLfVDWPs5M3hPV0kPx8T7S4UVzX07RcJRT6YG8KZUBq43OFH/kwCH+pXZM/eR5wAi'
        '5QGh8WkwtaTvlYi3X8L+EN+2e4Dg/0OhaOwkQlZVC7RTsW9A33PMKIK5L7Y0/L/PBtFS8T8ZTqMK4H9Q0yzYbigZ/51bgZ3qWG9i'
        'y3KYhP8RqK2Nzpkc/6qOfMjsqwr9f3NZVX5mzWxfALYdQwLvCP/43DlU/M8EbsR4A/bR835CdSAfi36NwCpJ9wFJkKfkAmMczMR2'
        'w5bKO+5gQ5sa/5MUtmaO/2nMYPTe3OASOCbUbl7SvwZpKsO/LW9jfVRjqp3Jp2Gy91GTImCua2E/OrY15cZ7PKN1Uvv/hICllv7J'
        '49mEzcTVXC/YHgrdJV91pqSQxMQo9ZLy478hnOHGxJWSwXKDJv5b5St4rQ/xAH4pXnxfSPBR4n/9tZjhwVWfvgi5QUxTToajPQLb'
        'hYEs+qKqJnmQb/g9HR4WsesNguusJwNBGtedx+lYgNOh7qV1zGtsPMD+RxXCfz4kdmZmbazx1ClOIINNYBbB/wAuYGLkk7F1F8x3'
        '8uTnj2GQ+4Iio0TwDmOsLzv8H1T5/86zYW+LxiUUVDr+X4gD4YbRxH8XPCd/xMTE1xX4DyXqVlqghH9VR4ZConwt7w47oLhFqVWq'
        'dN0KHLvNDuAW2w684XUH+H+eObX6wC3uQW1GDQCriGQfR2btl4hSLMtLSk2edCAvWjKuUfo3FDRyxX8bxUUk+38ZFMln+EUc/3hE'
        'Yi2/7EE98ru4XKp99gZmZFbTO9R0MUColMfgbHMt/DtL/yjwABQ6rBqS+9PcGU6UIQDJnL59u+rscuP/Na60zKFhCqy3m7TwXytZ'
        'OGPpW8jGHu8TvM0+8UBm41FqqYw6DMLY44QDRqbxpwoHPLYRSNOLx0IT2DNwvANTPIIKqcsU+WKj5gSnYCVJsn/mNLZ4vupZUrf8'
        '37+JwxGUj887C3ayAKaPCECe4W9kF8F/c25meZ2pps9Diptg34yEhIQU7Gn8xI09ke9Kw/8IuKR2+LdUofsKu0QEf4+UXlefYLaW'
        'gf90+DWH25lKwP9YuEw83VAYqMa/fwrxQXP8qzoyBJJZLTNWoLDfNf9llypPCfxzckiqcMs5Z/BxUq/y4983HzpTlUJyiSdjWxcW'
        'RNsRE/M0oj4q3MQ41iSrlrKP3wJcVyKwWgZMRK74N6RZA+4U/9ehO8V3vMD/44yZTEAGxBZWRwidbU8k99I6e53auy2A3ZoKhjwQ'
        'pm0+OHarrM+KyJ+RsaYYLhK5R0NC66mQEYy8rl9XzXMvwhEkh9nU0u5I+fG/hQcRjFPI/19o4D/gNOw3qqTrhp8UcH/dPDZ9uuAf'
        'v41kZteDtuxBFoLw2gbmyJwRDsnDvFDAu/nwLmKhT/bPm1d56qI1hT0pEazEAxlFFOVZkOPDnKgFtoce6KEqegYy+bT5JXFfTuGi'
        'yHKC/xbc4nCA2VhxM3uq2Nd/QgEbLibLzmstFp9MojnKkP+nwAkmMxFrhd3FYFiW/A8HvV8ER69S8B9YCN3IO9mA1PjHc7i9kyz/'
        'n1KqJKcUgYxHljZALlVGC83GbrVa7WDqqLxr8MQEyO9cbvxjJwtuljFLVtCJZS0YMg3kLWFRPol0gFN3R0GUsAdxv45N8n7wZ3PM'
        'TQP/+C4D7xT/2+FgB3dDu0N2gf9AEUwwmNkPbg/2QfW3Qrqv1tmu9sG+UVGZcCQqKuo6nIqaw+Ilf3MRmIT0PwSuLUt1PMSnZeIf'
        'iICT3k1IhCJSRo9IccCoGFpqd8Q38vvywd/tdrEP9zfK9r+3XfFfCQf/uPjbQsFMnmsbKxPzXfHfmD3BSVIXYlhcB9UyLoi3hv0/'
        'Lbkgl0eDODzWUE4sGrCX8q0UrMQDGaURYPgfJb3XR+Cw8xA9AYSE9DnB/7ss5gqbmjH+OzCRJ9ghCeGrndj3JSjwoapJqfa/5cyX'
        'Uir+h0KefJDM7Ngl4r/9IzWd8H86kNjLrlcuGf9YDl2J3FKJw1mNf7QbTrr1ZPgfpDbuaZktVVX+y54Qq/IwiMgziT32yEETKvwn'
        'y7FnM2G/JEykGLD4n2SQT9mDY0OIulHZXugRDCZppvFPhE9a2NTCsZlPy0LBtrRCWvgfLYXglBv/TW9ji3A+XP+S47+Il+9i0R++'
        'WCW3ZgLc0o7/q1LH36lkjlKvWyAEprmgFpiE9B8NTTDjfstticR2730Cwt90QtUr8rERoB6qGHUSL6UjFLBBzZAoKeky/t02Q7Kr'
        '0cSQDU/jjyVgp6b3IrCZTCorRm2AqtSJk8ULjgv8+2XKvoT3hfnGkAM8gnHg5vikrV3QRRbvK4KVXAIZ3UIDtLvVqLdL0ZPzRyAR'
        'WT2FDLaz+ZTfhcw6s1lDrMyJUAA5Xmp4uZloXF1Vu2y0qBcZWUUNG990pj+Wiv8adpBMl9gc3K1U/J+FMXzk+5qXEm2yeppkotHC'
        'fw/IMnaDRIML/nH8/JjHGf6r2uSO+KWzuzhdi1cJ2bmlMvJIZBDkVXbDKScfxuNQZNDC/34RcUnk9mVC38vAzVymsJYFQbZhMROF'
        'YqDDMKFnU/P/ZS88YKs0ABX+/ZPlO6jxX0dWlMuLfxS87JI5YUnQJDH/82H2lPCEhn4fbzrzaY3y46s68ziZlKtz3GHaW/GQ38lJ'
        '+kc5WFg2mk/zWEKq09S5gf0PE53kWOlaNQF8Koj/j4RhAotjbEJ8GGwPuOB/MQ83Z7r/V+/yb+kU/0uVoxyJFPKLjKzOddzr3Gve'
        'XMj/bQQGr7rLE4OQ727AMJVYZC5WiUlagYx3Qc+R2b2uJZ44L+rbiZQ4l4WZxjLvM30Yw5zglcBQuxXOu0tx07871ZkG+ZXLjv9Z'
        'BefcpRPyjKXifweLDEUHmUVEVMQ2sREl499wDXovpCc64R9b8dN68PifLXJHZoIpUCtOmVfZgBdEvQl5ysim9g52//cTtklTerrm'
        '/L9AEs79bshx1YvhM8MNUATw/gHNjkMTHrc3X+b4fuDANhyviyoNQIX/JXDWUxv/OKwk+E7xryKMfzZJVy6g+n+ZVNe16FHq6whW'
        'mY2J/c9TITAJ27+VWOJvX+HMtZNH40GKWqoIgQIPadC9XVEsREFH+UGSydQYKY++Ev6ngkkR8dgDLI25adZRVVMyucQCVHCA8Hou'
        'zewwMFtOCntZ3ukKy34/yGbxhd3Z8NFm9rsial/lEy0jkLEskppanxrI1sJP7QIev2CDn6s+Zkohsk8LkMINVnJlQYJEawcTtdoW'
        'wzo25j5l4cZiqc6oAh6iVTr+g0wQxi7xWDHn9BLx/zmW2IkcVcAFI1FxJdyuXSL+8bDy9RVHQw38G/+AdRz/OAp5PWvFC2Y+gzrj'
        'n1fxjYOwIj5NiCpb4ZIHi85hs5hxr4xQFf4fsvMx1W0VmCRhtSuc7aAMzMAW4jGWJG7e33hAcnBXSWVhvg/ZlRqAEv/dHEWtUQn4'
        '/4/EY3eN/1/5AHnZoxz1d0qh10rz+ov0Oc1ywr9SYBK2/8RCI5aEGIaammCeLzJ2xzauzIZqv2ChtAjuA4Up4O7Ip/i20MJr5cCB'
        'h40hW6G4rTP+cdCiUp72jIXkkZUNdd7P41KpC/7HgXVaDY8OUSIsq2Uh7Grn0WwlCDPoREiSjYlesXBhgC+qMuYWe3m1HcwyVDsB'
        'BqiNpJ9WoKsLHZJJ5AqJ/6kRTcSVuJ5kLZ69O/NInJSdTMUK2d4Q9FwSWalK6C28wu61kOAe62xCBqd13JsPxT7MKI9yrv85/3rH'
        'en2W2uGQW+n4b2aGsLpu7Y7ChUqqin7XNM2EHP/BeJHafqSBf/SowyrW/4wjrejQcNjGkpotqgRPxE9oj3plU0s7VRmMhyH7vYbG'
        'mgN+h6IOmvjHdkjYPbBR8+ExKl/uVVghZC3Eos9iuW3Hy5yUnyab8C56c05UaAAK/GPJ4B1UEv77S9/vGv+wqS6qNs0h2LZUwmaq'
        'NI0Y1870jY/kqu6Vbzn+n5Qs9FLkzxp4O3CO0GZCC8CagFdangyHM2pr40GYIA04H1cQ/30VgkkvE13/axmJnPDfxAYOHl2XyNT6'
        'iySWB//f6lGCZWI50GtlCDPRUNwTHBJk5e2tlKpahFH/EnGx4/97vbkjNT00oNqgRD78ImkR32MV6Goa2PykC0Xisddr/Mbf/lMX'
        '1R+7fH4HzpSTpSGarxBgjjnS1QQR5zYmn6//DfNUrIm1EZ/YGi/n9b9ntHFVKJbVVi8r/mecjT7I7K5OFbvZ2ROUbzVWxj8JAX1B'
        'E//Y1Cet/33FxFvxrbf2OKWoYq3tVCUcUkhna8TyCjkjtf1/yHOBlYdQvK8onQl2RwPFcQCuxO1B+0AybgwFWxcJ5zu18D8eG+Oy'
        '8hSLq5X497NkGCqG/5R3sPMRv9h55ao/K3W8S9nP1AC+VOQ16A/WEIp/tz1iiYwc+VOXpE844S+ZIo7nJe1+w83zpFPAyLsisKFy'
        'MbSuIP4XKF2RjVYkFd/Y2A4547+DrN3zMcvjpV/jC89v6Y5KskyiHj9eM0UvkhMStFgZm392ndA13gD1IkyPMXviC+N+EPlMfA6z'
        'u52sgu4djUuVVgJ4X1XJY5y6gCLaeDGb75lLzHot8h25vbU/PZWdG7OmjSp4x54Zu7CtazhPnDaugj87lZV3dFXPcsT/hWy7UnBm'
        'WZBLxc+hoKnqVuMU+B8OeT7a+K92S87/UWvWyWxzfNhjJckpokrC+p1ieY1UpbGVraM3DN8ZV5i877OqJcT/ENVp2aHbafu+UpmP'
        '8bq2w6pKRyRX9hQQ8e01MligINUY7HLUvgL/UxWWpwhn/KNDIo7zbvF/HT11ICvp+373jAmN0ZA5vj5M6HsYrK5rCP2fnzHCs8xr'
        'BNkc9bhP6nRF23MWGqK/ILm9FJVuOjnJ88+6fut8CKuCdCovYRPAxL9HS1X4nw7vVwT/fwYFn+ajVd7ou76GMAofkRz1d0tBdBXn'
        'fUghiWD65pkG/l5Nn5yy3aADvCxq+vrLbn8//D8kFMi/Dv6R+5gdN6Dw8Pw6FWBeyPCi65i005DcAQ2++eV9ytCVp0spCs1NdXz/'
        'Y+g5yKT5/xjWriYYaf4/618H/875/+6GvqdaewSM1993BVSxhz5YErFl0Xv9/PVn8U/CP8v/h5QmeDn/3z8D/zrppNPflgx96uoP'
        'QSeddNJJJ53+IdRLJDZDL3yfmHX4A+G+cn/7vDnlaerXeufXrORvm7VlHlKn/IL1D/5A7XkND26v5PIrPyIuyZGxBRewL/SxnzJv'
        '/RzCf0xAg46YUna1U+xTcHvvTF8kzlGmMcMNen9vdtKmxh1Ye/HvhkmXbTS3SZuNlwrjI7gju0YdL/U+CNHE+9sWRHrM9Tj9X6CF'
        'RfSP5xlbF1H761qIocHla+GIm+KEcJIv8GnJYSvWf3hO+I7lHsm+ST/Grn1PjngafTEnkiTx8JnLc969dDzvGPdmz0x5S7WVg5qQ'
        'nDiAf8iLhR6eEFpNZ1id/hT8B+DsKEU4bdiVemK9OU5mTzKUVNuLY0kKIftFTfzjMMs+LM0oXXZQAv5TcSp7HEkXGmojO2aw+Kjm'
        'kDQGHDguzdpL3qcAx7VeDuH4VqUxQzUO0mZkvijhfz6GC8H/sw7I+SMHivvyxXqDNPCPF0OzWHBfE2nnryzUfydPSRtHF7QGJtOw'
        'zD4sRuWkOCGfnNCPRWvh7UN4MjCc3J0Hg3D8Y4NNigh4GUgCDe3TSD7XwzxPkfl8MYs9wQGXt1RbOagJSYkD9ttI3KHHqeKx/I5b'
        'yI4VvXSO1enPwP8S+ONxD9QiCvZTz3KlYvjQ6M9WfmUO8vF46KJFE/+1d6ylEkOdHWHGkvGfd3Wgh/cUuJK5riZqFs1S6DWH3PTx'
        'vqgtjqM3SPsUuLc7CInebBmzKo0ZnobT+3t7PBRnE/i3FHz2YFW8ci2gCCZ4II85kOpVCv7fhAuIZclJMJCJn0Sae5pu0lzA9cFK'
        'V8D1chQ0QD5JLChtPM+n+QJdk8ppFlzi0/HrcLGtQYl/44O/8UzqJIRruvdCvLdLDb5HQBPbpTqoUYr5AbZAbTEqIyI7k6VJukgT'
        'p8FviMfYEcrQJQCd/gT8t7Kl0wXCfgkMb62gmAWet7Kz/EHVcjXxj5yjDzXxzzKhR7LU7C3BylQFtm9SMztdpCb2KcDrdGZqpDEL'
        'cdjp+qrqJoF/sYaiN8v7bhjfw1gK/iub2QKkPXQCrw8WP7Ik8LPUdAPB8j7E42e34SDvfRTXVYvYCb8qVmr3dxSIRV5h0toujn/S'
        'r9PSCmMcKDGX5OUobsJiHl+h61j7q5f0oZIisulSiW9SiGxi2JQ4UCxPVGyEqJNO9xT/U0R2wlksq2xbETU/WSzXW1AB/DvoWLKQ'
        'ZeszFNGF9RjBTF6Opxm1pX0KRtCJ1zmN2VSxweUigX8HT3PQAYofVQRPCy3aCf94VdZCGoZsr882BxpAotF7hpNg621ibZLPZXi5'
        'ILeeyPxAcp/Ussv7ajTJlhIB4bGsizP+3e1iYfMkmnil57b4yC58Z5HRtIeDKvKicljXJugsq9O9IPdJkdlJGxpw/IfDtWhKV8ma'
        '6EPSLqNyfrBnZfwrzHYCZg8KqNMP9+8grqYC/ya+Moct7DDRDLPNoZBd+CgFqHSf2mAxuqYxWy/SGI8S+DfJO5g5js55mkkrYbGF'
        'EB8bq4H/nnDTnSxD2sNHObzq+ZTZazQ2BHjkgsjE2tUmrePAdgCy/8d78nI+vF3UN4qBpq0z/pHZXMKj/pf9fA1UN7E4qCLvK5K9'
        'k4d1ztXpHlC1fdSedmM0w9M+2QQdS2B0EWyxsQdpLiS+f0B3Cf9Ks50m/t02wOVaqEz8qwAq7VPg5iB7LTunMZOa0dcF/57TyKa/'
        '5o1Bpdn/kCGepMuJ5fJzR9yZ6o59qB6WOrrJSR3czkGqCBl3u07kkjNy9q5NEON5d/jHPTedKJA36LkrCqG79W7ROVene0GruT0t'
        'i+FppdNaKUn+DxcT778F/q23FGY7Lfwb1sDVOugO8S/tUxAEVk/XNGbrhHjwsgv+ier9SoQF4v3U+M9HPHn5UL5PXzhu5e1KYhey'
        'BsNIMoeLBZ4z5Qwdk7DHYbKc63sdai1tTIc9HZmKvIVHtfBvKfFpv3bKdOL5Cr6xkMicSzOMOufqdA+opU1tT5sk5c93wv9HIkfS'
        'FwL/KrOdBv4NyyGhHrpT/Ev7FDxDGySlMatSSPX/j8TPS7TwT5TzYjZTC/zXAocPN8Yx/OP8MsZpUu6fpTBqMQkCWAhdD4BY1Pxg'
        'kalVZrFIVNTYkeUxXbLpP2q1K9LHut2Api74zykpsblOOv3F6AMne1qTYgtNy+G2cnGICv+dHA6aBuQByf6vMttp4H8xJDVAd4x/'
        'sU+BRww1QEppzGYz+397h4MaHGoWOOO///rn+H7fo5X4R3ynHpyeb6jYW+2Jo9IeWf1g5akUav6cbL7JHXzGWCyivwrnvaUNwbof'
        'F2nLat9U7pNQfQ5c93DB/08QoXvndPpb0ConexpOYZoypBJq9g0wuEv4x5J3zsvB1fvHpwv8q8x2Lvg3LwaHyDJzJ/hn+xQYWu6F'
        'ZF+2jVkOTmNWfYZD8v9nPFXJvculTGf8j8LxCX7IdzpY6qvwvw2SHzd49E9JlTeI3uyQcuVVMiXaVtIYgERpD6E5JGGd4YAkI7wI'
        'EQ7u0jMegT1uiiTz1t3SHgYy/oO2Fmml6NFJp78c7XOypyFvvH2FDW9AYx+nlv9RtV+oVTA+1Mn/F62NfxI2GHE3+Kf7FOQBXO3I'
        'zxlqV6Yxq4F9EsV4l4MXnfFvxFviWpMt4Bitsv+hRvha+cWweKfAfyW8T8KbSF6OzAaW7SByyj9ss5G8sE0KHTyfvw++wluI76IO'
        'RSxA71e2ycTC6q74dx8fr7WZok46/eVoo5M9DdPAiLjCy+tCnPR/bCsbFX7m8Lzqj5cT/z/2tDALwR3in+5TkLV/tp90aq8oZRoz'
        'j8n7c5LWBfdy0f89Rh9MKzy/7kGkxj+qtynB/MdbBgn/OLWyWc6fNQosNLxxDBQwed/3Kt9PdyLcqCYSahfxb3Ml78ghUvWRzfI+'
        'gDL+F8HZofoiSZ3+DjTdyZ7mTG1d9uIbyPbcLQv/hR441tb2BCo7VgihcgcSIa31Stp0jG1OdU/oU76vkStVypJyEMr4T6twZlOd'
        'dPr/oa6gtqeVjP9a4wx8gcvq8uDfRE0GmQ3+V/jfJGWGrjAZk8TOXq4Uo+X/s7nrjKXT34O+4/a0tDLw758O4diZ7/2One1MWh78'
        'e5+CWO//Ef6fACjIqXwPHpDB7TM4W2KWzTuL/9FJp78YBf3O7GkDy5r/B+eB42Y8Dj6bjcqLf9TgNt0O4X+BfzQ4xpTaueLPxys7'
        'F4q7Ix3/Ov0zyeNDak/rUKb+X3/umaz8C5s6ofLjH/Wxk+V5FcB/UNgy7R9ahs35f3k8nXLyD3UvzxaEEv4N1jydq3S6P+nBu4f6'
        '35I20FVJKvzXKksy0UmnfyoNhsT7qr9TIMpPjX+3r2Grzgc63ZdUbTdP13G/UEAGZK1W4n9CCtjb6Yyg0/1Ig3Cc3iP3V5frrInb'
        'r8T//PidIToj6HRfUv/rv3S7X/su2/910kknHf866aSTjn+ddNJJx79OOumk418nnXTS8a+TTjr9U2jrJv0Z6KSTTjrp9Deh/wPk'
        'M4UQ'),
    'bodyb': (55, 24, 30, '32,0,0,6,0,0,24,60;33,7,0,8,18,0,6,77;34,16,0,13,18,0,6,125;35,30,0,16,18,0,6,155;36,47,0,16,24,0,3,156;37,64,0,24,18,0,6,241;38,89,0,16,18,0,6,159;39,106,0,8,18,0,6,78;40,115,0,9,22,0,5,90;41,125,0,9,22,0,5,90;42,135,0,13,18,0,6,130;43,149,0,16,13,0,11,162;44,166,0,8,8,0,21,77;45,175,0,11,9,0,15,112;46,187,0,8,4,0,20,77;47,196,0,9,21,0,6,91;48,206,0,16,18,0,6,158;49,223,0,10,18,0,6,102;50,234,0,15,18,0,6,150;51,250,0,15,18,0,6,153;52,266,0,16,18,0,6,160;53,283,0,15,18,0,6,151;54,299,0,15,18,0,6,154;55,315,0,14,18,0,6,138;56,330,0,15,18,0,6,154;57,346,0,15,19,0,5,154;58,362,0,8,13,0,11,77;59,371,0,8,17,0,11,79;60,380,0,16,14,0,10,162;61,397,0,16,11,0,13,162;62,414,0,16,14,0,10,162;63,431,0,13,18,0,6,130;64,445,0,24,22,0,7,240;65,470,0,17,18,0,6,175;66,488,0,16,18,0,6,158;67,505,0,18,18,0,6,177;68,524,0,17,18,0,6,173;69,542,0,15,18,0,6,145;70,558,0,14,18,0,6,141;71,573,0,18,18,0,6,180;72,592,0,18,18,0,6,179;73,611,0,7,18,0,6,66;74,619,0,14,18,0,6,139;75,634,0,17,18,0,6,169;76,652,0,14,18,0,6,136;77,667,0,22,18,0,6,221;78,690,0,18,18,0,6,182;79,709,0,18,18,0,6,185;80,728,0,15,18,0,6,155;81,744,0,19,20,0,6,185;82,764,0,16,18,0,6,157;83,781,0,16,18,0,6,156;84,798,0,16,18,0,6,158;85,815,0,18,18,0,6,177;86,834,0,17,18,0,6,175;87,852,0,24,18,0,6,245;88,877,0,17,18,0,6,173;89,895,0,17,18,0,6,171;90,913,0,16,18,0,6,157;91,930,0,9,23,0,5,90;92,940,0,9,21,0,6,91;93,950,0,9,23,0,5,90;94,960,0,12,17,0,7,116;95,973,0,12,3,0,24,113;96,986,0,8,19,0,5,84;97,995,0,14,13,0,11,138;98,0,25,15,18,0,6,150;99,16,25,14,13,0,11,140;100,31,25,15,18,0,6,150;101,47,25,14,13,0,11,142;102,62,25,10,18,0,6,93;103,73,25,15,19,0,11,150;104,89,25,15,18,0,6,147;105,105,25,6,19,0,5,63;106,112,25,7,24,-1,5,63;107,120,25,14,18,0,6,137;108,135,25,6,18,0,6,63;109,142,25,22,13,0,11,216;110,165,25,15,13,0,11,147;111,181,25,15,13,0,11,146;112,197,25,15,18,0,11,150;113,213,25,15,18,0,11,150;114,229,25,10,13,0,11,95;115,240,25,13,13,0,11,132;116,254,25,9,17,0,7,85;117,264,25,15,13,0,11,147;118,280,25,14,13,0,11,141;119,295,25,20,13,0,11,201;120,316,25,14,13,0,11,137;121,331,25,14,18,0,11,141;122,346,25,14,13,0,11,136;123,361,25,11,23,0,5,109;124,373,25,9,29,0,1,86;125,383,25,11,23,0,5,109;126,395,25,16,10,0,14,162;176,412,25,11,18,0,6,110;183,424,25,8,10,0,14,77;8212,433,25,24,9,0,15,240;8230,458,25,23,4,0,20,230;8226,482,25,12,11,0,13,121',
        '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'
        'tfXrx5hvwSSTTDLJpNtG/w8RqX+x'),
    'label': (36, 17, 22, '32,0,0,4,0,0,17,43;33,5,0,5,13,0,4,55;34,11,0,9,13,0,4,89;35,21,0,11,13,0,4,109;36,33,0,11,17,0,2,111;37,45,0,17,14,0,4,171;38,63,0,12,13,0,4,113;39,76,0,6,13,0,4,55;40,83,0,6,16,0,4,63;41,90,0,6,16,0,4,63;42,97,0,9,13,0,4,92;43,107,0,11,10,0,7,114;44,119,0,5,6,0,15,54;45,125,0,8,6,0,11,79;46,134,0,5,3,0,14,54;47,140,0,7,15,0,4,64;48,148,0,11,13,0,4,112;49,160,0,7,13,0,4,72;50,168,0,11,13,0,4,106;51,180,0,11,13,0,4,108;52,192,0,11,13,0,4,113;53,204,0,11,13,0,4,107;54,216,0,11,13,0,4,109;55,228,0,10,13,0,4,98;56,239,0,11,13,0,4,109;57,251,0,11,14,0,3,109;58,263,0,5,9,0,8,54;59,269,0,6,13,0,8,56;60,276,0,11,10,0,7,114;61,288,0,11,8,0,9,114;62,300,0,11,10,0,7,114;63,312,0,9,13,0,4,92;64,322,0,17,16,0,5,170;65,340,0,12,13,0,4,124;66,353,0,11,13,0,4,112;67,365,0,13,13,0,4,125;68,379,0,12,13,0,4,123;69,392,0,10,13,0,4,103;70,403,0,10,13,0,4,100;71,414,0,13,13,0,4,127;72,428,0,13,13,0,4,127;73,442,0,5,13,0,4,47;74,448,0,10,13,0,4,99;75,459,0,12,13,0,4,120;76,472,0,10,13,0,4,96;77,483,0,16,13,0,4,157;78,500,0,13,13,0,4,129;79,514,0,13,13,0,4,131;80,528,0,11,13,0,4,110;81,540,0,13,14,0,4,131;82,554,0,11,13,0,4,111;83,566,0,11,13,0,4,111;84,578,0,11,13,0,4,112;85,590,0,13,13,0,4,125;86,604,0,12,13,0,4,124;87,617,0,17,13,0,4,173;88,635,0,12,13,0,4,122;89,648,0,12,13,0,4,121;90,661,0,11,13,0,4,111;91,673,0,6,15,0,4,63;92,680,0,7,15,0,4,64;93,688,0,6,15,0,4,63;94,695,0,8,12,0,5,82;95,704,0,8,2,0,17,80;96,713,0,6,13,0,4,60;97,720,0,10,10,0,7,98;98,731,0,11,13,0,4,106;99,743,0,10,10,0,7,99;100,754,0,11,13,0,4,106;101,766,0,10,10,0,7,100;102,777,0,7,14,0,3,66;103,785,0,11,14,0,7,106;104,797,0,10,13,0,4,104;105,808,0,4,14,0,3,45;106,813,0,5,18,-1,3,45;107,819,0,10,13,0,4,97;108,830,0,4,13,0,4,45;109,835,0,15,10,0,7,153;110,851,0,10,10,0,7,104;111,862,0,10,10,0,7,103;112,873,0,11,14,0,7,106;113,885,0,11,14,0,7,106;114,897,0,7,10,0,7,68;115,905,0,9,10,0,7,93;116,915,0,6,13,0,4,60;117,922,0,10,10,0,7,104;118,933,0,10,10,0,7,100;119,944,0,14,10,0,7,143;120,959,0,10,10,0,7,97;121,970,0,10,14,0,7,100;122,981,0,10,10,0,7,96;123,992,0,8,15,0,4,77;124,1001,0,6,21,0,0,61;125,1008,0,8,15,0,4,77;126,0,22,11,7,0,10,114;176,12,22,8,13,0,4,78;183,21,22,5,7,0,10,54;8212,27,22,17,6,0,11,170;8230,45,22,16,3,0,14,162;8226,62,22,9,8,0,9,86',
        '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'),
    'h2': (66, 30, 38, '32,0,0,8,0,0,30,76;33,9,0,10,22,0,8,96;34,20,0,16,22,0,8,157;35,37,0,19,22,0,8,193;36,57,0,20,28,0,5,195;37,78,0,30,23,0,8,301;38,109,0,20,22,0,8,199;39,130,0,10,22,0,8,98;40,141,0,11,28,0,6,112;41,153,0,11,28,0,6,112;42,165,0,16,22,0,8,162;43,182,0,20,16,0,14,202;44,203,0,10,9,0,27,96;45,214,0,14,11,0,19,140;46,229,0,10,5,0,25,96;47,240,0,11,27,0,7,114;48,252,0,20,22,0,8,198;49,273,0,13,22,0,8,127;50,287,0,19,22,0,8,187;51,307,0,19,22,0,8,191;52,327,0,20,22,0,8,200;53,348,0,19,22,0,8,189;54,368,0,19,22,0,8,192;55,388,0,17,22,0,8,173;56,406,0,19,22,0,8,192;57,426,0,19,23,0,7,192;58,446,0,10,16,0,14,96;59,457,0,10,22,0,14,99;60,468,0,20,17,0,13,202;61,489,0,20,14,0,16,202;62,510,0,20,17,0,13,202;63,531,0,16,22,0,8,163;64,548,0,30,27,0,9,300;65,579,0,22,22,0,8,218;66,602,0,20,22,0,8,198;67,623,0,22,22,0,8,221;68,646,0,22,22,0,8,217;69,669,0,18,22,0,8,182;70,688,0,18,22,0,8,176;71,707,0,22,22,0,8,225;72,730,0,22,22,0,8,224;73,753,0,8,22,0,8,83;74,762,0,17,22,0,8,174;75,780,0,21,22,0,8,211;76,802,0,17,22,0,8,170;77,820,0,28,22,0,8,277;78,849,0,23,22,0,8,228;79,873,0,23,22,0,8,231;80,897,0,19,22,0,8,193;81,917,0,23,24,0,8,232;82,941,0,20,22,0,8,196;83,962,0,20,22,0,8,195;84,983,0,20,22,0,8,198;85,0,29,22,22,0,8,221;86,23,29,22,22,0,8,218;87,46,29,31,22,0,8,306;88,78,29,22,22,0,8,216;89,101,29,21,22,0,8,214;90,123,29,20,22,0,8,196;91,144,29,11,27,0,7,112;92,156,29,11,27,0,7,114;93,168,29,11,27,0,7,112;94,180,29,14,21,0,9,144;95,195,29,15,4,0,30,141;96,211,29,11,23,0,7,105;97,223,29,17,17,0,13,172;98,241,29,19,22,0,8,187;99,261,29,17,17,0,13,175;100,279,29,19,22,0,8,187;101,299,29,18,17,0,13,177;102,318,29,12,24,0,6,117;103,331,29,19,24,0,13,188;104,351,29,18,22,0,8,184;105,370,29,8,24,0,6,79;106,379,29,9,31,-1,6,79;107,389,29,17,22,0,8,171;108,407,29,8,22,0,8,79;109,416,29,27,17,0,13,270;110,444,29,18,17,0,13,184;111,463,29,18,17,0,13,183;112,482,29,19,23,0,13,187;113,502,29,19,23,0,13,187;114,522,29,12,17,0,13,119;115,535,29,16,17,0,13,165;116,552,29,11,21,0,9,106;117,564,29,18,17,0,13,184;118,583,29,18,17,0,13,176;119,602,29,25,17,0,13,252;120,628,29,17,17,0,13,171;121,646,29,18,24,0,13,177;122,665,29,17,17,0,13,170;123,683,29,14,28,0,6,136;124,698,29,11,36,0,1,108;125,710,29,14,27,0,7,136;126,725,29,20,12,0,18,202;176,746,29,14,22,0,8,137;183,761,29,10,13,0,17,96;8212,772,29,30,11,0,19,300;8230,803,29,29,5,0,25,287;8226,833,29,15,14,0,16,151',
        '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'),
    'title': (121, 37, 47, '32,0,0,8,0,0,37,81;33,9,0,9,28,0,9,94;34,19,0,18,28,0,9,179;35,38,0,25,28,-1,9,238;36,64,0,25,36,0,5,248;37,90,0,36,28,0,9,356;38,127,0,25,28,0,9,246;39,153,0,10,28,0,9,103;40,164,0,13,35,0,8,126;41,178,0,13,35,0,8,126;42,192,0,20,28,0,9,204;43,213,0,25,21,0,16,249;44,239,0,9,11,0,32,93;45,249,0,17,13,0,24,169;46,267,0,9,7,0,30,93;47,277,0,14,34,0,8,138;48,292,0,25,28,0,9,247;49,318,0,15,28,0,9,148;50,334,0,23,28,0,9,228;51,358,0,24,28,0,9,235;52,383,0,25,28,0,9,250;53,409,0,23,28,0,9,228;54,433,0,23,28,0,9,235;55,457,0,21,28,0,9,209;56,479,0,23,28,0,9,233;57,503,0,23,28,0,9,235;58,527,0,9,20,0,17,93;59,537,0,9,25,0,18,94;60,547,0,25,22,0,15,249;61,573,0,25,18,0,19,249;62,599,0,25,22,0,15,249;63,625,0,22,28,0,9,216;64,648,0,38,36,0,9,383;65,687,0,27,28,0,9,271;66,715,0,25,28,0,9,245;67,741,0,28,28,0,9,276;68,770,0,27,28,0,9,266;69,798,0,23,28,0,9,231;70,822,0,22,28,0,9,221;71,845,0,28,28,0,9,280;72,874,0,27,28,0,9,273;73,902,0,10,28,0,9,98;74,913,0,21,28,0,9,214;75,935,0,26,28,0,9,260;76,962,0,21,28,0,9,212;77,984,0,34,28,0,9,340;78,0,37,28,28,0,9,275;79,29,37,28,28,0,9,284;80,58,37,24,28,0,9,240;81,83,37,28,30,0,9,284;82,112,37,25,28,0,9,247;83,138,37,25,28,0,9,248;84,164,37,24,28,0,9,241;85,189,37,27,28,0,9,268;86,217,37,27,28,0,9,268;87,245,37,38,28,0,9,379;88,284,37,27,28,0,9,265;89,312,37,27,28,0,9,262;90,340,37,24,28,0,9,241;91,365,37,13,35,0,8,126;92,379,37,14,34,0,8,138;93,394,37,13,35,0,8,126;94,408,37,18,27,0,10,176;95,427,37,19,5,0,37,180;96,447,37,11,28,0,9,112;97,459,37,21,20,0,17,210;98,481,37,23,28,0,9,227;99,505,37,21,20,0,17,211;100,527,37,23,28,0,9,227;101,551,37,21,20,0,17,213;102,573,37,14,28,0,9,141;103,588,37,23,28,0,17,227;104,612,37,22,28,0,9,222;105,635,37,9,28,0,9,93;106,645,37,11,36,-2,9,94;107,657,37,22,28,0,9,209;108,680,37,9,28,0,9,93;109,690,37,34,20,0,17,336;110,725,37,22,20,0,17,222;111,748,37,22,20,0,17,221;112,771,37,23,28,0,17,227;113,795,37,23,28,0,17,227;114,819,37,14,20,0,17,142;115,834,37,20,21,0,17,198;116,855,37,14,26,0,11,140;117,870,37,22,20,0,17,222;118,893,37,21,20,0,17,210;119,915,37,31,20,0,17,311;120,947,37,21,20,0,17,204;121,969,37,21,28,0,17,210;122,991,37,20,20,0,17,199;123,0,74,17,35,0,8,167;124,18,74,13,46,0,0,132;125,32,74,17,35,0,8,167;126,50,74,25,15,0,22,249;176,76,74,17,28,0,9,166;183,94,74,9,17,0,20,93;8212,104,74,38,13,0,24,380;8230,143,74,28,7,0,30,279;8226,172,74,16,17,0,20,163',
        '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'
        '3ySTTDLJJJNM+v+j/wPszUIE'),
    'big': (67, 86, 108, '48,0,0,56,66,0,21,561;49,57,0,33,64,0,22,335;50,91,0,52,65,0,21,516;51,144,0,54,66,0,21,539;52,199,0,57,64,0,22,567;53,257,0,52,65,0,22,520;54,310,0,53,66,0,21,533;55,364,0,47,64,0,22,474;56,412,0,53,66,0,21,531;57,466,0,53,66,0,21,533;46,520,0,21,14,0,73,208;45,542,0,39,31,0,55,387;43,582,0,57,46,0,40,568;32,640,0,20,0,0,86,199;37,661,0,80,66,0,21,798;176,742,0,38,64,0,22,380;8212,781,0,88,31,0,55,880',
        'eNrtXXdgVEUan02FJCR0goHQIr0qSscGAkoV8Sgq5UQpFoqinKIoeiAWUOopIMipeKd0EBGULgQwIFF6SCiGEBISAunJuwDZnW/e'
        'fFNedjmyZL//9k1582bnN/PNVwlBqPrfZ248npCRlRjz8+wRdYgWtT1sOKiZqFKDMV+sjYxNT4uJXL9wWG29jomt+bilG/bHpV+J'
        '27/xy1FNvIhlKnvagDSYq/CcoUddZG+pO2L2LycSMtLj9m1YMLgGVsPf0KfB6DvKd5+2eueRxOykY7vXzXy8qub31xv9xdo9p65m'
        'Xjy19fOxzW2yqgGtu7bwZh+FSaiC9L19HV/TiBSdSnf/bMfJ9JTDv0xr60VcQLbW0zYfTk078vOH7bz0v9QZIu5ElSYeYlfisSnV'
        'lI2CZuUbKvw/suAM2/Hpxa2VHXsP+C6JbXVpdW9vi5/0jQpaLzuN//Bpx9mqp+bUczX+w6ZE57OVTs64U7nauy8yTfvF+S2Ff+Oc'
        'jIIKSWMhLrxlo1xx0/Ff/uN0+rr40T6yusFxhfV+8xXW8RsbT/s7P94flhk3idwI/aGfZ/Ljz11WS96qWxxTH8N/t73YzGzvKT2N'
        'So2MwVrFTihv5ZueVELrHSfxH/FtLl85f1VHV+K/3bc5SLX8Hx6RfbpXv4NY59twPN5ln+3tlYsL/ocnsy882k5SeXFhpUzx63qc'
        'Mi2lnh78g+XyShr+BZnv+YlbVVxqqs3j/55fRXOzv764434JolZJA/U/qkaqEv8zncK//1uZgvr/DnEV/kMWCmuuDBV+epcjgjbZ'
        '0wL42oEnMFzfSvzbPuBX4hPC2r3tdcYJ+5uUz22gkzz4t1OVn8TfsFd4XR9wwVDhf3CmuOOrw0WH/1zZnK7Svfx6bVez1oucwX/Y'
        'HnGDuPtcg/+uZyVVk58UfPk7+eJGsQ9x9T8Bxf2LBf4XYBzPU4LKle3rcKtQTLAE+4bFHvwXHpSnZR+RjN/qq6/lq5pqen8sn55v'
        '0Pt8zQPyVucb6H3VPzSu1t85gf+7z8ta5D3tCvwPzpNXfg3FwyZpm8xuZjYG8n5biwP+h+IHRkO89srC8svCy+qb+Ef8w4P/61f/'
        '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'),
}


# ---------------------------------------------------------------- SDL2 drawing
SDL_INIT_VIDEO = 0x20
SDL_WINDOWPOS_CENTERED = 0x2FFF0000
SDL_WINDOW_SHOWN = 0x4
SDL_WINDOW_FULLSCREEN_DESKTOP = 0x1001
SDL_PIXELFORMAT_ABGR8888 = 0x16762004          # bytes R,G,B,A in memory
SDL_PIXELFORMAT_RGB24 = 0x17101803
SDL_TEXTUREACCESS_STATIC = 0
SDL_BLENDMODE_BLEND = 1
SDL_QUIT = 0x100
SDL_KEYDOWN = 0x300
SDL_MOUSEBUTTONDOWN = 0x401
KMOD_SHIFT, KMOD_CTRL, KMOD_ALT, KMOD_CAPS = 0x0003, 0x00C0, 0x0300, 0x2000
K_RETURN, K_ESC, K_BACK, K_TAB = 13, 27, 8, 9
K_F1, K_F2, K_F5, K_F8, K_F12 = 0x4000003A, 0x4000003B, 0x4000003E, 0x40000041, 0x40000045
K_UP, K_DOWN = 0x40000052, 0x40000051
K_KP_ENTER = 0x40000058
KEYPAD = {0x40000059 + i: str(i + 1) for i in range(9)}
KEYPAD.update({0x40000062: "0", 0x40000063: "."})
SHIFTED = dict(zip("1234567890-=[]\\;',./`", "!@#$%^&*()_+{}|:\"<>?~"))
W, H = 1920, 1080
FRAME_S = 0.1                   # 10 frames/s keeps most of the Pi's CPU free


class Rect(ctypes.Structure):
    _fields_ = [("x", c_int), ("y", c_int), ("w", c_int), ("h", c_int)]


def load_lib(names):
    for name in names:
        try:
            return ctypes.CDLL(name)
        except OSError:
            pass
    raise OSError("none of " + ", ".join(names) + " found")


class Gfx:
    def __init__(self, fullscreen):
        if not os.environ.get("XDG_RUNTIME_DIR"):          # sudo drops it; SDL then prints a harmless error
            d = "/tmp/runtime-%d" % os.getuid()
            try:
                os.makedirs(d, mode=0o700, exist_ok=True)
                os.environ["XDG_RUNTIME_DIR"] = d
            except OSError:
                pass
        S = self.sdl = load_lib(["libSDL2-2.0.so.0", "libSDL2.so"])
        sig = {
            "SDL_Init": ([c_uint32], c_int), "SDL_GetError": ([], c_char_p),
            "SDL_SetHint": ([c_char_p, c_char_p], c_int),
            "SDL_CreateWindow": ([c_char_p, c_int, c_int, c_int, c_int, c_uint32], c_void_p),
            "SDL_CreateRenderer": ([c_void_p, c_int, c_uint32], c_void_p),
            "SDL_RenderSetLogicalSize": ([c_void_p, c_int, c_int], c_int),
            "SDL_SetRenderDrawBlendMode": ([c_void_p, c_int], c_int),
            "SDL_SetRenderDrawColor": ([c_void_p, c_uint8, c_uint8, c_uint8, c_uint8], c_int),
            "SDL_RenderClear": ([c_void_p], c_int),
            "SDL_RenderFillRect": ([c_void_p, c_void_p], c_int),
            "SDL_RenderFillRects": ([c_void_p, c_void_p, c_int], c_int),
            "SDL_RenderDrawLine": ([c_void_p, c_int, c_int, c_int, c_int], c_int),
            "SDL_RenderCopy": ([c_void_p, c_void_p, c_void_p, c_void_p], c_int),
            "SDL_RenderPresent": ([c_void_p], None),
            "SDL_CreateTexture": ([c_void_p, c_uint32, c_int, c_int, c_int], c_void_p),
            "SDL_UpdateTexture": ([c_void_p, c_void_p, c_void_p, c_int], c_int),
            "SDL_SetTextureBlendMode": ([c_void_p, c_int], c_int),
            "SDL_SetTextureColorMod": ([c_void_p, c_uint8, c_uint8, c_uint8], c_int),
            "SDL_SetTextureAlphaMod": ([c_void_p, c_uint8], c_int),
            "SDL_PollEvent": ([c_void_p], c_int), "SDL_ShowCursor": ([c_int], c_int),
            "SDL_GetRendererOutputSize": ([c_void_p, POINTER(c_int), POINTER(c_int)], c_int),
            "SDL_RenderReadPixels": ([c_void_p, c_void_p, c_uint32, c_void_p, c_int], c_int),
            "SDL_CreateRGBSurfaceWithFormatFrom": ([c_void_p, c_int, c_int, c_int, c_int, c_uint32], c_void_p),
            "SDL_RWFromFile": ([c_char_p, c_char_p], c_void_p),
            "SDL_SaveBMP_RW": ([c_void_p, c_void_p, c_int], c_int),
            "SDL_FreeSurface": ([c_void_p], None), "SDL_Quit": ([], None),
            "SDL_DestroyRenderer": ([c_void_p], None), "SDL_DestroyWindow": ([c_void_p], None),
        }
        for name, (args, res) in sig.items():
            fn = getattr(S, name)
            fn.argtypes, fn.restype = args, res
        if S.SDL_Init(SDL_INIT_VIDEO) != 0:
            raise RuntimeError("SDL_Init: " + S.SDL_GetError().decode())
        S.SDL_SetHint(b"SDL_RENDER_SCALE_QUALITY", b"1")
        flags = SDL_WINDOW_FULLSCREEN_DESKTOP if fullscreen else SDL_WINDOW_SHOWN
        self.win = S.SDL_CreateWindow(b"QNX node monitor", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                      W if fullscreen else 1280, H if fullscreen else 720, flags)
        if not self.win:
            raise RuntimeError("SDL_CreateWindow: " + S.SDL_GetError().decode())
        self.ren = S.SDL_CreateRenderer(self.win, -1, 0)
        if not self.ren:
            raise RuntimeError("SDL_CreateRenderer: " + S.SDL_GetError().decode())
        S.SDL_RenderSetLogicalSize(self.ren, W, H)      # draw at 1920x1080, SDL scales to the screen
        S.SDL_SetRenderDrawBlendMode(self.ren, SDL_BLENDMODE_BLEND)
        self.ev = ctypes.create_string_buffer(64)
        self.r1, self.r2 = Rect(), Rect()
        self.fonts = {name: Font(self, name, spec) for name, spec in FONT_DATA.items()}

    # shapes
    def color(self, c, a=255):
        self.sdl.SDL_SetRenderDrawColor(self.ren, c[0], c[1], c[2], a)

    def clear(self, c):
        self.color(c)
        self.sdl.SDL_RenderClear(self.ren)

    def fill(self, x, y, w, h, c, a=255):
        r = self.r1
        r.x, r.y, r.w, r.h = int(x), int(y), int(w), int(h)
        self.color(c, a)
        self.sdl.SDL_RenderFillRect(self.ren, byref(r))

    def round_rect(self, x, y, w, h, rad, c, a=255):
        x, y, w, h, rad = int(x), int(y), int(w), int(h), int(min(rad, w // 2, h // 2))
        rows = []
        for dy in range(rad):
            inset = rad - int((rad * rad - (rad - dy - 0.5) ** 2) ** 0.5 + 0.5)
            rows.append((x + inset, y + dy, w - 2 * inset, 1))
            rows.append((x + inset, y + h - 1 - dy, w - 2 * inset, 1))
        rows.append((x, y + rad, w, h - 2 * rad))
        arr = (Rect * len(rows))(*[Rect(*r) for r in rows])
        self.color(c, a)
        self.sdl.SDL_RenderFillRects(self.ren, arr, len(rows))

    def card(self, x, y, w, h, border=(34, 43, 54), bg=(20, 26, 34), rad=18, thick=1):
        self.round_rect(x, y, w, h, rad, border)
        self.round_rect(x + thick, y + thick, w - 2 * thick, h - 2 * thick, rad - thick, bg)

    def circle(self, cx, cy, r, c, a=255):
        self.round_rect(cx - r, cy - r, 2 * r, 2 * r, r, c, a)

    def line(self, x0, y0, x1, y1, c, a=255):
        self.color(c, a)
        self.sdl.SDL_RenderDrawLine(self.ren, int(x0), int(y0), int(x1), int(y1))

    def thick_line(self, x0, y0, x1, y1, c, w=3, a=255):
        """A line w pixels wide, drawn as small squares (looks the same on every renderer)."""
        n = int(max(abs(x1 - x0), abs(y1 - y0))) + 1
        rects = []
        for i in range(n + 1):
            t = i / n
            rects.append(Rect(int(x0 + (x1 - x0) * t) - w // 2, int(y0 + (y1 - y0) * t) - w // 2, w, w))
        arr = (Rect * len(rects))(*rects)
        self.color(c, a)
        self.sdl.SDL_RenderFillRects(self.ren, arr, len(rects))

    def text(self, font, s, x, y, c, a=255, align="left"):
        return self.fonts[font].draw(s, x, y, c, a, align)

    def width(self, font, s):
        return self.fonts[font].width(s)

    def wrapped(self, font, s, x, y, w, c, max_lines=3):
        """Draws s word-wrapped to width w. Returns the y below the last line."""
        f = self.fonts[font]
        lines, cur = [], ""
        for word in s.split():
            test = (cur + " " + word).strip()
            if f.width(test) <= w or not cur:
                cur = test
            else:
                lines.append(cur)
                cur = word
        if cur:
            lines.append(cur)
        for line in lines[:max_lines]:
            f.draw(line, x, y, c)
            y += f.line + 4
        return y

    def present(self):
        self.sdl.SDL_RenderPresent(self.ren)

    def screenshot(self, path):
        S = self.sdl
        w, h = c_int(), c_int()
        S.SDL_GetRendererOutputSize(self.ren, byref(w), byref(h))
        buf = ctypes.create_string_buffer(w.value * h.value * 3)
        if S.SDL_RenderReadPixels(self.ren, None, SDL_PIXELFORMAT_RGB24, buf, w.value * 3) != 0:
            return False
        surf = S.SDL_CreateRGBSurfaceWithFormatFrom(buf, w.value, h.value, 24, w.value * 3, SDL_PIXELFORMAT_RGB24)
        ok = surf and S.SDL_SaveBMP_RW(surf, S.SDL_RWFromFile(path.encode(), b"wb"), 1) == 0
        if surf:
            S.SDL_FreeSurface(surf)
        return bool(ok)

    def events(self):
        """Yields ('quit',), ('key', sym, mod) or ('click', x, y)."""
        while self.sdl.SDL_PollEvent(self.ev):
            raw = self.ev.raw
            t = struct.unpack_from("<I", raw, 0)[0]
            if t == SDL_QUIT:
                yield ("quit",)
            elif t == SDL_KEYDOWN:
                yield ("key", struct.unpack_from("<i", raw, 20)[0], struct.unpack_from("<H", raw, 24)[0])
            elif t == SDL_MOUSEBUTTONDOWN and raw[16] == 1:
                yield ("click", struct.unpack_from("<i", raw, 20)[0], struct.unpack_from("<i", raw, 24)[0])

    def close(self):
        S = self.sdl
        S.SDL_DestroyRenderer(self.ren)
        S.SDL_DestroyWindow(self.win)
        S.SDL_Quit()


class Font:
    """Glyph atlas (white + alpha) in one texture; text colour comes from the colour mod."""

    def __init__(self, gfx, name, spec):
        h, self.ascent, self.line, table, data = spec[0], spec[1], spec[2], spec[3], "".join(spec[4:])
        alpha = zlib.decompress(base64.b64decode(data))
        rgba = bytearray(len(alpha) * 4)
        rgba[0::4] = rgba[1::4] = rgba[2::4] = b"\xff" * len(alpha)
        rgba[3::4] = alpha
        S = self.sdl = gfx.sdl
        self.ren = gfx.ren
        self.tex = S.SDL_CreateTexture(self.ren, SDL_PIXELFORMAT_ABGR8888, SDL_TEXTUREACCESS_STATIC, FONT_ATLAS_W, h)
        if not self.tex:
            raise RuntimeError("font texture: " + S.SDL_GetError().decode())
        buf = (ctypes.c_char * len(rgba)).from_buffer(rgba)
        S.SDL_UpdateTexture(self.tex, None, buf, FONT_ATLAS_W * 4)
        S.SDL_SetTextureBlendMode(self.tex, SDL_BLENDMODE_BLEND)
        self.g = {}
        for item in table.split(";"):
            o, x, y, w, gh, xo, yo, adv = (int(v) for v in item.split(","))
            self.g[chr(o)] = (Rect(x, y, w, gh), xo, yo, w, gh, adv / 10.0)
        self.src_missing = self.g.get("?")
        self.dst = Rect()

    def width(self, s):
        return int(sum(self.g.get(ch, self.src_missing)[5] for ch in s))

    def draw(self, s, x, y, c, a=255, align="left"):
        """y = top of the line. Returns the x after the text."""
        if align != "left":
            w = self.width(s)
            x -= w if align == "right" else w // 2
        S, d = self.sdl, self.dst
        S.SDL_SetTextureColorMod(self.tex, c[0], c[1], c[2])
        S.SDL_SetTextureAlphaMod(self.tex, a)
        pen = float(x)
        for ch in s:
            g = self.g.get(ch, self.src_missing)
            src, xo, yo, w, gh, adv = g
            if w:
                d.x, d.y, d.w, d.h = int(pen) + xo, int(y) + yo, w, gh
                S.SDL_RenderCopy(self.ren, self.tex, byref(src), byref(d))
            pen += adv
        return int(pen)


# ---------------------------------------------------------------- the dashboard
BG = (11, 15, 20)
CARD = (20, 26, 34)
BORDER = (34, 43, 54)
FIELD = (13, 18, 24)
TEXT = (230, 237, 243)
MUTED = (139, 152, 165)
DIM = (88, 100, 114)
GREEN = (52, 211, 153)
AMBER = (251, 191, 36)
RED = (248, 113, 113)
BLUE = (96, 165, 250)
YELLOW = (250, 204, 21)
TONE = {"good": GREEN, "warn": AMBER, "bad": RED, "info": BLUE, "plain": MUTED}
STATE_LOOK = {
    "BOOT": (MUTED, "STARTING"), "WAITING": (YELLOW, "WAITING FOR DETAILS"), "WIFI_ON": (BLUE, "WI-FI ON"),
    "CONNECTING": (BLUE, "CONNECTING"), "CONNECTED": (GREEN, "CONNECTED"), "FAILED": (RED, "FAILED"),
    "LOST": (AMBER, "SIGNAL LOST"),
}


class Field:
    def __init__(self, label, placeholder, limit, secret=False):
        self.label, self.placeholder, self.limit, self.secret = label, placeholder, limit, secret
        self.value = ""
        self.rect = (0, 0, 0, 0)


AXIS = ((248, 113, 113), (52, 211, 153), (96, 165, 250))      # X red, Y green, Z blue
ZONE_COLOR = ((52, 211, 153), (163, 230, 53), (251, 191, 36), (248, 113, 113))   # ISO zones A B C D
ZONE_NAME = ("GOOD", "ACCEPTABLE", "ALERT", "DANGER")
SKY, GROUND = (37, 70, 112), (92, 66, 38)


class Dashboard:
    def __init__(self, args, key):
        self.args = args
        self.log_lines = collections.deque(maxlen=60)
        self.gfx = Gfx(fullscreen=not args.window)
        self.udp = UdpListener(args.udp_port, self.log, on_packet=self.on_packet, on_status=self.on_status)
        self.vib_state = {}                      # node id -> (zone, running) for alarm events
        self.client = NodeClient(key, args.ctrl_port)
        self.wifi = None if args.manual else WifiCtl(args.wpa_cli, args.wifi_iface, args.wpa_ctrl)
        if self.wifi and self.wifi.error:
            self.log("Pi Wi-Fi control: %s. Manual mode: join the node's hotspot yourself." % self.wifi.error, "warn")
        self.fields = [Field("WI-FI NAME (SSID) FOR THE NODE", "network name", 32),
                       Field("PASSWORD", "password  (leave empty for an open network)", 64, secret=True),
                       Field("THIS PI'S IP ON THAT NETWORK", "e.g. 192.168.43.10", 15)]
        self.fields[2].value = guess_pi_ip()
        if self.wifi and not self.wifi.error:
            try:
                st = self.wifi.status()
                self.fields[0].value = st.get("ssid", "")
                self.fields[2].value = st.get("ip_address", "") or self.fields[2].value
            except WifiError:
                pass
        self._ip, self._ip_time = self.fields[2].value, time.monotonic()
        self.focus = 1 if self.fields[0].value else 0
        self.show_pass = False
        self.setup_aps = []                      # [(hotspot name, dBm)] of nodes in setup mode
        self.stage = "scan"                      # scan -> creds -> progress -> done
        self.sel = 0                             # highlighted node in the scan list
        self.picked = None                       # the node (hotspot) you selected
        self.step, self.step_failed, self.result_ok = 0, False, None
        self.view_node = None                    # node whose data is shown in the big card
        self.node_rows = []                      # clickable rows in the Nodes card
        self.scanning = False
        self.last_scan = -999.0
        self.msg, self.msg_tone = "The Pi scans for nodes in setup mode. Select one with Up / Down and press Enter.", "plain"
        self.busy = False
        self.waiting_node, self.waiting_outcome = None, 0.0
        self.forget_armed = self.quit_armed = 0.0
        self.buttons = []
        self.running = True
        self.want_shot = None
        self.log("Monitor started. Listening for nodes on UDP %d" % args.udp_port, "info")

    # -- events from the worker threads
    def log(self, text, tone="plain"):
        self.log_lines.append((time.strftime("%H:%M:%S"), text, tone))
        Log.write("ERROR" if tone == "bad" else "WARN" if tone == "warn" else "INFO", "event: " + text)

    def on_packet(self, node, seq, kind, vals, rssi, flags, src):
        """Logs vibration alarms: zone changes and machine start / stop."""
        if kind != "VIB" or len(vals) < 10 or flags & 1:
            return
        zone, run = int(vals[8]), int(vals[9])
        old = self.vib_state.get(node)
        self.vib_state[node] = (zone, run)
        if old is None:
            return
        name = node_name(node)
        if zone != old[0]:
            tone = ("good", "good", "warn", "bad")[zone] if zone < old[0] else ("plain", "info", "warn", "bad")[zone]
            self.log("%s vibration %s (zone %s): %.2f mm/s" % (name, ZONE_NAME[zone], "ABCD"[zone], vals[0]), tone)
        if run != old[1]:
            self.log("%s: machine %s" % (name, "started (%.1f Hz)" % vals[6] if run else "stopped"), "info")

    def on_status(self, st, old, ip):
        name = node_name(st.node)
        if old is None or old.state != st.state:
            tone = {"CONNECTED": "good", "FAILED": "bad", "LOST": "warn"}.get(st.state, "info")
            extra = " at %s (%d dBm)" % (st.ip, st.rssi) if st.state == "CONNECTED" else ""
            self.log("%s: %s%s" % (name, STATE_LOOK.get(st.state, (0, st.state))[1].lower(), extra), tone)
        if self.waiting_outcome and str(st.node) == str(self.waiting_node) and st.state == "CONNECTED":
            self.set_msg("%s is online at %s and sends its data to %s" % (name, st.ip, st.host), "good")
            self.waiting_outcome = 0.0
            self.step, self.result_ok, self.stage = 4, True, "done"
            if str(st.node).isdigit():
                self.view_node = int(st.node)          # show the new node's data straight away

    def set_msg(self, text, tone):
        if text != getattr(self, "msg", None):
            Log.write("ERROR" if tone == "bad" else "INFO", "screen [%s]: %s" % (getattr(self, "stage", "?"), text))
        self.msg, self.msg_tone = text, tone

    def manual(self):
        return self.wifi is None or self.wifi.error is not None

    def scan_list(self):
        """Nodes you can pick: found by the scan, or (manual mode) the one you joined yourself."""
        if self.manual():
            return [(self.args.node, None)]
        return list(self.setup_aps)

    def target_ap(self):
        return self.picked

    def main_node(self):
        """Node shown in the big card / status card: the one you picked, else node 1, else the lowest."""
        if self.view_node is not None:
            return self.view_node
        with self.udp.lock:
            ids = sorted(set(self.udp.nodes) | {int(k) for k in self.udp.status if str(k).isdigit()})
        return 1 if 1 in ids or not ids else ids[0]

    def node_online(self, nid):
        """True if the node sent data in the last 5 s (so it can't be in setup mode)."""
        nid = int(nid) if str(nid).isdigit() else nid
        with self.udp.lock:
            nd = self.udp.nodes.get(nid)
            return nd is not None and time.monotonic() - nd.last < 5

    def node_ip(self, nid):
        """The node's own address for its control port. Prefer the IP the node reports in its status
        packets: when MemoryGuard relays the node packets (UDP 5006) their source address is 127.0.0.1."""
        with self.udp.lock:
            st = self.udp.status.get(str(nid))
            nd = self.udp.nodes.get(nid)
        for ip in ((st[0].ip if st and st[0].state == "CONNECTED" else None),
                   (st[2] if st else None), (nd.src if nd else None)):
            if ip and valid_ipv4(ip) and not ip.startswith(("127.", "0.")):
                return ip
        return None

    # -- actions
    def scan(self, quiet=False):
        if self.scanning or self.busy or self.wifi is None or self.wifi.error:
            return
        self.scanning = True
        self.last_scan = time.monotonic()

        def work():
            try:
                aps = self.wifi.scan()
                online = [a for a, _ in aps if self.node_online(a.rsplit("-", 1)[-1])]
                if online:
                    Log.info("scan: ignoring %s - that node is online and sending data" % ", ".join(online))
                aps = [a for a in aps if a[0] not in online]
                new = {a for a, _ in aps} - {a for a, _ in self.setup_aps}
                for a in sorted(new):
                    self.log("%s is in setup mode, waiting for Wi-Fi details" % a, "warn")
                self.setup_aps = aps
                if not quiet:
                    self.set_msg("Found %d node%s in setup mode" % (len(aps), "" if len(aps) == 1 else "s"), "plain")
            except WifiError as e:
                self.log("Scan failed: %s" % e, "bad")
            self.scanning = False
        threading.Thread(target=work, daemon=True).start()

    def pick(self):
        nodes = self.scan_list()
        if not nodes:
            self.set_msg("No node found yet. Power the node (or hold its BOOT 3 s) and press F5 to scan.", "bad")
            return
        self.picked = nodes[self.sel % len(nodes)][0]
        self.stage = "creds"
        self.focus = 1 if self.fields[0].value else 0
        self.set_msg("Type the Wi-Fi details for %s and press Enter. Esc = back to the list." % self.picked, "plain")

    def send_details(self):
        if self.busy or not self.picked:
            return
        ssid, pw, host = (f.value for f in self.fields)
        problem = check_credentials(ssid, pw, host.strip())
        if problem:
            self.set_msg(problem, "bad")
            return
        ap = self.picked
        if self.node_online(ap.rsplit("-", 1)[-1]):
            self.set_msg("%s is already online and sending data, so its setup hotspot is gone. "
                         "Reset it first (F8 twice, or RESET 3x on the node)." % node_name(ap.rsplit("-", 1)[-1]), "bad")
            self.setup_aps = [a for a in self.setup_aps if a[0] != ap]
            self.stage = "scan"
            return
        Log.info("setup %s: sending Wi-Fi \"%s\" (password %d chars), Pi IP %s" % (ap, ssid, len(pw), host.strip()))
        self.busy = True
        self.stage, self.step, self.step_failed, self.result_ok = "progress", 0, False, None
        self.steps = ["Join %s's hotspot" % ap, "Send the signed Wi-Fi details",
                      "Pi returns to its own Wi-Fi", "Wait for %s to come online" % node_name(ap.rsplit("-", 1)[-1])]

        def progress(text):
            Log.info("setup %s: %s" % (ap, text))
            if text[:3] in ("1/4", "2/4", "3/4"):
                self.step = int(text[0]) - 1
            self.set_msg(text[3:].strip() if text[:3].endswith("/4") else text, "info")

        def work():
            end = time.monotonic() + 15
            while self.scanning and time.monotonic() < end:   # the Wi-Fi chip can't scan and join at once
                time.sleep(0.2)
            ok, text = provision_over_air(self.wifi, self.client, self.args, ap, ssid, pw, host.strip(), progress)
            self.busy = False
            if ok:
                self.fields[1].value = ""            # don't leave the password on screen
                nid = ap.rsplit("-", 1)[-1]
                self.log("Sent Wi-Fi \"%s\" to %s (signed)" % (ssid, ap), "good")
                self.step = 3
                self.set_msg("%s accepted the details. Waiting for %s to come online..." % (ap, node_name(nid)), "info")
                self.waiting_node, self.waiting_outcome = nid, time.monotonic()
                self.setup_aps = [a for a in self.setup_aps if a[0] != ap]
            else:
                self.log("Sending to %s failed: %s" % (ap, text), "bad")
                self.set_msg(text, "bad")
                self.step_failed, self.result_ok, self.stage = True, False, "done"
        threading.Thread(target=work, daemon=True).start()

    def forget(self):
        if self.busy:
            return
        nid = self.main_node()
        ip = self.node_ip(nid)
        if not ip or not self.node_online(nid):
            self.set_msg("%s is not sending data, so it can't be reset over Wi-Fi. If it shows SETUP it is already "
                         "reset - pick it from the list; otherwise press its RESET button 3 times." % node_name(nid), "bad")
            return
        now = time.monotonic()
        if now - self.forget_armed > 3:
            self.forget_armed = now
            self.set_msg("Press F8 again within 3 s to erase %s's Wi-Fi details (it goes back to setup mode)" % node_name(nid), "warn")
            return
        self.forget_armed = 0
        self.busy = True

        def work():
            ok, text = self.client.forget(ip)
            if not ok and "did not answer" in text:
                time.sleep(3)                            # the reply may be lost while the node switches radio mode
                if not self.node_online(nid):
                    ok, text = True, "%s stopped sending - it went back to setup mode" % node_name(nid)
                    Log.info("forget: no reply, but %s stopped sending, so the reset worked" % node_name(nid))
            self.busy = False
            self.log(("%s: " % node_name(nid)) + text if ok else "Forget failed: " + text, "warn" if ok else "bad")
            self.set_msg(text, "warn" if ok else "bad")
            if ok:
                with self.udp.lock:
                    self.udp.status.pop(str(nid), None)
                time.sleep(4)
                self.busy = False
                self.scan(quiet=True)
        threading.Thread(target=work, daemon=True).start()

    def refresh(self):
        if self.wifi is None or self.wifi.error:
            self.set_msg("Manual mode: join %s with password %s, then press Enter" % (
                self.args.node, setup_password(self.client.key, self.args.node)), "warn")
            return
        self.set_msg("Scanning for nodes in setup mode...", "plain")
        self.scan()

    def key(self, sym, mod):
        if not (self.stage == "creds" and 32 <= sym <= 126 and not mod & KMOD_CTRL):
            names = {K_F1: "F1", K_F2: "F2", K_F5: "F5", K_F8: "F8", K_F12: "F12", K_ESC: "Esc", K_TAB: "Tab",
                     K_RETURN: "Enter", K_KP_ENTER: "Enter", K_UP: "Up", K_DOWN: "Down", K_BACK: "Backspace"}
            Log.dbg("key %s (stage %s)" % (names.get(sym, hex(sym)), self.stage))
        if sym == K_F5:
            self.refresh()
        elif sym == K_F8:
            self.forget()
        elif sym == K_F12:
            self.want_shot = "dashboard_%s.bmp" % time.strftime("%Y%m%d_%H%M%S")
        elif sym == K_F2:                            # show the next online node's data
            with self.udp.lock:
                ids = sorted(self.udp.nodes)
            if ids:
                cur = self.main_node()
                self.view_node = ids[(ids.index(cur) + 1) % len(ids)] if cur in ids else ids[0]
        elif sym == K_ESC:
            if self.stage in ("creds", "done"):
                self.stage = "scan"
                self.set_msg("Select a node with Up / Down and press Enter.", "plain")
                return
            now = time.monotonic()
            if now - self.quit_armed < 2:
                self.running = False
            else:
                self.quit_armed = now
                self.set_msg("Press Esc again to quit", "warn")
        elif self.stage == "scan":
            n = len(self.scan_list())
            if sym == K_UP and n:
                self.sel = (self.sel - 1) % n
            elif sym == K_DOWN and n:
                self.sel = (self.sel + 1) % n
            elif sym in (K_RETURN, K_KP_ENTER):
                self.pick()
        elif self.stage == "done":
            if sym in (K_RETURN, K_KP_ENTER):
                self.stage = "scan" if self.result_ok else "creds"
                self.set_msg("Select a node with Up / Down and press Enter." if self.result_ok else
                             "Check the details and press Enter to try again.", "plain")
        elif self.stage == "creds":
            self.type_key(sym, mod)

    def type_key(self, sym, mod):
        f = self.fields[self.focus]
        if sym == K_TAB or sym in (K_UP, K_DOWN):
            back = mod & KMOD_SHIFT or sym == K_UP
            self.focus = (self.focus + (-1 if back else 1)) % len(self.fields)
        elif sym in (K_RETURN, K_KP_ENTER):
            self.send_details()
        elif sym == K_BACK:
            f.value = f.value[:-1]
        elif sym == K_F1:
            self.show_pass = not self.show_pass
        elif mod & KMOD_CTRL:
            if sym == ord("u"):
                f.value = ""
        elif mod & KMOD_ALT:
            pass
        else:
            ch = KEYPAD.get(sym)
            if ch is None and 32 <= sym <= 126:
                ch = chr(sym)
                if "a" <= ch <= "z":
                    if bool(mod & KMOD_SHIFT) != bool(mod & KMOD_CAPS):
                        ch = ch.upper()
                elif mod & KMOD_SHIFT:
                    ch = SHIFTED.get(ch, ch)
            if ch and len((f.value + ch).encode()) <= f.limit:
                f.value += ch

    def click(self, x, y):
        for (rx, ry, rw, rh), nid in self.node_rows:          # Nodes card: choose whose data to show
            if rx <= x < rx + rw and ry <= y < ry + rh:
                self.view_node = nid
                return
        if self.stage == "creds":
            for i, f in enumerate(self.fields):
                fx, fy, fw, fh = f.rect
                if fx <= x < fx + fw and fy <= y < fy + fh:
                    self.focus = i
                    return
        for (bx, by, bw, bh), action in self.buttons:
            if bx <= x < bx + bw and by <= y < by + bh:
                action()
                return

    # -- drawing helpers
    def pill(self, x_right, y, text, color):
        g = self.gfx
        w = g.width("label", text) + 44
        x = x_right - w
        g.round_rect(x, y, w, 34, 17, color, 40)
        g.circle(x + 18, y + 17, 6, color)
        g.text("label", text, x + 30, y + 7, color)
        return x

    def card_head(self, x, y, w, title, sub, accent):
        g = self.gfx
        g.card(x, y, w, self._card_h)
        g.fill(x + 1, y + 24, 5, 48, accent)
        g.text("h2", title, x + 30, y + 22, TEXT)
        if sub:
            g.text("small", sub, x + 30, y + 62, MUTED)

    def live_pill(self, x_right, y, age):
        if age < 1.5:
            self.pill(x_right, y, "LIVE", GREEN)
        elif age < 6:
            self.pill(x_right, y, "STALE", AMBER)
        else:
            self.pill(x_right, y, "OFFLINE", RED)

    def draw_header(self, now):
        g = self.gfx
        x = g.text("title", "QNX Node Monitor", 48, 26, TEXT)
        g.text("title", "  ·  Raspberry Pi", x, 26, MUTED)
        g.text("small", "QNX 8.0  ·  Wi-Fi sensor nodes  ·  credentials given only by this Pi", 50, 76, DIM)
        g.text("h2", time.strftime("%H:%M:%S"), W - 48, 22, TEXT, align="right")
        with self.udp.lock:
            total = sum(nd.rate(now) for nd in self.udp.nodes.values())
            count = len(self.udp.nodes)
        if now - self._ip_time > 10:                      # re-check the Pi's IP every 10 s
            self._ip, self._ip_time = guess_pi_ip(), now
        info = "Pi %s  ·  UDP %d  ·  %d node%s  ·  %d packets/s" % (
            self._ip or "no network", self.args.udp_port, count, "" if count == 1 else "s", total)
        g.text("small", info, W - 48, 70, MUTED, align="right")

    def graph(self, x, y, w, h, hist, idx, colors, now, label, unit, window=30.0):
        """Several values (hist entries are (time, values); idx picks which) on one shared scale."""
        g = self.gfx
        pts = [(t, v) for t, v in hist if now - t <= window]
        g.text("label", label, x, y - 26, MUTED)
        g.fill(x, y + h, w, 1, BORDER)
        if len(pts) < 2:
            g.text("small", "collecting...", x, y + h // 2 - 12, DIM)
            return
        lo = min(min(v[i] for i in idx) for _, v in pts)
        hi = max(max(v[i] for i in idx) for _, v in pts)
        g.text("small", "%+.1f" % hi, x + w, y - 26, DIM, align="right")
        g.text("small", "%+.1f %s" % (lo, unit), x + w, y + h + 6, DIM, align="right")
        if hi - lo < 0.2:
            mid = (hi + lo) / 2
            lo, hi = mid - 0.1, mid + 0.1
        pad = (hi - lo) * 0.1
        lo, hi = lo - pad, hi + pad
        if lo < 0 < hi:                                   # zero line
            zy = y + h - (0 - lo) / (hi - lo) * h
            g.fill(x, zy, w, 1, (40, 50, 62))
        step = max(1, len(pts) // 160)
        sample = pts[::step] + [pts[-1]]
        for i, c in zip(idx, colors):
            prev = None
            for t, v in sample:
                p = (x + w - (now - t) / window * w, y + h - (v[i] - lo) / (hi - lo) * h)
                if prev:
                    g.line(prev[0], prev[1], p[0], p[1], c)
                    g.line(prev[0], prev[1] + 1, p[0], p[1] + 1, c)
                prev = p

    def horizon(self, cx, cy, r, pitch, roll):
        """Attitude indicator: sky / ground split, tilted by roll and moved by pitch."""
        g = self.gfx
        rr = math.radians(-roll)
        dx, dy = math.cos(rr), math.sin(rr)
        nx, ny = -dy, dx                                  # points to the ground side
        off = max(-r + 8, min(r - 8, pitch * 2.2))
        p0x, p0y = cx, cy + off
        sky, ground = [], []
        for yy in range(-r, r + 1, 2):
            half = int(math.sqrt(max(0, r * r - yy * yy)))
            xl, xr, ay = cx - half, cx + half, cy + yy
            if abs(nx) < 1e-6:
                xi = xl if (ay - p0y) * ny > 0 else xr + 1
            else:
                xi = p0x - (ay - p0y) * ny / nx
            xi = int(max(xl, min(xr + 1, xi)))
            left, right = (xl, xi - xl), (xi, xr + 1 - xi)
            if abs(nx) < 1e-6:
                g_part, s_part = ((xl, xr + 1 - xl), (xr, 0)) if (ay - p0y) * ny > 0 else ((xr, 0), (xl, xr + 1 - xl))
            elif nx > 0:
                g_part, s_part = right, left
            else:
                g_part, s_part = left, right
            if s_part[1] > 0:
                sky.append(Rect(s_part[0], ay, s_part[1], 2))
            if g_part[1] > 0:
                ground.append(Rect(g_part[0], ay, g_part[1], 2))
        S = g.sdl
        for rects, col in ((sky, SKY), (ground, GROUND)):
            if rects:
                arr = (Rect * len(rects))(*rects)
                g.color(col)
                S.SDL_RenderFillRects(g.ren, arr, len(rects))
        # horizon line, clipped to the circle
        fx, fy = p0x - cx, p0y - cy
        b = fx * dx + fy * dy
        disc = b * b - (fx * fx + fy * fy - r * r)
        if disc > 0:
            t1, t2 = -b - math.sqrt(disc), -b + math.sqrt(disc)
            for d in (-1, 0, 1):
                g.line(p0x + t1 * dx + nx * d, p0y + t1 * dy + ny * d, p0x + t2 * dx + nx * d, p0y + t2 * dy + ny * d, TEXT)
        # pitch marks every 10 degrees
        for deg in (-20, -10, 10, 20):
            mx, my = p0x - nx * deg * 2.2, p0y - ny * deg * 2.2
            if (mx - cx) ** 2 + (my - cy) ** 2 < (r - 20) ** 2:
                L = 22 if deg % 20 else 34
                g.line(mx - dx * L, my - dy * L, mx + dx * L, my + dy * L, (200, 210, 220), 160)
        # fixed board symbol + ring
        for d in (-1, 0, 1):
            g.line(cx - 62, cy + d, cx - 22, cy + d, YELLOW)
            g.line(cx + 22, cy + d, cx + 62, cy + d, YELLOW)
        g.circle(cx, cy, 5, YELLOW)
        for k in range(3):
            self._ring(cx, cy, r + k, BORDER if k else (70, 84, 100))

    def _ring(self, cx, cy, r, c):
        g = self.gfx
        pts = 120
        prev = None
        for i in range(pts + 1):
            a = 2 * math.pi * i / pts
            p = (cx + r * math.cos(a), cy + r * math.sin(a))
            if prev:
                g.line(prev[0], prev[1], p[0], p[1], c)
            prev = p

    # -- cards
    def draw_imu_card(self, x, y, w, h, now):
        g = self.gfx
        self._card_h = h
        nid = self.main_node()                          # the node you picked (click / F2), else node 1
        with self.udp.lock:
            nd = self.udp.nodes.get(nid)
            snap = None
            if nd:
                snap = (list(nd.vals), nd.rssi, nd.flags, nd.seq, nd.last, nd.src, nd.rate(now), nd.loss(),
                        list(nd.hist), nd.kind)
        self.card_head(x, y, w, node_name(nid), NODE_INFO.get(nid, ""), BLUE)
        if snap is None:
            self.pill(x + w - 24, y + 26, "WAITING", DIM)
            if NODE_KIND.get(nid) == "IMU":
                self.horizon(x + 190, y + 236, 112, 0, 0)
            g.wrapped("body", "Waiting for %s on UDP %d. A node without Wi-Fi opens its setup hotspot "
                      "QNX-NODE-%s: give it the Wi-Fi details with the form below." % (node_name(nid), self.args.udp_port, nid),
                      x + 360, y + 150, w - 400, MUTED)
            return
        vals, rssi, flags, seq, last, src, rate, loss, hist, kind = snap
        age = now - last
        self.live_pill(x + w - 24, y + 26, age)
        if kind == "ENV" and len(vals) >= 3:
            self.draw_env(x, y, w, h, now, vals, rssi, flags, seq, src, rate, loss, hist, age)
            return
        if kind == "VIB" and len(vals) >= 11:
            self.draw_vib(x, y, w, h, now, vals, rssi, flags, seq, src, rate, loss, hist, age)
            return
        if kind != "IMU" or len(vals) < 7:
            g.text("body", "%s data: %s" % (kind, ", ".join("%g" % v for v in vals)), x + 30, y + 120, TEXT)
            return
        ax, ay, az, gx, gy, gz, temp = vals[:7]
        pitch, roll = imu_angles(vals)
        failed = flags & 1
        stale = age >= 6 or failed
        cx, cy = x + 190, y + 232
        self.horizon(cx, cy, 112, 0 if failed else pitch, 0 if failed else roll)
        g.text("bodyb", "Pitch %+.1f°" % pitch, cx - 12, y + 356, TEXT, align="right")
        g.text("bodyb", "Roll %+.1f°" % roll, cx + 12, y + 356, TEXT)
        # numbers
        col = DIM if stale else TEXT
        x0 = x + 350
        g.text("label", "ACCELERATION  (g)", x0, y + 106, MUTED)
        g.text("label", "ROTATION  (°/s)", x0 + 290, y + 106, MUTED)
        for i, (a, r) in enumerate(((ax, gx), (ay, gy), (az, gz))):
            ry = y + 138 + i * 60
            g.text("h2", "XYZ"[i], x0, ry + 4, AXIS[i])
            g.text("title", "%+.3f" % a, x0 + 250, ry, col, align="right")
            g.text("h2", "XYZ"[i], x0 + 290, ry + 4, AXIS[i])
            g.text("title", "%+.1f" % r, x0 + 520, ry, col, align="right")
        amag = math.sqrt(ax * ax + ay * ay + az * az)
        g.text("body", "|a| %.2f g    ·    %.1f °C    ·    Wi-Fi %d dBm" % (amag, temp, rssi), x0, y + 330, MUTED)
        if failed:
            g.text("bodyb", "MPU6050 not answering on the node (check SDA/SCL)", x0, y + 300, AMBER)
        # graphs
        gx0, gw = x0 + 580, x + w - 30 - (x0 + 580)
        self.graph(gx0, y + 132, gw, 70, hist, (0, 1, 2), AXIS, now, "ACCEL  last 30 s", "g")
        self.graph(gx0, y + 280, gw, 70, hist, (3, 4, 5), AXIS, now, "GYRO  last 30 s", "°/s")
        g.text("small", "%d pkt/s  ·  loss %.1f%%  ·  seq %d  ·  from %s  ·  %s ago" % (
            rate, loss, seq, src, ("%.1f s" % age) if age < 60 else ("%d min" % (age // 60))),
            x0, y + h - 34, DIM)

    def zone_bar(self, x, y, w, v, zone):
        """Horizontal ISO severity scale A | B | C | D with a marker at the measured velocity."""
        g = self.gfx
        top = ISO_ZONES[2] * 1.6
        edges = (0.0,) + ISO_ZONES + (top,)
        for i in range(4):
            x0 = x + w * edges[i] / top
            x1 = x + w * edges[i + 1] / top
            g.fill(x0, y, x1 - x0 - 2, 12, ZONE_COLOR[i], 255 if i == zone else 90)
            g.text("label", "ABCD"[i], (x0 + x1) / 2, y + 18, ZONE_COLOR[i], align="center")
        mx = x + w * min(v, top) / top
        g.fill(mx - 2, y - 8, 4, 28, TEXT)
        for i, e in enumerate(ISO_ZONES):
            g.text("small", "%g" % e, x + w * e / top, y + 44, DIM, align="center")

    def zone_trend(self, x, y, w, h, hist, now, window=300.0):
        """Velocity trend with the ISO zones as coloured bands."""
        g = self.gfx
        pts = [(t, v[0]) for t, v in hist if now - t <= window and len(v) >= 11]
        hi = max([ISO_ZONES[2] * 1.3] + [v * 1.1 for _, v in pts])
        edges = (0.0,) + ISO_ZONES + (hi,)
        for i in range(4):
            lo_e, hi_e = edges[i], min(edges[i + 1], hi)
            if lo_e >= hi:
                break
            y0 = y + h - hi_e / hi * h
            y1 = y + h - lo_e / hi * h
            g.fill(x, y0, w, y1 - y0, ZONE_COLOR[i], 28)
            g.text("small", "%s" % "ABCD"[i], x + w + 8, (y0 + y1) / 2 - 12, ZONE_COLOR[i])
        g.text("label", "VELOCITY  last %d min  (mm/s RMS)" % (window // 60), x, y - 28, MUTED)
        g.fill(x, y + h, w, 1, BORDER)
        if len(pts) < 2:
            g.text("small", "collecting...", x + 10, y + h // 2 - 12, DIM)
            return
        step = max(1, len(pts) // 240)
        prev = None
        for t, v in pts[::step] + [pts[-1]]:
            p = (x + w - (now - t) / window * w, y + h - min(v, hi) / hi * h)
            if prev:
                g.line(prev[0], prev[1], p[0], p[1], TEXT)
                g.line(prev[0], prev[1] + 1, p[0], p[1] + 1, TEXT)
            prev = p

    def draw_vib(self, x, y, w, h, now, vals, rssi, flags, seq, src, rate, loss, hist, age):
        """Node 1 card: industrial machine-vibration monitoring (ISO 10816-3 style)."""
        g = self.gfx
        vel, vx, vy, vz, arms, apeak, freq, temp, zone, run, tilt = vals[:11]
        zone = max(0, min(3, int(zone)))
        failed = flags & 1
        stale = age >= 6 or failed
        zcol = DIM if stale else ZONE_COLOR[zone]
        self.pill(x + w - 160, y + 26, "ZONE %s  ·  %s" % ("ABCD"[zone], ZONE_NAME[zone]) if not failed else "NO SENSOR",
                  zcol if not failed else RED)
        # left: velocity, zone scale, machine state
        x0 = x + 30
        g.text("label", "VIBRATION VELOCITY  (mm/s RMS)", x0, y + 104, MUTED)
        ex = g.text("big", "—" if failed else "%.2f" % vel, x0 - 4, y + 118, zcol)
        g.text("h2", "mm/s", ex + 10, y + 166, MUTED)
        self.zone_bar(x0, y + 244, 360, vel, zone)
        if failed:
            g.text("bodyb", "MPU6050 not answering", x0, y + 312, AMBER)
            g.text("small", "check SDA = D4, SCL = D5, 3V3, GND", x0, y + 344, MUTED)
        else:
            g.circle(x0 + 10, y + 334, 9, GREEN if run else DIM)
            g.text("bodyb", "RUNNING" if run else "IDLE", x0 + 30, y + 320, GREEN if run else MUTED)
            if run and freq > 0:
                g.text("body", "%.1f Hz   %.0f rpm" % (freq, freq * 60), x0 + 390, y + 320, TEXT, align="right")
        # middle: per-axis velocity and acceleration figures
        x1 = x + 450
        g.text("label", "VELOCITY PER AXIS", x1, y + 104, MUTED)
        top = max(ISO_ZONES[2] * 1.3, vx, vy, vz)
        for i, v in enumerate((vx, vy, vz)):
            ry = y + 132 + i * 36
            g.text("bodyb", "XYZ"[i], x1, ry, AXIS[i])
            g.round_rect(x1 + 30, ry + 8, 200, 14, 7, (40, 50, 62))
            if not failed:
                g.round_rect(x1 + 30, ry + 8, max(14, 200 * min(v, top) / top), 14, 7, AXIS[i], 200 if not stale else 90)
            g.text("body", "—" if failed else "%.2f" % v, x1 + 330, ry, TEXT if not stale else DIM, align="right")
        crest = apeak / arms if arms > 1e-4 else 0.0
        rows = (("Acceleration RMS", "%.3f g" % arms), ("Acceleration peak", "%.3f g" % apeak),
                ("Crest factor", "%.1f" % crest if run else "—"), ("Sensor temperature", "%.1f °C" % temp),
                ("Mounting moved", "%.1f°" % tilt))
        for i, (k, v) in enumerate(rows):
            ry = y + 236 + i * 24
            g.text("small", k, x1, ry, MUTED)
            col = AMBER if (k == "Mounting moved" and tilt > 3) or (k == "Crest factor" and run and crest > 6) else TEXT
            g.text("small", "—" if failed else v, x1 + 330, ry, col if not stale else DIM, align="right")
        # right: trend with the zone bands
        x2 = x + 830
        self.zone_trend(x2, y + 136, x + w - 60 - x2, 190, hist, now)
        note = ""
        if flags & 2:
            note = "  ·  samples lost (FIFO overflow)"
        if not failed and tilt > 3:
            note += "  ·  sensor mounting moved %.0f° - check it is tight" % tilt
        g.text("small", "%.1f results/s  ·  loss %.1f%%  ·  seq %d  ·  from %s  ·  Wi-Fi %d dBm  ·  %s ago%s" % (
            rate, loss, seq, src, rssi, ("%.1f s" % age) if age < 60 else ("%d min" % (age // 60)), note),
            x + 30, y + h - 34, AMBER if note else DIM)

    def draw_env(self, x, y, w, h, now, vals, rssi, flags, seq, src, rate, loss, hist, age):
        """Node 2 card for the GY-BME/PM 280 module. The module carries either a BME280 (temperature,
        humidity, pressure) or a BMP280 (no humidity); flags bit1 from the node says which.
        Columns: temperature, humidity (BME280 only), pressure, altitude estimated from the pressure."""
        g = self.gfx
        temp, hum, pres = vals[:3]
        failed = flags & 1
        no_hum = bool(flags & 2) or hum < 0
        stale = age >= 6 or failed
        chip = "BMP280" if no_hum else "BME280"
        self.pill(x + w - 160, y + 26, "%s  ·  %s" % (chip, "temp + pressure" if no_hum else "temp + humidity + pressure"),
                  AMBER if no_hum else GREEN)

        def alt(p):                                   # international barometric formula, sea level 1013.25 hPa
            return 44330.0 * (1.0 - (p / SEA_LEVEL_HPA) ** 0.1903) if p > 0 else 0.0

        cols = [("TEMPERATURE", "°C", temp, 1, AMBER, lambda v: v[0])]
        if not no_hum:
            cols.append(("HUMIDITY", "%RH", hum, 0, BLUE, lambda v: v[1]))
        cols.append(("PRESSURE", "hPa", pres, 1, (167, 139, 250), lambda v: v[2]))
        cols.append(("ALTITUDE (est.)", "m", alt(pres), 0, GREEN, lambda v: alt(v[2])))
        cw = (w - 60) // len(cols)
        recent = [(t, v2) for t, v2 in hist if len(v2) >= 3 and now - t <= 300.0]
        for i, (label, unit, v, dec, col, pick) in enumerate(cols):
            cx = x + 30 + i * cw
            g.text("label", label, cx, y + 104, MUTED)
            text = "—" if failed else "%.*f" % (dec, v)
            font = "big" if g.width("big", text) + g.width("h2", unit) + 30 <= cw - 10 else "title"
            ex = g.text(font, text, cx - 4, y + 118 if font == "big" else y + 150, DIM if stale or failed else col)
            if not failed:
                g.text("h2", unit, ex + 8, y + 166, MUTED)
            pts = [(t, (pick(v2),)) for t, v2 in recent]
            if len(pts) >= 2:
                lo, hi = min(p[1][0] for p in pts), max(p[1][0] for p in pts)
                g.text("small", "min %.*f  ·  max %.*f" % (dec, lo, dec, hi), cx, y + 216, DIM)
            self.graph(cx, y + 272, cw - 40, 44, pts, (0,), (col,), now, "last 5 min", unit, window=300.0)
        if failed:
            g.text("bodyb", "GY-BME/PM 280 not answering on the node: check SDA = IO4, SCL = IO5, CSB to 3V3",
                   x + 30, y + 216, AMBER)
        g.text("small", "%d pkt/s  ·  loss %.1f%%  ·  seq %d  ·  from %s  ·  Wi-Fi %d dBm  ·  %s ago" % (
            rate, loss, seq, src, rssi, ("%.1f s" % age) if age < 60 else ("%d min" % (age // 60))),
            x + 30, y + h - 34, DIM)

    def draw_nodes(self, x, y, w, h, now):
        g = self.gfx
        self._card_h = h
        self.card_head(x, y, w, "Nodes", "Click a live node (or F2) to show its data", MUTED)
        with self.udp.lock:
            rows = [(nd.id, now - nd.last, nd.src, nd.rate(now), nd.rssi, nd.loss()) for nd in
                    sorted(self.udp.nodes.values(), key=lambda n: n.id)]
        ry = y + 100
        self.node_rows = []
        viewed = self.main_node()
        for ap, sig in self.setup_aps:
            rows.append((ap, None, "", 0, sig, 0.0))
        if not rows:
            g.wrapped("body", "No nodes yet. Power a node: it opens a setup hotspot QNX-NODE-<id> and shows up here "
                      "after a scan (F5).", x + 30, ry, w - 60, DIM, max_lines=4)
            return
        for nid, age, src, rate, rssi, loss in rows[:4]:
            if age is None:
                color, state, name = YELLOW, "SETUP MODE", nid
                detail = "own setup hotspot  ·  %d dBm  ·  needs Wi-Fi" % rssi
            else:
                color = GREEN if age < 1.5 else AMBER if age < 6 else RED
                state = "LIVE" if age < 1.5 else "STALE" if age < 6 else "OFFLINE"
                name = node_name(nid)
                detail = "%s  ·  %d/s  ·  %d dBm  ·  loss %.1f%%" % (src, rate, rssi, loss)
            if age is not None and nid == viewed:
                g.round_rect(x + 18, ry - 10, w - 36, 66, 12, BLUE, 30)
            if age is not None:
                self.node_rows.append(((x + 18, ry - 10, w - 36, 66), nid))
            g.circle(x + 40, ry + 15, 8, color)
            g.text("bodyb", name, x + 60, ry, TEXT)
            g.text("label", state, x + w - 30, ry + 4, color, align="right")
            g.text("small", detail, x + 60, ry + 34, MUTED)
            ry += 72
            g.fill(x + 30, ry - 10, w - 60, 1, BORDER)

    def stepper(self, x_right, y):
        """Scan > Select > Wi-Fi > Data, current step highlighted."""
        g = self.gfx
        cur = {"scan": 0, "creds": 2, "progress": 2, "done": 3}[self.stage]
        if self.stage == "scan" and self.scan_list():
            cur = 1
        names = ("Scan", "Select", "Wi-Fi", "Data")
        x = x_right - sum(g.width("label", n) + 40 for n in names) + 12
        for i, n in enumerate(names):
            col = YELLOW if i == cur else (GREEN if i < cur else DIM)
            g.circle(x + 6, y + 9, 6, col)
            x = g.text("label", n, x + 18, y, col) + 22

    def check_icon(self, cx, cy, col):
        g = self.gfx
        g.circle(cx, cy, 15, col)
        g.thick_line(cx - 7, cy, cx - 2, cy + 5, (8, 14, 24))
        g.thick_line(cx - 2, cy + 5, cx + 7, cy - 5, (8, 14, 24))

    def cross_icon(self, cx, cy, col):
        g = self.gfx
        g.circle(cx, cy, 15, col)
        g.thick_line(cx - 6, cy - 6, cx + 6, cy + 6, (8, 14, 24))
        g.thick_line(cx + 6, cy - 6, cx - 6, cy + 6, (8, 14, 24))

    def button(self, x, y, w, label, action, primary=False, color=None, enabled=True):
        g = self.gfx
        if primary:
            g.round_rect(x, y, w, 52, 12, BLUE if enabled else DIM)
            g.text("bodyb", label, x + w // 2, y + 12, (8, 14, 24), align="center")
        else:
            g.card(x, y, w, 52, border=(60, 74, 90), bg=CARD, rad=12)
            g.text("bodyb", label, x + w // 2, y + 12, color or TEXT, align="center")
        if enabled:
            self.buttons.append(((x, y, w, 52), action))

    def footer_msg(self, x, y, w):
        g = self.gfx
        msg = self.msg
        while g.width("body", msg) > w and len(msg) > 4:
            msg = msg[:-4] + "..."
        g.text("body", msg, x, y, TONE[self.msg_tone])

    def draw_form(self, x, y, w, h, now):
        g = self.gfx
        self._card_h = h
        self.buttons = []
        titles = {"scan": "Add a node", "creds": "Wi-Fi details", "progress": "Connecting",
                  "done": "Node online" if self.result_ok else "Not connected"}
        self.card_head(x, y, w, titles[self.stage], None, YELLOW)
        self.stepper(x + w - 26, y + 30)
        by = y + h - 112                                    # button row
        if self.stage == "scan":
            self.draw_scan_list(x, y, w, by, now)
            self.button(x + 30, by, 300, "Select  (Enter)", self.pick, primary=True, enabled=bool(self.scan_list()))
            self.button(x + 348, by, 200, "Scan now  F5", self.refresh)
            self.button(x + 566, by, 164, "Reset  F8", self.forget, color=RED)
        elif self.stage == "creds":
            self.draw_fields(x, y, w, now)
            self.button(x + 30, by, 360, "Send to %s  (Enter)" % self.picked, self.send_details, primary=True)
            self.button(x + 408, by, 200, "Back  (Esc)", lambda: self.key(K_ESC, 0))
        else:
            self.draw_steps(x, y, w, now)
            if self.stage == "done" and self.result_ok:
                nid = self.picked.rsplit("-", 1)[-1]
                self.button(x + 30, by, 360, "View %s data  (Enter)" % node_name(nid), lambda: self.key(K_RETURN, 0), primary=True)
                self.button(x + 408, by, 260, "Add another  (Esc)", lambda: self.key(K_ESC, 0))
            elif self.stage == "done":
                self.button(x + 30, by, 300, "Try again  (Enter)", lambda: self.key(K_RETURN, 0), primary=True)
                self.button(x + 348, by, 260, "Back to list  (Esc)", lambda: self.key(K_ESC, 0))
        self.footer_msg(x + 30, by + 66, w - 60)

    def draw_scan_list(self, x, y, w, bottom, now):
        g = self.gfx
        nodes = self.scan_list()
        if self.manual():
            g.text("small", "Manual mode (no wpa_cli): join %s on the Pi, password %s" % (
                self.args.node, setup_password(self.client.key, self.args.node)), x + 30, y + 66, AMBER)
        elif self.scanning:
            g.text("small", "Scanning for nodes in setup mode" + "." * (int(now * 2) % 4), x + 30, y + 66, BLUE)
        else:
            ago = now - self.last_scan
            with self.udp.lock:
                live = any(now - n.last < 5 for n in self.udp.nodes.values())
            how = "F5 to scan (auto-scan paused while nodes are sending)" if live or self.args.no_scan \
                else "scans every 10 s"
            g.text("small", "Nodes in setup mode near the Pi  ·  scanned %d s ago  ·  %s" % (ago, how),
                   x + 30, y + 66, MUTED)
        ry = y + 106
        if not nodes:
            # radar sweep while nothing is found
            cx, cy, r = x + 110, y + 220, 72
            g.circle(cx, cy, r, (16, 30, 46))
            for k in range(3):
                self._ring(cx, cy, r * (k + 1) // 3, (52, 78, 104))
            g.line(cx - r, cy, cx + r, cy, (40, 60, 82))
            g.line(cx, cy - r, cx, cy + r, (40, 60, 82))
            a = (now * 2.0) % (2 * math.pi)
            for t in range(18):
                b = a - t * 0.04
                g.thick_line(cx, cy, cx + r * math.cos(b), cy + r * math.sin(b), BLUE, 2, 230 - t * 12)
            g.circle(cx, cy, 5, BLUE)
            with self.udp.lock:
                some = bool(self.udp.nodes)
            g.text("h2", "No new nodes found" if some else "No nodes found yet", x + 220, y + 160, TEXT)
            g.wrapped("body", "Power a node: with no Wi-Fi it opens the hotspot QNX-NODE-<id>. "
                      "A node that is already set up: press its RESET button 3 times.", x + 220, y + 204, w - 250, MUTED,
                      max_lines=4)
            return
        self.sel %= len(nodes)
        for i, (ap, sig) in enumerate(nodes[:4]):
            selected = i == self.sel
            rect = (x + 30, ry, w - 60, 60)
            if selected:
                g.card(rect[0], ry, rect[2], 60, border=YELLOW, bg=(38, 34, 18), rad=12, thick=2)
            else:
                g.card(rect[0], ry, rect[2], 60, border=(44, 55, 68), bg=FIELD, rad=12)
            self.buttons.append((rect, (lambda k=i: (setattr(self, "sel", k), self.pick()))))
            g.circle(x + 62, ry + 30, 9, YELLOW if selected else MUTED)
            g.text("bodyb", ap, x + 86, ry + 6, TEXT)
            nid = ap.rsplit("-", 1)[-1]
            g.text("small", "%s  ·  %s" % (node_name(nid), NODE_INFO.get(int(nid) if nid.isdigit() else 0, "sensor node")),
                   x + 86, ry + 34, MUTED)
            if sig is not None:
                lvl = 4 if sig >= -55 else 3 if sig >= -65 else 2 if sig >= -75 else 1
                g.text("body", "%d dBm" % sig, x + w - 60, ry + 16, MUTED, align="right")
                self.bars(x + w - 210, ry + 14, lvl, YELLOW if selected else MUTED)
            else:
                g.text("small", "joined by hand", x + w - 60, ry + 20, MUTED, align="right")
            ry += 72

    def draw_fields(self, x, y, w, now):
        g = self.gfx
        g.text("small", "For %s  ·  sent over the air, signed with the shared key" % self.picked,
               x + 30, y + 66, GREEN)
        fy = y + 96
        for i, f in enumerate(self.fields):
            focused = i == self.focus
            g.text("label", f.label, x + 30, fy, BLUE if focused else MUTED)
            bx, by, bw, bh = x + 30, fy + 22, w - 60, 50
            f.rect = (bx, by, bw, bh)
            g.card(bx, by, bw, bh, border=BLUE if focused else (44, 55, 68), bg=FIELD, rad=10, thick=2 if focused else 1)
            if f.value:
                shown = f.value if not f.secret or self.show_pass else "•" * len(f.value)
                while g.width("body", shown) > bw - 150 and len(shown) > 1:
                    shown = shown[1:]
                end = g.text("body", shown, bx + 18, by + 10, TEXT)
            else:
                end = bx + 18
                g.text("body", f.placeholder, bx + 18, by + 10, DIM)
            if focused and int(now * 2) % 2 == 0:
                g.fill(end + 2, by + 11, 2, 28, BLUE)
            if f.secret:
                g.text("small", "F1 hide" if self.show_pass else "F1 show", bx + bw - 18, by + 13, DIM, align="right")
            fy += 84

    def draw_steps(self, x, y, w, now):
        g = self.gfx
        nid = self.picked.rsplit("-", 1)[-1] if self.picked else "?"
        g.text("small", "%s  ·  %s" % (self.picked, node_name(nid)), x + 30, y + 66,
               GREEN if self.result_ok else RED if self.stage == "done" else MUTED)
        steps = getattr(self, "steps", ["", "", "", ""])
        sy = y + 100
        for i, text in enumerate(steps):
            cx, cy = x + 52, sy + 18
            if i < self.step or (self.stage == "done" and self.result_ok):
                self.check_icon(cx, cy, GREEN)
                col = TEXT
            elif i == self.step and self.step_failed:
                self.cross_icon(cx, cy, RED)
                col = RED
            elif i == self.step and self.stage == "progress":
                self._ring(cx, cy, 14, (50, 62, 78))
                a = now * 6
                for t in range(10):
                    b = a + t * 0.25
                    g.circle(cx + 14 * math.cos(b), cy + 14 * math.sin(b), 2, BLUE)
                col = BLUE
            else:
                self._ring(cx, cy, 14, (60, 72, 88))
                col = DIM
            g.text("body", text, x + 84, sy + 4, col)
            if i < 3:
                g.fill(cx - 1, cy + 18, 2, 26, GREEN if i < self.step else (50, 60, 72))
            sy += 62

    def kv(self, x, y, w, label, value, color=TEXT):
        g = self.gfx
        g.text("body", label, x, y, MUTED)
        while g.width("bodyb", value) > w - 190 and len(value) > 4:
            value = value[:-4] + "..."
        g.text("bodyb", value, x + w, y, color, align="right")
        g.fill(x, y + 38, w, 1, BORDER)

    def bars(self, x, y, level, color):
        g = self.gfx
        for i in range(4):
            bh = 8 + i * 7
            g.round_rect(x + i * 12, y + 30 - bh, 8, bh, 2, color if i < level else (50, 60, 72))

    def draw_status(self, x, y, w, h, now):
        g = self.gfx
        self._card_h = h
        nid = self.main_node()
        with self.udp.lock:
            entry = self.udp.status.get(str(nid))
        self.card_head(x, y, w, node_name(nid) + " Wi-Fi", None, BLUE)
        in_setup = ("QNX-NODE-%s" % nid) in dict(self.setup_aps)
        if entry is None:
            if in_setup:
                self.pill(x + w - 24, y + 26, "SETUP", YELLOW)
                g.text("title", "SETUP MODE", x + 30, y + 84, YELLOW)
                g.wrapped("body", "%s has no Wi-Fi details and has opened its hotspot QNX-NODE-%s. Send it the "
                          "details with the form." % (node_name(nid), nid), x + 30, y + 150, w - 60, MUTED, max_lines=4)
            else:
                self.pill(x + w - 24, y + 26, "UNKNOWN", DIM)
                g.text("title", "NOT SEEN YET", x + 30, y + 84, DIM)
                g.wrapped("body", "%s reports here once it is on the Wi-Fi. If it is new, power it and press F5 to "
                          "find its setup hotspot." % node_name(nid), x + 30, y + 150, w - 60, MUTED, max_lines=4)
            return
        st, t, ip = entry
        age = now - t
        if in_setup:
            self.pill(x + w - 24, y + 26, "SETUP", YELLOW)
        elif age < 12:
            self.pill(x + w - 24, y + 26, "REPORTING", GREEN)
        else:
            self.pill(x + w - 24, y + 26, "SILENT", AMBER)
        state = "SETUP" if in_setup else st.state
        color, label = STATE_LOOK.get(state, (MUTED, state))
        if age >= 12 and not in_setup:
            color, label = AMBER, "NOT REPORTING"
        g.circle(x + 44, y + 108, 11, color)
        g.circle(x + 44, y + 108, 18, color, 50)
        g.text("title", label, x + 72, y + 84, color)
        ky, kw = y + 150, w - 60
        self.kv(x + 30, ky, kw, "Network", st.ssid or "—")
        self.kv(x + 30, ky + 46, kw, "Node IP", st.ip if st.state == "CONNECTED" else "—")
        if st.state == "CONNECTED":
            lvl = 4 if st.rssi >= -55 else 3 if st.rssi >= -65 else 2 if st.rssi >= -75 else 1
            g.text("body", "Signal", x + 30, ky + 92, MUTED)
            ex = x + 30 + kw - g.width("bodyb", "%d dBm" % st.rssi)
            g.text("bodyb", "%d dBm" % st.rssi, ex, ky + 92, TEXT)
            self.bars(ex - 62, ky + 92, lvl, GREEN)
            g.fill(x + 30, ky + 130, kw, 1, BORDER)
        else:
            self.kv(x + 30, ky + 92, kw, "Signal", "—")
        host_col = AMBER if self._ip and st.host not in ("-", self._ip) else TEXT
        self.kv(x + 30, ky + 138, kw, "Sends to", st.host if st.host != "-" else "not set", host_col)
        problem = reason_text(st.reason)
        self.kv(x + 30, ky + 184, kw, "Last problem", problem or "none", RED if problem and st.state != "CONNECTED" else TEXT)
        self.kv(x + 30, ky + 230, kw, "MAC", st.mac)
        g.text("small", "last report %.0f s ago  ·  control %s:%d" % (age, self.node_ip(nid) or ip, self.args.ctrl_port),
               x + 30, y + h - 40, DIM)

    def draw_log(self, x, y, w, h):
        g = self.gfx
        self._card_h = h
        self.card_head(x, y, w, "Events", None, MUTED)
        ly = y + 82
        for t, text, tone in list(self.log_lines)[-12:]:
            g.text("small", t, x + 30, ly, DIM)
            msg = text
            while g.width("small", msg) > w - 150 and len(msg) > 4:
                msg = msg[:-4] + "..."
            g.text("small", msg, x + 120, ly, TONE[tone] if tone != "plain" else TEXT)
            ly += 30

    def draw_footer(self):
        hints = {
            "scan": "Up / Down select node   ·   Enter choose   ·   F5 scan now   ·   F2 show next node's data   ·   "
                    "F8 twice reset node   ·   F12 screenshot   ·   Esc twice quit",
            "creds": "Tab / Up / Down next field   ·   Enter send   ·   F1 show password   ·   Esc back to the list",
            "progress": "Sending the Wi-Fi details over the air...",
            "done": "Enter continue   ·   Esc back to the list   ·   F2 show next node's data",
        }
        self.gfx.text("small", hints[self.stage], W // 2, H - 44, DIM, align="center")

    def render(self, now):
        g = self.gfx
        g.clear(BG)
        self.draw_header(now)
        self.draw_imu_card(48, 118, 1260, 400, now)
        self.draw_nodes(1336, 118, W - 48 - 1336, 400, now)
        self.draw_form(48, 546, 760, 470, now)
        self.draw_status(836, 546, 520, 470, now)
        self.draw_log(1384, 546, W - 48 - 1384, 470)
        self.draw_footer()
        if self.want_shot:
            path, self.want_shot = self.want_shot, None
            ok = g.screenshot(path)
            self.log(("Screenshot saved: " + path) if ok else "Screenshot failed", "info" if ok else "bad")
        g.present()

    def run(self):
        self.udp.start()
        shot_at = time.monotonic() + self.args.shot_after if self.args.screenshot else None
        quit_at = time.monotonic() + self.args.quit_after if self.args.quit_after else None
        try:
            while self.running:
                t0 = time.monotonic()
                for ev in self.gfx.events():
                    if ev[0] == "quit":
                        self.running = False
                    elif ev[0] == "key":
                        self.key(ev[1], ev[2])
                    elif ev[0] == "click":
                        self.click(ev[1], ev[2])
                with self.udp.lock:
                    known = list(self.udp.nodes.values())
                any_online = any(t0 - n.last < 5 for n in known)
                any_silent = any(t0 - n.last >= 10 for n in known)
                # Each scan takes the Pi's Wi-Fi off its channel for a few seconds: every node's packets are
                # lost meanwhile and MemoryGuard reports them OFFLINE. So the Pi only scans on its own when it
                # has to: every 10 s while no node is sending, every 60 s while a known node is silent (it may
                # be in setup mode), never while every node is sending. F5 always scans at once.
                if self.args.no_scan:
                    every = None
                elif not any_online:
                    every = 10 if self.stage == "scan" else 60
                elif any_silent:
                    every = 60
                else:
                    every = None
                if every is not None and t0 - self.last_scan > every and not self.busy:
                    self.scan(quiet=True)
                if t0 - getattr(self, "_beat", 0) > 30:   # heartbeat in the log every 30 s
                    self._beat = t0
                    self.heartbeat(t0)
                if self.waiting_outcome and t0 - self.waiting_outcome > 60:
                    self.set_msg("Not online after 60 s - check the Wi-Fi name, password and 2.4 GHz. "
                                 "With wrong details the node reopens its setup hotspot.", "bad")
                    self.waiting_outcome = 0.0
                    self.step_failed, self.result_ok, self.stage = True, False, "done"
                    self.scan(quiet=True)
                if shot_at and t0 >= shot_at:
                    self.want_shot, shot_at = self.args.screenshot, None
                try:
                    self.render(t0)
                except Exception as e:            # keep the dashboard running, but record what broke
                    Log.error("drawing failed in stage %s: %r" % (self.stage, e), once_key=repr(e))
                    try:
                        self.gfx.present()
                    except Exception:
                        pass
                if quit_at and t0 >= quit_at:
                    break
                time.sleep(max(0.0, FRAME_S - (time.monotonic() - t0)))
        except KeyboardInterrupt:
            Log.info("stopped with Ctrl+C")
        except Exception:
            Log.error("dashboard crashed")
            raise
        finally:
            Log.info("dashboard closed")
            self.gfx.close()

    def heartbeat(self, now):
        with self.udp.lock:
            nodes = ["%s: %d/s, seq %s, loss %.1f%%, last %.1f s ago from %s" % (
                node_name(n.id), n.rate(now), n.seq, n.loss(), now - n.last, n.src) for n in self.udp.nodes.values()]
            stats = ["%s %s" % (node_name(k), v[0].state) for k, v in self.udp.status.items()]
        Log.info("heartbeat: stage %s, busy %s, setup hotspots %s, udp bad packets %d" % (
            self.stage, self.busy, [a for a, _ in self.setup_aps], self.udp.bad))
        for line in nodes + stats:
            Log.info("heartbeat:   " + line)


# ---------------------------------------------------------------- command line mode
def cli_log(text, tone="plain"):
    Log.info(text)
    print("[%s] %s" % (time.strftime("%H:%M:%S"), text), flush=True)


def print_status(st, ip):
    print("%s  (MAC %s, control %s)\n  state    %s\n  network  %s\n  node IP  %s\n  signal   %s\n  sends to %s\n  problem  %s"
          % (node_name(st.node), st.mac, ip, st.state, st.ssid or "-", st.ip, ("%d dBm" % st.rssi) if st.rssi else "-",
             st.host, reason_text(st.reason) or "none"))


def cli_wifi(args):
    if args.manual:
        return None
    w = WifiCtl(args.wpa_cli, args.wifi_iface, args.wpa_ctrl)
    if w.error:
        print("Pi Wi-Fi control not available (%s). Using manual mode." % w.error)
        return None
    return w


def cli_scan(args):
    w = cli_wifi(args)
    if w is None:
        return 1
    aps = w.scan()
    for ap, sig in aps:
        print("%-14s %4d dBm   setup hotspot, waiting for Wi-Fi details" % (ap, sig))
    if not aps:
        print("No node in setup mode found.")
    return 0


def cli_status(args, key):
    if args.node_ip:
        st = NodeClient(key, args.ctrl_port).status(args.node_ip)
        if st is None:
            print("No answer from %s" % args.node_ip)
            return 1
        print_status(st, args.node_ip)
        return 0
    got = {}
    u = UdpListener(args.udp_port, cli_log, on_status=lambda st, old, ip: got.setdefault(st.node, (st, ip)))
    if u.error:
        sys.exit(u.error + " (is the dashboard running? use --node-ip IP)")
    u.start()
    print("Listening 6 s for node reports on UDP %d..." % args.udp_port)
    time.sleep(6)
    for st, ip in got.values():
        print_status(st, ip)
    if not got:
        print("No node reported.")
    return 0 if got else 1


def cli_set(args, key):
    host = args.host or guess_pi_ip()
    pw = args.password
    if pw is None:
        pw = getpass.getpass("Password for \"%s\" (Enter = open network): " % args.set)
    problem = check_credentials(args.set, pw, host)
    if problem:
        print(problem)
        return 2
    wifi = cli_wifi(args)
    node_ap = args.node
    if wifi is not None and not args.node_given:
        aps = wifi.scan()
        if not aps:
            print("No node in setup mode found.")
            return 1
        node_ap = aps[0][0]
    nid = node_ap.rsplit("-", 1)[-1]
    online = threading.Event()
    u = UdpListener(args.udp_port, lambda *a: None, on_status=lambda st, old, ip:
                    online.set() if str(st.node) == nid and st.state == "CONNECTED" else None)
    client = NodeClient(key, args.ctrl_port)
    ok, text = provision_over_air(wifi, client, args, node_ap, args.set, pw, host, lambda t: print(t, flush=True))
    print(text)
    if not ok:
        return 1
    if u.error:
        print("(can't watch for the node coming online: %s)" % u.error)
        return 0
    u.start()
    print("Waiting for %s to come online on \"%s\"..." % (node_name(nid), args.set))
    if online.wait(args.timeout):
        print("%s is online and reporting to %s." % (node_name(nid), host))
        return 0
    print("%s did not report within %d s (wrong password? it reopens its setup hotspot then)" % (node_name(nid), args.timeout))
    return 3


def cli_forget(args, key):
    if not args.node_ip:
        print("Give the node's IP with --node-ip (see --status)")
        return 2
    ok, text = NodeClient(key, args.ctrl_port).forget(args.node_ip)
    print(text)
    return 0 if ok else 1


def cli_listen(args):
    def show(node, seq, kind, vals, rssi, flags, src):
        if kind == "IMU" and len(vals) >= 7:
            p, r = imu_angles(vals)
            text = "a %+.2f %+.2f %+.2f g  gyro %+6.1f %+6.1f %+6.1f dps  %.1f C  pitch %+5.1f roll %+5.1f" % (
                tuple(vals[:7]) + (p, r))
        elif kind == "VIB" and len(vals) >= 11:
            text = "%.2f mm/s zone %s (x %.2f y %.2f z %.2f)  a %.3f g rms %.3f g peak  %s  %.1f C  tilt %.1f" % (
                vals[0], "ABCD"[max(0, min(3, int(vals[8])))], vals[1], vals[2], vals[3], vals[4], vals[5],
                ("%.1f Hz %.0f rpm" % (vals[6], vals[6] * 60)) if vals[9] else "idle", vals[7], vals[10])
        elif kind == "ENV" and len(vals) >= 3:
            text = "%.2f C  %s  %.2f hPa" % (vals[0], ("%.1f %%RH" % vals[1]) if vals[1] >= 0 else "no humidity",
                                            vals[2])
        else:
            text = ", ".join("%g" % v for v in vals)
        print("%s #%-6d %s %s  %d dBm%s  (%s)" % (node_name(node), seq, kind, text, rssi,
                                                  "  SENSOR FAILED" if flags & 1 else "", src), flush=True)

    def status(st, old, ip):
        print("%s status: %s on \"%s\" %s %d dBm" % (node_name(st.node), st.state, st.ssid, st.ip, st.rssi), flush=True)
    u = UdpListener(args.udp_port, cli_log, show, status)
    if u.error:
        sys.exit(u.error)
    print("Listening on UDP %d (Ctrl+C to stop)" % args.udp_port)
    try:
        u.run()
    except (KeyboardInterrupt, BrokenPipeError):
        pass


class Args:
    def __init__(self, argv):
        self.window = "--window" in argv
        self.manual = "--manual" in argv
        self.udp_port, self.ctrl_port, self.setup_ip = NODE_PORT, CTRL_PORT, SETUP_IP
        self.wpa_cli, self.wifi_iface, self.wpa_ctrl = WPA_CLI, None, None
        self.set = self.password = self.host = self.screenshot = self.node_ip = None
        self.node, self.node_given = "QNX-NODE-1", False
        self.key = load_prov_key()
        self.timeout, self.shot_after, self.quit_after = 45, 3.0, 0.0
        self.mode = "dashboard"
        self.log_path = None
        self.debug = "--debug" in argv
        self.no_scan = "--no-scan" in argv
        it = iter(argv)
        for a in it:
            if a == "--udp-port":
                self.udp_port = int(next(it))
            elif a == "--ctrl-port":
                self.ctrl_port = int(next(it))
            elif a == "--setup-ip":
                self.setup_ip = next(it)
            elif a == "--wpa-cli":
                self.wpa_cli = next(it)
            elif a == "--wpa-ctrl":
                self.wpa_ctrl = next(it)
            elif a == "--wifi-iface":
                self.wifi_iface = next(it)
            elif a == "--set":
                self.mode, self.set = "set", next(it)
            elif a == "--password":
                self.password = next(it)
            elif a == "--host":
                self.host = next(it)
            elif a == "--node":
                self.node, self.node_given = next(it), True
            elif a == "--node-ip":
                self.node_ip = next(it)
            elif a == "--key":
                self.key = next(it)
            elif a == "--log":
                self.log_path = next(it)
            elif a == "--timeout":
                self.timeout = int(next(it))
            elif a == "--screenshot":
                self.screenshot = next(it)
            elif a == "--shot-after":
                self.shot_after = float(next(it))
            elif a == "--quit-after":
                self.quit_after = float(next(it))
            elif a == "--setup-pass":
                self.mode = "setup-pass"
            elif a in ("--status", "--forget", "--listen", "--genkey", "--scan", "--diagnose"):
                self.mode = a[2:]
            elif a in ("-h", "--help"):
                self.mode = "help"
            elif a.startswith("QNX-NODE-") and self.mode == "setup-pass":
                self.node = a
            elif a not in ("--window", "--manual", "--debug", "--no-scan"):
                sys.exit("Unknown option %s (see --help)" % a)


def main():
    args = Args(sys.argv[1:])
    if args.mode not in ("help", "genkey", "setup-pass"):
        Log.open(args.log_path, args.debug)
        if Log.path:
            print("Log file: %s%s" % (Log.path, "  (debug detail on)" if args.debug else ""))
    if args.mode == "help":
        print(__doc__)
        return 0
    if args.mode == "genkey":
        k = secrets.token_hex(32)
        print("New shared key:\n  %s\nPut it in BOTH places, then re-flash the nodes:\n"
              "  %s next to node_dashboard.py:  %s\n"
              "  secrets.h of every node sketch:  #define PROV_KEY_HEX_VALUE \"%s\"" % (k, PROV_KEY_FILE, k, k))
        return 0
    if args.mode == "listen":
        return cli_listen(args)
    if args.mode == "scan":
        return cli_scan(args)
    key = key_bytes(args.key)
    if args.mode == "setup-pass":
        print("%s hotspot password: %s" % (args.node, setup_password(key, args.node)))
        return 0
    if args.mode == "status":
        return cli_status(args, key)
    if args.mode == "diagnose":
        return cli_diagnose(args, key)
    if args.mode == "set":
        return cli_set(args, key)
    if args.mode == "forget":
        return cli_forget(args, key)
    try:
        Dashboard(args, key).run()
    except (OSError, RuntimeError) as e:
        sys.exit("Can't start the HDMI dashboard (%s). The --scan / --set / --status / --listen modes work without it." % e)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
