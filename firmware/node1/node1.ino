/*
  Node 1 - Seeed XIAO ESP32C3 + MPU6050 + 0.96" yellow/blue OLED   (firmware 3.8 "stay connected", industrial vibration node)
  ----------------------------------------------------------------------------------------------------
  A wireless machine-vibration monitoring node for the QNX monitoring system on the Raspberry Pi.
  Mount it firmly on the machine (motor / pump / fan bearing housing, screwed or glued, not taped).
  No wires to the Pi.

  How it gets its Wi-Fi (only the QNX Pi can give it):
    1. With no Wi-Fi details stored, the node opens its own setup hotspot "QNX-NODE-1".
       The hotspot password is derived from the shared key below, so only the Pi can compute it.
    2. The Pi's dashboard joins that hotspot for a few seconds and connects to 192.168.4.1:7000.
    3. The node gives a one-time challenge; the Pi sends the Wi-Fi name, password and its own IP,
       signed with HMAC-SHA256 (shared key) and with the password encrypted. Anything unsigned is refused.
    4. The node closes the hotspot, joins that Wi-Fi and starts sending data to the Pi.
  The details are kept in flash. The Pi can re-send or erase them over Wi-Fi later (same port 7000).
  To erase them on the node itself (back to the setup hotspot):
    - press the RESET button 3 times quickly (within ~3 s per press), or
    - hold the BOOT button for 3 s while the node is running (not while pressing RESET).
  If saved details stop working, the setup hotspot reopens for 90 s every 3 minutes.

  Clean output (3.3): single-sample read glitches are removed before filtering, every reported value is
  the median of the last 3 results (a lone spike never reaches the Pi), and the sensor's own noise floor
  (learned while idle) is subtracted, so a still sensor reads ~0.00 mm/s. Settings: GLITCH_G, MEDIAN_OF_3,
  NOISE_AUTO. A real change shows after one extra result (~0.5 s).

  Stay connected (3.7): the node keeps its Wi-Fi link to the QNX Pi whatever the sensor does. Sensor
  trouble never resets the node: it keeps sending frames (held, or FAULT while the sensor is failing).
  A watchdog restarts a hung node in 8 s, and keeps the Wi-Fi details. After 3 crash/brownout/watchdog
  resets in a row, the node starts in SAFE MODE: sensor off, low Wi-Fi power, still connected and sending
  FAULT frames, so it stays visible in the QNX system instead of looping. The next power-on is normal.
  FIFO drain (3.8): some MPU6050-marked chips (MPU-6500 type) have only a 512-byte FIFO = 85 ms of samples,
  less than one frequency analysis takes on the ESP32-C3. The FIFO is now emptied into a 0.4 s buffer in
  RAM all the time, also between the FFT stages, so it never overflows.
  The FIFO temperature frame check (3.4-3.6) is off by default (FRAME_CHECK 0) until it is confirmed on
  this chip; corrupt data is caught by the gravity and 2 g checks instead.

  Data integrity (3.4): the MPU FIFO carries accel + temperature (8-byte frames). Every frame's temperature
  word must match the chip's temperature register, so a FIFO stream that lost a byte (garbage on all axes,
  fake 20-130 mm/s zone D) is caught on the first bad frame, the FIFO is re-synced and that data never
  reaches the filters. FIFO overflow is read from the chip's overflow flag. A half second with more than
  10 % of samples above 4 g is rejected as corrupt data. The I2C bus is recovered (9 clock pulses) when the
  MPU stops answering. The reset reason (e.g. BROWNOUT = power supply dip) is printed and shown on the
  OLED, and only real power-on / RESET-button resets count towards the 3x RESET erase.

  Data to the Pi (UDP port 5005):
    every ~0.5 s $ND,1,<seq>,VIB,<vel>,<vel x>,<vel y>,<vel z>,<acc rms>,<acc peak>,<freq>,<temp>,<zone>,
                    <running>,<tilt>,<rssi>,<flags>*<xor>
    every 5 s    $ST,1,<mac>,<state>,<ssid hex>,<ip>,<rssi>,<reason>,<pi ip>*<xor>   (and on every change)
    vel = vibration velocity RMS in mm/s (largest axis, ~10 Hz and up), acc in g (gravity removed),
    freq = dominant vibration frequency in Hz (0 when idle), temp = sensor chip temperature in C,
    zone 0-3 = ISO 10816-3 zone A-D, running 0/1 (>= RUN_MM_S with a clear spectral peak),
    tilt = degrees the mounting moved from its saved angle (saved the first time the node is online;
    a short press of BOOT saves the current angle again, e.g. after re-mounting the sensor),
    flags bit0 = MPU read failed (frames keep coming every 0.5 s, so the Pi sees a FAULT, not silence),
    bit1 = samples were lost (FIFO overflow), bit2 = held result: the MPU FIFO is re-syncing after an
    axis slip and this is the last good result again (sent so the Pi sees no gap).

  Wiring: MPU6050 and OLED share the I2C bus
    VCC -> 3V3,  GND -> GND,  SDA -> D4 (GPIO6),  SCL -> D5 (GPIO7),  MPU AD0 -> GND (0x68)
    Power from the XIAO's USB-C. Plug the small antenna into the U.FL socket.

  Arduino IDE: board "XIAO_ESP32C3", Tools > USB CDC On Boot > Enabled
  Libraries:   Adafruit SSD1306, Adafruit GFX
*/

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <Wire.h>
#include <Preferences.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Fonts/FreeSansBold9pt7b.h>
#include "esp_random.h"
#include "esp_system.h"
#include "esp_task_wdt.h"

// ======================= settings =======================
#define NODE_NAME   "NODE-1"
#define NODE_ID     1
#define FW_VERSION  "3.8"

// Shared key: must be the same 64 hex characters as PROV_KEY in node_dashboard.py.
// Make your own on the Pi with:  python3 node_dashboard.py --genkey   and paste it in both files.
#include "secrets.h"
static const char PROV_KEY_HEX[] = PROV_KEY_HEX_VALUE;

#define PI_PORT      5005     // monitoring dashboard on the Pi
#define CTRL_PORT    7000     // the Pi talks to the node here (setup hotspot and normal Wi-Fi)
#define RUN_MM_S     1.0f     // machine counts as running above this vibration velocity (mm/s RMS) ...
#define PEAK_PROMINENCE 6.0f  // ... AND with a clear spectral peak (peak / average of the band); an idle
                              // sensor only shows noise, which has no clear peak
// Severity zone limits in mm/s RMS (ISO 10816-3, group 2 = medium machines 15-300 kW, rigid mounting).
// Group 1 (large machines 300 kW-50 MW, rigid): 2.3 / 4.5 / 7.1.  Flexible mounting: 1.4 / 2.8 / 4.5 -> 2.3 / 4.5 / 7.1.
#define ZONE_AB      1.4f     // A good (new machine)      / B acceptable
#define ZONE_BC      2.8f     // B acceptable              / C alert: plan maintenance
#define ZONE_CD      4.5f     // C alert                   / D danger: damage likely
#define STATUS_MS    5000     // Wi-Fi status packet every 5 s

#define PIN_SDA      6        // D4
#define PIN_SCL      7        // D5
#define PIN_BOOT     9        // the XIAO's BOOT button (pressed = LOW)
#define OLED_ADDR    0x3C
#define MPU_ADDR     0x68

#define CONNECT_TIMEOUT_MS   20000
#define NONCE_TTL_MS         15000
#define AUTH_LOCKOUT_MS      3000
#define SETUP_AFTER_FAIL_MS  180000   // saved details failing this long -> reopen the setup hotspot
#define SETUP_WINDOW_MS      90000    // ... for this long, then try the saved details again
#define REASON_TIMEOUT       1000     // our own code for "no answer in time"
#define SETUP_CHANNEL        6        // Wi-Fi channel of the setup hotspot (1-13)
#define WIFI_TX_POWER        WIFI_POWER_8_5dBm   // lower TX power: fixes "authentication timed out" on many
                                                 // ESP32-C3 boards; raise (e.g. WIFI_POWER_15dBm) if range is poor
#define SAFE_TX_POWER WIFI_POWER_5dBm   // Wi-Fi power in SAFE MODE (less current: helps a weak supply)
#define SETUP_AP_OPEN        0        // 1 = setup hotspot without a Wi-Fi password (the details are still
                                      //     signed and the password encrypted with the shared key)
// =========================================================

Adafruit_SSD1306 oled(128, 64, &Wire, -1);
Preferences prefs;
WiFiUDP udp;
WiFiServer ctrl(CTRL_PORT);
WiFiClient client;

static const GFXfont *BIG = &FreeSansBold9pt7b;

enum NodeState { S_BOOT, S_SETUP, S_WIFI_ON, S_CONNECTING, S_CONNECTED, S_FAILED, S_LOST };
static NodeState state = S_BOOT;
static uint32_t stateSince = 0;

static char ssid[33] = "";
static char pass[65] = "";
static char hostStr[16] = "";
static IPAddress hostIp;
static bool haveCreds = false, credsVerified = false;
static char apSsid[24], apPass[17];

static uint16_t lastReason = 0;
static uint32_t retryAt = 0, retryDelay = 5000, failingSince = 0, setupUntil = 0, applyAt = 0;
static uint16_t attempt = 0, freshFails = 0;

static volatile bool evGotIp = false, evDisc = false;
static volatile int apStations = 0;             // devices joined to our setup hotspot
static volatile uint16_t evReason = 0;

enum Toast { T_NONE, T_VERIFIED, T_REJECTED, T_CLEARED, T_BADDATA, T_ZEROED };
static Toast toast = T_NONE;
static uint32_t toastUntil = 0;

static uint32_t lastQnx = 0;
static bool qnxSeen = false;

static uint8_t provKey[32];
static bool keyOk = false;
static uint8_t nonce[16];
static char nonceHex[33];
static bool nonceValid = false;
static uint32_t nonceAt = 0, lockoutUntil = 0;

static uint32_t lastDraw = 0, lastMpuTry = 0, lastStatusAt = 0, seq = 0, lastPacketAt = 0;
static uint32_t bootDownSince = 0;
static bool bootCountCleared = false;           // triple-reset detection
static char macStr[18];
static bool oledOk = false;

static esp_reset_reason_t resetWhy = ESP_RST_UNKNOWN;
static bool safeMode = false, stableCleared = false;
static int quickFails = 0;

static const char *resetName(esp_reset_reason_t r) {
  switch (r) {
    case ESP_RST_POWERON:   return "POWER ON";
    case ESP_RST_EXT:       return "RESET PIN";
    case ESP_RST_SW:        return "SOFTWARE";
    case ESP_RST_PANIC:     return "CRASH";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:       return "WATCHDOG";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_DEEPSLEEP: return "DEEP SLEEP";
    default:                return "OTHER";
  }
}

// ---------------------------------------------------------------- small helpers
static int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  c |= 0x20;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

// Decodes hlen hex characters into out. Returns the byte count, or -1 if bad.
static int hexDecode(const char *h, size_t hlen, uint8_t *out, size_t maxOut) {
  if (hlen % 2) return -1;
  size_t n = hlen / 2;
  if (n > maxOut) return -1;
  for (size_t i = 0; i < n; i++) {
    int hi = hexVal(h[2 * i]), lo = hexVal(h[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)(hi << 4 | lo);
  }
  return (int)n;
}

static void hexEncode(const uint8_t *in, size_t n, char *out) {
  static const char d[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = d[in[i] >> 4];
    out[2 * i + 1] = d[in[i] & 15];
  }
  out[2 * n] = 0;
}

// HMAC-SHA256, self-contained (no mbedtls): works on every esp32 Arduino core, including 4.x where
// mbedtls_md_hmac() no longer exists.
struct Sha256 {            // functions live inside the struct: the Arduino IDE's automatic
  uint32_t h[8];            // prototypes would otherwise be placed before this type exists
  uint8_t buf[64];
  uint64_t len;
  size_t n;

  static inline uint32_t ror(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }

  void block(const uint8_t *p) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t t1 = hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
      uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  void init() {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(h, iv, sizeof iv);
    len = 0;
    n = 0;
  }

  void update(const uint8_t *p, size_t count) {
    len += count;
    while (count--) {
      buf[n++] = *p++;
      if (n == 64) { block(buf); n = 0; }
    }
  }

  void final(uint8_t out[32]) {
    uint64_t bits = len * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    pad = 0;
    while (n != 56) update(&pad, 1);
    uint8_t l[8];
    for (int i = 0; i < 8; i++) l[i] = (uint8_t)(bits >> (56 - 8 * i));
    update(l, 8);
    for (int i = 0; i < 8; i++) {
      out[4 * i] = h[i] >> 24; out[4 * i + 1] = h[i] >> 16; out[4 * i + 2] = h[i] >> 8; out[4 * i + 3] = h[i];
    }
  }
};

static void hmac256(const uint8_t *msg, size_t n, uint8_t out[32]) {   // key = provKey (32 bytes)
  uint8_t pad[64], inner[32];
  Sha256 c;
  memset(pad, 0x36, 64);
  for (int i = 0; i < 32; i++) pad[i] ^= provKey[i];
  c.init(); c.update(pad, 64); c.update(msg, n); c.final(inner);
  memset(pad, 0x5c, 64);
  for (int i = 0; i < 32; i++) pad[i] ^= provKey[i];
  c.init(); c.update(pad, 64); c.update(inner, 32); c.final(out);
}

static bool sameBytes(const uint8_t *a, const uint8_t *b, size_t n) {   // constant time
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
  return d == 0;
}

// Password encryption: XOR with HMAC(key, "ENC" | nonce | block number)
static void keystreamXor(const uint8_t nonceBytes[16], uint8_t *data, size_t n) {
  uint8_t in[20], block[32];
  memcpy(in, "ENC", 3);
  memcpy(in + 3, nonceBytes, 16);
  for (size_t i = 0; i < n; i++) {
    if (i % 32 == 0) {
      in[19] = (uint8_t)(i / 32);
      hmac256(in, sizeof in, block);
    }
    data[i] ^= block[i % 32];
  }
  memset(block, 0, sizeof block);
}

static bool validPassword(const char *p, size_t n) {
  if (n == 0) return true;                       // open network
  if (n >= 8 && n <= 63) return true;            // WPA2 passphrase
  if (n == 64) {                                 // raw 64-hex-digit key
    for (size_t i = 0; i < n; i++) if (hexVal(p[i]) < 0) return false;
    return true;
  }
  return false;
}

static const char *stateName(NodeState s) {
  switch (s) {
    case S_BOOT:       return "BOOT";
    case S_SETUP:      return "SETUP";
    case S_WIFI_ON:    return "WIFI_ON";
    case S_CONNECTING: return "CONNECTING";
    case S_CONNECTED:  return "CONNECTED";
    case S_FAILED:     return "FAILED";
    case S_LOST:       return "LOST";
  }
  return "?";
}

static bool isWrongPassword(uint16_t r) { return r == 202 || r == 15 || r == 204 || r == 14 || r == 2; }
static bool isNoNetwork(uint16_t r)     { return r == 201 || (r >= 210 && r <= 212); }

static const char *reasonToken(uint16_t r) {
  static char buf[16];
  if (r == 0) return "none";
  if (r == REASON_TIMEOUT) return "timeout";
  if (r == 200) return "ap_lost";
  if (isWrongPassword(r)) return "wrong_password";
  if (isNoNetwork(r)) return "no_network";
  snprintf(buf, sizeof buf, "code_%u", r);
  return buf;
}

static const char *reasonText(uint16_t r) {
  static char buf[22];
  if (r == REASON_TIMEOUT) return "no answer (timeout)";
  if (r == 200) return "AP out of range";
  if (isWrongPassword(r)) return "wrong password?";
  if (isNoNetwork(r)) return "network not found";
  if (r == 0) return "";
  snprintf(buf, sizeof buf, "error code %u", r);
  return buf;
}

// ---------------------------------------------------------------- talking to the Pi
static void ctrlSend(const char *s) {            // reply on the open TCP connection, if any
  if (client && client.connected()) {
    client.print(s);
    client.print('\n');
  }
}

static uint8_t xorSum(const char *s, int n) {
  uint8_t x = 0;
  for (int i = 0; i < n; i++) x ^= (uint8_t)s[i];
  return x;
}

// <kind>,<id>,<mac>,<state>,<ssid hex>,<ip>,<rssi>,<reason>,<pi ip>
static int statusBody(char *out, size_t n, const char *kind) {
  char ssidHex[65], ip[16] = "0.0.0.0";
  hexEncode((const uint8_t *)ssid, strlen(ssid), ssidHex);
  int rssi = 0;
  if (state == S_CONNECTED) {
    IPAddress a = WiFi.localIP();
    snprintf(ip, sizeof ip, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    rssi = WiFi.RSSI();
  }
  return snprintf(out, n, "%s,%d,%s,%s,%s,%s,%d,%s,%s", kind, NODE_ID, macStr, stateName(state), ssidHex, ip,
                  rssi, reasonToken(lastReason), hostStr[0] ? hostStr : "-");
}

static void sendStatus(const char *kind) {
  char body[200], line[210];
  statusBody(body, sizeof body, kind);
  snprintf(line, sizeof line, "$%s", body);
  ctrlSend(line);
  if (state == S_CONNECTED && hostStr[0]) {         // also tell the dashboard over Wi-Fi
    int n = statusBody(body, sizeof body, "ST");
    int len = snprintf(line, sizeof line, "$%s*%02X", body, xorSum(body, n));
    udp.beginPacket(hostIp, PI_PORT);
    udp.write((const uint8_t *)line, len);
    udp.endPacket();
    lastStatusAt = millis();
  }
}

static void showToast(Toast t, uint32_t ms) {
  toast = t;
  toastUntil = millis() + ms;
}

static void setState(NodeState s) {
  state = s;
  stateSince = millis();
  Serial.printf("[node] state %s\n", stateName(s));
  sendStatus("EVT");
}

static void restartServer() {
  ctrl.stop();
  ctrl.begin();
  ctrl.setNoDelay(true);
}

// Opens the setup hotspot. window = 0: stay until new details arrive.
static void enterSetup(uint32_t window) {
  if (client) client.stop();
  if (WiFi.getMode() != WIFI_OFF) WiFi.disconnect();
  WiFi.mode(WIFI_AP);
  apStations = 0;
  WiFi.softAP(apSsid, SETUP_AP_OPEN ? nullptr : apPass, SETUP_CHANNEL, 0, 2);
  WiFi.setTxPower(WIFI_TX_POWER);
  restartServer();
  setupUntil = window ? millis() + window : 0;
  Serial.printf("[node] setup hotspot \"%s\" (%s) open at %u.%u.%u.%u:%d\n", apSsid,
                SETUP_AP_OPEN ? "no password" : "WPA2", WiFi.softAPIP()[0],
                WiFi.softAPIP()[1], WiFi.softAPIP()[2], WiFi.softAPIP()[3], CTRL_PORT);
  setState(S_SETUP);
}

static void startWifi() {
  attempt = 0;
  retryDelay = 5000;
  lastReason = 0;
  if (WiFi.getMode() & WIFI_AP) WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  restartServer();
  setState(S_WIFI_ON);
}

static void beginConnect() {
  attempt++;
  WiFi.begin(ssid, pass[0] ? pass : nullptr);
  WiFi.setTxPower(safeMode ? SAFE_TX_POWER : WIFI_TX_POWER);
  WiFi.setSleep(false);                            // no power-save: steadier 20 Hz data, faster replies
  setState(S_CONNECTING);
}

static void failWith(uint16_t r) {
  uint32_t now = millis();
  lastReason = r;
  if (!failingSince) failingSince = now;
  if (!credsVerified && ++freshFails >= 2) {        // new details that never worked: ask the Pi again
    Serial.println("[node] new Wi-Fi details failed twice - reopening the setup hotspot");
    enterSetup(0);
    return;
  }
  if (credsVerified && now - failingSince > SETUP_AFTER_FAIL_MS) {
    failingSince = now;
    enterSetup(SETUP_WINDOW_MS);
    return;
  }
  retryAt = now + retryDelay;
  retryDelay = min<uint32_t>(retryDelay * 2, 30000);
  setState(S_FAILED);
}

static void eraseCreds() {
  prefs.remove("ssid");
  prefs.remove("pass");
  prefs.remove("host");
  prefs.remove("ok");
  memset(pass, 0, sizeof pass);
  ssid[0] = hostStr[0] = 0;
  haveCreds = credsVerified = false;
  lastReason = 0;
  failingSince = 0;
}

static bool takeNonce(uint8_t out[16]) {     // the challenge can be used once
  bool ok = nonceValid && (millis() - nonceAt) <= NONCE_TTL_MS;
  if (ok) memcpy(out, nonce, 16);
  nonceValid = false;
  return ok;
}

static bool checkMac(const char *signedPart, size_t signedLen, const char *macHex) {
  uint8_t mac[32], want[32];
  if (strlen(macHex) != 64 || hexDecode(macHex, 64, mac, 32) != 32) return false;
  static char msg[400];
  if (signedLen + 32 >= sizeof msg) return false;
  memcpy(msg, signedPart, signedLen);
  memcpy(msg + signedLen, nonceHex, 32);
  hmac256((const uint8_t *)msg, signedLen + 32, want);
  return sameBytes(mac, want, 32);
}

static void rejectAuth() {
  lockoutUntil = millis() + AUTH_LOCKOUT_MS;
  showToast(T_REJECTED, 2500);
  Serial.println("[node] rejected a message with a bad signature");
  ctrlSend("$ERR,AUTH");
}

// "SET,<ssid hex>,<encrypted password hex>,<pi ip>,<mac hex>"
static void handleSet(char *p) {
  uint8_t n16[16];
  if (!takeNonce(n16)) { ctrlSend("$ERR,NONCE"); return; }
  char *macHex = strrchr(p, ',');
  if (!macHex) { ctrlSend("$ERR,FORMAT"); return; }
  macHex++;
  if (!checkMac(p, macHex - p, macHex)) { rejectAuth(); return; }

  char *f[4] = {nullptr, nullptr, nullptr, nullptr};      // signature is good: split the fields
  int count = 0;
  for (char *c = p; c < macHex && count < 4; ) {
    char *comma = strchr(c, ',');
    if (!comma || comma >= macHex) break;
    *comma = 0;
    f[count++] = c;
    c = comma + 1;
  }
  uint8_t newSsid[33], newPass[65];
  int ns = (count == 4) ? hexDecode(f[1], strlen(f[1]), newSsid, 32) : -1;
  int np = (count == 4) ? hexDecode(f[2], strlen(f[2]), newPass, 64) : -1;
  IPAddress newHost;
  bool ok = ns >= 1 && np >= 0 && newHost.fromString(f[3]) && memchr(newSsid, 0, ns) == nullptr;
  if (ok) {
    keystreamXor(n16, newPass, np);
    ok = memchr(newPass, 0, np) == nullptr && validPassword((const char *)newPass, np);
  }
  if (!ok) {
    memset(newPass, 0, sizeof newPass);
    showToast(T_BADDATA, 2500);
    ctrlSend("$ERR,BADDATA");
    return;
  }
  memcpy(ssid, newSsid, ns);  ssid[ns] = 0;
  memcpy(pass, newPass, np);  pass[np] = 0;
  memset(newPass, 0, sizeof newPass);
  strncpy(hostStr, f[3], sizeof hostStr - 1);
  hostStr[sizeof hostStr - 1] = 0;
  hostIp = newHost;
  prefs.putString("ssid", ssid);
  prefs.putString("pass", pass);
  prefs.putString("host", hostStr);
  prefs.putString("ok", "0");
  haveCreds = true;
  credsVerified = false;
  freshFails = 0;
  failingSince = 0;
  Serial.printf("[node] new Wi-Fi details from QNX: \"%s\", Pi at %s\n", ssid, hostStr);
  ctrlSend("$OK,SET");
  showToast(T_VERIFIED, 1800);
  applyAt = millis() + 3000;                       // switch networks once the Pi has the reply (it then
                                                   // closes the connection), or after 3 s at the latest
}

// "FORGET,<mac hex>"
static void handleForget(char *p) {
  uint8_t n16[16];
  if (!takeNonce(n16)) { ctrlSend("$ERR,NONCE"); return; }
  char *macHex = strrchr(p, ',');
  if (!checkMac(p, macHex + 1 - p, macHex + 1)) { rejectAuth(); return; }
  ctrlSend("$OK,FORGET");                          // answer first, then the slow flash erase
  eraseCreds();
  Serial.println("[node] Wi-Fi details erased by QNX");
  showToast(T_CLEARED, 2000);
  applyAt = millis() + 3000;                       // same: wait for the Pi to read the reply
}

static void handleLine(char *line) {
  char *p = strchr(line, '$');
  if (!p) return;
  p++;
  lastQnx = millis();
  qnxSeen = true;
  if (!strcmp(p, "STATUS")) {
    sendStatus("STATUS");
  } else if (!strcmp(p, "NONCE")) {
    if (!keyOk) { ctrlSend("$ERR,NOKEY"); return; }
    if ((int32_t)(millis() - lockoutUntil) < 0) { ctrlSend("$ERR,BUSY"); return; }
    esp_fill_random(nonce, sizeof nonce);
    uint32_t t = micros();
    for (int i = 0; i < 4; i++) nonce[12 + i] ^= (uint8_t)(t >> (8 * i));
    hexEncode(nonce, sizeof nonce, nonceHex);
    nonceValid = true;
    nonceAt = millis();
    char out[48];
    snprintf(out, sizeof out, "$NONCE,%s", nonceHex);
    ctrlSend(out);
  } else if (!strncmp(p, "SET,", 4)) {
    handleSet(p);
  } else if (!strncmp(p, "FORGET,", 7)) {
    handleForget(p);
  } else {
    ctrlSend("$ERR,UNKNOWN");
  }
}

static void pollCtrl() {
  static char buf[400];
  static size_t len = 0;
  static bool overflow = false;
  WiFiClient c = ctrl.available();
  if (c) {                                         // one Pi connection at a time; newest wins
    if (client) client.stop();
    client = c;
    client.setNoDelay(true);
    len = 0;
    overflow = false;
    lastQnx = millis();
    qnxSeen = true;
  }
  if (!client) return;
  while (client.available()) {
    int ch = client.read();
    if (ch == '\n' || ch == '\r') {
      if (len && !overflow) {
        buf[len] = 0;
        handleLine(buf);
      }
      len = 0;
      overflow = false;
    } else if (len < sizeof buf - 1) {
      buf[len++] = (char)ch;
    } else {
      overflow = true;
    }
  }
  if (!client.connected()) client.stop();
}

// ---------------------------------------------------------------- Wi-Fi
static void onWifiEvent(arduino_event_id_t event, arduino_event_info_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
    evGotIp = true;
  } else if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
    evReason = info.wifi_sta_disconnected.reason;
    evDisc = true;
  } else if (event == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
    apStations = apStations + 1;
    Serial.println("[node] a device joined the setup hotspot");
  } else if (event == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) {
    if (apStations > 0) apStations = apStations - 1;
    Serial.println("[node] a device left the setup hotspot");
  }
}

static void wifiTask() {
  uint32_t now = millis();
  bool piDone = !(client && client.connected()) && now - lastQnx > 300;
  if (applyAt && ((int32_t)(now - applyAt) >= 0 || piDone)) {   // after a SET or FORGET reply went out
    applyAt = 0;
    if (client) client.stop();
    if (haveCreds) startWifi();
    else enterSetup(0);
  }
  if (evGotIp) {
    evGotIp = false;
    if (state == S_CONNECTING || state == S_LOST) {
      lastReason = 0;
      retryDelay = 5000;
      failingSince = 0;
      if (!credsVerified) {
        credsVerified = true;
        prefs.putString("ok", "1");
      }
      setState(S_CONNECTED);
    }
  }
  if (evDisc) {
    evDisc = false;
    uint16_t r = evReason;
    if (r != 8) {                                   // 8 = we left on purpose
      if (state == S_CONNECTED) {
        lastReason = r;
        retryAt = now + 1000;
        if (!failingSince) failingSince = now;
        setState(S_LOST);
      } else if (state == S_CONNECTING) {
        failWith(r);
      }
    }
  }
  switch (state) {
    case S_SETUP:
      if (setupUntil && (int32_t)(now - setupUntil) >= 0 && haveCreds && !(client && client.connected())) {
        startWifi();                               // setup window over: try the saved details again
      }
      break;
    case S_WIFI_ON:
      if (now - stateSince >= 900) beginConnect();
      break;
    case S_CONNECTING:
      if (now - stateSince >= CONNECT_TIMEOUT_MS) {
        WiFi.disconnect();
        failWith(REASON_TIMEOUT);
      }
      break;
    case S_FAILED:
    case S_LOST:
      if ((int32_t)(now - retryAt) >= 0) beginConnect();
      break;
    default:
      break;
  }
}

static void zeroMount();

// BOOT button: short press (< 1 s) = take the current mounting angle as normal; hold 3 s = erase Wi-Fi details
static void bootButton() {
  static bool heldDone = false;
  if (digitalRead(PIN_BOOT) == LOW) {
    if (!bootDownSince) bootDownSince = millis() | 1;
    if (!heldDone && millis() - bootDownSince > 3000) {
      heldDone = true;
      eraseCreds();
      Serial.println("[node] BOOT held: Wi-Fi details erased");
      showToast(T_CLEARED, 2000);
      enterSetup(0);
    }
  } else {
    if (bootDownSince && !heldDone) {
      uint32_t held = millis() - bootDownSince;
      if (held >= 50 && held < 1000) zeroMount();
    }
    bootDownSince = 0;
    heldDone = false;
  }
}

// ---------------------------------------------------------------- MPU6050 vibration analysis
// Industrial machine-vibration monitoring. The MPU6050 samples acceleration at 1 kHz into its own FIFO,
// so no sample is lost while the node is busy with Wi-Fi or the OLED. Every 512 samples (~0.5 s):
//   - vibration velocity RMS per axis in mm/s, band ~10 Hz and up (the measure ISO 10816-3 / 20816 use)
//   - acceleration RMS and peak in g with gravity removed, crest factor = peak / RMS
//   - dominant vibration frequency from a 1024-point FFT (= running speed if it is the 1x peak)
//   - severity zone A/B/C/D from the velocity, running/idle, and how far the sensor's mounting
//     has tilted since start-up (a loose or moved sensor)
// Note: the MPU6050 is a hobby-grade sensor (noise floor about 0.2 mm/s, usable up to ~180 Hz). It is
// fine for demos and trends; a certified industrial accelerometer is needed for formal ISO assessments.
#define FS_HZ        1000        // sample rate
#define HOP          512         // new result every 512 samples
#define NFFT         1024        // FFT length (~1 Hz resolution)
#define ACC_LSB      4096.0f     // +-8 g range
#define HP_HZ        10.0f       // 2-pole Butterworth high-pass on the acceleration: the ISO band starts at 10 Hz
#define VEL_HP_COEF  0.9876f     // 1st-order 2 Hz high-pass after integrating (removes drift only)
#define FREQ_MIN_HZ  5.0f        // dominant-frequency search band
#define FREQ_MAX_HZ  250.0f
#define STILL_G      0.5f        // below this acceleration RMS the sensor is at rest (gravity check is valid)
#define SLIP_COS     0.866f      // cos 30 deg: at rest the gravity direction cannot turn more in 0.5 s
// Clean output (firmware 3.3):
#define GLITCH_G     1.0f        // a single sample this far (g) from BOTH neighbours, which agree with each
                                 // other, is an I2C read glitch, not vibration: it is replaced by their average
#define MEDIAN_OF_3  1           // 1 = each reported value is the median of the last 3 results (~1.5 s):
                                 //     a one-off spike is removed, a real change shows after one extra result
#define NOISE_AUTO   1           // 1 = learn the sensor's own noise floor while idle and subtract it, so a
                                 //     still sensor reads ~0.00 mm/s instead of 0.2-0.7 mm/s of noise
#define NOISE_START_MM_S 0.15f   // starting noise floor per axis (mm/s RMS)
#define NOISE_MAX_MM_S   0.5f    // the learned floor never goes above this (protects real low vibration)
// Data integrity (firmware 3.4):
#define FRAME_CHECK  0           // 1 = FIFO frames carry the temperature word as an alignment check (3.4-3.6)
#define FRAME_BYTES  (FRAME_CHECK ? 8 : 6)   // FIFO frame: accel x/y/z [+ temperature]
#define GRAV_MIN     0.7f        // the half-second mean must be ~1 g (gravity); outside this = corrupt data
#define GRAV_MAX     1.3f
#define WDT_MS       8000        // watchdog: a loop stuck this long restarts the node (Wi-Fi details kept)
#define SAFE_AFTER   3           // this many crash / brownout / watchdog resets in a row -> SAFE MODE
#define STABLE_MS    60000       // running this long clears the crash counter
#define TEMP_TOL     300         // temperature word in each FIFO frame vs its running average (raw, 340 = 1 C)
#define PROBE_FRAMES 8           // after every FIFO start: frames used to find which word holds the temperature
#define PROBE_SPREAD 300         // the temperature word barely changes over 8 ms (raw units)
#define PROBE_NEAR   400         // ... and is near the temperature register (raw, ~1.2 C)
#define PROBE_GIVEUP 20          // this many failed searches in a row -> run without the frame check
#define BIG_G        2.0f        // a half second with more than BIG_FRAC of samples above this is corrupt:
#define BIG_FRAC     0.05f       //   real machine vibration of 2 g sustained would be > 40 mm/s
#define HOLD_MAX_MS  10000       // re-syncing longer than this without a good result -> reported as FAULT
#define I2C_HZ       400000
#define I2C_TIMEOUT_MS 10        // a failing I2C transfer gives up after 10 ms (the default 50 ms stalls the loop)
#define OLED_MS      200         // OLED refresh: 5 per second keeps the shared I2C bus free for the MPU
#define DIAG_MS      5000        // "[diag]" line on the serial monitor every 5 s

static bool mpuOk = false, vibReady = false;
static float bqB0, bqB1, bqB2, bqA1, bqA2;                     // high-pass biquad coefficients
static float bx1[3], bx2[3], by1[3], by2[3];                   // per-axis biquad state
static float hpA[3], vInt[3], vPrev[3], hpV[3];                // per-axis filter state
static double sumA2[3], sumV2[3], sumRaw[3];
static float peakMag2 = 0;
static float ringA[3][NFFT];                                   // last 1024 high-passed samples per axis
static int ringPos = 0, hopCount = 0, warmHops = 0;
static float fre[NFFT], fim[NFFT], twc[NFFT / 2], tws[NFFT / 2];
static bool fftReady = false;
static float baseG[3];
static bool baseSet = false;            // mounting reference (gravity direction), kept in flash
static uint32_t lastAnalyseAt = 0, udpSent = 0, udpFailed = 0;
static float peakProminence = 0, gravNow[3] = {0, 0, 0};

static uint16_t fifoOverflows = 0;
static bool overflowThisHop = false, lostRecently = false;
static float prevGrav[3] = {0, 0, 0};          // gravity direction of the last result at rest (axis-slip check)
static bool haveGrav = false, justResynced = false;
static uint8_t holdHops = 0;                   // held results still to send while re-syncing
static uint16_t fifoSlips = 0;
static float glPrev[3], glCur[3];               // glitch filter: previous and pending sample (g)
static uint8_t glHave = 0;
static uint32_t glitches = 0;
static float hVel[3][3], hAcc[3], hPeak[3];     // last 3 results for the median
static uint8_t hCount = 0, hPos = 0;
static float noiseFloor[3] = {NOISE_START_MM_S, NOISE_START_MM_S, NOISE_START_MM_S};
static int16_t tempRef = 0;                     // temperature register (raw), the FIFO frame check
static bool resyncNow = false;                  // set while processing: stop reading the old FIFO stream
static uint32_t misaligned = 0, corruptHops = 0, busRecoveries = 0, lastGoodAt = 0;
static uint16_t bigCount = 0;
static uint32_t i2cErrors = 0, goodResults = 0;
static uint8_t lastFrame[8];                    // last frame that passed the check (for the diagnostic dump)
static int8_t tSlot = -1;                       // which 16-bit word of the frame holds the temperature (found)
static uint8_t probeN = 0, probeFails = 0;
static int16_t probeW[PROBE_FRAMES][4];
static float tMean = 0;
static bool frameCheck = true, layoutLogged = false;

// results (sent to the Pi and shown on the OLED)
static float velRms = 0, velAxis[3] = {0, 0, 0}, accRms = 0, accPeak = 0, domFreq = 0, tempC = 0, tiltDelta = 0;
static int zone = 0;
static bool running = false;

static bool mpuWrite(uint8_t reg, uint8_t val) {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(reg);
  Wire.write(val);
  if (Wire.endTransmission() == 0) return true;
  i2cErrors++;
  return false;
}

static bool mpuRead(uint8_t reg, uint8_t *buf, uint8_t len) {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) { i2cErrors++; return false; }
  if (Wire.requestFrom((uint8_t)MPU_ADDR, len) != len) { i2cErrors++; return false; }
  for (uint8_t i = 0; i < len; i++) buf[i] = Wire.read();
  return true;
}

#define SWQ_BYTES 2400                   // 400 samples = 0.4 s (a multiple of 6 and 8)
static uint8_t swq[SWQ_BYTES];
static int swqHead = 0, swqLen = 0;
static uint32_t swqFull = 0;

static bool readTempRef() {
  uint8_t t[2];
  if (!mpuRead(0x41, t, 2)) return false;
  tempRef = (int16_t)(t[0] << 8 | t[1]);
  return true;
}

static void fifoRestart() {
  mpuWrite(0x6A, 0x04);                  // FIFO reset
  delay(1);
  mpuWrite(0x23, FRAME_CHECK ? 0x88 : 0x08);   // FIFO gets accel [+ temperature]
  uint8_t st;
  mpuRead(0x3A, &st, 1);                 // clear a pending overflow flag
  readTempRef();
  mpuWrite(0x6A, 0x40);                  // FIFO on
  resyncNow = true;                      // any bytes already fetched belong to the old stream
  swqHead = swqLen = 0;
  probeN = 0;                            // find the temperature word again in the new stream
}

// Software FIFO: the MPU FIFO is emptied into this RAM buffer as often as possible (also in the middle of
// the FFT), so even a 512-byte MPU FIFO (85 ms) never overflows. Samples are processed from here.

static void fifoDrain() {
  if (!mpuOk) return;
  uint8_t c[2], c2[2], st = 0;
  if (!mpuRead(0x3A, &st, 1) || !mpuRead(0x72, c, 2) || !mpuRead(0x72, c2, 2)) {
    mpuOk = false; vibReady = false; return;
  }
  int n = min(c[0] << 8 | c[1], c2[0] << 8 | c2[1]);   // smaller of two reads: always safe to read
  if ((st & 0x10) || n >= 1016) {                 // FIFO overflowed: samples were lost, start over cleanly
    fifoOverflows++;
    overflowThisHop = true;
    if (fifoOverflows <= 5 || fifoOverflows % 20 == 0)
      Serial.printf("[node] MPU FIFO overflow #%u (samples lost)\n", fifoOverflows);
    fifoRestart();
    return;
  }
  n -= n % FRAME_BYTES;
  int room = SWQ_BYTES - swqLen;
  room -= room % FRAME_BYTES;
  if (n > room) { n = room; swqFull++; }          // RAM buffer full: leave the rest in the MPU FIFO
  static uint8_t buf[120];                        // 15-20 samples per I2C read
  while (n > 0) {
    int chunk = n > (int)sizeof buf ? (int)sizeof buf : n;
    if (!mpuRead(0x74, buf, chunk)) {             // a failed read may have consumed part of a frame:
      fifoRestart();                              // never continue in the middle of the stream
      mpuOk = false; vibReady = false; return;
    }
    for (int i = 0; i < chunk; i++) swq[(swqHead + swqLen + i) % SWQ_BYTES] = buf[i];
    swqLen += chunk;
    n -= chunk;
  }
}

// I2C bus recovery: a device stuck in the middle of a byte holds SDA low; 9 clock pulses free it.
static void i2cRecover() {
  Wire.end();
  pinMode(PIN_SDA, INPUT_PULLUP);
  pinMode(PIN_SCL, OUTPUT);
  for (int i = 0; i < 9 && digitalRead(PIN_SDA) == LOW; i++) {
    digitalWrite(PIN_SCL, LOW);  delayMicroseconds(5);
    digitalWrite(PIN_SCL, HIGH); delayMicroseconds(5);
  }
  pinMode(PIN_SDA, OUTPUT);              // STOP: SDA low -> high while SCL is high
  digitalWrite(PIN_SDA, LOW);  delayMicroseconds(5);
  digitalWrite(PIN_SCL, HIGH); delayMicroseconds(5);
  digitalWrite(PIN_SDA, HIGH); delayMicroseconds(5);
  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.setClock(I2C_HZ);
  Wire.setTimeOut(I2C_TIMEOUT_MS);
  busRecoveries++;
}

// Raw register access, so it also works with MPU6500 / clone chips
// Clears all filter state. The filters then settle for 4 results (~2 s) before results count again.
static void resetFilters() {
  for (int i = 0; i < 3; i++) {
    bx1[i] = bx2[i] = by1[i] = by2[i] = hpA[i] = vInt[i] = vPrev[i] = hpV[i] = 0;
    sumA2[i] = sumV2[i] = sumRaw[i] = 0;
  }
  lastAnalyseAt = millis();
  peakMag2 = 0;
  hopCount = 0;
  warmHops = 0;
  glHave = 0;
  hCount = hPos = 0;
  bigCount = 0;
}

static bool mpuInit() {
  uint8_t id = 0;
  if (!mpuRead(0x75, &id, 1)) {
    i2cRecover();                        // free a stuck bus, then try once more
    if (!mpuRead(0x75, &id, 1)) return false;
    Serial.println("[node] I2C bus recovered");
  }
  Serial.printf("[node] MPU WHO_AM_I = 0x%02X\n", id);
  mpuWrite(0x6B, 0x80);                  // reset
  delay(100);
  bool ok = mpuWrite(0x6B, 0x01);        // wake up, gyro clock
  ok &= mpuWrite(0x19, 0x00);            // sample rate = 1 kHz / (1 + 0)
  ok &= mpuWrite(0x1A, 0x01);            // low-pass ~184 Hz (keeps the 1 kHz rate)
  ok &= mpuWrite(0x1B, 0x08);            // gyro +-500 deg/s (not used for vibration)
  ok &= mpuWrite(0x1C, 0x10);            // accel +-8 g: headroom for shocks
  ok &= mpuWrite(0x38, 0x10);            // FIFO overflow flag on (INT pin not used)
  delay(50);
  fifoRestart();
  // RBJ biquad high-pass, Q = 0.7071 (Butterworth)
  float w0 = 2.0f * (float)M_PI * HP_HZ / FS_HZ, cw = cosf(w0), al = sinf(w0) / (2.0f * 0.70710678f), a0 = 1 + al;
  bqB0 = (1 + cw) / 2 / a0; bqB1 = -(1 + cw) / a0; bqB2 = bqB0; bqA1 = -2 * cw / a0; bqA2 = (1 - al) / a0;
  resetFilters();
  return ok;
}

static void fftSetup() {
  for (int i = 0; i < NFFT / 2; i++) {
    twc[i] = cosf(2.0f * (float)M_PI * i / NFFT);
    tws[i] = -sinf(2.0f * (float)M_PI * i / NFFT);
  }
  fftReady = true;
}

// Dominant frequency of one axis (Hann window, radix-2 FFT, parabolic peak interpolation)
static float dominantFreq(int axis) {
  if (!fftReady) fftSetup();
  for (int i = 0; i < NFFT; i++) {
    int src = (ringPos + i) % NFFT;                                         // oldest sample first
    float hann = 0.5f - 0.5f * (i < NFFT / 2 ? twc[i] : -twc[i - NFFT / 2]);  // Hann window from the table
    fre[i] = ringA[axis][src] * hann;
    fim[i] = 0;
  }
  for (int i = 1, j = 0; i < NFFT; i++) {                                   // bit reversal
    int bit = NFFT >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) { float t = fre[i]; fre[i] = fre[j]; fre[j] = t; }
  }
  for (int len = 2; len <= NFFT; len <<= 1) {
    fifoDrain();                                   // keep the MPU FIFO empty during the FFT (~10 ms/stage)
    int step = NFFT / len;
    for (int i = 0; i < NFFT; i += len) {
      for (int k = 0; k < len / 2; k++) {
        float c = twc[k * step], s = tws[k * step];
        int a = i + k, b = i + k + len / 2;
        float tr = fre[b] * c - fim[b] * s, ti = fre[b] * s + fim[b] * c;
        fre[b] = fre[a] - tr; fim[b] = fim[a] - ti;
        fre[a] += tr;         fim[a] += ti;
      }
    }
  }
  int k0 = (int)(FREQ_MIN_HZ * NFFT / FS_HZ), k1 = (int)(FREQ_MAX_HZ * NFFT / FS_HZ), best = k0;
  float bestM = -1, sumMag = 0;
  for (int k = k0; k <= k1; k++) {
    float m = fre[k] * fre[k] + fim[k] * fim[k];
    sumMag += sqrtf(m);
    if (m > bestM) { bestM = m; best = k; }
  }
  float avgMag = sumMag / (k1 - k0 + 1);
  peakProminence = avgMag > 0 ? sqrtf(bestM) / avgMag : 0;
  float l = sqrtf(fre[best - 1] * fre[best - 1] + fim[best - 1] * fim[best - 1]);
  float c = sqrtf(bestM);
  float r = sqrtf(fre[best + 1] * fre[best + 1] + fim[best + 1] * fim[best + 1]);
  float d = (l - 2 * c + r) != 0 ? 0.5f * (l - r) / (l - 2 * c + r) : 0;
  return (best + d) * FS_HZ / NFFT;
}

// Takes the current gravity direction as the normal mounting angle and keeps it in flash.
static void zeroMount() {
  float n = sqrtf(gravNow[0] * gravNow[0] + gravNow[1] * gravNow[1] + gravNow[2] * gravNow[2]);
  if (n < 0.5f) return;                              // no sensor data yet
  for (int i = 0; i < 3; i++) baseG[i] = gravNow[i] / n;
  baseSet = true;
  tiltDelta = 0;
  prefs.putFloat("bx", baseG[0]);
  prefs.putFloat("by", baseG[1]);
  prefs.putFloat("bz", baseG[2]);
  Serial.printf("[node] mounting angle zeroed (gravity %.2f %.2f %.2f)\n", baseG[0], baseG[1], baseG[2]);
  showToast(T_ZEROED, 1500);
}

static void sendPacket(bool held = false);

static float median3(float a, float b, float c) {
  if (a > b) { float t = a; a = b; b = t; }
  if (b > c) { float t = b; b = c; c = t; }
  return a > b ? a : b;
}

static void analyse() {
  float vr[3], ar2 = 0, mean[3];
  for (int i = 0; i < 3; i++) {
    vr[i] = sqrt(sumV2[i] / HOP) * 1000.0;         // m/s -> mm/s
    ar2 += sumA2[i] / HOP;
    mean[i] = sumRaw[i] / HOP;
    sumA2[i] = sumV2[i] = sumRaw[i] = 0;
  }
  float peak = sqrtf(peakMag2);
  peakMag2 = 0;
  uint16_t big = bigCount;
  bigCount = 0;
  lostRecently = overflowThisHop;
  overflowThisHop = false;
  lastAnalyseAt = millis();
  if (warmHops < 4) {                                // filters still settling
    warmHops++;
    if (holdHops) {                                  // re-syncing after an axis slip: repeat the last good
      holdHops--;                                    // result, marked held (flags bit2), so the Pi sees no gap
      sendPacket(true);
    }
    return;
  }
  float gm = sqrtf(mean[0] * mean[0] + mean[1] * mean[1] + mean[2] * mean[2]);
  if (big > BIG_FRAC * HOP || gm < GRAV_MIN || gm > GRAV_MAX) {   // corrupt half second: impossible vibration,
    corruptHops++;                                   // or the average is not gravity (shifted FIFO bytes)
    if (corruptHops <= 5 || corruptHops % 20 == 0)
      Serial.printf("[node] corrupt data rejected (#%lu: %u samples above %.0f g, mean %.2f g) - re-syncing\n",
                    (unsigned long)corruptHops, big, BIG_G, gm);
    fifoRestart();
    resetFilters();
    holdHops = 4;
    if (millis() - lastPacketAt >= 400) sendPacket(true);
    return;
  }
  // gravity direction of this half second (the mean of the raw samples)
  float g = sqrtf(mean[0] * mean[0] + mean[1] * mean[1] + mean[2] * mean[2]);
  float gl[3];
  for (int i = 0; i < 3; i++) gl[i] = g > 0.5f ? mean[i] / g : 0;
  float rms = sqrtf(ar2);
  // MPU FIFO axis slip: if the FIFO read ever loses 2 bytes, x/y/z rotate. At rest the gravity direction
  // then jumps ~90 deg in one result and the 10 Hz high-pass turns the 1 g step into a fake ~15 mm/s
  // zone D value. A sensor at rest cannot turn 30 deg in 0.5 s, so re-sync the FIFO and the filters
  // instead of sending that result. A second jump right after a re-sync is accepted (a real move).
  if (g > 0.5f && rms < STILL_G && haveGrav && !justResynced) {
    float dot = gl[0] * prevGrav[0] + gl[1] * prevGrav[1] + gl[2] * prevGrav[2];
    if (dot < SLIP_COS) {
      fifoSlips++;
      Serial.printf("[node] MPU FIFO axis slip #%u (gravity moved %.0f deg at rest) - re-syncing\n",
                    fifoSlips, acosf(dot < -1 ? -1 : dot) * 57.2958f);
      fifoRestart();
      resetFilters();
      holdHops = 4;
      justResynced = true;
      sendPacket(true);                              // the last good result, marked held
      return;
    }
  }
  justResynced = false;
  if (g > 0.5f && rms < STILL_G) {                   // reference for the next check: only at rest
    memcpy(prevGrav, gl, sizeof prevGrav);
    haveGrav = true;
  }
  int k = 0;
  for (int i = 1; i < 3; i++) if (vr[i] > vr[k]) k = i;
  float f = dominantFreq(k);                         // also measures how clear the peak is (uses this result)
  // Clean output: median of the last 3 results, then the sensor's own noise floor removed.
  for (int i = 0; i < 3; i++) hVel[i][hPos] = vr[i];
  hAcc[hPos] = rms;
  hPeak[hPos] = peak;
  hPos = (hPos + 1) % 3;
  if (hCount < 3) hCount++;
  float mv[3], macc = rms, mpeak = peak;
  for (int i = 0; i < 3; i++) mv[i] = vr[i];
  if (MEDIAN_OF_3 && hCount == 3) {
    for (int i = 0; i < 3; i++) mv[i] = median3(hVel[i][0], hVel[i][1], hVel[i][2]);
    macc = median3(hAcc[0], hAcc[1], hAcc[2]);
    mpeak = median3(hPeak[0], hPeak[1], hPeak[2]);
  }
  bool idleNow = !(mv[k] >= RUN_MM_S && peakProminence >= PEAK_PROMINENCE);
  for (int i = 0; i < 3; i++) {
    if (NOISE_AUTO && idleNow && mv[i] < NOISE_MAX_MM_S * 2) {   // learn slowly while idle (~25 s)
      noiseFloor[i] = 0.98f * noiseFloor[i] + 0.02f * mv[i];
      if (noiseFloor[i] > NOISE_MAX_MM_S) noiseFloor[i] = NOISE_MAX_MM_S;
    }
    float nf = NOISE_AUTO ? noiseFloor[i] : 0;
    float v2 = mv[i] * mv[i] - nf * nf;              // noise adds in power, so subtract it that way
    velAxis[i] = v2 > 0 ? sqrtf(v2) : 0;
  }
  k = 0;
  for (int i = 1; i < 3; i++) if (velAxis[i] > velAxis[k]) k = i;
  velRms = velAxis[k];                               // ISO: the largest direction counts
  accRms = macc;
  accPeak = mpeak < macc ? macc : mpeak;
  running = velRms >= RUN_MM_S && peakProminence >= PEAK_PROMINENCE;
  domFreq = running ? f : 0;
  float vRounded = roundf(velRms * 100) / 100;       // zone from the value as sent, so the Pi's check agrees
  zone = vRounded < ZONE_AB ? 0 : vRounded < ZONE_BC ? 1 : vRounded < ZONE_CD ? 2 : 3;
  for (int i = 0; i < 3; i++) gravNow[i] = gl[i];
  if (g > 0.5f && !baseSet && state == S_CONNECTED) {   // first time installed and online: this is "normal"
    zeroMount();
  }
  if (g > 0.5f && baseSet) {                         // gravity direction vs the saved mounting angle
    float dot = gravNow[0] * baseG[0] + gravNow[1] * baseG[1] + gravNow[2] * baseG[2];
    tiltDelta = acosf(dot > 1 ? 1 : dot < -1 ? -1 : dot) * 57.2958f;
  } else {
    tiltDelta = 0;
  }
  uint8_t t[2];
  if (mpuRead(0x41, t, 2)) {
    tempRef = (int16_t)(t[0] << 8 | t[1]);           // keeps the FIFO frame check current
    tempC = tempRef / 340.0f + 36.53f;
  }
  vibReady = true;
  lastGoodAt = millis();
  goodResults++;
  static uint32_t lastLog = 0;
  if (millis() - lastLog > 5000) {
    lastLog = millis();
    Serial.printf("[node] vibration %.2f mm/s (zone %c, %s)  x %.2f y %.2f z %.2f  a %.3f g rms, %.3f g peak, "
                  "%.1f Hz (peak %.1fx), mount %.1f deg%s, FIFO slips %u, glitches %lu, noise %.2f/%.2f/%.2f, "
                  "misaligned %lu, corrupt %lu, overflows %u, bus recoveries %lu\n",
                  velRms, 'A' + zone, running ? "running" : "idle", velAxis[0], velAxis[1], velAxis[2], accRms,
                  accPeak, f, peakProminence, tiltDelta, lostRecently ? "  (samples lost)" : "", fifoSlips,
                  (unsigned long)glitches, noiseFloor[0], noiseFloor[1], noiseFloor[2], (unsigned long)misaligned,
                  (unsigned long)corruptHops, fifoOverflows, (unsigned long)busRecoveries);
    if (state == S_CONNECTED)
      Serial.printf("[node] to Pi %s:%d  sent %lu, failed %lu, Wi-Fi %d dBm\n", hostStr, PI_PORT,
                    (unsigned long)udpSent, (unsigned long)udpFailed, (int)WiFi.RSSI());
  }
  sendPacket();
}

static void processClean(const float *gs) {
  const float dt = 1.0f / FS_HZ;
  float mag2 = 0;
  for (int i = 0; i < 3; i++) {
    float g = gs[i];
    sumRaw[i] += g;
    float y = bqB0 * g + bqB1 * bx1[i] + bqB2 * bx2[i] - bqA1 * by1[i] - bqA2 * by2[i];   // 10 Hz high-pass
    bx2[i] = bx1[i]; bx1[i] = g; by2[i] = by1[i]; by1[i] = y;
    hpA[i] = y;                                      // gravity, drift and low-frequency noise removed
    vInt[i] = 0.999f * vInt[i] + hpA[i] * 9.80665f * dt;   // leaky integral -> velocity in m/s
    hpV[i] = VEL_HP_COEF * (hpV[i] + vInt[i] - vPrev[i]);
    vPrev[i] = vInt[i];
    sumA2[i] += hpA[i] * hpA[i];
    sumV2[i] += hpV[i] * hpV[i];
    ringA[i][ringPos] = hpA[i];
    mag2 += hpA[i] * hpA[i];
  }
  if (mag2 > peakMag2) peakMag2 = mag2;
  if (fabsf(gs[0]) > BIG_G || fabsf(gs[1]) > BIG_G || fabsf(gs[2]) > BIG_G) bigCount++;
  ringPos = (ringPos + 1) % NFFT;
  if (++hopCount >= HOP) {
    hopCount = 0;
    analyse();
  }
}

// Glitch filter, one sample behind: a sample that jumps more than GLITCH_G away from both its neighbours
// (while the two neighbours agree) or that is at the +-8 g limit with normal neighbours is a bad read.
// It is replaced by the average of its neighbours. Real vibration changes smoothly at 1 kHz sampling.
// Finds which of the 4 words of the first frames is the temperature: nearly constant and close to the
// temperature register. The 3 words after it (wrapping round) are accel x, y, z. Datasheet order is
// x, y, z, temp, but this works for any rotation of it (other chip variants, or a stream that starts shifted).
static bool probeLayout() {
  int best = -1;
  long bestScore = 0;
  for (int k = 0; k < 4; k++) {
    long mn = 99999, mx = -99999, sum = 0;
    for (int f = 0; f < PROBE_FRAMES; f++) {
      long v = probeW[f][k];
      if (v < mn) mn = v;
      if (v > mx) mx = v;
      sum += v;
    }
    long mean = sum / PROBE_FRAMES, spread = mx - mn, near = labs(mean - tempRef);
    if (spread > PROBE_SPREAD || near > PROBE_NEAR) continue;
    long score = near + 2 * spread;
    if (best < 0 || score < bestScore) { best = k; bestScore = score; tMean = mean; }
  }
  if (!layoutLogged || best != tSlot) {
    Serial.printf("[diag] FIFO frames:");
    for (int f = 0; f < 3; f++)
      Serial.printf("  [%d %d %d %d]", probeW[f][0], probeW[f][1], probeW[f][2], probeW[f][3]);
    Serial.printf("  temp register %d -> temperature in word %d%s\n", tempRef, best,
                  best < 0 ? " (NOT FOUND)" : best == 3 ? " (datasheet order)" : " (rotated order)");
    layoutLogged = true;
  }
  tSlot = best;
  return best >= 0;
}

static void processSample(const uint8_t *b) {
  int16_t w[4] = {0, 0, 0, 0};
  for (int k = 0; k < FRAME_BYTES / 2; k++) w[k] = (int16_t)(b[2 * k] << 8 | b[2 * k + 1]);
  if (!FRAME_CHECK) { frameCheck = false; tSlot = 3; }   // accel-only frames: words 0-2 = x, y, z
  if (frameCheck && probeN < PROBE_FRAMES) {      // first frames after a FIFO start: find the layout
    memcpy(probeW[probeN++], w, sizeof w);
    if (probeN < PROBE_FRAMES) return;
    if (probeLayout()) {
      probeFails = 0;
      return;
    }
    misaligned++;
    if (++probeFails >= PROBE_GIVEUP) {            // never found: keep measuring without the check
      frameCheck = false;
      tSlot = 3;
      Serial.println("[node] FIFO temperature word not found - running WITHOUT the frame check "
                     "(corrupt-data check still on). Please send this log.");
      return;
    }
    fifoRestart();
    resetFilters();
    holdHops = 4;
    if (millis() - lastPacketAt >= 400) sendPacket(true);
    return;
  }
  if (tSlot < 0) tSlot = 3;
  int16_t tw = w[tSlot];                          // temperature word of this frame
  if (frameCheck && abs(tw - (int)tMean) > TEMP_TOL) {   // not where it belongs: the stream lost a byte
    misaligned++;
    if (misaligned <= 5 || misaligned % 50 == 0) {
      Serial.printf("[node] MPU FIFO misaligned (#%lu, temp word %d vs %d) - re-syncing\n",
                    (unsigned long)misaligned, tw, (int)tMean);
      if (misaligned <= 3) {                       // raw words: shows how the stream was shifted
        Serial.printf("[diag] last good frame %6d %6d %6d %6d | bad frame %6d %6d %6d %6d\n",
                      (int16_t)(lastFrame[0] << 8 | lastFrame[1]), (int16_t)(lastFrame[2] << 8 | lastFrame[3]),
                      (int16_t)(lastFrame[4] << 8 | lastFrame[5]), (int16_t)(lastFrame[6] << 8 | lastFrame[7]),
                      (int16_t)(b[0] << 8 | b[1]), (int16_t)(b[2] << 8 | b[3]), (int16_t)(b[4] << 8 | b[5]),
                      (int16_t)(b[6] << 8 | b[7]));
      }
    }
    fifoRestart();
    resetFilters();
    holdHops = 4;
    if (millis() - lastPacketAt >= 400) sendPacket(true);   // the last good result, marked held
    return;
  }
  memcpy(lastFrame, b, FRAME_BYTES);
  tMean += 0.01f * (tw - tMean);                   // follows slow temperature changes
  float g[3];
  bool sat[3];
  for (int i = 0; i < 3; i++) {
    int16_t r = w[(tSlot + 1 + i) % 4];            // accel x, y, z follow the temperature word
    g[i] = r / ACC_LSB;
    sat[i] = r >= 32760 || r <= -32760;
  }
  if (glHave < 2) {                                // fill the window first
    memcpy(glHave ? glCur : glPrev, g, sizeof g);
    if (glHave == 1) processClean(glPrev);
    glHave++;
    return;
  }
  float out[3];
  bool fixed = false;
  for (int i = 0; i < 3; i++) {
    float c = glCur[i], p = glPrev[i], n = g[i];
    bool spike = fabsf(p - n) < GLITCH_G * 0.5f &&
                 ((c - p > GLITCH_G && c - n > GLITCH_G) || (p - c > GLITCH_G && n - c > GLITCH_G));
    bool atLimit = fabsf(c) >= 7.99f && fabsf(p) < 7.0f && fabsf(n) < 7.0f && !sat[i];
    out[i] = (spike || atLimit) ? 0.5f * (p + n) : c;
    fixed |= spike || atLimit;
  }
  if (fixed) glitches++;
  processClean(out);
  memcpy(glPrev, out, sizeof out);
  memcpy(glCur, g, sizeof g);
}

static void pollMpu() {
  if (safeMode) return;                           // SAFE MODE: sensor off, the node only stays connected
  if (!mpuOk) {
    if (millis() - lastMpuTry > 2000) {           // sensor missing: try again every 2 s
      lastMpuTry = millis();
      mpuOk = mpuInit();
      if (!mpuOk) vibReady = false;
    }
    return;
  }
  if (millis() - lastAnalyseAt > 3000) {         // no samples for 3 s (e.g. the MPU reset itself): restart it
    Serial.println("[node] MPU stopped delivering samples - restarting it");
    mpuOk = false;
    vibReady = false;
    lastMpuTry = 0;
    return;
  }
  fifoDrain();
  resyncNow = false;
  uint8_t frame[8];
  int done = 0;
  while (mpuOk && swqLen >= FRAME_BYTES && done < 200) {   // at most 200 samples per loop pass
    for (int i = 0; i < FRAME_BYTES; i++) frame[i] = swq[(swqHead + i) % SWQ_BYTES];
    swqHead = (swqHead + FRAME_BYTES) % SWQ_BYTES;
    swqLen -= FRAME_BYTES;
    processSample(frame);
    done++;
    if (resyncNow) { resyncNow = false; return; }  // FIFO was reset: the buffered samples are gone too
    if ((done & 31) == 0) fifoDrain();              // processing takes time too
  }
}

static void sendPacket(bool held) {
  if (state != S_CONNECTED || !hostStr[0]) return;
  char body[200], pkt[210];
  bool stale = held && millis() - lastGoodAt > HOLD_MAX_MS;   // re-syncing for too long: the data is bad
  unsigned flags = (mpuOk && vibReady && !stale ? 0u : 1u) | (lostRecently ? 2u : 0u) | (held ? 4u : 0u);
  int n = snprintf(body, sizeof body, "ND,%d,%lu,VIB,%.2f,%.2f,%.2f,%.2f,%.4f,%.4f,%.1f,%.1f,%d,%d,%.1f,%d,%u",
                   NODE_ID, (unsigned long)seq++, velRms, velAxis[0], velAxis[1], velAxis[2], accRms, accPeak,
                   domFreq, tempC, zone, running ? 1 : 0, tiltDelta, (int)WiFi.RSSI(), flags);
  int len = snprintf(pkt, sizeof pkt, "$%s*%02X", body, xorSum(body, n));
  udp.beginPacket(hostIp, PI_PORT);
  udp.write((const uint8_t *)pkt, len);
  if (udp.endPacket()) udpSent++;
  else udpFailed++;
  lastPacketAt = millis();
}

// ---------------------------------------------------------------- OLED drawing
// Rows 0-15 are yellow, rows 16-63 are blue. Nothing is drawn across row 15/16.
static uint16_t textW(const char *s, const GFXfont *f, uint8_t size) {
  int16_t x1, y1;
  uint16_t w, h;
  oled.setFont(f);
  oled.setTextSize(size);
  oled.getTextBounds(s, 0, 0, &x1, &y1, &w, &h);
  return w;
}

static void textAt(const char *s, int x, int top, const GFXfont *f = nullptr, uint8_t size = 1) {
  int16_t x1, y1;
  uint16_t w, h;
  oled.setFont(f);
  oled.setTextSize(size);
  oled.getTextBounds(s, 0, 0, &x1, &y1, &w, &h);
  oled.setCursor(x - x1, top - y1);                 // puts the top of the text at "top"
  oled.print(s);
}

static void textCenter(const char *s, int top, const GFXfont *f = nullptr, uint8_t size = 1) {
  textAt(s, (128 - (int)textW(s, f, size)) / 2, top, f, size);
}

static void title(const char *s, int top = 19) {      // bold title in the blue area
  if (textW(s, BIG, 1) <= 126) textCenter(s, top, BIG);
  else if (strlen(s) * 12 <= 128) textCenter(s, top, nullptr, 2);
  else textCenter(s, top + 4);
}

static void fitCopy(char *dst, const char *src, size_t maxChars) {   // "LongNetworkNa.."
  size_t n = strlen(src);
  if (n <= maxChars) { strcpy(dst, src); return; }
  memcpy(dst, src, maxChars - 2);
  strcpy(dst + maxChars - 2, "..");
}

static int rssiLevel() {
  int r = WiFi.RSSI();
  if (r >= -55) return 4;
  if (r >= -65) return 3;
  if (r >= -75) return 2;
  return 1;
}

static void drawStatusBar(uint32_t now) {               // yellow area
  textAt(NODE_NAME, 0, 4);

  if (state == S_CONNECTED && now - lastPacketAt < 200 && (now / 100) % 2) {
    oled.fillTriangle(44, 5, 44, 11, 48, 8, SSD1306_WHITE);   // blinks while data goes out
  }

  bool active = qnxSeen && (now - lastQnx < 5000 || (client && client.connected()));
  if (active) {                                        // "QNX": the Pi is talking to us
    oled.fillRoundRect(62, 2, 25, 12, 3, SSD1306_WHITE);
    oled.setTextColor(SSD1306_BLACK);
    textAt("QNX", 66, 4);
    oled.setTextColor(SSD1306_WHITE);
  } else {
    oled.drawRoundRect(62, 2, 25, 12, 3, SSD1306_WHITE);
    textAt("QNX", 66, 4);
  }

  if (haveCreds) {                                     // padlock = Wi-Fi details stored
    oled.drawFastHLine(96, 3, 3, SSD1306_WHITE);
    oled.drawFastVLine(95, 4, 3, SSD1306_WHITE);
    oled.drawFastVLine(99, 4, 3, SSD1306_WHITE);
    oled.fillRect(94, 7, 7, 6, SSD1306_WHITE);
  }

  if (state == S_SETUP) {                              // "AP" = our own setup hotspot is on
    oled.drawRoundRect(106, 2, 22, 12, 3, SSD1306_WHITE);
    textAt("AP", 111, 4);
    return;
  }
  int level = 0;
  if (state == S_CONNECTED) level = rssiLevel();
  else if (state == S_CONNECTING || state == S_WIFI_ON) level = (now / 250) % 5;
  for (int i = 0; i < 4; i++) {
    int h = 3 + i * 3, x = 106 + i * 6, y = 14 - h;
    if (i < level) oled.fillRect(x, y, 4, h, SSD1306_WHITE);
    else oled.drawRect(x, y, 4, h, SSD1306_WHITE);
  }
}

static void drawCheck(int cx, int cy) {
  for (int d = 0; d < 2; d++) {
    oled.drawLine(cx - 6, cy + d, cx - 2, cy + 4 + d, SSD1306_WHITE);
    oled.drawLine(cx - 2, cy + 4 + d, cx + 6, cy - 4 + d, SSD1306_WHITE);
  }
}

static void drawCross(int cx, int cy) {
  for (int d = 0; d < 2; d++) {
    oled.drawLine(cx - 5 + d, cy - 5, cx + 5 + d, cy + 5, SSD1306_WHITE);
    oled.drawLine(cx + 5 + d, cy - 5, cx - 5 + d, cy + 5, SSD1306_WHITE);
  }
}

static void drawToast() {
  const char *t1 = "", *l1 = "", *l2 = "";
  oled.drawCircle(13, 41, 10, SSD1306_WHITE);
  switch (toast) {
    case T_VERIFIED: t1 = "VERIFIED"; l1 = "signed by QNX"; l2 = "joining Wi-Fi";  drawCheck(13, 41); break;
    case T_REJECTED: t1 = "REJECTED"; l1 = "bad signature"; l2 = "not from QNX";   drawCross(13, 41); break;
    case T_CLEARED:  t1 = "CLEARED";  l1 = "Wi-Fi details";  l2 = "erased";        oled.fillRect(7, 40, 13, 3, SSD1306_WHITE); break;
    case T_BADDATA:  t1 = "INVALID";  l1 = "bad name, pass"; l2 = "or Pi address";  drawCross(13, 41); break;
    case T_ZEROED:   t1 = "ZEROED";   l1 = "mounting angle"; l2 = "saved as normal"; drawCheck(13, 41); break;
    default: break;
  }
  if (28 + textW(t1, BIG, 1) <= 128) textAt(t1, 28, 21, BIG);
  else textAt(t1, 28, 23, nullptr, 1);
  textAt(l1, 28, 41);
  textAt(l2, 28, 51);
}

static void drawWifiArcs(int cx, int cy, int shown) {
  oled.fillCircle(cx, cy, 2, SSD1306_WHITE);
  for (int i = 0; i < shown && i < 3; i++) {
    int r = 6 + i * 5;
    oled.drawCircleHelper(cx, cy, r, 0x1 | 0x2, SSD1306_WHITE);
    oled.drawCircleHelper(cx, cy, r - 1, 0x1 | 0x2, SSD1306_WHITE);
  }
}

static void drawScreen() {
  if (!oledOk) return;
  uint32_t now = millis();
  char line[24], tmp[24];
  oled.clearDisplay();
  oled.setTextColor(SSD1306_WHITE);

  if (state == S_BOOT) {
    textCenter("QNX WIFI NODE", 4);
    title(NODE_NAME);
    uint32_t t = min<uint32_t>(now, 1500);
    oled.drawRoundRect(14, 40, 100, 7, 3, SSD1306_WHITE);
    oled.fillRoundRect(14, 40, 6 + (94 * t) / 1500, 7, 3, SSD1306_WHITE);
    if (resetWhy != ESP_RST_POWERON && resetWhy != ESP_RST_EXT && resetWhy != ESP_RST_UNKNOWN &&
        resetWhy != ESP_RST_SW && (now / 500) % 2) {
      char why[24];
      snprintf(why, sizeof why, "reset: %s", resetName(resetWhy));   // e.g. "reset: BROWNOUT"
      textCenter(why, 53);
    } else {
      textCenter(now < 3000 ? "3x RESET = setup" : "VIBRATION v" FW_VERSION, 53);
    }
    oled.display();
    return;
  }

  drawStatusBar(now);

  if (toast != T_NONE && (int32_t)(toastUntil - now) > 0) {
    drawToast();
    oled.display();
    return;
  }
  toast = T_NONE;

  uint32_t inState = now - stateSince;
  switch (state) {
    case S_SETUP: {
      title("SETUP");
      textCenter(apSsid, 37);
      bool piHere = client && client.connected();
      if (piHere) {
        textCenter("QNX Pi connected", 46);
      } else if (apStations > 0) {
        textCenter("Pi joined hotspot", 46);
      } else if (setupUntil) {
        uint32_t left = (int32_t)(setupUntil - now) > 0 ? (setupUntil - now) / 1000 : 0;
        snprintf(line, sizeof line, "Wi-Fi retry in %lus", (unsigned long)left);
        textCenter(line, 46);
      } else {
        textCenter("waiting for QNX Pi", 46);
      }
      for (int x = 4; x < 124; x += 4) oled.drawPixel(x, 59, SSD1306_WHITE);
      uint32_t p = (now / 20) % 200;                  // block sliding back and forth
      int x = p < 100 ? p : 200 - p;
      oled.fillRoundRect(4 + x, 57, 20, 5, 2, SSD1306_WHITE);
      break;
    }
    case S_WIFI_ON:
      title("WIFI ON");
      textCenter("radio starting", 37);
      drawWifiArcs(64, 61, 1 + inState / 250);
      break;
    case S_CONNECTING: {
      title("CONNECTING");
      fitCopy(tmp, ssid, 21);
      textCenter(tmp, 37);
      snprintf(line, sizeof line, "attempt %u  %lus", attempt, (unsigned long)(inState / 1000));
      textCenter(line, 46);
      oled.drawRoundRect(4, 56, 120, 6, 3, SSD1306_WHITE);
      oled.fillRoundRect(4, 56, max<uint32_t>(6, (120 * min<uint32_t>(inState, CONNECT_TIMEOUT_MS)) / CONNECT_TIMEOUT_MS), 6, 3, SSD1306_WHITE);
      break;
    }
    case S_CONNECTED: {
      title("CONNECTED");
      fitCopy(tmp, ssid, 21);
      textCenter(tmp, 37);
      IPAddress a = WiFi.localIP();
      snprintf(line, sizeof line, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
      textCenter(line, 46);
      if ((now / 4000) % 2 == 0) {
        uint32_t s = inState / 1000;
        snprintf(line, sizeof line, "%d dBm  %02lu:%02lu:%02lu", (int)WiFi.RSSI(),
                 (unsigned long)(s / 3600), (unsigned long)(s / 60 % 60), (unsigned long)(s % 60));
      } else if (safeMode) {
        snprintf(line, sizeof line, "SAFE MODE: no sensor");
      } else if (!mpuOk) {
        snprintf(line, sizeof line, "MPU6050 not found");
      } else if (!vibReady) {
        snprintf(line, sizeof line, "measuring...");
      } else if ((now / 4000) % 2 == 1 && (now / 8000) % 2 == 0) {
        snprintf(line, sizeof line, "%.2f mm/s  ZONE %c", velRms, 'A' + zone);
      } else if (running) {
        snprintf(line, sizeof line, "%.1f Hz  %.0f rpm", domFreq, domFreq * 60);
      } else {
        snprintf(line, sizeof line, "IDLE  %.2f mm/s", velRms);
      }
      textCenter(line, 55);
      break;
    }
    case S_FAILED: {
      title("FAILED");
      textCenter(reasonText(lastReason), 37);
      uint32_t left = (int32_t)(retryAt - now) > 0 ? (retryAt - now + 999) / 1000 : 0;
      snprintf(line, sizeof line, "retry in %lus", (unsigned long)left);
      textCenter(line, 46);
      textCenter("hold BOOT 3s = setup", 55);
      break;
    }
    case S_LOST: {
      title("LOST WIFI");
      fitCopy(tmp, ssid, 21);
      textCenter(tmp, 37);
      static const char *dots[] = {"reconnecting", "reconnecting.", "reconnecting..", "reconnecting..."};
      textCenter(dots[(now / 300) % 4], 46);
      textCenter(reasonText(lastReason), 55);
      break;
    }
    default:
      break;
  }
  oled.display();
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  resetWhy = esp_reset_reason();
  Serial.begin(115200);
  pinMode(PIN_BOOT, INPUT_PULLUP);

  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.setClock(I2C_HZ);
  Wire.setTimeOut(I2C_TIMEOUT_MS);
  oledOk = oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);
  if (!oledOk) Serial.println("[node] OLED not found at 0x3C");
  oled.setTextWrap(false);
  if (oledOk) {
    oled.clearDisplay();
    oled.setTextColor(SSD1306_WHITE);
    textCenter("QNX WIFI NODE", 4);
    title("VIBRATION");
    textCenter("starting sensor", 46);
    oled.display();
  }
  // Crash counter: crash / brownout / watchdog resets in a row. After SAFE_AFTER of them the node starts
  // in SAFE MODE (sensor off, low Wi-Fi power) so it stays connected and visible instead of looping.
  // A normal power-on or RESET press starts normally; 60 s of stable running clears the counter.
  prefs.begin("qnxnode", false);
  bool badReset = resetWhy == ESP_RST_PANIC || resetWhy == ESP_RST_INT_WDT || resetWhy == ESP_RST_TASK_WDT ||
                  resetWhy == ESP_RST_WDT || resetWhy == ESP_RST_BROWNOUT;
  char qf[8] = "";
  prefs.getString("quickfails", qf, sizeof qf);
  quickFails = badReset ? atoi(qf) + 1 : 0;
  snprintf(qf, sizeof qf, "%d", quickFails);
  prefs.putString("quickfails", qf);
  safeMode = quickFails >= SAFE_AFTER;
  if (safeMode)
    Serial.printf("[node] SAFE MODE: %d bad resets in a row - sensor off, low Wi-Fi power, staying connected\n",
                  quickFails);
  mpuOk = safeMode ? false : mpuInit();
  fftSetup();
  if (!mpuOk && !safeMode) Serial.println("[node] MPU6050 not found at 0x68 (check SDA/SCL, AD0 to GND)");
  lastMpuTry = millis();

  keyOk = strlen(PROV_KEY_HEX) == 64 && hexDecode(PROV_KEY_HEX, 64, provKey, 32) == 32;
  if (!keyOk) Serial.println("[node] PROV_KEY_HEX must be 64 hex characters - setup disabled");

  // Setup hotspot name and password. The password = first 16 hex of HMAC(key, "SETUP-AP,<name>"),
  // which the Pi computes the same way.
  snprintf(apSsid, sizeof apSsid, "QNX-NODE-%d", NODE_ID);
  char msg[40];
  int n = snprintf(msg, sizeof msg, "SETUP-AP,%s", apSsid);
  uint8_t h[32];
  hmac256((const uint8_t *)msg, n, h);
  hexEncode(h, 8, apPass);

  uint64_t m = ESP.getEfuseMac();
  snprintf(macStr, sizeof macStr, "%02X:%02X:%02X:%02X:%02X:%02X", (uint8_t)m, (uint8_t)(m >> 8),
           (uint8_t)(m >> 16), (uint8_t)(m >> 24), (uint8_t)(m >> 32), (uint8_t)(m >> 40));

  WiFi.persistent(false);              // the Wi-Fi library must not keep its own copy
  WiFi.setAutoReconnect(false);        // we reconnect ourselves, with the OLED showing it
  WiFi.onEvent(onWifiEvent);
  WiFi.setHostname("node-1");
  WiFi.mode(WIFI_OFF);

  baseG[0] = prefs.getFloat("bx", 0); baseG[1] = prefs.getFloat("by", 0); baseG[2] = prefs.getFloat("bz", 0);
  baseSet = fabsf(baseG[0]) + fabsf(baseG[1]) + fabsf(baseG[2]) > 0.5f;   // saved mounting angle
  char mfw[8] = "";
  prefs.getString("mountfw", mfw, sizeof mfw);
  if (strcmp(mfw, "3.4")) {              // angles saved by older firmware may come from misaligned FIFO data:
    baseSet = false;                     // save the mounting angle again once, from clean data
    prefs.putString("mountfw", "3.4");
    Serial.println("[node] firmware 3.4: the mounting angle will be saved again from clean data");
  }
  prefs.getString("ssid", ssid, sizeof ssid);
  prefs.getString("pass", pass, sizeof pass);
  prefs.getString("host", hostStr, sizeof hostStr);
  char ok[4] = "";
  prefs.getString("ok", ok, sizeof ok);
  haveCreds = ssid[0] != 0 && hostIp.fromString(hostStr);
  credsVerified = haveCreds && ok[0] == '1';
  if (!haveCreds) { ssid[0] = pass[0] = hostStr[0] = 0; }

  // Reset reason. BROWNOUT = the 3.3 V supply dipped (weak USB port/cable, loose 3V3/GND wire, or the
  // Wi-Fi radio starting on a weak supply). Kept in flash so a reboot loop is visible on the serial monitor.
  char rc[12] = "";
  prefs.getString("brownouts", rc, sizeof rc);
  int brownouts = atoi(rc) + (resetWhy == ESP_RST_BROWNOUT ? 1 : 0);
  if (resetWhy == ESP_RST_BROWNOUT) {
    snprintf(rc, sizeof rc, "%d", brownouts);
    prefs.putString("brownouts", rc);
  }
  Serial.printf("[node] reset reason: %s (brownouts so far: %d)\n", resetName(resetWhy), brownouts);
  if (resetWhy == ESP_RST_BROWNOUT)
    Serial.println("[node] BROWNOUT: the supply voltage dropped. Use a good USB port/charger and cable, check the "
                   "3V3/GND wires, add a 100-470 uF capacitor across 3V3-GND");
  else if (resetWhy == ESP_RST_PANIC || resetWhy == ESP_RST_INT_WDT || resetWhy == ESP_RST_TASK_WDT ||
           resetWhy == ESP_RST_WDT)
    Serial.println("[node] the previous run crashed - please send the serial log from before this line");

  // Triple reset: every boot adds 1 to a counter in flash; after 3 s of running it goes back to 0.
  // So pressing RESET 3 times quickly reaches 3 and erases the Wi-Fi details. Only power-on / RESET-pin
  // resets count: a brownout or crash loop must not erase the Wi-Fi details.
  bool countable = resetWhy == ESP_RST_POWERON || resetWhy == ESP_RST_EXT || resetWhy == ESP_RST_UNKNOWN;
  char cnt[12] = "";
  prefs.getString("boots", cnt, sizeof cnt);
  int boots = countable ? atoi(cnt) + 1 : 0;
  snprintf(cnt, sizeof cnt, "%d", boots >= 3 ? 0 : boots);
  prefs.putString("boots", cnt);
  if (boots >= 3) {
    bootCountCleared = true;
    if (haveCreds) {
      eraseCreds();
      showToast(T_CLEARED, 2500);
      Serial.println("[node] RESET pressed 3 times: Wi-Fi details erased");
    }
  } else if (boots == 2) {
    Serial.println("[node] RESET pressed twice - once more within 3 s erases the Wi-Fi details");
  }

  Serial.printf("[node] %s fw %s, MAC %s, %s\n", NODE_NAME, FW_VERSION, macStr,
                haveCreds ? "Wi-Fi details stored" : "no Wi-Fi details: setup hotspot next");
  // Watchdog: if the loop ever hangs (e.g. a stuck I2C bus), restart in 8 s. The Wi-Fi details are kept.
  esp_task_wdt_config_t wdt = {WDT_MS, 0, true};
  if (esp_task_wdt_reconfigure(&wdt) != ESP_OK) esp_task_wdt_init(&wdt);
  esp_task_wdt_add(NULL);
  setState(S_BOOT);
}

// Loop timing: the MPU FIFO holds ~128 ms of samples, so no part of the loop may block that long.
static uint32_t tLoopMax = 0, tMpuMax = 0, tOledMax = 0, tWifiMax = 0, lastDiag = 0;

static void diagLine(uint32_t now) {
  if (now - lastDiag < DIAG_MS) return;
  lastDiag = now;
  Serial.printf("[diag] %s, loop max %lu ms (MPU %lu, OLED %lu, Wi-Fi %lu) | good results %lu, overflows %u, "
                "misaligned %lu, corrupt %lu, I2C errors %lu, bus recoveries %lu, buffer full %lu, mpu %s\n",
                stateName(state), (unsigned long)(tLoopMax / 1000), (unsigned long)(tMpuMax / 1000),
                (unsigned long)(tOledMax / 1000), (unsigned long)(tWifiMax / 1000), (unsigned long)goodResults,
                fifoOverflows, (unsigned long)misaligned, (unsigned long)corruptHops, (unsigned long)i2cErrors,
                (unsigned long)busRecoveries, (unsigned long)swqFull, safeMode ? "OFF (safe mode)" : mpuOk ? "ok" : "FAILED");
  tLoopMax = tMpuMax = tOledMax = tWifiMax = 0;
}

void loop() {
  uint32_t now = millis(), t0 = micros(), t;
  esp_task_wdt_reset();
  if (!stableCleared && now > STABLE_MS) {           // a minute without trouble: not a crash loop
    stableCleared = true;
    if (quickFails) { quickFails = 0; prefs.putString("quickfails", "0"); }
  }
  pollCtrl();
  wifiTask();
  bootButton();
  t = micros() - t0;
  if (t > tWifiMax) tWifiMax = t;

  if (!bootCountCleared && now > 3000) {              // ran 3 s: this boot doesn't count towards 3 resets
    bootCountCleared = true;
    prefs.putString("boots", "0");
  }
  if (state == S_BOOT && now >= 1600) {
    if (haveCreds) startWifi();
    else enterSetup(0);
  }
  uint32_t t1 = micros();
  pollMpu();                                        // reads the 1 kHz samples; sends a result every ~0.5 s
  t = micros() - t1;
  if (t > tMpuMax) tMpuMax = t;
  if (state == S_CONNECTED && !vibReady && now - lastPacketAt >= 500 && now > 8000) {
    sendPacket();                                   // sensor not delivering: keep reporting it as failed
  }
  if (state == S_CONNECTED && now - lastStatusAt >= STATUS_MS) sendStatus("ST");
  if (now - lastDraw >= OLED_MS) {
    lastDraw = now;
    uint32_t t2 = micros();
    drawScreen();
    t = micros() - t2;
    if (t > tOledMax) tOledMax = t;
  }
  t = micros() - t0;
  if (t > tLoopMax) tLoopMax = t;
  diagLine(now);
}
