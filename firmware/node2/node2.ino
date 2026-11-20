/*
  Node 2 - PCBCupid GLYPH C6 (ESP32-C6) + GY-BME/PM 280 + 0.96" yellow/blue OLED  (firmware 2.1, fully wireless)
  ----------------------------------------------------------------------------------------------------------
  A wireless sensor node for the QNX monitoring system on the Raspberry Pi. No wires to the Pi.
  Same Wi-Fi setup as Node 1:
    1. With no Wi-Fi details stored, the node opens its own setup hotspot "QNX-NODE-2"
       (password derived from the shared key below, so only the Pi can compute it).
    2. The Pi's dashboard finds it, joins it for a few seconds and connects to 192.168.4.1:7000.
    3. The Pi sends the Wi-Fi name, password and its own IP, signed with HMAC-SHA256 (shared key),
       password encrypted. Anything unsigned is refused.
    4. The node closes the hotspot, joins that Wi-Fi and starts sending data to the Pi.
  Back to setup: press RESET 3 times quickly, hold BOOT 3 s while running, or F8 twice on the dashboard.

  Data to the Pi (UDP port 5005):
    every 500 ms  $ND,2,<seq>,ENV,<temp C>,<humidity %>,<pressure hPa>,<rssi>,<flags>*<xor>
    every 5 s     $ST,2,<mac>,<state>,<ssid hex>,<ip>,<rssi>,<reason>,<pi ip>*<xor>   (and on every change)
    flags bit0 = sensor read failed, bit1 = no humidity (the module is a BMP280, humidity sent as -1)

  Sensor: GY-BME/PM 280 module (6 pins). These modules carry either a BME280 (temperature, humidity,
  pressure) or a BMP280 (temperature, pressure only - very common). The code reads the chip ID and
  handles both; the OLED, the serial log and the dashboard say which one yours has.

  Wiring (sensor and OLED share the I2C bus; the GLYPH's GLINK/Qwiic connector carries the same bus)
    GY-BME/PM 280:  VCC -> 3V3   GND -> GND   SCL -> IO5   SDA -> IO4
                    CSB -> 3V3   (selects I2C; if left open some modules stay silent)
                    SDO -> GND   (address 0x76; SDO -> 3V3 gives 0x77 - both are found automatically)
    OLED:           VCC -> 3V3   GND -> GND   SCL -> IO5   SDA -> IO4   (address 0x3C)
    Use 3V3, not 5V: many GY-BME/PM 280 boards have no regulator.
    Power from the GLYPH's USB-C (or a LiPo on the rear pads).

  Arduino IDE: esp32 core 3.x or 4.x, board "PCBCUPID GLYPH C6" if listed, otherwise "ESP32C6 Dev Module";
               Tools > USB CDC On Boot > Enabled
  Libraries:   Adafruit SSD1306, Adafruit GFX   (the sensor is read directly, no BME280/BMP280 library needed)
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

// ======================= settings =======================
#define NODE_NAME   "NODE-2"
#define NODE_ID     2
#define FW_VERSION  "2.1"

// Shared key: must be the same 64 hex characters as PROV_KEY in node_dashboard.py.
// Make your own on the Pi with:  python3 node_dashboard.py --genkey   and paste it in both files.
#include "secrets.h"
static const char PROV_KEY_HEX[] = PROV_KEY_HEX_VALUE;

#define PI_PORT      5005     // monitoring dashboard on the Pi
#define CTRL_PORT    7000     // the Pi talks to the node here (setup hotspot and normal Wi-Fi)
#define SEND_MS      500      // one sensor packet every 500 ms
#define STATUS_MS    5000     // Wi-Fi status packet every 5 s

#define PIN_SDA      4        // IO4 (GLYPH C6 I2C SDA)
#define PIN_SCL      5        // IO5 (GLYPH C6 I2C SCL)
#define PIN_BOOT     9        // the GLYPH's BOOT button (pressed = LOW)
#define OLED_ADDR    0x3C

#define CONNECT_TIMEOUT_MS   20000
#define NONCE_TTL_MS         15000
#define AUTH_LOCKOUT_MS      3000
#define SETUP_AFTER_FAIL_MS  180000   // saved details failing this long -> reopen the setup hotspot
#define SETUP_WINDOW_MS      90000    // ... for this long, then try the saved details again
#define REASON_TIMEOUT       1000     // our own code for "no answer in time"
#define SETUP_CHANNEL        6        // Wi-Fi channel of the setup hotspot (1-13)
#define WIFI_TX_POWER        WIFI_POWER_8_5dBm   // same as Node 1 (fixed "authentication timed out" there);
                                                 // raise (e.g. WIFI_POWER_15dBm) if the range is poor
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

enum Toast { T_NONE, T_VERIFIED, T_REJECTED, T_CLEARED, T_BADDATA };
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

static bool envOk = false, hasHumidity = false;
static uint8_t bmeAddr = 0;
static float tempC = 0, humidity = -1, pressureHpa = 0;
static uint32_t lastSend = 0, lastDraw = 0, lastEnvTry = 0, lastStatusAt = 0, seq = 0, lastPacketAt = 0;
static uint32_t bootDownSince = 0;
static bool bootCountCleared = false;           // triple-reset detection
static char macStr[18];
static bool oledOk = false;

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
  WiFi.setTxPower(WIFI_TX_POWER);
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

static void bootButton() {                         // hold BOOT 3 s = erase Wi-Fi details
  if (digitalRead(PIN_BOOT) == LOW) {
    if (!bootDownSince) bootDownSince = millis() | 1;
    if (millis() - bootDownSince > 3000) {
      bootDownSince = 0;
      eraseCreds();
      Serial.println("[node] BOOT held: Wi-Fi details erased");
      showToast(T_CLEARED, 2000);
      enterSetup(0);
      while (digitalRead(PIN_BOOT) == LOW) delay(10);
    }
  } else {
    bootDownSince = 0;
  }
}

// ---------------------------------------------------------------- BME280 / BMP280 + packets
// Read directly (Bosch datasheet formulas), so GY-BME/PM 280 modules work with either chip on them:
// chip ID 0x60 = BME280 (with humidity), 0x56 / 0x57 / 0x58 = BMP280 (no humidity).
static const char *envChip() { return !envOk ? "sensor" : hasHumidity ? "BME280" : "BMP280"; }

// Logs every I2C address that answers, to tell wiring problems apart (called when the sensor is missing).
static void i2cScanLog() {
  char list[96] = "";
  int found = 0;
  for (uint8_t a = 1; a < 127; a++) {
    Wire.beginTransmission(a);
    if (Wire.endTransmission() == 0) {
      size_t l = strlen(list);
      snprintf(list + l, sizeof list - l, " 0x%02X", a);
      found++;
    }
  }
  Serial.printf("[node] I2C scan (SDA=IO%d, SCL=IO%d):%s\n", PIN_SDA, PIN_SCL, found ? list : " nothing answers");
  if (!found) Serial.println("[node]   -> check 3V3/GND and that SDA/SCL are not swapped");
  else if (found == 1 && strstr(list, "0x3C")) Serial.println("[node]   -> only the OLED answers: the GY-BME/PM 280 is not seen. Tie CSB to 3V3, SDO to GND, check its VCC/GND");
}
static uint16_t T1, P1;
static int16_t T2, T3, P2, P3, P4, P5, P6, P7, P8, P9, H2, H4, H5;
static uint8_t H1, H3;
static int8_t H6;

static bool bmeWrite(uint8_t reg, uint8_t val) {
  Wire.beginTransmission(bmeAddr);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

static bool bmeRead(uint8_t reg, uint8_t *buf, uint8_t len) {
  Wire.beginTransmission(bmeAddr);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom(bmeAddr, len) != len) return false;
  for (uint8_t i = 0; i < len; i++) buf[i] = Wire.read();
  return true;
}

static uint16_t u16le(const uint8_t *b) { return (uint16_t)(b[0] | b[1] << 8); }
static int16_t s16le(const uint8_t *b) { return (int16_t)(b[0] | b[1] << 8); }

static bool envInit() {
  static const uint8_t addrs[] = {0x76, 0x77};
  uint8_t id = 0;
  bmeAddr = 0;
  for (uint8_t a : addrs) {
    bmeAddr = a;
    if (bmeRead(0xD0, &id, 1) && (id == 0x60 || id == 0x58 || id == 0x57 || id == 0x56)) break;
    if (id) Serial.printf("[node] device at 0x%02X has chip id 0x%02X - not a BME280/BMP280\n", a, id);
    id = 0;
    bmeAddr = 0;
  }
  if (!bmeAddr) return false;
  hasHumidity = id == 0x60;
  Serial.printf("[node] GY-BME/PM 280: %s found at 0x%02X (chip id 0x%02X)%s\n", hasHumidity ? "BME280" : "BMP280",
                bmeAddr, id, hasHumidity ? "" : " - this chip has no humidity sensor");
  bmeWrite(0xE0, 0xB6);                                // soft reset
  delay(10);
  uint8_t st = 1;
  for (int i = 0; i < 20 && (st & 1); i++) { delay(5); bmeRead(0xF3, &st, 1); }   // wait for NVM copy

  uint8_t c[26];
  if (!bmeRead(0x88, c, 26)) return false;
  T1 = u16le(c + 0);  T2 = s16le(c + 2);  T3 = s16le(c + 4);
  P1 = u16le(c + 6);  P2 = s16le(c + 8);  P3 = s16le(c + 10); P4 = s16le(c + 12); P5 = s16le(c + 14);
  P6 = s16le(c + 16); P7 = s16le(c + 18); P8 = s16le(c + 20); P9 = s16le(c + 22);
  if (hasHumidity) {
    uint8_t h[7];
    H1 = c[25];                                        // register 0xA1
    if (!bmeRead(0xE1, h, 7)) return false;
    H2 = s16le(h);
    H3 = h[2];
    H4 = (int16_t)((int8_t)h[3] * 16 | (h[4] & 0x0F));
    H5 = (int16_t)((int8_t)h[5] * 16 | (h[4] >> 4));
    H6 = (int8_t)h[6];
    bmeWrite(0xF2, 0x01);                              // humidity x1 (must come before 0xF4)
  }
  bmeWrite(0xF5, 0x0C);                                // standby 0.5 ms, IIR filter x4
  return bmeWrite(0xF4, 0x57);                         // temp x2, pressure x16, normal mode
}

static bool envSample() {
  uint8_t d[8];
  if (!bmeRead(0xF7, d, hasHumidity ? 8 : 6)) return false;
  int32_t adcP = (int32_t)d[0] << 12 | (int32_t)d[1] << 4 | d[2] >> 4;
  int32_t adcT = (int32_t)d[3] << 12 | (int32_t)d[4] << 4 | d[5] >> 4;
  if (adcT == 0x80000 || adcP == 0x80000) return false;          // "no measurement yet" value

  double v1 = (adcT / 16384.0 - T1 / 1024.0) * T2;
  double v2 = (adcT / 131072.0 - T1 / 8192.0) * (adcT / 131072.0 - T1 / 8192.0) * T3;
  double tFine = v1 + v2;
  tempC = tFine / 5120.0;

  v1 = tFine / 2.0 - 64000.0;
  v2 = v1 * v1 * P6 / 32768.0;
  v2 = v2 + v1 * P5 * 2.0;
  v2 = v2 / 4.0 + P4 * 65536.0;
  v1 = (P3 * v1 * v1 / 524288.0 + P2 * v1) / 524288.0;
  v1 = (1.0 + v1 / 32768.0) * P1;
  if (v1 == 0) return false;
  double p = 1048576.0 - adcP;
  p = (p - v2 / 4096.0) * 6250.0 / v1;
  v1 = P9 * p * p / 2147483648.0;
  v2 = p * P8 / 32768.0;
  pressureHpa = (p + (v1 + v2 + P7) / 16.0) / 100.0;

  if (hasHumidity) {
    int32_t adcH = (int32_t)d[6] << 8 | d[7];
    double h = tFine - 76800.0;
    h = (adcH - (H4 * 64.0 + H5 / 16384.0 * h)) *
        (H2 / 65536.0 * (1.0 + H6 / 67108864.0 * h * (1.0 + H3 / 67108864.0 * h)));
    h = h * (1.0 - H1 * h / 524288.0);
    humidity = h < 0 ? 0 : h > 100 ? 100 : h;
  } else {
    humidity = -1;
  }
  return true;
}

static void readEnv() {
  static uint32_t lastLog = 0, misses = 1;     // setup() already logged one scan
  if (!envOk) {
    if (millis() - lastEnvTry > 2000) {                // sensor missing: try again every 2 s
      lastEnvTry = millis();
      envOk = envInit();
      if (!envOk && misses++ % 15 == 0) i2cScanLog();  // explain why, every ~30 s
      if (envOk) misses = 0;
    }
    return;
  }
  if (!envSample()) {
    envOk = false;
    Serial.println("[node] sensor stopped answering - retrying");
    return;
  }
  if (millis() - lastLog > 5000) {                     // readings in the serial monitor every 5 s
    lastLog = millis();
    if (hasHumidity) Serial.printf("[node] %s  %.2f C  %.1f %%RH  %.2f hPa\n", envChip(), tempC, humidity, pressureHpa);
    else Serial.printf("[node] %s  %.2f C  %.2f hPa  (no humidity on this chip)\n", envChip(), tempC, pressureHpa);
  }
}

static void sendPacket() {
  if (state != S_CONNECTED || !hostStr[0]) return;
  char body[128], pkt[136];
  unsigned flags = (envOk ? 0u : 1u) | (hasHumidity ? 0u : 2u);
  int n = snprintf(body, sizeof body, "ND,%d,%lu,ENV,%.2f,%.1f,%.2f,%d,%u", NODE_ID, (unsigned long)seq++,
                   tempC, hasHumidity ? humidity : -1.0f, pressureHpa, (int)WiFi.RSSI(), flags);
  int len = snprintf(pkt, sizeof pkt, "$%s*%02X", body, xorSum(body, n));
  udp.beginPacket(hostIp, PI_PORT);
  udp.write((const uint8_t *)pkt, len);
  udp.endPacket();
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
    textCenter(now < 3000 ? "3x RESET = setup" : "BME/BMP280 v" FW_VERSION, 53);
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
      } else if (envOk && hasHumidity) {
        snprintf(line, sizeof line, "%.1fC %.0f%% %.0fhPa", tempC, humidity, pressureHpa);
      } else if (envOk) {
        snprintf(line, sizeof line, "%.1fC  %.1f hPa", tempC, pressureHpa);
      } else {
        snprintf(line, sizeof line, "sensor not found");
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
  Serial.begin(115200);
  pinMode(PIN_BOOT, INPUT_PULLUP);

  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.setClock(400000);
  oledOk = oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);
  if (!oledOk) Serial.println("[node] OLED not found at 0x3C");
  oled.setTextWrap(false);
  envOk = envInit();
  if (!envOk) {
    Serial.println("[node] GY-BME/PM 280 not found at 0x76/0x77 (check SDA=IO4, SCL=IO5, 3V3, GND, CSB->3V3)");
    i2cScanLog();
  }
  lastEnvTry = millis();

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
  WiFi.setHostname("node-2");
  WiFi.mode(WIFI_OFF);

  prefs.begin("qnxnode", false);
  prefs.getString("ssid", ssid, sizeof ssid);
  prefs.getString("pass", pass, sizeof pass);
  prefs.getString("host", hostStr, sizeof hostStr);
  char ok[4] = "";
  prefs.getString("ok", ok, sizeof ok);
  haveCreds = ssid[0] != 0 && hostIp.fromString(hostStr);
  credsVerified = haveCreds && ok[0] == '1';
  if (!haveCreds) { ssid[0] = pass[0] = hostStr[0] = 0; }

  // Triple reset: every boot adds 1 to a counter in flash; after 3 s of running it goes back to 0.
  // So pressing RESET 3 times quickly reaches 3 and erases the Wi-Fi details.
  char cnt[12] = "";
  prefs.getString("boots", cnt, sizeof cnt);
  int boots = atoi(cnt) + 1;
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
  setState(S_BOOT);
}

void loop() {
  uint32_t now = millis();
  pollCtrl();
  wifiTask();
  bootButton();

  if (!bootCountCleared && now > 3000) {              // ran 3 s: this boot doesn't count towards 3 resets
    bootCountCleared = true;
    prefs.putString("boots", "0");
  }
  if (state == S_BOOT && now >= 1600) {
    if (haveCreds) startWifi();
    else enterSetup(0);
  }
  if (now - lastSend >= SEND_MS) {
    lastSend = now;
    readEnv();
    sendPacket();
  }
  if (state == S_CONNECTED && now - lastStatusAt >= STATUS_MS) sendStatus("ST");
  if (now - lastDraw >= 80) {
    lastDraw = now;
    drawScreen();
  }
}
