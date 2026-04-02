// =============================================================
// CAN-Ethernet Telemetry Gateway — Teensy 4.1
// =============================================================
// Sends engine telemetry over a TLS-secured TCP connection
// to a Python server on port 8077.
//
// Libraries: QNEthernet, mbed TLS, ArduinoJson
// =============================================================

#include <Arduino.h>
#include <QNEthernet.h>
#include <ArduinoJson.h>

// mbed TLS headers
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"

using namespace qindesign::network;

// ----- Network configuration (edit to match your network) -----
static const IPAddress deviceIP(192, 168, 1, 100);
static const IPAddress gateway(192, 168, 1, 1);
static const IPAddress subnet(255, 255, 255, 0);
static const IPAddress dnsServer(8, 8, 8, 8);

// Python server address
static const IPAddress serverIP(192, 168, 1, 50);
static const uint16_t  serverPort = 8077;

// How often to send telemetry (milliseconds)
static const unsigned long SEND_INTERVAL_MS = 10000;

// ----- Global objects -----
EthernetClient tcp;                   // raw TCP socket via QNEthernet

mbedtls_ssl_context      ssl;         // TLS session state
mbedtls_ssl_config       conf;        // TLS configuration
mbedtls_entropy_context  entropy;     // entropy source for RNG
mbedtls_ctr_drbg_context ctr_drbg;   // random-number generator

bool          tlsReady    = false;    // true once handshake succeeds
unsigned long lastSendMs  = 0;        // timestamp of last telemetry send

// =============================================================
//  BIO callbacks — let mbed TLS read/write through QNEthernet
// =============================================================
// mbed TLS doesn't know about Arduino sockets, so we provide
// two small functions it can call to send and receive bytes.

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    EthernetClient *c = (EthernetClient *)ctx;
    if (!c->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
    int n = c->write(buf, len);
    return (n > 0) ? n : MBEDTLS_ERR_SSL_WANT_WRITE;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    EthernetClient *c = (EthernetClient *)ctx;
    if (!c->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
    if (c->available() == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    int n = c->read(buf, len);
    return (n > 0) ? n : MBEDTLS_ERR_SSL_WANT_READ;
}

// =============================================================
//  Helper: print an mbed TLS error code as readable text
// =============================================================
static void printTlsError(const char *label, int ret) {
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    Serial.printf("  [TLS] %s: -0x%04X  %s\n", label, (unsigned)-ret, buf);
}

// =============================================================
//  Read engine temperature
// =============================================================
// Placeholder — returns a fixed value.
// Replace this with a real CAN bus read when hardware is ready.

static float readEngineTemperature() {
    return 87.5f;   // degrees Celsius
}

// =============================================================
//  1. Ethernet setup
// =============================================================
static void setupEthernet() {
    Serial.println("[ETH] Starting Ethernet with static IP...");

    Ethernet.begin(deviceIP, subnet, gateway);

    // Brief pause so the PHY link comes up
    delay(2000);

    if (Ethernet.linkState()) {
        Serial.print("[ETH] Link is UP — IP: ");
        Serial.println(Ethernet.localIP());
    } else {
        Serial.println("[ETH] WARNING: link is DOWN (check cable)");
    }
}

// =============================================================
//  2. TLS session setup
// =============================================================
// Initialises mbed TLS, opens a TCP connection to the server,
// then performs a TLS handshake.  Certificate verification is
// DISABLED so this works as a simple demo — do NOT ship this
// in production without proper CA verification.

static bool setupTls() {
    // --- init all mbed TLS contexts ---
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // --- seed the random-number generator ---
    const char *pers = "teensy_tls";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                     &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers));
    if (ret != 0) { printTlsError("ctr_drbg_seed", ret); return false; }

    // --- set up TLS config (client mode, TLS 1.2+) ---
    ret = mbedtls_ssl_config_defaults(&conf,
                                       MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) { printTlsError("ssl_config_defaults", ret); return false; }

    // DEMO ONLY: skip server certificate verification
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) { printTlsError("ssl_setup", ret); return false; }

    // --- open raw TCP connection via QNEthernet ---
    Serial.printf("[TCP] Connecting to %u.%u.%u.%u:%u ...\n",
                  serverIP[0], serverIP[1], serverIP[2], serverIP[3],
                  serverPort);

    if (!tcp.connect(serverIP, serverPort)) {
        Serial.println("[TCP] Connection FAILED");
        return false;
    }
    Serial.println("[TCP] Connected");

    // Tell mbed TLS to use our BIO callbacks for I/O
    mbedtls_ssl_set_bio(&ssl, &tcp, bio_send, bio_recv, NULL);

    // --- perform TLS handshake ---
    Serial.println("[TLS] Starting handshake...");
    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0) {
        printTlsError("handshake", ret);
        tcp.stop();
        return false;
    }

    Serial.println("[TLS] Handshake OK — secure session established");
    return true;
}

// =============================================================
//  3. Build & send a JSON telemetry message
// =============================================================
static void sendTelemetry() {
    // --- create JSON payload with ArduinoJson ---
    JsonDocument doc;
    doc["device"]    = "CAN-Ethernet Telemetry Gateway";
    doc["parameter"] = "EngineTemperature";
    doc["value"]     = readEngineTemperature();
    doc["unit"]      = "C";

    // Serialize to a string
    char jsonBuf[256];
    size_t len = serializeJson(doc, jsonBuf, sizeof(jsonBuf));

    // --- send over the TLS session ---
    int ret = mbedtls_ssl_write(&ssl, (const unsigned char *)jsonBuf, len);

    if (ret > 0) {
        Serial.printf("[TX] Sent %d bytes: %s\n", ret, jsonBuf);
    } else {
        printTlsError("ssl_write", ret);
        Serial.println("[TX] Send FAILED — will retry next cycle");
    }
}

// =============================================================
//  Arduino entry points
// =============================================================
void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 3000) { }   // wait up to 3 s for Serial
    Serial.println("=== CAN-Ethernet Telemetry Gateway ===\n");

    // 1. Bring up Ethernet
    setupEthernet();

    // 2. Establish TLS session to the Python server
    tlsReady = setupTls();
    if (!tlsReady) {
        Serial.println("\n** TLS setup failed — telemetry will NOT be sent **");
        Serial.println("** Check server, cable, and IP addresses            **");
    }
}

void loop() {
    // Nothing to do if TLS isn't up
    if (!tlsReady) return;

    // 4. Send telemetry every 10 seconds
    unsigned long now = millis();
    if (now - lastSendMs >= SEND_INTERVAL_MS) {
        lastSendMs = now;
        sendTelemetry();
    }
}
