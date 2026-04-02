#!/usr/bin/env python3
"""
CAN-Ethernet Telemetry Gateway — TLS Test Server
=================================================
Listens on port 8077 with TLS enabled.
Accepts connections from the Teensy 4.1 gateway and prints
received JSON telemetry to the console.

Quick start
-----------
1. Generate a self-signed cert (once):

       cd tools/
       openssl req -x509 -newkey rsa:2048 -keyout server.key \
           -out server.crt -days 365 -nodes \
           -subj "/CN=telemetry-server"

2. Run the server:

       python3 tls_server.py

3. Power on the Teensy — you should see JSON payloads arrive
   every 10 seconds.

Dependencies: Python 3.7+ (stdlib only, no pip packages needed).
"""

import json
import socket
import ssl
import sys
from datetime import datetime, timezone

# ----- Configuration (edit to match your network) -----
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8077
CERT_FILE   = "server.crt"   # generated with openssl (see above)
KEY_FILE    = "server.key"

BUFFER_SIZE = 4096


def create_tls_context() -> ssl.SSLContext:
    """Build a TLS server context using the self-signed cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # Accept connections from clients that don't present a certificate
    # (the Teensy demo uses VERIFY_NONE on its side).
    ctx.verify_mode = ssl.CERT_NONE

    # Allow TLS 1.2+ (matches mbed TLS defaults on the Teensy)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx


def handle_client(conn: ssl.SSLSocket, addr: tuple) -> None:
    """Read telemetry payloads from one Teensy until it disconnects."""
    print(f"[+] Secure session from {addr[0]}:{addr[1]}  "
          f"(TLS {conn.version()})")

    with conn:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                print(f"[-] {addr[0]}:{addr[1]} disconnected\n")
                break

            # The Teensy may send multiple JSON objects back-to-back
            # in one TCP segment, so split on '}{' boundaries.
            raw = data.decode("utf-8", errors="replace")
            fragments = raw.replace("}{", "}\n{").split("\n")

            for fragment in fragments:
                fragment = fragment.strip()
                if not fragment:
                    continue
                try:
                    payload = json.loads(fragment)
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    print(f"  [{ts}]  {payload.get('parameter', '?')} = "
                          f"{payload.get('value', '?')} {payload.get('unit', '')}")
                except json.JSONDecodeError:
                    print(f"  [WARN] Non-JSON data: {fragment!r}")


def main() -> None:
    ctx = create_tls_context()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(1)

    print("=" * 52)
    print("  CAN-Ethernet Telemetry Gateway — TLS Server")
    print("=" * 52)
    print(f"  Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"  Cert: {CERT_FILE}   Key: {KEY_FILE}")
    print(f"  Waiting for Teensy connection...\n")

    try:
        while True:
            client_sock, addr = sock.accept()
            try:
                tls_conn = ctx.wrap_socket(client_sock, server_side=True)
                handle_client(tls_conn, addr)
            except ssl.SSLError as e:
                print(f"[!] TLS error from {addr[0]}:{addr[1]}: {e}")
            except ConnectionResetError:
                print(f"[-] {addr[0]}:{addr[1]} reset the connection")
    except KeyboardInterrupt:
        print("\n[*] Server stopped (Ctrl+C)")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
