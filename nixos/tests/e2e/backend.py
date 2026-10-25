"""Echo exactly what the proxy sent, without inventing identity information."""

import http.server
import json
import os
import socketserver
import ssl
import sys
import threading


class Echo(http.server.BaseHTTPRequestHandler):
    def address_string(self):
        return "test-client"

    def do_GET(self):
        body = json.dumps(
            {
                "path": self.path,
                "headers": dict(self.headers),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if len(sys.argv) > 2:
    socket_path = "/run/backend/http.sock"
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    unix = socketserver.ThreadingUnixStreamServer(socket_path, Echo)
    # The fixture is shared with DynamicUser services and OCI sidecars.
    os.chmod(socket_path, 0o666)
    threading.Thread(target=unix.serve_forever, daemon=True).start()
    tls = http.server.ThreadingHTTPServer((sys.argv[1], 3001), Echo)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/run/certs/cert.pem", "/run/certs/key.pem")
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    threading.Thread(target=tls.serve_forever, daemon=True).start()
    legacy = http.server.ThreadingHTTPServer((sys.argv[1], 3002), Echo)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/run/certs/cert.pem", "/run/certs/key.pem")
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("AES128-SHA:@SECLEVEL=0")
    legacy.socket = context.wrap_socket(legacy.socket, server_side=True)
    threading.Thread(target=legacy.serve_forever, daemon=True).start()

http.server.ThreadingHTTPServer((sys.argv[1], 3000), Echo).serve_forever()
