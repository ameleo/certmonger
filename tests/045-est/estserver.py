#!/usr/bin/python3
#
# A minimal EST (RFC 7030) server for testing est-submit.  It serves
# /.well-known/est/[label/]{cacerts,simpleenroll,simplereenroll} over TLS,
# requires HTTP Basic authentication for simpleenroll and a client
# certificate issued by its CA for simplereenroll, and signs requests using
# the openssl command.  Each request is logged, one line at a time.

import argparse
import base64
import http.server
import os
import ssl
import subprocess
import sys
import tempfile


def openssl(*args, data=None):
    return subprocess.run(["openssl"] + list(args), input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True).stdout


def certs_only(pem_files):
    args = ["crl2pkcs7", "-nocrl", "-outform", "DER"]
    for f in pem_files:
        args += ["-certfile", f]
    return base64.encodebytes(openssl(*args))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def log(self, what):
        with open(self.server.opts.log, "a") as f:
            f.write(what + "\n")

    def reply(self, code, ctype=None, body=b"", headers=()):
        self.send_response(code)
        if ctype is not None:
            self.send_header("Content-Type", ctype)
            if ctype.startswith("application/pkcs7-mime"):
                self.send_header("Content-Transfer-Encoding", "base64")
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def operation(self):
        path = self.path.split("?")[0]
        prefix = "/.well-known/est/"
        if not path.startswith(prefix):
            return None
        parts = path[len(prefix):].split("/")
        label = self.server.opts.label
        if label is not None:
            if len(parts) != 2 or parts[0] != label:
                return None
            parts = parts[1:]
        if len(parts) != 1:
            return None
        return parts[0]

    def do_GET(self):
        op = self.operation()
        if op != "cacerts":
            self.log("GET %s 404" % self.path)
            self.reply(404, "text/plain", b"not found\n")
            return
        self.log("GET cacerts 200")
        self.reply(200, "application/pkcs7-mime",
                   certs_only(self.server.opts.cacerts))

    def do_POST(self):
        op = self.operation()
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if op not in ("simpleenroll", "simplereenroll"):
            self.log("POST %s 404" % self.path)
            self.reply(404, "text/plain", b"not found\n")
            return
        opts = self.server.opts
        if op == "simpleenroll":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Basic "):
                self.log("POST %s 401 no credentials" % op)
                self.reply(401, "text/plain", b"authentication required\n",
                           [("WWW-Authenticate", 'Basic realm="est"')])
                return
            user, _, password = base64.b64decode(auth[6:]).decode().partition(":")
            if user != opts.user or password != opts.password:
                self.log("POST %s 401 bad credentials for %s" % (op, user))
                self.reply(401, "text/plain", b"bad credentials\n",
                           [("WWW-Authenticate", 'Basic realm="est"')])
                return
            who = "user " + user
        else:
            peer = self.connection.getpeercert()
            if not peer:
                self.log("POST %s 403 no client certificate" % op)
                self.reply(403, "text/plain", b"client certificate required\n")
                return
            subject = dict(x[0] for x in peer["subject"])
            who = "certificate " + subject.get("commonName", "?")
        if self.server.pending > 0:
            self.server.pending -= 1
            self.log("POST %s 202 %s" % (op, who))
            self.reply(202, "text/plain", b"pending\n",
                       [("Retry-After", str(opts.retry_after))])
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/pkcs10":
            self.log("POST %s 415" % op)
            self.reply(415, "text/plain", b"expected application/pkcs10\n")
            return
        csr = base64.b64decode(body)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "req.der"), "wb") as f:
                f.write(csr)
            self.server.serial += 1
            openssl("x509", "-req", "-inform", "DER",
                    "-in", os.path.join(d, "req.der"),
                    "-CA", opts.ca, "-CAkey", opts.ca_key,
                    "-set_serial", str(self.server.serial), "-days", "1",
                    "-out", os.path.join(d, "cert.pem"))
            reply = certs_only([os.path.join(d, "cert.pem")])
        self.log("POST %s 200 %s" % (op, who))
        self.reply(200, "application/pkcs7-mime; smime-type=certs-only",
                   reply)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--ca-key", required=True)
    parser.add_argument("--cacerts", action="append", required=True)
    parser.add_argument("--user", default="user")
    parser.add_argument("--password", default="secret")
    parser.add_argument("--label")
    parser.add_argument("--pending", type=int, default=0)
    parser.add_argument("--retry-after", type=int, default=30)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--log", required=True)
    opts = parser.parse_args()

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.opts = opts
    server.pending = opts.pending
    server.serial = 1000
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(opts.cert, opts.key)
    context.load_verify_locations(opts.ca)
    context.verify_mode = ssl.CERT_OPTIONAL
    server.socket = context.wrap_socket(server.socket, server_side=True)
    with open(opts.port_file + ".tmp", "w") as f:
        f.write("%d\n" % server.server_address[1])
    os.rename(opts.port_file + ".tmp", opts.port_file)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
