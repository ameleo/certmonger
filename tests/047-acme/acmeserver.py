#!/usr/bin/python3
#
# A minimal ACME (RFC 8555) server for testing acme-submit.  It checks the
# JWS of every request, requires an external account binding when given
# one, and either authorizes the names of an order at once, as a CA which
# trusts the external account does, or requires a dns-01 challenge for
# each name, which it checks by asking a DNS server, or a device-attest-01
# challenge (draft-ietf-acme-device-attest) answered with a WebAuthn "tpm"
# attestation statement, whose attestation key it certifies itself after
# importing an HMAC key under the TPM's endorsement key.  It signs requests
# using the openssl command.  Each request is logged, one line at a time.

import argparse
import base64
import datetime
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import \
    decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text):
    text = text.replace("+", "-").replace("/", "_").rstrip("=")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64(data):
    return base64.b64encode(data).decode()


def tpm2b(data):
    return struct.pack(">H", len(data)) + data


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def bytes(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated structure")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.bytes(1)[0]

    def u16(self):
        return struct.unpack(">H", self.bytes(2))[0]

    def u32(self):
        return struct.unpack(">I", self.bytes(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.bytes(8))[0]

    def tpm2b(self):
        return self.bytes(self.u16())

    def done(self):
        return self.pos == len(self.data)


def cbor_decode(data):
    """Decode the subset of CBOR which attestation objects use."""
    def item(pos):
        ib = data[pos]
        major, info = ib >> 5, ib & 0x1f
        pos += 1
        if info < 24:
            value = info
        elif info in (24, 25, 26, 27):
            n = 1 << (info - 24)
            value = int.from_bytes(data[pos:pos + n], "big")
            pos += n
        else:
            raise ValueError("indefinite lengths are not supported")
        if major == 0:
            return value, pos
        if major == 1:
            return -1 - value, pos
        if major in (2, 3):
            raw = data[pos:pos + value]
            if len(raw) != value:
                raise ValueError("truncated CBOR")
            return (raw if major == 2 else raw.decode()), pos + value
        if major == 4:
            out = []
            for _ in range(value):
                v, pos = item(pos)
                out.append(v)
            return out, pos
        if major == 5:
            out = {}
            for _ in range(value):
                k, pos = item(pos)
                v, pos = item(pos)
                out[k] = v
            return out, pos
        raise ValueError("unsupported CBOR type %d" % major)
    value, pos = item(0)
    if pos != len(data):
        raise ValueError("trailing data after CBOR item")
    return value


# TPM constants
TPM_GENERATED = 0xff544347
ST_ATTEST_CERTIFY = 0x8017
ALG_RSA, ALG_KEYEDHASH, ALG_SHA256, ALG_HMAC, ALG_NULL = \
    0x0001, 0x0008, 0x000b, 0x0005, 0x0010
ALG_RSASSA, ALG_ECDSA, ALG_ECC = 0x0014, 0x0018, 0x0023
FIXED_TPM, FIXED_PARENT, SENSITIVE_DATA_ORIGIN = 1 << 1, 1 << 4, 1 << 5
USER_WITH_AUTH, NO_DA, RESTRICTED, DECRYPT, SIGN = \
    1 << 6, 1 << 10, 1 << 16, 1 << 17, 1 << 18
CURVES = {0x0003: ec.SECP256R1(), 0x0004: ec.SECP384R1()}


def parse_public(tpmt):
    """Read a TPMT_PUBLIC: its attributes and its public key."""
    r = Reader(tpmt)
    kind, name_alg, attributes = r.u16(), r.u16(), r.u32()
    r.tpm2b()
    sym = r.u16()
    if sym != ALG_NULL:
        r.u16()
        r.u16()
    scheme = r.u16()
    scheme_hash = r.u16() if scheme != ALG_NULL else None
    if kind == ALG_RSA:
        bits, exponent = r.u16(), r.u32()
        n = int.from_bytes(r.tpm2b(), "big")
        key = rsa.RSAPublicNumbers(exponent or 65537, n).public_key()
    elif kind == ALG_ECC:
        curve = r.u16()
        kdf = r.u16()
        if kdf != ALG_NULL:
            r.u16()
        x = int.from_bytes(r.tpm2b(), "big")
        y = int.from_bytes(r.tpm2b(), "big")
        key = ec.EllipticCurvePublicNumbers(x, y, CURVES[curve]).public_key()
    else:
        raise ValueError("unsupported key type %#x" % kind)
    if not r.done():
        raise ValueError("trailing data in the public area")
    if name_alg != ALG_SHA256:
        raise ValueError("unsupported name algorithm")
    name = struct.pack(">H", ALG_SHA256) + hashlib.sha256(tpmt).digest()
    return attributes, (scheme, scheme_hash), key, name


def parse_attest(attest, qualifying_data, certified_name):
    r = Reader(attest)
    if r.u32() != TPM_GENERATED or r.u16() != ST_ATTEST_CERTIFY:
        raise ValueError("not a TPM2_Certify statement")
    signer = r.tpm2b()
    if len(signer) != 34 or signer[:2] != b"\x00\x0b":
        raise ValueError("malformed qualified signer")
    if r.tpm2b() != qualifying_data:
        raise ValueError("extraData does not match")
    r.u64(), r.u32(), r.u32(), r.u8(), r.u64()
    name = r.tpm2b()
    qualified = r.tpm2b()
    if not r.done():
        raise ValueError("trailing data in the statement")
    if name != certified_name:
        raise ValueError("the statement certifies another key")
    if len(qualified) != len(name) or qualified[:2] != name[:2] or \
            qualified == name:
        raise ValueError("bad qualified name (external object?)")


def kdfa(key, label, context_u, context_v, bits):
    out = b""
    i = 1
    while len(out) * 8 < bits:
        out += hmac.new(key, struct.pack(">I", i) + label.encode() + b"\0" +
                        context_u + context_v + struct.pack(">I", bits),
                        hashlib.sha256).digest()
        i += 1
    return out[:bits // 8]


def make_import(ek_public):
    """An HMAC key which only the TPM of the (RSA-2048) EK can import."""
    secret = secrets.token_bytes(32)
    seed_value = secrets.token_bytes(32)
    public = struct.pack(">HHI", ALG_KEYEDHASH, ALG_SHA256,
                         USER_WITH_AUTH | NO_DA | RESTRICTED | SIGN)
    public += tpm2b(b"") + struct.pack(">HH", ALG_HMAC, ALG_SHA256)
    public += tpm2b(hashlib.sha256(seed_value + secret).digest())
    name = struct.pack(">H", ALG_SHA256) + hashlib.sha256(public).digest()
    sensitive = struct.pack(">H", ALG_KEYEDHASH) + tpm2b(b"") + \
        tpm2b(seed_value) + tpm2b(secret)
    seed = secrets.token_bytes(32)
    encrypted_seed = ek_public.encrypt(
        seed, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                           algorithm=hashes.SHA256(), label=b"DUPLICATE\0"))
    sym_key = kdfa(seed, "STORAGE", name, b"", 128)
    enc = Cipher(algorithms.AES(sym_key), modes.CFB(b"\0" * 16)).encryptor()
    encrypted = enc.update(tpm2b(sensitive)) + enc.finalize()
    hmac_key = kdfa(seed, "INTEGRITY", b"", b"", 256)
    integrity = hmac.new(hmac_key, encrypted + name, hashlib.sha256).digest()
    duplicate = tpm2b(tpm2b(integrity) + encrypted)
    return tpm2b(public), duplicate, tpm2b(encrypted_seed), secret, name


def verify_tpm_signature(key, alg, sig, data):
    """The "sig" of a WebAuthn "tpm" statement, as WebAuthn (8.3) defines
    it: a TPMT_SIGNATURE (TPM 2.0 Part 2, 11.3.4), whose scheme and hash are
    those which "alg" names."""
    r = Reader(sig)
    scheme = (r.u16(), r.u16())
    if alg == -257 and scheme == (ALG_RSASSA, ALG_SHA256):
        signature = r.tpm2b()
        if not r.done():
            raise ValueError("trailing data after TPMT_SIGNATURE")
        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    elif alg == -7 and scheme == (ALG_ECDSA, ALG_SHA256):
        sig_r = int.from_bytes(r.tpm2b(), "big")
        sig_s = int.from_bytes(r.tpm2b(), "big")
        if not r.done():
            raise ValueError("trailing data after TPMT_SIGNATURE")
        key.verify(encode_dss_signature(sig_r, sig_s), data,
                   ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("signature scheme does not match alg")


def self_test():
    """Check that verify_tpm_signature() accepts a TPMT_SIGNATURE, and
    refuses anything else, so that the tests show what the helper sends."""
    data = b"certInfo"
    ec_key = ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(65537, 2048)
    r, s = decode_dss_signature(ec_key.sign(data, ec.ECDSA(hashes.SHA256())))
    ecdsa = struct.pack(">HH", ALG_ECDSA, ALG_SHA256) + \
        tpm2b(r.to_bytes(32, "big")) + tpm2b(s.to_bytes(32, "big"))
    bare_rsa = rsa_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    rsassa = struct.pack(">HH", ALG_RSASSA, ALG_SHA256) + tpm2b(bare_rsa)
    other = ec_key.sign(b"something else", ec.ECDSA(hashes.SHA256()))
    o_r, o_s = decode_dss_signature(other)
    verify_tpm_signature(ec_key.public_key(), -7, ecdsa, data)
    verify_tpm_signature(rsa_key.public_key(), -257, rsassa, data)
    nonsense = [
        (ec_key, -7, b"", "nothing"),
        (ec_key, -7, os.urandom(72), "random bytes"),
        (ec_key, -7, encode_dss_signature(r, s), "a DER ECDSA signature"),
        (rsa_key, -257, bare_rsa, "a bare RSA signature"),
        (ec_key, -7, ecdsa + b"\0", "trailing data"),
        (ec_key, -7, ecdsa[:-1], "a truncated structure"),
        (ec_key, -7, struct.pack(">HH", ALG_ECDSA, 0x000c) + ecdsa[4:],
         "another hash"),
        (rsa_key, -257, struct.pack(">HH", 0x0016, ALG_SHA256) + rsassa[4:],
         "another scheme"),
        (ec_key, -257, ecdsa, "another alg"),
        (ec_key, -7, ecdsa[:4] + tpm2b(o_r.to_bytes(32, "big")) +
         tpm2b(o_s.to_bytes(32, "big")), "a signature of other data"),
    ]
    for key, alg, sig, what in nonsense:
        try:
            verify_tpm_signature(key.public_key(), alg, sig, data)
        except Exception:
            continue
        sys.exit("sig accepted: %s" % what)
    print("sig: TPMT_SIGNATURE accepted, anything else refused")


def dns_query(server, name, rtype=16):
    """Ask a DNS server (HOST:PORT) for the records of a name, and return
    the rcode, the TXT strings (or names, for CNAMEs) and the CNAME target,
    if the name is an alias."""
    host, port = server.rsplit(":", 1)
    qid = secrets.randbelow(65536)
    query = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\0" + struct.pack(">HH", rtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, (host, int(port)))
        while True:
            msg, _ = sock.recvfrom(65535)
            if struct.unpack(">H", msg[:2])[0] == qid:
                break

    def read_name(pos):
        labels, jumped, end = [], False, pos
        while True:
            n = msg[pos]
            if n & 0xc0 == 0xc0:
                if not jumped:
                    end = pos + 2
                pos, jumped = ((n & 0x3f) << 8) | msg[pos + 1], True
                continue
            if n == 0:
                return ".".join(labels).lower(), (end if jumped else pos + 1)
            labels.append(msg[pos + 1:pos + 1 + n].decode())
            pos += 1 + n
    flags, qd, an = struct.unpack(">HHH", msg[2:8])
    pos = 12
    for _ in range(qd):
        _, pos = read_name(pos)
        pos += 4
    values, cname = [], None
    for _ in range(an):
        owner, pos = read_name(pos)
        rr_type, _, _, length = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        rdata = msg[pos:pos + length]
        if rr_type == 5 and owner == name.lower():
            cname, _ = read_name(pos)
        elif rr_type == 16 and owner == name.lower():
            text, i = b"", 0
            while i < len(rdata):
                text += rdata[i + 1:i + 1 + rdata[i]]
                i += 1 + rdata[i]
            values.append(text.decode())
        pos += length
    return flags & 0xf, values, cname


class Problem(Exception):
    def __init__(self, code, kind, detail):
        self.code, self.kind, self.detail = code, kind, detail


class State:
    def __init__(self, opts):
        self.opts = opts
        self.lock = threading.Lock()
        self.nonces = set()
        self.accounts = {}
        self.orders = {}
        self.sessions = {}
        self.bad_nonce = opts.bad_nonce
        self.counter = 0
        with open(opts.ca_key, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(f.read(), None)
        with open(opts.ca, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def next_id(self):
        self.counter += 1
        return str(self.counter)

    def nonce(self):
        n = b64u(secrets.token_bytes(16))
        self.nonces.add(n)
        return n


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    @property
    def state(self):
        return self.server.state

    def log(self, what):
        with open(self.state.opts.log, "a") as f:
            f.write(what + "\n")

    def url(self, path):
        return "https://%s%s" % (self.headers["Host"], path)

    def reply(self, code, body=None, ctype="application/json", headers=()):
        data = b""
        if body is not None:
            data = body if isinstance(body, bytes) else \
                json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Replay-Nonce", self.state.nonce())
        self.send_header("Cache-Control", "no-store")
        if body is not None:
            self.send_header("Content-Type", ctype)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def problem(self, p):
        self.log("  -> %d %s: %s" % (p.code, p.kind, p.detail))
        kind = p.kind if ":" in p.kind else "urn:ietf:params:acme:error:" + \
            p.kind
        self.reply(p.code, {"type": kind, "detail": p.detail},
                   "application/problem+json")

    def directory(self):
        meta = {}
        if self.state.opts.eab_kid:
            meta["externalAccountRequired"] = True
        return {"newNonce": self.url("/new-nonce"),
                "newAccount": self.url("/new-account"),
                "newOrder": self.url("/new-order"),
                "meta": meta}

    def do_HEAD(self):
        self.log("HEAD " + self.path)
        self.reply(200)

    def do_GET(self):
        self.log("GET " + self.path)
        if self.path == "/directory":
            self.reply(200, self.directory())
        elif self.path == "/new-nonce":
            self.reply(204)
        else:
            self.reply(404)

    # JWS
    def verify_jws(self, body, expect_jwk=False):
        st = self.state
        try:
            jws = json.loads(body)
            protected = json.loads(unb64u(jws["protected"]))
            payload_b64 = jws["payload"]
            signature = unb64u(jws["signature"])
        except Exception:
            raise Problem(400, "malformed", "not a flattened JWS")
        if protected.get("alg") != "ES256":
            raise Problem(400, "badSignatureAlgorithm", "ES256 only")
        if st.bad_nonce:
            st.bad_nonce = False
            raise Problem(400, "badNonce", "try again")
        nonce = protected.get("nonce")
        if nonce not in st.nonces:
            raise Problem(400, "badNonce", "unknown nonce")
        st.nonces.discard(nonce)
        if protected.get("url") != self.url(self.path):
            raise Problem(401, "unauthorized", "url mismatch")
        if ("jwk" in protected) == ("kid" in protected):
            raise Problem(400, "malformed", "need exactly one of jwk, kid")
        account = None
        if "jwk" in protected:
            if not expect_jwk:
                raise Problem(400, "malformed", "use kid")
            jwk = protected["jwk"]
        else:
            if expect_jwk:
                raise Problem(400, "malformed", "use jwk")
            kid = protected["kid"]
            account = st.accounts.get(kid)
            if account is None:
                raise Problem(400, "accountDoesNotExist", "no such account")
            jwk = account["jwk"]
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise Problem(400, "badPublicKey", "P-256 only")
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(unb64u(jwk["x"]), "big"),
            int.from_bytes(unb64u(jwk["y"]), "big"),
            ec.SECP256R1()).public_key()
        if len(signature) != 64:
            raise Problem(400, "malformed", "bad ES256 signature length")
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                   int.from_bytes(signature[32:], "big"))
        try:
            key.verify(der, (jws["protected"] + "." + payload_b64).encode(),
                       ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise Problem(401, "unauthorized", "bad signature")
        payload = unb64u(payload_b64) if payload_b64 else None
        return jwk, account, payload

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        path = self.path
        with self.state.lock:
            try:
                if path.startswith("/attest/v1/ak/"):
                    self.log("POST " + path)
                    return self.attest_service(path, json.loads(body))
                if self.headers.get("Content-Type") != \
                        "application/jose+json":
                    raise Problem(415, "malformed", "wrong content type")
                if path == "/new-account":
                    return self.new_account(body)
                jwk, account, payload = self.verify_jws(body)
                self.log("POST %s%s" % (path, "" if payload is not None
                                        else " (POST-as-GET)"))
                if path == "/new-order":
                    return self.new_order(account, payload)
                parts = path.strip("/").split("/")
                order = self.state.orders.get(parts[1]) \
                    if len(parts) > 1 else None
                if order is None or order["account"] != account["kid"]:
                    raise Problem(404, "malformed", "no such resource")
                if parts[0] == "order" and len(parts) == 2:
                    return self.get_order(order)
                if parts[0] == "order" and parts[2:] == ["finalize"]:
                    return self.finalize(account, order, payload)
                if parts[0] == "authz" and "authzs" in order:
                    return self.get_dns_authz(account, order, parts)
                if parts[0] == "chall" and "authzs" in order:
                    return self.dns_challenge(order, parts, payload)
                if parts[0] == "authz":
                    return self.get_authz(order)
                if parts[0] == "chall":
                    return self.challenge(account, order, payload)
                if parts[0] == "cert":
                    return self.reply(200, order["chain"],
                                      "application/pem-certificate-chain")
                raise Problem(404, "malformed", "no such resource")
            except Problem as p:
                self.problem(p)

    def new_account(self, body):
        st = self.state
        jwk, _, payload = self.verify_jws(body, expect_jwk=True)
        request = json.loads(payload)
        thumb = b64u(hashlib.sha256(json.dumps(
            jwk, sort_keys=True, separators=(",", ":")).encode()).digest())
        eab = request.get("externalAccountBinding")
        self.log("POST /new-account%s" % (" (eab)" if eab else ""))
        if st.opts.eab_kid:
            if eab is None:
                raise Problem(401, "externalAccountRequired", "need EAB")
            eprot = json.loads(unb64u(eab["protected"]))
            if eprot.get("alg") != "HS256" or \
                    eprot.get("kid") != st.opts.eab_kid or \
                    eprot.get("url") != self.url("/new-account"):
                raise Problem(401, "unauthorized", "bad EAB header")
            if json.loads(unb64u(eab["payload"])) != jwk:
                raise Problem(401, "unauthorized", "EAB binds another key")
            mac = hmac.new(unb64u(st.opts.eab_key),
                           (eab["protected"] + "." +
                            eab["payload"]).encode(),
                           hashlib.sha256).digest()
            if not hmac.compare_digest(mac, unb64u(eab["signature"])):
                raise Problem(401, "unauthorized", "bad EAB MAC")
        for kid, account in st.accounts.items():
            if account["thumb"] == thumb:
                return self.reply(200, {"status": "valid"},
                                  headers=[("Location", kid)])
        kid = self.url("/acct/" + st.next_id())
        st.accounts[kid] = {"kid": kid, "jwk": jwk, "thumb": thumb}
        self.reply(201, {"status": "valid"}, headers=[("Location", kid)])

    def new_order(self, account, payload):
        st = self.state
        identifiers = json.loads(payload)["identifiers"]
        self.log("  identifiers: " + ", ".join(
            "%s:%s" % (i["type"], i["value"]) for i in identifiers))
        if st.opts.attest:
            if len(identifiers) != 1 or \
                    identifiers[0]["type"] != "permanent-identifier":
                raise Problem(400, "rejectedIdentifier",
                              "one permanent-identifier expected")
            if st.opts.device_id and \
                    identifiers[0]["value"] != st.opts.device_id:
                raise Problem(400, "rejectedIdentifier", "unknown device")
        elif any(i["type"] not in ("dns", "ip") for i in identifiers):
            raise Problem(400, "rejectedIdentifier", "dns or ip only")
        oid = st.next_id()
        order = {"id": oid, "account": account["kid"],
                 "identifiers": identifiers, "status": "pending",
                 "processing": 0, "token": b64u(secrets.token_bytes(16)),
                 "authz": "pending" if st.opts.attest or st.opts.offer
                 else "valid", "attested": None}
        if st.opts.offer == "dns-01":
            # One authorization for each name; that of a wildcard name is
            # for the name without its "*." label (RFC 8555 7.1.3).
            order["authzs"] = []
            for i in identifiers:
                wildcard = i["value"].startswith("*.")
                order["authzs"].append({
                    "identifier": {"type": "dns", "value":
                                   i["value"][2:] if wildcard
                                   else i["value"]},
                    "wildcard": wildcard, "status": "pending",
                    "challenge": "pending",
                    "token": b64u(secrets.token_bytes(16))})
        if order["authz"] == "valid":
            order["status"] = "ready"
        st.orders[oid] = order
        self.reply(201, self.order_json(order),
                   headers=[("Location", self.url("/order/" + oid))])

    def order_json(self, order):
        out = {"status": order["status"],
               "identifiers": order["identifiers"],
               "authorizations": [self.url("/authz/%s/%d" % (order["id"], i))
                                  for i in range(len(order.get("authzs",
                                                               [0])))],
               "finalize": self.url("/order/%s/finalize" % order["id"])}
        if order["status"] == "valid":
            out["certificate"] = self.url("/cert/" + order["id"])
        if order.get("error"):
            out["error"] = order["error"]
        return out

    def get_order(self, order):
        headers = []
        if order["status"] == "processing":
            order["processing"] -= 1
            if order["processing"] <= 0:
                order["status"] = "valid"
            else:
                headers.append(("Retry-After",
                                str(self.state.opts.retry_after)))
        self.reply(200, self.order_json(order), headers=headers)

    def get_authz(self, order):
        st = self.state
        challenges = []
        if st.opts.attest:
            challenges.append({"type": "device-attest-01",
                               "url": self.url("/chall/" + order["id"]),
                               "status": order["authz"],
                               "token": order["token"]})
        elif st.opts.offer:
            challenges.append({"type": st.opts.offer,
                               "url": self.url("/chall/" + order["id"]),
                               "status": order["authz"],
                               "token": order["token"]})
        self.reply(200, {"status": order["authz"],
                         "identifier": order["identifiers"][0],
                         "challenges": challenges})

    # dns-01
    def dns_authz(self, order, parts):
        try:
            return int(parts[2]), order["authzs"][int(parts[2])]
        except (IndexError, ValueError):
            raise Problem(404, "malformed", "no such authorization")

    def dns_challenge_json(self, order, index, authz):
        out = {"type": "dns-01",
               "url": self.url("/chall/%s/%d" % (order["id"], index)),
               "status": authz["challenge"], "token": authz["token"]}
        if authz.get("error"):
            out["error"] = authz["error"]
        return out

    def dns_check(self, account, order, authz):
        """Look for the TXT record, as a CA does, following a CNAME."""
        st = self.state
        name = "_acme-challenge." + authz["identifier"]["value"]
        expected = b64u(hashlib.sha256(
            (authz["token"] + "." + account["thumb"]).encode()).digest())
        seen, via = [], ""
        for _ in range(8):
            rcode, seen, cname = dns_query(st.opts.dns_server, name)
            if cname is None or seen:
                break
            name, via = cname, " (via %s)" % cname
        if expected in seen and not st.opts.dns_fail:
            authz["status"] = authz["challenge"] = "valid"
            self.log("  dns-01 %s%s: TXT record found%s" %
                     (authz["identifier"]["value"],
                      " (wildcard)" if authz["wildcard"] else "", via))
        else:
            authz["status"] = authz["challenge"] = "invalid"
            authz["error"] = {"type": "urn:ietf:params:acme:error:"
                              "unauthorized",
                              "detail": "no TXT record with the expected "
                              "value at %s" % name}
            self.log("  dns-01 %s: TXT record %s%s" %
                     (authz["identifier"]["value"],
                      "found, but refused" if expected in seen
                      else "not found", via))
        statuses = [a["status"] for a in order["authzs"]]
        if "invalid" in statuses:
            order["status"] = "invalid"
        elif all(s == "valid" for s in statuses):
            order["status"] = "ready"

    def get_dns_authz(self, account, order, parts):
        index, authz = self.dns_authz(order, parts)
        if authz["challenge"] == "processing":
            self.dns_check(account, order, authz)
        out = {"status": authz["status"],
               "identifier": authz["identifier"],
               "challenges": [self.dns_challenge_json(order, index, authz)]}
        if authz["wildcard"]:
            out["wildcard"] = True
        self.reply(200, out)

    def dns_challenge(self, order, parts, payload):
        index, authz = self.dns_authz(order, parts)
        if payload == b"{}" and authz["challenge"] == "pending":
            # Checked the next time the client looks.
            authz["challenge"] = "processing"
        self.reply(200, self.dns_challenge_json(order, index, authz),
                   headers=[("Link", "<%s>;rel=\"up\"" % self.url(
                       "/authz/%s/%d" % (order["id"], index)))])

    def challenge(self, account, order, payload):
        st = self.state
        chall = {"type": "device-attest-01",
                 "url": self.url("/chall/" + order["id"]),
                 "token": order["token"]}
        if payload and payload != b"{}" and order["authz"] == "pending":
            answer = json.loads(payload)
            key_authorization = order["token"] + "." + account["thumb"]
            try:
                order["attested"] = self.verify_attestation(
                    unb64u(answer["attObj"]), key_authorization)
                order["authz"] = "valid"
                order["status"] = "ready"
                self.log("  attestation verified")
            except Exception as e:
                order["authz"] = "invalid"
                order["status"] = "invalid"
                order["error"] = {
                    "type": "urn:ietf:params:acme:error:"
                            "badAttestationStatement",
                    "detail": str(e)}
                self.log("  attestation refused: %s" % e)
        chall["status"] = order["authz"]
        if order.get("error"):
            chall["error"] = order["error"]
        self.reply(200, chall)

    def verify_attestation(self, att_obj, key_authorization):
        st = self.state
        obj = cbor_decode(att_obj)
        if set(obj) != {"fmt", "attStmt"} or obj["fmt"] != "tpm":
            raise ValueError("not a tpm attestation object without authData")
        stmt = obj["attStmt"]
        if set(stmt) != {"ver", "alg", "x5c", "sig", "certInfo",
                         "pubArea"} or stmt["ver"] != "2.0":
            raise ValueError("malformed tpm attestation statement")
        ak_cert = x509.load_der_x509_certificate(stmt["x5c"][0])
        st.ca_key.public_key().verify(
            ak_cert.signature, ak_cert.tbs_certificate_bytes,
            ec.ECDSA(ak_cert.signature_hash_algorithm))
        eku = ak_cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
        if x509.ObjectIdentifier("2.23.133.8.3") not in eku:
            raise ValueError("not an AK certificate")
        verify_tpm_signature(ak_cert.public_key(), stmt["alg"], stmt["sig"],
                             stmt["certInfo"])
        attributes, _, key, name = parse_public(stmt["pubArea"])
        need = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | SIGN
        if attributes & need != need or attributes & RESTRICTED:
            raise ValueError("not a device key")
        parse_attest(stmt["certInfo"],
                     hashlib.sha256(key_authorization.encode()).digest(),
                     name)
        return key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.
                                SubjectPublicKeyInfo)

    def finalize(self, account, order, payload):
        st = self.state
        if order["status"] != "ready":
            raise Problem(403, "orderNotReady", "order not ready")
        csr_der = unb64u(json.loads(payload)["csr"])
        csr = x509.load_der_x509_csr(csr_der)
        if order["attested"] is not None and \
                csr.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo) != \
                order["attested"]:
            raise Problem(400, "badCSR", "not the attested key")
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "req.der"), "wb") as f:
                f.write(csr_der)
            ext = os.path.join(d, "ext")
            with open(ext, "w") as f:
                f.write("basicConstraints=CA:FALSE\n")
                if order["attested"] is not None:
                    f.write("certificatePolicies=1.3.6.1.4.1.99999.1.1\n")
            subprocess.run(
                ["openssl", "x509", "-req", "-inform", "DER", "-in",
                 os.path.join(d, "req.der"), "-CA", st.opts.ca,
                 "-CAkey", st.opts.ca_key, "-set_serial",
                 str(secrets.randbelow(1 << 62)), "-days", "1",
                 "-copy_extensions", "copy", "-extfile", ext,
                 "-out", os.path.join(d, "cert.pem")],
                check=True, capture_output=True)
            with open(os.path.join(d, "cert.pem"), "rb") as f:
                chain = f.read()
        with open(st.opts.ca, "rb") as f:
            chain += f.read()
        order["chain"] = chain
        if st.opts.processing:
            order["status"] = "processing"
            order["processing"] = st.opts.processing
            headers = [("Retry-After", str(st.opts.retry_after))]
        else:
            order["status"] = "valid"
            headers = []
        self.reply(200, self.order_json(order), headers=headers +
                   [("Location", self.url("/order/" + order["id"]))])

    # The attestation key certification service.
    def attest_service(self, path, request):
        st = self.state
        if path.endswith("/begin"):
            if request.get("eab_kid") != st.opts.eab_kid:
                raise Problem(403, "unauthorized", "unknown device")
            ak_public = base64.b64decode(request["ak_public"])
            proof = hmac.new(unb64u(st.opts.eab_key), ak_public,
                             hashlib.sha256).digest()
            if not hmac.compare_digest(proof,
                                       base64.b64decode(request["eab_proof"])):
                raise Problem(403, "unauthorized", "bad proof")
            ek_cert = x509.load_der_x509_certificate(
                base64.b64decode(request["ek_certificate"]))
            if st.opts.ek_ca:
                with open(st.opts.ek_ca, "rb") as f:
                    issuer = x509.load_pem_x509_certificate(f.read())
                ek_cert.verify_directly_issued_by(issuer)
            r = Reader(ak_public)
            tpmt = r.tpm2b()
            if not r.done():
                raise Problem(400, "malformed", "ak_public")
            attributes, scheme, ak_key, ak_name = parse_public(tpmt)
            if attributes & (RESTRICTED | SIGN) != RESTRICTED | SIGN or \
                    attributes & DECRYPT:
                raise Problem(400, "malformed", "not an attestation key")
            public, duplicate, seed, secret, hmac_name = \
                make_import(ek_cert.public_key())
            sid = b64u(secrets.token_bytes(16))
            nonce = secrets.token_bytes(32)
            st.sessions[sid] = {"secret": secret, "name": hmac_name,
                                "ak": ak_key, "ak_name": ak_name,
                                "nonce": nonce}
            return self.reply(200, {"session": sid,
                                    "import_public": b64(public),
                                    "import_duplicate": b64(duplicate),
                                    "import_seed": b64(seed),
                                    "nonce": b64(nonce)})
        if path.endswith("/finish"):
            session = st.sessions.pop(request.get("session"), None)
            if session is None:
                raise Problem(403, "unauthorized", "unknown session")
            info = base64.b64decode(request["certify_info"])
            sig = Reader(base64.b64decode(request["certify_signature"]))
            if sig.u16() != ALG_HMAC or sig.u16() != ALG_SHA256:
                raise Problem(400, "malformed", "not an HMAC signature")
            mac = sig.bytes(32)
            expected = hmac.new(session["secret"],
                                hashlib.sha256(info).digest(),
                                hashlib.sha256).digest()
            if not sig.done() or not hmac.compare_digest(mac, expected):
                raise Problem(403, "unauthorized", "bad HMAC")
            try:
                r = Reader(info)
                if r.u32() != TPM_GENERATED or r.u16() != ST_ATTEST_CERTIFY:
                    raise ValueError("not a TPM2_Certify statement")
                if r.tpm2b()[2:] == b"":
                    raise ValueError("bad signer")
                if r.tpm2b() != session["nonce"]:
                    raise ValueError("nonce mismatch")
                r.u64(), r.u32(), r.u32(), r.u8(), r.u64()
                name, qualified = r.tpm2b(), r.tpm2b()
                if name != session["ak_name"] or qualified == name:
                    raise ValueError("certifies another key")
            except ValueError as e:
                raise Problem(403, "unauthorized", str(e))
            now = datetime.datetime.now(datetime.timezone.utc)
            san = x509.DirectoryName(x509.Name([
                x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.1"),
                                   "id:00001014"),
                x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.2"),
                                   "swtpm"),
                x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.3"),
                                   "id:20240125")]))
            cert = x509.CertificateBuilder() \
                .subject_name(x509.Name([])) \
                .issuer_name(st.ca_cert.subject) \
                .public_key(session["ak"]) \
                .serial_number(x509.random_serial_number()) \
                .not_valid_before(now - datetime.timedelta(minutes=5)) \
                .not_valid_after(now + datetime.timedelta(
                    days=st.opts.ak_days)) \
                .add_extension(x509.SubjectAlternativeName([san]),
                               critical=True) \
                .add_extension(x509.ExtendedKeyUsage(
                    [x509.ObjectIdentifier("2.23.133.8.3")]),
                    critical=False) \
                .add_extension(x509.BasicConstraints(ca=False,
                                                     path_length=None),
                               critical=True) \
                .sign(st.ca_key, hashes.SHA256())
            self.log("  attestation key certified")
            return self.reply(200, {
                "ak_certificate": b64(cert.public_bytes(
                    serialization.Encoding.DER)),
                "chain": [b64(st.ca_cert.public_bytes(
                    serialization.Encoding.DER))]})
        raise Problem(404, "malformed", "no such operation")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if sys.argv[1:2] == ["--dns-query"]:
        rcode, values, cname = dns_query(sys.argv[2], sys.argv[3])
        for value in values:
            print(value)
        if cname:
            print("CNAME " + cname)
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--ca-key", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--eab-kid")
    parser.add_argument("--eab-key")
    parser.add_argument("--attest", action="store_true")
    parser.add_argument("--device-id")
    parser.add_argument("--ek-ca")
    parser.add_argument("--ak-days", type=int, default=365)
    parser.add_argument("--offer")
    parser.add_argument("--processing", type=int, default=0)
    parser.add_argument("--retry-after", type=int, default=1)
    parser.add_argument("--bad-nonce", action="store_true")
    parser.add_argument("--dns-server")
    parser.add_argument("--dns-fail", action="store_true")
    opts = parser.parse_args()

    server = http.server.ThreadingHTTPServer(("localhost", 0), Handler)
    server.state = State(opts)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(opts.cert, opts.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    with open(opts.port_file + ".tmp", "w") as f:
        f.write("%d\n" % server.server_address[1])
    os.rename(opts.port_file + ".tmp", opts.port_file)
    server.serve_forever()


if __name__ == "__main__":
    main()
