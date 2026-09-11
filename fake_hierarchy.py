#!/usr/bin/env python3
"""
A miniature root/TLD/authoritative chain on loopback, so the iterative
resolver can be exercised with no internet access at all.

    127.0.0.11:53   root   delegates .com -> a.gtld.test (glue 127.0.0.12)
                           delegates .net -> ns1.example.com (NO glue)
    127.0.0.12:53   .com   delegates example.com -> ns1.example.com
                           (glue 127.0.0.13)
    127.0.0.13:53   auth   www.example.com    A     93.184.216.34
                           www.example.com    AAAA  2606:2800:220:1:248:1893:25c8:1946
                           ns1.example.com    A     127.0.0.13
                           alias.example.com  CNAME www.example.com
                           deep.example.com   CNAME alias.example.com
                           host.example.net   A     10.9.8.7
                           anything else      NXDOMAIN

All three bind :53 on separate 127/8 aliases, because a referral gives
you an address and never a port -- the resolver always talks to 53.

Referral following, glue handling, CNAME chasing and NODATA (a name
exists but has no record of the requested type -- e.g. host.example.net
has an A but no AAAA) are the things in resolver.c most likely to be
subtly wrong, and testing them against the live roots is slow, flaky,
and gives you no way to construct the interesting cases on demand.

Run:  sudo python3 fake_hierarchy.py
Then: DNS_ROOT_HINTS=127.0.0.11 ./server -p 5354
"""

import socket
import struct
import sys
import threading

TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_AAAA = 1, 2, 5, 28
CLASS_IN = 1

QTYPE_NAMES = {TYPE_A: "A", TYPE_AAAA: "AAAA"}


def encode_name(name):
    out = b""
    if name:
        for label in name.split("."):
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def decode_name(msg, off, depth=0):
    labels = []
    if depth > 10:
        raise ValueError("pointer loop")
    while True:
        if off >= len(msg):
            raise ValueError("overrun")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            off += 2
            sub, _ = decode_name(msg, ptr, depth + 1)
            labels.append(sub)
            return ".".join(labels), off
        labels.append(msg[off + 1:off + 1 + n].decode())
        off += 1 + n
    return ".".join(labels), off


def rr(name, rtype, ttl, rdata):
    return (encode_name(name)
            + struct.pack(">HHIH", rtype, CLASS_IN, ttl, len(rdata))
            + rdata)


def build(qid, question, flags, answers=(), authority=(), additional=()):
    hdr = struct.pack(">HHHHHH", qid, flags, 1,
                      len(answers), len(authority), len(additional))
    return (hdr + question + b"".join(answers)
            + b"".join(authority) + b"".join(additional))


class Zone(threading.Thread):
    def __init__(self, addr, handler, label):
        super().__init__(daemon=True)
        self.handler = handler
        self.label = label
        self.queries = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((addr, 53))

    def run(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(1500)
            except OSError:
                return
            try:
                qid = struct.unpack(">H", data[:2])[0]
                qname, off = decode_name(data, 12)
                qtype, _ = struct.unpack(">HH", data[off:off + 4])
                question = data[12:off + 4]
                self.queries += 1
                reply = self.handler(qid, qname.lower(), qtype, question)
                if reply:
                    self.sock.sendto(reply, peer)
            except Exception as e:
                print(f"  [{self.label}] {e}", file=sys.stderr)


def root_handler(qid, qname, qtype, question):
    # .com referral, with glue
    if qname.endswith("com"):
        auth = [rr("com", TYPE_NS, 3600, encode_name("a.gtld.test"))]
        addl = [rr("a.gtld.test", TYPE_A, 3600, socket.inet_aton("127.0.0.12"))]
        return build(qid, question, 0x8000, authority=auth, additional=addl)
    # .net referral with NO glue, forcing out-of-band NS resolution
    if qname.endswith("net"):
        auth = [rr("net", TYPE_NS, 3600, encode_name("ns1.example.com"))]
        return build(qid, question, 0x8000, authority=auth)
    return build(qid, question, 0x8003)          # NXDOMAIN


def tld_handler(qid, qname, qtype, question):
    if qname.endswith("example.com"):
        auth = [rr("example.com", TYPE_NS, 3600,
                   encode_name("ns1.example.com"))]
        addl = [rr("ns1.example.com", TYPE_A, 3600,
                   socket.inet_aton("127.0.0.13"))]
        return build(qid, question, 0x8000, authority=auth, additional=addl)
    return build(qid, question, 0x8003)


# name -> { "A": ..., "AAAA": ..., "CNAME": ... }. A name with a CNAME
# has ONLY a CNAME entry, matching real zone files. A name can have A
# without AAAA (host.example.net) -- that's what exercises NODATA.
AUTH_RECORDS = {
    "www.example.com": {
        "A": "93.184.216.34",
        "AAAA": "2606:2800:220:1:248:1893:25c8:1946",
    },
    "ns1.example.com":   {"A": "127.0.0.13"},
    "alias.example.com": {"CNAME": "www.example.com"},
    "deep.example.com":  {"CNAME": "alias.example.com"},
    "host.example.net":  {"A": "10.9.8.7"},          # no AAAA: NODATA case
}


# Engineered long CNAME chain, purely to give the TCP fallback tests a
# response that genuinely can't fit in dns_build_response()'s 512 byte
# UDP cap. Every other name in this file resolves to a handful of
# records that comfortably fit under 512 bytes, so none of them can
# exercise the TC path at all.
#
# Two max-length (63 byte) labels per hop name make each encoded name
# ~141 bytes on the wire. With BIG_HOP1 as the query name:
#   header (12) + question (~145)                        = ~157
#   answer 1: CNAME, owner compressed to offset 12 (2 bytes)
#             + fixed RR fields (10) + target name (~141) = ~153  -> o=310
#   answer 2: CNAME, owner written in full (~141, since its
#             owner != the original qname, so not compressible)
#             + fixed RR fields (10) + target name (~141) = ~292
# 310 + 292 = 602 > 512, and specifically the owner of answer 2 (141
# bytes) fits in the 202 bytes remaining, but its target name (also
# 141 bytes) needs more than the ~51 bytes left after that -- so
# dns_build_response() rewinds the whole of answer 2, sets TC, and
# emits only answer 1. Over TCP (cap 65535) all three records
# (2 CNAMEs + the final A) fit with room to spare.
def _max_label(ch):
    return ch * 63


BIG_HOP1 = f"{_max_label('a')}.{_max_label('b')}.example.com"
BIG_HOP2 = f"{_max_label('c')}.{_max_label('d')}.example.com"
BIG_HOP3 = f"{_max_label('e')}.{_max_label('f')}.example.com"

AUTH_RECORDS[BIG_HOP1] = {"CNAME": BIG_HOP2}
AUTH_RECORDS[BIG_HOP2] = {"CNAME": BIG_HOP3}
AUTH_RECORDS[BIG_HOP3] = {"A": "10.0.0.2"}


def auth_handler(qid, qname, qtype, question):
    rec = AUTH_RECORDS.get(qname)
    if not rec:
        return build(qid, question, 0x8403)      # AA + NXDOMAIN

    # A CNAME answers regardless of qtype, same as a real authoritative
    # server: the owner name is an alias, it has no other record types.
    if "CNAME" in rec:
        ans = [rr(qname, TYPE_CNAME, 300, encode_name(rec["CNAME"]))]
        return build(qid, question, 0x8400, answers=ans)   # AA + NOERROR

    type_name = QTYPE_NAMES.get(qtype)
    val = rec.get(type_name) if type_name else None

    if val is None:
        # Name exists, zone is authoritative for it, but nothing of the
        # requested type -- NOERROR with an empty answer section
        # (NODATA), not NXDOMAIN.
        return build(qid, question, 0x8400)

    if type_name == "A":
        ans = [rr(qname, TYPE_A, 300, socket.inet_aton(val))]
    else:
        ans = [rr(qname, TYPE_AAAA, 300, socket.inet_pton(socket.AF_INET6, val))]
    return build(qid, question, 0x8400, answers=ans)


if __name__ == "__main__":
    zones = [
        Zone("127.0.0.11", root_handler, "root"),
        Zone("127.0.0.12", tld_handler, "com"),
        Zone("127.0.0.13", auth_handler, "auth"),
    ]
    for z in zones:
        z.start()
    print("fake hierarchy up: root=127.0.0.11 com=127.0.0.12 "
          "auth=127.0.0.13 (all :53)", flush=True)
    for z in zones:
        z.join()