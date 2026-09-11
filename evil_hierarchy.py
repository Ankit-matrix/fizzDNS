#!/usr/bin/env python3
"""
A DELIBERATELY HOSTILE root/TLD/auth chain, for testing the resolver's
acceptance rules rather than its happy path.

fake_hierarchy.py answers honestly and proves referral following, glue,
CNAME chasing and NODATA work. This one lies, and proves the resolver
refuses to believe it. Every zone here tries a specific attack that a
resolver without bailiwick checks or question matching would fall for,
and the paired test asserts the lie did not land -- in the cache or in
the answer.

    127.0.0.21:53   root   delegates com -> a.gtld.evil (glue .22)
    127.0.0.22:53   com     ATTACK 1  out-of-bailiwick referral
                            ATTACK 2  out-of-bailiwick glue
    127.0.0.23:53   auth    ATTACK 3  out-of-bailiwick answer injection
                            ATTACK 4  in-bailiwick but off-chain injection
                            ATTACK 5  wrong transaction id
                            ATTACK 6  mismatched question section
                            ATTACK 7  bad reply first, then a good one

Separate 127/8 aliases and a separate file from fake_hierarchy.py so the
honest-path tests keep running against an honest server -- mixing the
two would make a failure ambiguous between "the resolver broke" and
"the test server lied to it".

Run:  python3 evil_hierarchy.py
Then: DNS_ROOT_HINTS=127.0.0.21 ./server -p 5355
"""

import socket
import struct
import sys
import threading

TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_AAAA = 1, 2, 5, 28
CLASS_IN = 1

#what the attacker wants us to cache, and must never appear anywhere
EVIL_IP = "6.6.6.6"


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
            sub, _ = decode_name(msg, ptr, depth + 1)
            labels.append(sub)
            off += 2
            break
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
    """A handler may return bytes, or a list of bytes to send several
    datagrams -- attack 7 needs to get a bad reply in before a good one."""

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
                if reply is None:
                    continue
                for pkt in (reply if isinstance(reply, list) else [reply]):
                    self.sock.sendto(pkt, peer)
            except Exception as e:
                print(f"  [{self.label}] {e}", file=sys.stderr)


def root_handler(qid, qname, qtype, question):
    if qname.endswith("com"):
        auth = [rr("com", TYPE_NS, 3600, encode_name("a.gtld.evil"))]
        addl = [rr("a.gtld.evil", TYPE_A, 3600, socket.inet_aton("127.0.0.22"))]
        return build(qid, question, 0x8000, authority=auth, additional=addl)
    return build(qid, question, 0x8003)


def tld_handler(qid, qname, qtype, question):
    """The .com server. It is only allowed to talk about .com."""

    # ATTACK 1: out-of-bailiwick referral. A .com server delegating
    # bank.co.uk, which it has no authority over whatsoever. A resolver
    # that follows this can be walked to any zone in the DNS.
    if qname == "poison.example.com":
        auth = [rr("bank.co.uk", TYPE_NS, 3600, encode_name("ns.attacker.net"))]
        addl = [rr("ns.attacker.net", TYPE_A, 3600, socket.inet_aton(EVIL_IP))]
        return build(qid, question, 0x8000, authority=auth, additional=addl)

    # ATTACK 2: a legitimate delegation carrying an extra glue record for
    # a name outside this zone. Believing it sends every later query for
    # that zone to the attacker's address.
    if qname.endswith("example.com"):
        auth = [rr("example.com", TYPE_NS, 3600, encode_name("ns1.example.com"))]
        addl = [
            rr("ns1.example.com", TYPE_A, 3600, socket.inet_aton("127.0.0.23")),
            rr("ns1.attacker.net", TYPE_A, 3600, socket.inet_aton(EVIL_IP)),
        ]
        return build(qid, question, 0x8000, authority=auth, additional=addl)

    return build(qid, question, 0x8003)


AUTH_RECORDS = {
    "victim.example.com":    {"A": "10.0.0.1"},
    "unrelated.example.com": {"A": "10.0.0.9"},
    "target.example.com":    {"A": "10.0.0.3"},
    "chain.example.com":     {"CNAME": "target.example.com"},
    "ns1.example.com":       {"A": "127.0.0.13"},
}


def auth_handler(qid, qname, qtype, question):
    # ATTACK 5: right question, WRONG transaction id. connect() already
    # restricts the source address, so the id is the only thing left
    # proving this datagram answers the query we actually sent.
    if qname == "badid.example.com":
        ans = [rr(qname, TYPE_A, 300, socket.inet_aton(EVIL_IP))]
        return build(qid ^ 0xBEEF, question, 0x8400, answers=ans)

    # ATTACK 6: right id, question section for a DIFFERENT name. An id
    # is 16 bits; on its own it will happily accept an answer about a
    # name we never asked about.
    if qname == "badq.example.com":
        other = encode_name("somethingelse.example.com") + struct.pack(">HH", TYPE_A, CLASS_IN)
        ans = [rr(qname, TYPE_A, 300, socket.inet_aton(EVIL_IP))]
        return build(qid, other, 0x8400, answers=ans)

    # ATTACK 7: a spoof-shaped reply first, the truth second. Rejecting
    # the bad datagram is not enough -- the resolver has to keep reading
    # until the timeout, or it turns every spoof attempt into a denial
    # of service against a name that does resolve.
    if qname == "racy.example.com":
        evil = [rr(qname, TYPE_A, 300, socket.inet_aton(EVIL_IP))]
        good = [rr(qname, TYPE_A, 300, socket.inet_aton("10.0.0.7"))]
        return [
            build(qid ^ 0x1234, question, 0x8400, answers=evil),
            build(qid, question, 0x8400, answers=good),
        ]

    # ATTACK 3: the real answer, plus an unrequested record for a name in
    # someone else's zone stapled into the ANSWER section.
    if qname == "victim.example.com" and qtype == TYPE_A:
        ans = [
            rr(qname, TYPE_A, 300, socket.inet_aton("10.0.0.1")),
            rr("www.bank.co.uk", TYPE_A, 300, socket.inet_aton(EVIL_IP)),
        ]
        return build(qid, question, 0x8400, answers=ans)

    # ATTACK 4: the sharp one. The injected record is INSIDE this
    # server's zone, so bailiwick alone lets it through -- but it is not
    # on the CNAME chain starting at the queried name, and nobody asked
    # for it. Only the chain check catches this.
    if qname == "offchain.example.com" and qtype == TYPE_A:
        ans = [
            rr(qname, TYPE_A, 300, socket.inet_aton("10.0.0.2")),
            rr("unrelated.example.com", TYPE_A, 300, socket.inet_aton(EVIL_IP)),
        ]
        return build(qid, question, 0x8400, answers=ans)

    rec = AUTH_RECORDS.get(qname)
    if not rec:
        return build(qid, question, 0x8403)

    if "CNAME" in rec:
        ans = [rr(qname, TYPE_CNAME, 300, encode_name(rec["CNAME"]))]
        return build(qid, question, 0x8400, answers=ans)

    if qtype == TYPE_A and "A" in rec:
        ans = [rr(qname, TYPE_A, 300, socket.inet_aton(rec["A"]))]
        return build(qid, question, 0x8400, answers=ans)

    return build(qid, question, 0x8400)          # NODATA


if __name__ == "__main__":
    zones = [
        Zone("127.0.0.21", root_handler, "evil-root"),
        Zone("127.0.0.22", tld_handler, "evil-com"),
        Zone("127.0.0.23", auth_handler, "evil-auth"),
    ]
    for z in zones:
        z.start()
    print("evil hierarchy up: root=127.0.0.21 com=127.0.0.22 "
          "auth=127.0.0.23 (all :53)", flush=True)
    for z in zones:
        z.join()
