#!/usr/bin/env python3
"""
Integration test for the iterative resolver.

Assumes fake_hierarchy.py is running and a resolver is listening on
127.0.0.1:5354 (both UDP and TCP) with DNS_ROOT_HINTS=127.0.0.11.
`make offline` wires all of that up.

Covers the cases that are hard to trigger against the live roots and
easy to get wrong:

  - a plain referral chain with glue at every step
  - a referral with NO glue, where the NS name has to be resolved first
  - a single CNAME, where the client must get BOTH the CNAME and the A
  - a two hop CNAME chain, in order
  - an authoritative NXDOMAIN, which must be rcode 3 and not SERVFAIL
  - a repeat query, which must come from cache
  - mixed case, which must be echoed back byte for byte (DNS-0x20)
  - malformed input, which must not produce a reply or a crash
  - an AAAA query against a host that has one, resolved through the
    same referral chain as A
  - an AAAA query against a host that only has an A record: NODATA,
    rcode NOERROR with zero answers, NOT SERVFAIL and NOT NXDOMAIN
  - TCP: the same lookups working over TCP framing
  - TCP: RFC 7766 pipelining -- more than one query per connection
  - TCP fallback proper -- a response too big for UDP comes back with
    TC=1 and a truncated answer, and the SAME query over TCP comes
    back with TC=0 and the complete answer
  - TCP: a connection that sends a length prefix but never the promised
    body must close cleanly, and the server must still be healthy for
    the next client afterward
"""

import socket
import struct
import sys
import time

from fake_hierarchy import BIG_HOP1, BIG_HOP2, BIG_HOP3  # noqa: F401 (HOP2 kept for readability)

HOST, PORT = "127.0.0.1", 5354
TCP_PORT = PORT  # server.c binds TCP on the same -p value as UDP
failures = []


def check(cond, label, detail=""):
    if cond:
        print(f"  ok    {label}" + (f" ({detail})" if detail else ""))
    else:
        print(f"  FAIL  {label}" + (f" ({detail})" if detail else ""))
        failures.append(label)


def encode_query(name, qid, qtype=1):
    b = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        b += bytes([len(label)]) + label.encode()
    return b + b"\x00" + struct.pack(">HH", qtype, 1)

def encode_query_edns(name, qid, qtype=1, payload=1232, do_bit=False):
    """Same as encode_query(), plus an OPT record in the additional
    section advertising `payload` as our UDP receive capacity."""
    q = encode_query(name, qid, qtype)
    q = q[:10] + struct.pack(">H", 1) + q[12:]     # ARCOUNT 0 -> 1
    ttl = 0x8000 if do_bit else 0
    opt = b"\x00" + struct.pack(">HHIH", 41, payload, ttl, 0)
    return q + opt


def get_edns_opt(msg):
    """(payload_size, rdlength) of the OPT record in the additional
    section, or None. Assumes NSCOUNT == 0, always true for this
    resolver's own responses."""
    _, qd, an = struct.unpack(">HHH", msg[2:8])
    arcount = struct.unpack(">H", msg[10:12])[0]
    off = 12
    for _ in range(qd):
        _, off = decode_name(msg, off)
        off += 4
    for _ in range(an):
        _, off = decode_name(msg, off)
        _, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10 + rdlen
    if arcount == 0:
        return None
    rtype, rclass, _, rdlen = struct.unpack(">HHIH", msg[off + 1:off + 11])
    return (rclass, rdlen) if rtype == 41 else None


def decode_name(msg, off, depth=0):
    labels = []
    if depth > 10:
        raise ValueError("pointer loop")
    while True:
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


def ask(name, qid, timeout=20, raw=None, qtype=1):
    """Returns (reply_bytes, elapsed_seconds) or (None, elapsed)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    payload = raw if raw is not None else encode_query(name, qid, qtype)
    t0 = time.time()
    try:
        s.sendto(payload, (HOST, PORT))
        data, _ = s.recvfrom(4096)
        return data, time.time() - t0
    except socket.timeout:
        return None, time.time() - t0
    finally:
        s.close()


def parse_answers(msg):
    """Returns (rcode, [(owner, type, value), ...])."""
    flags, qd, an = struct.unpack(">HHH", msg[2:8])
    off = 12
    for _ in range(qd):
        _, off = decode_name(msg, off)
        off += 4
    out = []
    for _ in range(an):
        owner, off = decode_name(msg, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if rtype == 1:
            out.append((owner, "A", socket.inet_ntoa(rdata)))
        elif rtype == 28:
            out.append((owner, "AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype == 5:
            target, _ = decode_name(msg, off)
            out.append((owner, "CNAME", target))
        else:
            out.append((owner, str(rtype), rdata.hex()))
        off += rdlen
    return flags & 0xF, out


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def encode_query_tcp(name, qid, qtype=1):
    payload = encode_query(name, qid, qtype)
    return struct.pack(">H", len(payload)) + payload


def ask_tcp(queries, timeout=10):
    """queries: list of (name, qid, qtype), all sent on ONE connection
    before any reply is read, to exercise RFC 7766 pipelining. Returns
    a list of reply bytes (or None on timeout/short-close), one per
    query, in the order the queries were given."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    replies = []
    try:
        s.connect((HOST, TCP_PORT))
        for name, qid, qtype in queries:
            s.sendall(encode_query_tcp(name, qid, qtype))
        for _ in queries:
            hdr = _recv_exact(s, 2)
            if hdr is None:
                replies.append(None)
                continue
            mlen = struct.unpack(">H", hdr)[0]
            replies.append(_recv_exact(s, mlen))
    except (socket.timeout, ConnectionError, OSError):
        while len(replies) < len(queries):
            replies.append(None)
    finally:
        s.close()
    return replies


print("iterative resolver integration tests\n")

# --- plain referral chain, glue at every step ---
r, _ = ask("www.example.com", 0x1001)
check(r is not None, "www.example.com got a response")
if r:
    check(struct.unpack(">H", r[:2])[0] == 0x1001, "transaction id echoed")
    check(struct.unpack(">H", r[2:4])[0] & 0x8000, "QR set")
    check(not (struct.unpack(">H", r[2:4])[0] & 0x0200), "TC not set")
    rcode, ans = parse_answers(r)
    check(rcode == 0, "rcode NOERROR", f"got {rcode}")
    check(len(ans) == 1, "one answer", f"got {len(ans)}")
    check(ans == [("www.example.com", "A", "93.184.216.34")],
          "correct A record", f"got {ans}")

# --- referral with no glue: .net delegation names ns1.example.com ---
r, _ = ask("host.example.net", 0x1002)
check(r is not None, "host.example.net got a response (missing glue path)")
if r:
    rcode, ans = parse_answers(r)
    check(rcode == 0, "no-glue rcode NOERROR", f"got {rcode}")
    check(ans == [("host.example.net", "A", "10.9.8.7")],
          "no-glue chain resolved", f"got {ans}")

# --- single CNAME: client gets the CNAME and the A ---
r, _ = ask("alias.example.com", 0x1003)
check(r is not None, "alias.example.com got a response")
if r:
    rcode, ans = parse_answers(r)
    check(len(ans) == 2, "CNAME + A returned", f"got {len(ans)}")
    check(ans and ans[0][1] == "CNAME", "first record is the CNAME")
    check(ans and ans[-1] == ("www.example.com", "A", "93.184.216.34"),
          "chain terminates at the right A record", f"got {ans}")

# --- two hop chain, in order ---
r, _ = ask("deep.example.com", 0x1004)
check(r is not None, "deep.example.com got a response")
if r:
    rcode, ans = parse_answers(r)
    check(len(ans) == 3, "full 3-record chain", f"got {len(ans)}")
    check([a[1] for a in ans] == ["CNAME", "CNAME", "A"],
          "chain order is CNAME, CNAME, A", f"got {[a[1] for a in ans]}")

# --- authoritative NXDOMAIN ---
r, _ = ask("missing.example.com", 0x1005)
check(r is not None, "missing.example.com got a response")
if r:
    rcode, ans = parse_answers(r)
    check(rcode == 3, "rcode NXDOMAIN", f"got {rcode}")
    check(len(ans) == 0, "no answers on NXDOMAIN")

# --- cache hit ---
r, elapsed = ask("www.example.com", 0x1006)
check(r is not None, "repeat query answered")
if r:
    check(elapsed < 0.05, "served from cache", f"{elapsed * 1000:.1f} ms")

# --- mixed case echoed verbatim (DNS-0x20) ---
q = encode_query("WwW.ExAmPlE.cOm", 0x1007)
r, _ = ask(None, 0x1007, raw=q)
check(r is not None, "mixed case query answered")
if r:
    check(r[12:len(q)] == q[12:], "question echoed byte for byte")
    rcode, ans = parse_answers(r)
    check(rcode == 0 and len(ans) == 1, "mixed case still resolves",
          f"rcode {rcode}, {len(ans)} answers")

# --- malformed input: no reply, no crash ---
r, _ = ask(None, 0, timeout=2, raw=b"\x00\x01\x02")
check(r is None, "truncated query silently dropped")

r, _ = ask(None, 0, timeout=2, raw=encode_query("x.example.com", 0x1008)[:14])
check(r is None, "query with a chopped QNAME dropped")

r, _ = ask("www.example.com", 0x1009)
check(r is not None, "server still healthy after malformed input")

# --- AAAA: host that has one, through the same referral chain as A ---
r, _ = ask("www.example.com", 0x1010, qtype=28)
check(r is not None, "www.example.com AAAA got a response")
if r:
    rcode, ans = parse_answers(r)
    check(rcode == 0, "aaaa rcode NOERROR", f"got {rcode}")
    check(ans == [("www.example.com", "AAAA",
                    "2606:2800:220:1:248:1893:25c8:1946")],
          "correct AAAA record", f"got {ans}")

# --- AAAA on a CNAME chain: type carries through the alias ---
r, _ = ask("alias.example.com", 0x1011, qtype=28)
check(r is not None, "alias.example.com AAAA got a response")
if r:
    rcode, ans = parse_answers(r)
    check([a[1] for a in ans] == ["CNAME", "AAAA"],
          "aaaa chain order is CNAME, AAAA", f"got {[a[1] for a in ans]}")

# --- NODATA: host.example.net has an A but no AAAA. This must be
# NOERROR with zero answers -- not SERVFAIL (the bug this change fixed)
# and not NXDOMAIN (the name does exist). ---
r, _ = ask("host.example.net", 0x1012, qtype=28)
check(r is not None, "host.example.net AAAA got a response (NODATA path)")
if r:
    rcode, ans = parse_answers(r)
    check(rcode == 0, "nodata rcode is NOERROR, not SERVFAIL", f"got {rcode}")
    check(len(ans) == 0, "nodata has zero answers", f"got {ans}")

# ============================================================
# EDNS0
# ============================================================

# --- the same big chain that forced TCP fallback now fits over UDP
# once the client advertises a bigger payload ---
r, _ = ask("x", 0x3001, raw=encode_query_edns(BIG_HOP1, 0x3001, payload=1232))
check(r is not None, "edns big chain got a UDP response")
if r:
    flags = struct.unpack(">H", r[2:4])[0]
    rcode, ans = parse_answers(r)
    check(not (flags & 0x0200), "edns big chain does not set TC over UDP",
          f"flags {flags:#06x}")
    check([a[1] for a in ans] == ["CNAME", "CNAME", "A"],
          "edns big chain returns the full 3-record chain over UDP",
          f"got {[a[1] for a in ans]}")
    opt = get_edns_opt(r)
    check(opt is not None, "edns response carries an OPT record")
    if opt:
        check(opt[0] == 1232, "opt advertises our payload size", f"got {opt}")
        check(opt[1] == 0, "opt rdlength is 0 (no options)", f"got {opt}")

# --- a client claiming a small payload is held to it ---
r, _ = ask("x", 0x3002, raw=encode_query_edns(BIG_HOP1, 0x3002, payload=600))
check(r is not None, "edns small-payload query got a response")
if r:
    check(len(r) <= 600, "response honours the smaller advertised payload",
          f"got {len(r)} bytes")

# --- a plain query (no OPT) gets no OPT back ---
r, _ = ask("www.example.com", 0x3003)
check(r is not None, "plain query still answered")
if r:
    check(get_edns_opt(r) is None, "plain query gets no OPT record back")

# ============================================================
# TCP
# ============================================================

# --- TCP: basic query, mirrors the UDP case ---
(r,) = ask_tcp([("www.example.com", 0x2001, 1)])
check(r is not None, "tcp www.example.com got a response")
if r:
    check(struct.unpack(">H", r[:2])[0] == 0x2001, "tcp transaction id echoed")
    rcode, ans = parse_answers(r)
    check(rcode == 0, "tcp rcode NOERROR", f"got {rcode}")
    check(ans == [("www.example.com", "A", "93.184.216.34")],
          "tcp correct A record", f"got {ans}")

# --- TCP: CNAME chain, same shape as the UDP case ---
(r,) = ask_tcp([("deep.example.com", 0x2002, 1)])
check(r is not None, "tcp deep.example.com got a response")
if r:
    rcode, ans = parse_answers(r)
    check([a[1] for a in ans] == ["CNAME", "CNAME", "A"],
          "tcp chain order is CNAME, CNAME, A", f"got {[a[1] for a in ans]}")

# --- TCP: RFC 7766 pipelining -- two queries, one connection, both
# sent before either reply is read ---
r1, r2 = ask_tcp([("www.example.com", 0x2003, 1),
                   ("alias.example.com", 0x2004, 1)])
check(r1 is not None and r2 is not None, "tcp pipelined queries both answered")
if r1 and r2:
    id1 = struct.unpack(">H", r1[:2])[0]
    id2 = struct.unpack(">H", r2[:2])[0]
    check(id1 == 0x2003 and id2 == 0x2004,
          "tcp pipelined replies came back in request order",
          f"got {id1:#06x}, {id2:#06x}")
    _, ans2 = parse_answers(r2)
    check(len(ans2) == 2, "second pipelined reply is the alias chain",
          f"got {len(ans2)} answers")

# --- TCP fallback: the actual point of the feature. BIG_HOP1 ->
# BIG_HOP2 -> BIG_HOP3 (see fake_hierarchy.py) is engineered so the
# full 3-record answer does not fit in a 512 byte UDP response. ---
r, _ = ask(BIG_HOP1, 0x2005)
check(r is not None, "big chain got a UDP response")
if r:
    flags = struct.unpack(">H", r[2:4])[0]
    rcode, ans = parse_answers(r)
    check(bool(flags & 0x0200), "big chain sets TC over UDP",
          f"flags {flags:#06x}")
    check(rcode == 0, "big chain rcode NOERROR despite truncation",
          f"got {rcode}")
    check(len(ans) < 3, "big chain UDP answer is a strict prefix of the chain",
          f"got {len(ans)} of 3 answers")

(r,) = ask_tcp([(BIG_HOP1, 0x2006, 1)])
check(r is not None, "big chain got a TCP response")
if r:
    flags = struct.unpack(">H", r[2:4])[0]
    rcode, ans = parse_answers(r)
    check(not (flags & 0x0200), "big chain does not set TC over TCP",
          f"flags {flags:#06x}")
    check(rcode == 0, "tcp big chain rcode NOERROR", f"got {rcode}")
    check([a[1] for a in ans] == ["CNAME", "CNAME", "A"],
          "tcp big chain returns the full 3-record chain",
          f"got {[a[1] for a in ans]}")
    check(ans[-1] == (BIG_HOP3, "A", "10.0.0.2"),
          "tcp big chain terminates at the right A record", f"got {ans[-1]}")

# --- TCP: length prefix promises a body that never arrives. The
# connection must close cleanly (not hang, not crash the server), and
# the server must still answer the next client normally. ---
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
closed = False
try:
    s.connect((HOST, TCP_PORT))
    s.sendall(struct.pack(">H", 100))   # promise 100 bytes, send none
    s.shutdown(socket.SHUT_WR)
    closed = s.recv(1) == b""
except (socket.timeout, ConnectionError, OSError):
    closed = False
finally:
    s.close()
check(closed, "tcp connection with a missing body closes cleanly")

(r,) = ask_tcp([("www.example.com", 0x2007, 1)])
check(r is not None, "tcp server still healthy after malformed framing")

print(f"\n{len(failures)} failures")
sys.exit(1 if failures else 0)

