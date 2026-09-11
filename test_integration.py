#!/usr/bin/env python3
"""
Full-stack tests against a running resolver. Two halves:

  PART A  the resolver versus evil_hierarchy.py -- do the acceptance
          rules added to resolver.c actually hold when a real server
          lies to a real resolver over a real socket? The unit tests
          check dns_name_in_bailiwick() in isolation; these check that
          it is wired into the paths that matter.

  PART B  every feature at once, concurrently -- Bloom filter, LRU
          cache, TTLs, iterative resolution and the acceptance rules
          driven simultaneously from many threads. Features that each
          work alone can still interact: the Bloom filter is read
          without the cache mutex, so a lost hit would show up here and
          nowhere else.

Usage:  python3 test_integration.py [port]     (default 5355)
Assumes evil_hierarchy.py is up and the server was started with
DNS_ROOT_HINTS=127.0.0.21.
"""

import concurrent.futures
import random
import socket
import struct
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5355
PART = sys.argv[2].upper() if len(sys.argv) > 2 else "AB"   # A, B or AB
SERVER = ("127.0.0.1", PORT)
EVIL_IP = "6.6.6.6"

checks = 0
failures = 0
_lock = threading.Lock()


def check(cond, msg):
    global checks, failures
    with _lock:
        checks += 1
        if cond:
            print(f"  ok    {msg}")
        else:
            failures += 1
            print(f"  FAIL  {msg}")


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


def query(name, qtype=1, timeout=8.0, qid=None):
    """Returns (rcode, [(owner, type, value)]) or None on timeout."""
    qid = qid if qid is not None else random.randint(0, 0xFFFF)
    pkt = (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
           + encode_name(name) + struct.pack(">HH", qtype, 1))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, SERVER)
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        return None
    finally:
        s.close()

    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        raise AssertionError(f"server echoed id {rid:#x}, sent {qid:#x}")

    off = 12
    for _ in range(qd):
        _, off = decode_name(data, off)
        off += 4

    out = []
    for _ in range(an):
        owner, off = decode_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1:
            out.append((owner.lower(), "A", socket.inet_ntoa(rdata)))
        elif rtype == 28:
            out.append((owner.lower(), "AAAA",
                        socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype == 5:
            tgt, _ = decode_name(data, off - rdlen)
            out.append((owner.lower(), "CNAME", tgt.lower()))
    return flags & 0xF, out


def addrs(answers):
    return [v for (_, t, v) in answers if t in ("A", "AAAA")]


# ---------------------------------------------------------------- A

def test_sanity():
    print("\n-- the honest path still works --")
    r = query("victim.example.com")
    check(r is not None, "victim.example.com answered")
    if r:
        rcode, ans = r
        check(rcode == 0, f"rcode NOERROR (got {rcode})")
        check("10.0.0.1" in addrs(ans), f"correct address (got {addrs(ans)})")

    r = query("chain.example.com")
    check(r is not None, "CNAME chain answered")
    if r:
        _, ans = r
        check([t for (_, t, _) in ans] == ["CNAME", "A"],
              f"chain is CNAME then A (got {[t for (_, t, _) in ans]})")
        check("10.0.0.3" in addrs(ans), f"chain terminates correctly ({addrs(ans)})")


def test_bailiwick_referral():
    print("\n-- ATTACK 1: out-of-bailiwick referral --")
    r = query("poison.example.com")
    check(r is not None, "poison.example.com did not hang the resolver")
    if r:
        rcode, ans = r
        # The .com server delegated bank.co.uk. Refusing it leaves no
        # usable delegation, so NOERROR/no-answer (NODATA) is the
        # correct outcome. What must NOT happen is following it.
        check(EVIL_IP not in addrs(ans),
              f"attacker address not returned (got {addrs(ans)})")
        check(len(ans) == 0,
              f"refused delegation yields no answer (got {ans})")

    # And the zone it tried to hijack must be untouched afterwards.
    r = query("www.bank.co.uk")
    if r:
        _, ans = r
        check(EVIL_IP not in addrs(ans),
              f"bank.co.uk not poisoned by the referral (got {addrs(ans)})")
    else:
        check(True, "bank.co.uk not poisoned by the referral (unresolvable)")


def test_bailiwick_answer():
    print("\n-- ATTACK 3: out-of-bailiwick answer injection --")
    r = query("victim.example.com")
    check(r is not None, "victim.example.com answered")
    if r:
        _, ans = r
        check("10.0.0.1" in addrs(ans), "the real answer survived filtering")
        check(EVIL_IP not in addrs(ans),
              f"injected bank.co.uk record dropped (got {addrs(ans)})")
        check(all(o == "victim.example.com" for (o, _, _) in ans),
              f"no foreign owner names in the answer (got {ans})")

    # The injected record must not have reached the cache either. This
    # is the part that matters: a dropped-but-cached record poisons
    # every later query even though the first answer looked clean.
    r = query("www.bank.co.uk")
    if r:
        _, ans = r
        check(EVIL_IP not in addrs(ans),
              f"injected record did not reach the cache (got {addrs(ans)})")
    else:
        check(True, "injected record did not reach the cache (unresolvable)")


def test_offchain_injection():
    print("\n-- ATTACK 4: in-bailiwick but off-chain injection --")
    # unrelated.example.com really exists and is 10.0.0.9. The attack
    # staples a 6.6.6.6 record for it onto an answer about a different
    # name. Bailiwick passes it (same zone); only the chain check stops it.
    r = query("offchain.example.com")
    check(r is not None, "offchain.example.com answered")
    if r:
        _, ans = r
        check("10.0.0.2" in addrs(ans), "the real answer survived")
        check(EVIL_IP not in addrs(ans),
              f"off-chain record dropped (got {addrs(ans)})")

    r = query("unrelated.example.com")
    check(r is not None, "unrelated.example.com answered")
    if r:
        _, ans = r
        check("10.0.0.9" in addrs(ans),
              f"real value served, not the injected one (got {addrs(ans)})")
        check(EVIL_IP not in addrs(ans), "cache not poisoned off-chain")


def test_txid_and_question():
    print("\n-- ATTACKS 5/6: transaction id and question matching --")
    r = query("badid.example.com", timeout=15)
    if r:
        rcode, ans = r
        check(EVIL_IP not in addrs(ans),
              f"wrong-id reply rejected (got {addrs(ans)})")
        check(rcode != 0 or len(ans) == 0,
              f"wrong-id reply produced no answer (rcode {rcode}, {ans})")
    else:
        check(True, "wrong-id reply rejected (query timed out, as expected)")

    r = query("badq.example.com", timeout=15)
    if r:
        rcode, ans = r
        check(EVIL_IP not in addrs(ans),
              f"mismatched-question reply rejected (got {addrs(ans)})")
        check(rcode != 0 or len(ans) == 0,
              f"mismatched-question reply produced no answer ({ans})")
    else:
        check(True, "mismatched-question reply rejected (timed out, as expected)")


def test_spoof_then_truth():
    print("\n-- ATTACK 7: spoofed reply first, real reply second --")
    # Rejecting the spoof is necessary but not sufficient: if the
    # resolver stops reading after the first bad datagram, an attacker
    # denies service to any name just by racing it.
    r = query("racy.example.com", timeout=15)
    check(r is not None, "resolver kept reading past the spoofed datagram")
    if r:
        _, ans = r
        check(EVIL_IP not in addrs(ans), f"spoof rejected (got {addrs(ans)})")
        check("10.0.0.7" in addrs(ans),
              f"genuine reply still accepted (got {addrs(ans)})")


# ---------------------------------------------------------------- B

def test_concurrent_all_features():
    print("\n-- PART B: every feature at once, 16 threads --")

    # A mix chosen so all of them run simultaneously:
    #   hot      repeated -> cache hits, Bloom says "maybe", must be right
    #   cold     unique   -> Bloom rejects without the lock, must be a miss
    #   evil     attacks  -> acceptance rules under contention
    #   churn    many     -> LRU eviction, so Bloom counters go up AND down
    hot = ["victim.example.com", "unrelated.example.com", "target.example.com"]
    evil = ["offchain.example.com", "victim.example.com"]

    expected = {
        "victim.example.com": "10.0.0.1",
        "unrelated.example.com": "10.0.0.9",
        "target.example.com": "10.0.0.3",
        "offchain.example.com": "10.0.0.2",
    }

    wrong = []
    lost = []
    poisoned = []

    def worker(n):
        rng = random.Random(n)
        for i in range(25):
            roll = rng.random()
            if roll < 0.45:
                name = rng.choice(hot)
            elif roll < 0.70:
                name = f"cold{n}x{i}.example.com"
            elif roll < 0.85:
                name = rng.choice(evil)
            else:
                name = f"churn{rng.randrange(4000)}.example.com"

            try:
                r = query(name, timeout=10)
            except AssertionError as e:
                wrong.append(f"{name}: {e}")
                continue

            if r is None:
                if name in expected:
                    lost.append(name)
                continue

            _, ans = r
            got = addrs(ans)
            if EVIL_IP in got:
                poisoned.append(f"{name} -> {got}")
            if name in expected and got and expected[name] not in got:
                wrong.append(f"{name} -> {got}, want {expected[name]}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(worker, range(16)))

    check(not poisoned, f"no attacker data served under load ({poisoned[:3]})")
    check(not wrong, f"no wrong or corrupted answers ({wrong[:3]})")
    check(not lost,
          f"no cached answer lost to the Bloom fast path ({lost[:3]})")


def test_thundering_herd():
    print("\n-- PART B: simultaneous first-lookups of one cold name --")
    # 24 threads race on a name that is not cached, so they collide on
    # the insert path: Bloom add, LRU insert and cache lookup all at the
    # same instant for the same key. Every one of them must still get
    # the same correct answer.
    name = f"herd{random.randrange(10**9)}.example.com"

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        results = list(ex.map(lambda _: query(name, timeout=10), range(24)))

    answered = [r for r in results if r is not None]
    check(len(answered) == len(results),
          f"all {len(results)} racing lookups answered ({len(answered)} did)")

    rcodes = {r[0] for r in answered}
    check(len(rcodes) <= 1,
          f"all racers agree on the rcode (got {rcodes})")

    # Now it is warm: the same name must come back consistently, which
    # is the check that the Bloom counters were left correct by the race.
    after = query(name, timeout=10)
    check(after is not None, "the raced name is still resolvable afterwards")
    if after and answered:
        check(after[0] == answered[0][0],
              "cached result matches what the racers got")


def test_cache_consistency_under_eviction():
    print("\n-- PART B: hot names survive cache eviction pressure --")
    # Drive far more distinct names through than the cache holds, from
    # several threads, while re-checking a hot name throughout. If a
    # Bloom counter is ever decremented for the wrong key during
    # eviction, the hot name starts reading as absent and this fails.
    stop = threading.Event()
    bad = []

    def hammer(n):
        i = 0
        while not stop.is_set() and i < 400:
            query(f"evict{n}x{i}.example.com", timeout=6)
            i += 1

    def verify():
        while not stop.is_set():
            r = query("victim.example.com", timeout=8)
            if r is None:
                bad.append("timeout")
            elif "10.0.0.1" not in addrs(r[1]):
                bad.append(f"got {addrs(r[1])}")
            time.sleep(0.05)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(6)]
    v = threading.Thread(target=verify, daemon=True)
    for t in threads:
        t.start()
    v.start()
    for t in threads:
        t.join()
    stop.set()
    v.join(timeout=10)

    check(not bad, f"hot entry stayed correct throughout eviction ({bad[:3]})")


if __name__ == "__main__":
    print(f"full-stack tests against 127.0.0.1:{PORT}")

    probe = query("victim.example.com", timeout=10)
    if probe is None:
        print("\nERR: no response -- is the server up with "
              "DNS_ROOT_HINTS=127.0.0.21?")
        sys.exit(2)

    if "A" in PART:
        test_sanity()
        test_bailiwick_referral()
        test_bailiwick_answer()
        test_offchain_injection()
        test_txid_and_question()
        test_spoof_then_truth()

    if "B" in PART:
        test_concurrent_all_features()
        test_thundering_herd()
        test_cache_consistency_under_eviction()

    print(f"\n{checks} checks, {failures} failures")
    sys.exit(1 if failures else 0)
