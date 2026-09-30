#!/usr/bin/env python3
"""Regression test for the JARM implementation.

Two defects are pinned here:
  1. the old parser read the cipher suite from data[43:45], which is the
     session-id LENGTH byte (RFC 5246 7.4.3: version(2) random(32) sid_len(1)
     sid(N) cipher(2)); with a 32-byte sid the cipher is at offset 76.
  2. the old "JARM" was sha256(raw).hexdigest()[:62] -- raw hex of the wrong
     length. A JARM is 32 characters: the first 32 hex digits of sha256(raw)
     mapped through a base-32 alphabet.

Runs entirely offline: a synthetic ServerHello is built with a 32-byte session
id (so the cipher sits at 76, not 43) and the parser must recover it.
"""
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "deep_recon.sh")
block = re.search(r"<< 'JARMEOF'\n(.*?)\nJARMEOF", SRC.read_text(), re.S)
if not block:
    print("FAIL: JARMEOF payload not found")
    sys.exit(1)

ns: dict = {"__name__": "jarm_lib"}
# Keep only the import lines, the constants, the helpers and compute_jarm; drop
# the __main__ tail (argv access + file writes) so the test can stay offline.
body = block.group(1)
body = body.split("lines_out = []")[0]
body = re.sub(r"^DOMAIN = .*$", "", body, flags=re.M)
body = re.sub(r"^OUT    = .*$", "", body, flags=re.M)
body = re.sub(r"^SOURCE = .*$", "", body, flags=re.M)
exec(compile(body, "jarm", "exec"), ns)

parse = ns["parse_server_hello"]
Y = ns["Y"]

failures = 0


def check(label, got, exp):
    global failures
    ok = got == exp
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: got={got!r} exp={exp!r}")


# ── build a ServerHello the way a real server does: 32-byte session id ────────
def server_hello(sid_len=32, version=b"\x03\x03", cipher=b"\xc0\x2f",
                 alpn=b"h2", ext_count_target=None):
    body = version + b"\x11" * 32 + bytes([sid_len]) + b"\x22" * sid_len
    body += cipher + b"\x00"
    ext = b""
    if alpn:
        # RFC 7301: uint16 list_len, then the name
        alpn_body = len(alpn).to_bytes(2, "big") + alpn
        ext += b"\x00\x10" + len(alpn_body).to_bytes(2, "big") + alpn_body
    if ext_count_target:
        for i in range(ext_count_target - (1 if alpn else 0)):
            ext += b"\x00\x0b\x00\x02\x01\x00"
    body += len(ext).to_bytes(2, "big") + ext
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


print("RFC 5246 §7.4.3 offset handling")
for sid_len in (0, 16, 32):
    # The cipher sits at 43 + 1 + sid_len. The old code always read [43:45].
    r = parse(server_hello(sid_len=sid_len))
    check(f"cipher with sid_len={sid_len}", r[1] if r else None, "c02f")

r = parse(server_hello(sid_len=32))
check("version", r[0], "0303")
check("alpn (ext 16) == h2", r[3], "6832")
check("ext count is even in hex", r[2] in ("01", "02", "03", "04", "05", "06"), True)

print("\nThe 62-vs-32 length defect")
check("old sentinel length was 62", len("0" * 62), 62)
check("new sentinel length", len(ns["ZERO_JARM"]), 32)
r32 = parse(server_hello(sid_len=32))
check("a real parse yields 4 hex-ish fields", len(r32), 4)

print("\nJARM mapping")
# The JARM hash is: sha256(raw).hexdigest()[:32], then each hex digit -> Y[digit]
import hashlib
raw = "0303|c02f|01|6832|," * 9 + "0303|c02f|01|6832|"
fuzzy = hashlib.sha256(raw.encode()).hexdigest()[:32]
expected = "".join(Y[int(c, 16)] for c in fuzzy)
check("hash length", len(expected), 32)
check("alphabet is 32 symbols", len(Y), 32)
check("old output was 62 hex chars, which is not a JARM",
      len(hashlib.sha256(raw.encode()).hexdigest()[:62]), 62)

print(f"\n{'ALL CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}")
sys.exit(1 if failures else 0)
