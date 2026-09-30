#!/usr/bin/env python3
"""Regression test: extract snmp_get_request() from deep_recon.sh and diff the
packets it emits against a reference built straight from RFC 1157 / RFC 3416.

The original packet hardcoded \\x30\\x26 and \\xa0\\x19 while computing the
community length dynamically. 0x19 is correct for every community, but 0x26 is
correct only for a SIX-byte community -- i.e. exactly "public", the first string
tried. The other eight iterations declared a message length short by
(len-6) bytes, so a device requiring "private" could never be found.
"""
import atexit
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "deep_recon.sh")
text = SRC.read_text()

m = re.search(r"^  snmp_get_request\(\) \{$.*?^  \}$", text, re.S | re.M)
if not m:
    print("FAIL: snmp_get_request() not found in", SRC)
    sys.exit(1)
# Portable temp file: /tmp does not exist on all systems (e.g. Termux),
# so honour $TMPDIR via tempfile instead of a hardcoded /tmp path.
_fn = tempfile.NamedTemporaryFile("w", suffix="_snmp_fn.sh", delete=False)
_fn.write(m.group(0).replace("\n  ", "\n") + "\n")
_fn.close()
atexit.register(lambda: os.path.exists(_fn.name) and os.unlink(_fn.name))
FN = _fn.name


def reference(comm: str) -> str:
    b = bytes.fromhex
    varbind_payload = b("06082b06010201010100" "0500")      # OID(10) + NULL(2) = 12
    varbind = b("300c") + varbind_payload                   # SEQUENCE, 14
    vb_list = b("300e") + varbind                           # SEQUENCE OF, 16
    pdu_payload = b("020100") * 3 + vb_list                 # reqid, non-rep, max-rep
    pdu = b("a019") + pdu_payload                           # [0] IMPLICIT, 25
    msg = b("020100") + b("04") + bytes([len(comm)]) + comm.encode() + pdu
    return (b("30") + bytes([len(msg)]) + msg).hex()


COMMUNITIES = ["public", "private", "community", "manager", "admin",
               "monitor", "snmp", "cisco", "default"]

failures = 0
for comm in COMMUNITIES:
    out = subprocess.run(
        ["bash", "-c",
         f'source {FN}; snmp_get_request {comm!r} | od -An -tx1 | tr -d " \\n"'],
        capture_output=True, text=True)
    got, exp = out.stdout.strip(), reference(comm)
    ok = got == exp
    failures += not ok
    print(f"  {comm:<10} {'MATCH' if ok else 'MISMATCH'}  ({len(exp)//2} bytes)")
    if not ok:
        print(f"      got {got}\n      exp {exp}")

print(f"\n{len(COMMUNITIES) - failures}/{len(COMMUNITIES)} SNMP GetRequest packets byte-exact")
sys.exit(1 if failures else 0)
