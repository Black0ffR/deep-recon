#!/usr/bin/env python3
"""Extract every quoted heredoc from deep_recon.sh and byte-compile the Python ones.

The original script inlines 14 Python/C payloads. Several of the defects in the
review (JARM offsets, SNMP BER lengths, OOXML inflate, TIFF endianness) live
inside those payloads, and `bash -n` cannot see a Python syntax error -- a
broken heredoc only fails at runtime, silently, mid-module.
"""
import re
import sys
import py_compile
import tempfile
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "deep_recon.sh")
text = SRC.read_text()
lines = text.split("\n")

# `<< 'TAG'` or `<< 'TAG' args` -- start capture at the next line
OPEN = re.compile(r"<<\s*'([A-Z0-9_]+)'")
blocks = []
i = 0
while i < len(lines):
    m = OPEN.search(lines[i])
    if m:
        tag = m.group(1)
        body, j = [], i + 1
        while j < len(lines) and lines[j].strip() != tag:
            body.append(lines[j])
            j += 1
        blocks.append((i + 1, tag, "\n".join(body)))
        i = j
    i += 1

PY_TAGS = {"PYEOF", "JARMEOF", "JWTEOF", "TECHEOF", "NVDEOF", "WORDEOF",
           "METAEOF", "EXIFEOF", "SSRFEOF", "PBEOF"}

ok = fail = skipped = 0
for lineno, tag, body in blocks:
    if tag not in PY_TAGS:
        skipped += 1
        print(f"  SKIP  L{lineno:<5} <<'{tag}'  (non-python, {len(body.splitlines())} lines)")
        continue
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(body)
        path = fh.name
    try:
        py_compile.compile(path, doraise=True)
        ok += 1
        print(f"  OK    L{lineno:<5} <<'{tag}'  ({len(body.splitlines())} lines)")
    except py_compile.PyCompileError as exc:
        fail += 1
        first = [l for l in str(exc).splitlines() if "Error" in l or "line" in l]
        print(f"  FAIL  L{lineno:<5} <<'{tag}'  {first[:2]}")
    finally:
        Path(path).unlink(missing_ok=True)

print(f"\n{ok} python payloads compile, {fail} failed, {skipped} non-python heredocs skipped")
sys.exit(1 if fail else 0)
