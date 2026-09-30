#!/usr/bin/env python3
"""Static invariants: assert that each fixed defect is actually gone, and that
the old broken shapes have not been reintroduced.

This is a lint for the review findings rather than a behavioural test — the
behavioural ones live in the sibling test_*.py files.
"""
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "deep_recon.sh")
s = SRC.read_text()

# "gone" checks must look at CODE, not at the comments that explain what the
# old bug was -- those comments deliberately quote the broken shapes.
_code_lines = []
for _ln in s.split("\n"):
    _st = _ln.lstrip()
    if _st.startswith("#"):
        continue
    # drop trailing comments, but keep anything inside a quoted string
    _out, _q = [], None
    for _ch in _ln:
        if _q:
            _out.append(_ch)
            if _ch == _q:
                _q = None
            continue
        if _ch in "\"'":
            _q = _ch
            _out.append(_ch)
            continue
        if _ch == "#":
            break
        _out.append(_ch)
    _code_lines.append("".join(_out))
code = "\n".join(_code_lines)
orig = (SRC.parent / "deep_recon.sh.orig")
o = orig.read_text() if orig.exists() else ""

fails, passes = [], []


def gone(name, pattern, flags=re.M):
    """The broken shape must not appear in executable code."""
    if re.search(pattern, code, flags):
        fails.append(f"{name}: pattern still present -> /{pattern}/")
    else:
        passes.append(name)


def present(name, pattern, flags=re.M):
    """The fixed shape must appear."""
    if re.search(pattern, s, flags):
        passes.append(name)
    else:
        fails.append(f"{name}: expected pattern missing -> /{pattern}/")


def contains(name, needle):
    """Plain substring check, for text that is painful to regex (backslashes)."""
    if needle in code:
        passes.append(name)
    else:
        fails.append(f"{name}: substring missing -> {needle!r}")


def is_new(name, pattern, flags=re.M):
    """The shape must be new relative to the original file."""
    in_o = bool(re.search(pattern, o, flags)) if o else False
    in_s = bool(re.search(pattern, s, flags))
    if in_s and not in_o:
        passes.append(name)
    else:
        fails.append(f"{name}: not newly introduced (in original: {in_o}, in fixed: {in_s})")


print("S1 — wrong result / broken execution")
gone("F1  no hardcoded cipher offset data[43:45]", r"cipher\s*=\s*struct\.unpack\('>H',\s*data\[43:45\]\)")
present("F1  session-id length is honoured", r"if off \+ 2 > len\(data\)|off \+= sid_len|sid_len")
gone("F2  no 62-char JARM", r"hexdigest\(\)\[:62\]")
present("F2  JARM sentinel is 32 chars", r'ZERO_JARM\s*=\s*"0" \* 32')
gone("F3  no HEAD-based header audit", r"curl -skI")
gone("F4  no array mutation in a pipeline subshell",
     r"while IFS= read -r ip; do ldap_ips\+=")
present("F4  ldap_ips collected with mapfile", r"mapfile -t ldap_ips")
gone("F5  no read() on a directory", r'read\(output_dir/"supplemental/wellknown"\)')
gone("F7  no hardcoded \\x30\\x26 SNMP header", r"\\x30\\x26")
contains("F7  SNMP message length is derived", "msg_len_hex")
gone("F9  no latin-1 decode of the raw OOXML container",
     r'text = data\.decode\(.latin-1., errors=.ignore.\)\n    patterns = \{\n        "dc:creator"')
present("F9  zipfile is used", r"zipfile\.ZipFile\(io\.BytesIO\(data\)\)")
gone("F10 no xargs grep with no file operand", r"xargs grep -h")
gone("F11 no \\\\?all in the SPF check", r"~all\|\\\\\?all")
present("F11 SPF uses \\?all", r"~all\|\\\?all")
gone("F13 no grep -c ... || echo 0", r'grep -c [^\n]*\|\| echo 0')
gone("F25 no `|| echo \"000\"` after curl -w", r'\|\| echo "000"\)')
# Narrow: only the curl -w status-code guards matter. `count_lines ... || echo 0`
# and `jq ... || echo 0` are legitimate (count_lines already yields 0, and jq
# prints nothing on error).
gone("F25 no `|| echo 0` after curl -w", r'-w "%\{http_code\}"[^\n]*\|\| echo 0\)')
gone("F25 no `|| echo 000` after curl -w", r'-w "%\{http_code\}"[^\n]*\|\| echo "000"\)')

print("\nS2 — dead / mislabelled features")
gone("F14 no never-incremented tests_passed denominator", r"tests_blocked \+ tests_passed\)\}\"")
present("F14 tests_passed is incremented", r"\(\(tests_passed\+\+\)\)")
gone("F17 no second omega_run_command.sh writer with --input", r"python3 \$\{omega\} \\\n  --input ")
present("F19 JWT analysis writes the key the playbook greps", r"lines\.append\(f\"FLAGS:")
present("F20 sso_fingerprint.txt now has a producer", r"sso_fingerprint\.txt")
gone("F22 no unread found_buckets array", r"found_buckets")
present("F22 public buckets have their own artifact", r's3_public\.txt')
present("F21 ws_host is actually used", r'"\$\{ws_host\}\$\{ws_path\}"')
gone("F18 no dead vt_data assignment", r'vt_data=\$\(rate_limited_curl \\\n    "https://www\.virustotal\.com/vtapi/v2')

print("\nS3 — robustness / environment")
gone("F27 no divergent `cut -d. -f1` base name", r'base_name=\$\(echo "\$DOMAIN" \| cut -d\. -f1\)')
present("F27 one base_name helper", r"^base_name\(\) \{")
gone("F30 no set-order top-100", r"base_words\s*=\s*list\(words\)\[:100\]")
present("F30 deterministic ordering", r"sorted\(words, key=lambda w: \(-len\(w\), w\)\)")
gone("F31 no tautological cert counter", r'grep -v "^\$\(date \+%Y-%m\)"')
gone("F32 no 1.5s NVD sleep", r"time\.sleep\(1\.5\)")
present("F32 NVD rate respects the documented limit", r"NVD_SLEEP = 0\.7 if NVD_KEY else 6\.2")
gone("F33 no unbounded document read", r"return r\.read\(\)\n    except Exception")
present("F33 download is bounded", r"MAX_DOC_BYTES")
gone("F34 no hardcoded little-endian TIFF", r"struct\.unpack_from\('<H', tiff, offset\)")
present("F34 byte-order mark is honoured", r"bo = tiff\[0:2\]")
gone("F36 no bare `cp \$curr_ports` without a size test", r"\n\s*cp \"\$curr_ports\" \"\$prev_ports\"\n\s*fi\n\s*else")
present("F36 cert baseline is guarded by -s", r"if \[\[ -s \"\$curr_certs\" \]\]; then")
present("F36 sub baseline is guarded by -s", r"if \[\[ -s \"\$curr\" \]\]; then")
present("F36 cert baseline IS guarded", r'if \[\[ -s "\$curr_certs" \]\]; then')
present("F36 baselines guarded", r'if \[\[ -s "\$curr_certs" \]\]; then')
gone("F38 no `find .` for the APK", r'found_apk=\$\(find \. -maxdepth 2')
present("F38 APK search is scoped to the output dir", r'find "\$\{OUTPUT_DIR\}" -maxdepth 2')
gone("F39 help no longer truncated at 40 lines", r"head -40")

print("\nDesign fixes")
present("D1  module dependency graph", r"declare -A MODULE_DEPS")
present("D1  dependency resolution", r"^resolve_modules\(\) \{")
present("D3  scope is enforced, not just copied", r"^apply_scope\(\) \{")
present("D3  rDNS prefers the operator scope file", r"operator-supplied scope \(authoritative\)")
present("D4  HTTP cache", r"^rate_limited_curl\(\) \{")
present("D5  per-tool accounting", r"^run_tool\(\) \{")
present("D6  DEGRADED state", r'module_done\(\) \{')
present("D6  DEGRADED branch in the status writer", r'DEGRADED\) warn')
present("D7  resume is implemented", r"^resume_satisfied\(\) \{")
present("D8  coverage table in the report", r"^coverage_table\(\) \{")
present("D8  coverage roll-up artifact", r"coverage\.json")
present("D12 config file", r"^load_config\(\) \{")
present("D12 credentials are configurable", r"VT_API_KEY=\"\$\{VT_API_KEY:-\}\"")
present("D2  auth tier gate", r"require explicit authorization")
gone("D2  passive-only no longer contains auth", r"--passive-only\) PASSIVE_ONLY=true; MODULES=\"[^\"]*\bauth\b")
present("D9  request budget", r"^budget_take\(\) \{")
is_new("F16 discover module exists", r"^module_discover\(\) \{")
gone("F16 no module silently fabricates the host file",
     r'\[\[ ! -s "\$live_hosts" \]\] && echo "https://\$\{DOMAIN\}" > "\$live_hosts"')
present("F16 consumers use require_live_hosts", r"^require_live_hosts\(\) \{")

print()
for n in passes:
    print(f"  PASS  {n}")
for n in fails:
    print(f"  FAIL  {n}")
print(f"\n{len(passes)} passed, {len(fails)} failed")
sys.exit(1 if fails else 0)
