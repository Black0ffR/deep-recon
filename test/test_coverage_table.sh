#!/bin/bash
# Render coverage_table() against a fixture state dir and check the markdown.
# Usage: test_coverage_table.sh [path-to-deep_recon.sh]
# Portable: resolves the script under test relative to this file (not a
# hardcoded checkout path) and honours $TMPDIR (/tmp is absent on Termux).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-${HERE}/../deep_recon.sh}"
TMPBASE="${TMPDIR:-${TMP:-/tmp}}"
MODULE_STATUS_DIR=${TMPBASE}/_cov_$$/modules
rm -rf "${TMPBASE}/_cov_$$"; mkdir -p "$MODULE_STATUS_DIR"
trap 'rm -rf "${TMPBASE}/_cov_$$"' EXIT
printf '%s\n' '{"module":"discover","state":"DEGRADED","seconds":3,"tool_errors":1,"reason":"dnsx missing | only apex | x"}' > "$MODULE_STATUS_DIR/a.json"
printf '%s\n' '{"module":"asn","state":"RAN","seconds":7,"tool_errors":0,"reason":""}'                                    > "$MODULE_STATUS_DIR/b.json"
eval "$(sed -n '/^coverage_table() {/,/^}$/p' "$SRC")"
out=$(coverage_table)
printf '%s\n' "$out"
echo "---"
fail=0
chk() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
chk "header"        'printf "%s\n" "$out" | grep -qxF "| Module | State | Time | Tool errors | Note |"'
chk "separator"     'printf "%s\n" "$out" | grep -qxF "|---|---|---:|---:|---|"'
chk "degraded row"  'printf "%s\n" "$out" | grep -qF "discover | **DEGRADED** | 3s | 1 |"'
chk "pipe escaped"  'printf "%s\n" "$out" | grep -qF "dnsx missing \\| only apex \\| x"'
chk "ran row"       'printf "%s\n" "$out" | grep -qF "asn | **RAN** | 7s | 0 |"'
n=$(printf "%s\n" "$out" | grep -c .)
chk "exactly 4 non-empty lines (header + separator + 2 modules)" '[ "$n" -eq 4 ]'
exit $fail
