#!/bin/bash
# Run every check for the fixed script.
#   test/run_all.sh [path-to-deep_recon.sh]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
S="${1:-deep_recon.sh}"
fails=0
hr() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
run() {
  local name="$1"; shift
  hr "$name"
  if "$@"; then printf '  \033[32mOK\033[0m\n'; else printf '  \033[31mFAILED\033[0m\n'; fails=$((fails+1)); fi
}

printf '\033[1mTarget: %s\033[0m\n' "$S"

hr "bash -n (shell syntax)"
if bash -n "$S"; then printf '  \033[32mOK\033[0m\n'; else printf '  \033[31mFAILED\033[0m\n'; fails=$((fails+1)); fi

run "inline Python payloads compile"  python3 test/check_heredocs.py "$S"
run "SNMP GetRequest packets"           python3 test/test_snmp_packet.py "$S"
run "JARM parser + hash"                python3 test/test_jarm.py "$S"
run "OOXML/PDF metadata extraction"     python3 test/test_metadata.py "$S"
run "coverage table rendering"          bash test/test_coverage_table.sh "$S"
run "static invariants"                 python3 test/test_invariants.py "$S"

hr "CLI surface"
bash "$S" --help >/dev/null 2>&1 && printf '  \033[32mOK\033[0m  --help\n' || { printf '  \033[31mFAILED\033[0m  --help\n'; fails=$((fails+1)); }

out=$(bash "$S" 2>&1)
grep -q 'Domain required' <<< "$out" && printf '  \033[32mOK\033[0m  missing -d prints an error (was silent)\n' \
  || { printf '  \033[31mFAILED\033[0m  missing -d\n'; fails=$((fails+1)); }

out=$(bash "$S" -d x.invalid --authz-ref 2>&1)
grep -q 'requires a value' <<< "$out" && printf '  \033[32mOK\033[0m  option value validation\n' \
  || { printf '  \033[31mFAILED\033[0m  option value validation\n'; fails=$((fails+1)); }

out=$(bash "$S" -d x.invalid -m auth 2>&1)
grep -q 'require explicit authorization' <<< "$out" && printf '  \033[32mOK\033[0m  auth tier gated behind --authz-ref\n' \
  || { printf '  \033[31mFAILED\033[0m  auth tier gate\n'; fails=$((fails+1)); }

out=$(bash "$S" -d x.invalid --passive-only --dry-run 2>&1)
grep -q 'would run: discover' <<< "$out" && ! grep -q 'would run: auth' <<< "$out" \
  && printf '  \033[32mOK\033[0m  --passive-only excludes auth/intelligence\n' \
  || { printf '  \033[31mFAILED\033[0m  passive tier contents\n'; fails=$((fails+1)); }

out=$(bash "$S" -d x.invalid -m correlation --dry-run 2>&1)
grep -qE 'would run:.*(^|[ ,])ct([ ,]|$)' <<< "$out" \
  && grep -qE 'would run:.*(^|[ ,])wayback([ ,]|$)' <<< "$out" \
  && printf '  \033[32mOK\033[0m  dependency closure pulls in ct+wayback\n' \
  || { printf '  \033[31mFAILED\033[0m  dependency closure\n'; fails=$((fails+1)); }

hr "result"
if [[ $fails -eq 0 ]]; then
  printf '\033[32mALL CHECKS PASSED\033[0m\n'; exit 0
else
  printf '\033[31m%d CHECK GROUP(S) FAILED\033[0m\n' "$fails"; exit 1
fi
