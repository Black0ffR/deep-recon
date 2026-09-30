# FIXES.md — what changed, and why

`deep_recon.sh` (original) → `deep_recon.sh` (fixed)
Original preserved as `deep_recon.sh.orig` for diffing.

Every finding from the static review is listed. "Verified" means there is an
executable check for it in `test/`; the command is named so you can re-run it.

```
bash test/run_all.sh          # everything
python3 test/test_invariants.py deep_recon.sh   # 66 static invariants
python3 test/test_snmp_packet.py  deep_recon.sh # 9/9 packets byte-exact
python3 test/test_jarm.py        deep_recon.sh # RFC 5246 offsets + 32-char JARM
python3 test/test_metadata.py    deep_recon.sh # OOXML inflate, PDF streams
bash    test/test_coverage_table.sh             # report coverage rendering
```

---

## 1. Corrections to the review itself

Two claims in the original review were wrong and are corrected here. Both were
caught while implementing, not by inspection.

**F7 (SNMP) was overstated.** The review said the hand-built BER lengths were
"wrong for *every* community string and mutually inconsistent". That is not
right. Checking the arithmetic against RFC 1157/3416:

| field | value | depends on community length? |
|---|---|---|
| `a0 19` (PDU) | 25 = 3+3+3+16 | no — correct for every string |
| `30 26` (message) | 38 = 3+2+len+27 | **yes — correct only when len = 6** |

`30 26` happens to be exactly right for `"public"`, the first string tried, so
the probe did work for the default community. The real defect is narrower and
still serious: the community length is computed dynamically while the two
enclosing lengths are hardcoded, so the other eight iterations sent a PDU whose
declared message length was short by `len−6` bytes, and a device requiring
`private` could never be found. The fix derives all lengths; `test_snmp_packet.py`
now proves all nine packets byte-exact.

**The review also asserted the JARM sentinel guard was "62 vs 64 zeros"** — that
part was correct, but the deeper point is that neither string was a JARM.

Two more implementation-time corrections worth recording, both found by
`test_jarm.py` and `test_metadata.py` against the *fixed* code:

- **ALPN extension length is 2 bytes, not 1.** My first rewrite of the JARM
  parser read `ebody[1]` as the ALPN name length. RFC 7301 specifies
  `uint16 list_len; opaque protocol_name`. Caught by a synthetic ServerHello.
- **`.{0,4_000_000}?` compiles but never matches.** Python's `re` does not accept
  underscore separators inside `{m,n}`, so the quantifier is silently garbage —
  the whole PDF compressed-stream branch was a no-op. Fixed to `.{0,4000000}`.

---

## 2. S1 — wrong result or broken execution

| # | Where | Defect | Fix | Verified by |
|---|---|---|---|---|
| F1 | `extract_cipher_and_version` | Read the cipher suite from hardcoded bytes `43:45`, which is the session-id **length** byte. RFC 5246 §7.4.3 puts the cipher at `43+1+sid_len` (offset 76 for a 32-byte sid). Every probe returned garbage. | Length-prefixed ServerHello walk; `sid_len` honoured; ALPN parsed per RFC 7301 | `test_jarm.py` (sid_len 0/16/32) |
| F2 | `jarm_hash` | Emitted `sha256(raw).hexdigest()[:62]` — raw hex of the wrong length. A JARM is 32 chars: first 32 hex digits of the digest mapped through base-32. Sentinel was 62 zeros, guard tested 64, so neither suppressed anything. | Real JARM mapping, 32-char sentinel, guard checks length 32 before reporting, `tlsx` used when present | `test_jarm.py` |
| — | ClientHello | No extensions block at all, so modern stacks had nothing to negotiate. | Full ClientHello: SNI, ALPN, supported_versions, sigalgs, ec_point_formats; 10 probes | — |
| F3 | L1600, L2359, L3108 | Header audit used `curl -I` (HEAD). Many origins/CDNs omit `Set-Cookie` and return a reduced header block on HEAD, producing **false** "No CSP" / "No HSTS" / "cookie missing flags" findings. Cascaded into `module_cve`'s tech fingerprint. | `curl -skL -D - -o /dev/null` (real GET, headers captured, body discarded) at all three sites | `test_invariants.py` |
| F4 | `ldap_ips` collection | `… \| while read; do ldap_ips+=(…); done` — the `while` is the last element of a pipeline, so it ran in a **subshell** and the increment was discarded. `[[ ${#ldap_ips[@]} -gt 0 ]]` was always false, and the module printed a *false* reason ("No LDAP ports found") even when naabu output contained `:389`. | `mapfile -t ldap_ips < <(…)`; distinct messages for "no scan artifacts" vs "no LDAP ports" | `test_invariants.py` |
| F5 | SSRF payload | `read(output_dir/"supplemental/wellknown")` pointed at a **directory**. `Path.read_text()` raises `IsADirectoryError`, `read()`'s bare `except` turned it into `""`, so the webhook branch was permanently False. | `rglob` the directory, concatenate the real files, list the matching lines | `test_invariants.py` |
| F6 | `module_rdns` | `-s SCOPE_FILE` was copied into the output tree then ignored: rDNS preferred `asn/ipv4_cidrs.txt` whenever it existed, so the PTR sweep ran over the whole announced prefix set of the ASN even with an explicit scope file. | `apply_scope()` in `main`; rDNS prefers the operator file and says so; `in_scope_ip` gate on SNMP/other IP probes | `test_invariants.py` + manifest `scope_authoritative` |
| F7 | SNMP packet | Enclosing BER lengths hardcoded while the community length was dynamic (see correction above). | All lengths derived; `snmp_get_request()` + `snmp_selftest()` | `test_snmp_packet.py` 9/9 byte-exact |
| F8 | SNMP verdict | "did any bytes come back" ⇒ `Community 'public' works`, then `break`, so the other eight strings were never tried. A rejecting agent counts as success. | Require a GetResponse (`a2`) **with** an OCTET STRING varbind; rejections logged separately; loop continues | `test_invariants.py` |
| F9 | `extract_office_metadata` | `data.decode('latin-1')` over the raw ZIP and regexed `<dc:creator>`. OOXML members are **DEFLATE**-compressed, so the XML is not in those bytes — the Office half of module 21 produced nothing for any real Word/Excel file. Secondary: stored the key `lastModifiedBy` while the report looked for `cp:lastModifiedBy`, so the author-leak finding could never fire. | `zipfile.ZipFile(BytesIO(data))`, read `docProps/core.xml` + `app.xml`; full key preserved | `test_metadata.py` (deflated container test) |
| F10 | L2669, L3939 | `grep -rl … \| xargs grep -h …` — when the outer grep matched nothing, xargs ran `grep` with no file operand, which read **the script's stdin**. With a terminal it hung forever; with a pipe it ate the caller's data. | `grep -rh … \| wc -l` at both sites | `test_invariants.py` |
| F11 | SPF branch | `grep -qiE '~all|\\?all'` — the second alternative means "optional backslash then `all`", so it matched the bare substring `all` **anywhere**. Every SPF took the soft-fail branch, the `-all` branch was unreachable, and a hard-fail domain was reported as spoofable. | `grep -qiE '~all|\?all'` | `test_invariants.py` |
| F12 | 6 grep sites | Domain escaped in one half of each pattern, raw in the adjacent half — so the same name was a literal in one position and a wildcard in the next, leaking in-domain hosts into the acquisition list that module 19 then probed. | `dom_regex` / `domain_re` / `domain_anchor_re` helpers used everywhere | `test_invariants.py` |

---

## 3. S2 — dead or mislabelled features

| # | Where | Defect | Fix |
|---|---|---|---|
| F13 | 5 sites | `grep -c … \|\| echo 0` → `"0\n0"` (not a valid integer). The file documented this exact bug and avoided it in one place, then never propagated the fix. | `\|\| true` + `${var:-0}` |
| F14 | evasion report | `tests_passed` declared, never incremented, used as the denominator → "3 blocked / 3 tested" after 5 probes. | `((tests_passed++))` in `run_evasion_test` |
| F15 | `waf_detected` | Both branches ran the identical probe set; the detection was decorative. | `EVASION_TIER` set per branch; a bypass is only *reported* when a WAF was actually confirmed, otherwise labelled as baseline |
| F16 | 6 modules | `[[ ! -s "$live_hosts" ]] && echo apex > "$live_hosts"` — six modules *created* the host inventory with one line when missing. A 1-host run looked identical to a 50-host run. | New `module_discover` (module 0) owns the inventory; consumers call `require_live_hosts`, which falls back to the apex **and records it in the module status** so the report shows reduced coverage |
| F17 | OMEGA | Two producers wrote `omega_run_command.sh` with incompatible flags (`--input-dir` vs `--input`). | Single writer; detects the flag from the target file |
| F18 | VirusTotal | Fetched the v3 API with an empty key, then the retired `vtapi/v2` endpoint, then **read neither**. `vt_data` was assigned twice and used zero times. | `VT_API_KEY` from the environment, response actually parsed; without a key the module says so instead of logging as if it had worked |
| F19 | JWT → playbook | Writer emitted `!!`, playbook grepped `"FLAGS:"` → the JWT playbook section could never be generated. | Writer emits `FLAGS:` |
| F20 | SSO | Providers were emitted as a `finding` into `findings_summary.txt`; the playbook read `auth/session/sso_fingerprint.txt`, which **nothing ever wrote**. | `module_auth` now writes the file with the exact header the playbook greps for |
| F21 | WebSocket | `ws_host` (the `https:`→`wss:` rewrite) computed then discarded; probe ran over `http://`. | Uses `${ws_host}${ws_path}` |
| F22 | S3 | `found_buckets` appended 42× and never read; and the only artifact the priority engine scores (`s3_exists.txt`) is written for 403/301/302 only — so the *highest*-severity class, 200 Publicly Readable, was the one case missing from the scored file. | `s3_public.txt` written and added to the report |
| F23 | 3 sites | `code` held the SOAP response body while `http_code` held the status; `gql_code` declared and never assigned; `ws_host` above. | Names match contents; dead variables removed |
| — | `CDN_ASNS` | Declared and never read (the used list is `cdn_asns`, without the `AS` prefix). | Removed |

---

## 4. S3 — robustness and environment

| # | Where | Defect | Fix |
|---|---|---|---|
| F24 | `error()` at L97/L101 | `LOG_FILE` was `""` until after arg parsing, and `tee -a ""` exits without copying stdin to stdout — so `error "Domain required"` printed **nothing** and the script exited 1 silently. | `LOG_FILE` bootstrapped before parsing; `_log_tee` falls back to `cat`; `section()` now logs all three lines |
| F25 | 39 sites | `curl -w '%{http_code}' … \|\| echo "000"` → `"000\n000"`, because curl already printed `000` before exiting non-zero. | `\|\| true` throughout; new `http_code()` helper |
| F26 | Azure | 400 treated as "account exists" (ambiguous on the legacy endpoint); `azure_exists.txt` was written but never read and absent from the report. | Records `MAY_EXIST_<code>`; added to the report |
| F27 | 7 sites | Two different "base name" derivations — `cut -d. -f1` in one module, `rev \| cut -d. -f2 \| rev` in six. For `target.co.uk` they give `target` and `co`, producing buckets like `co-backup`, an RTDB named `co-default-rtdb…`, and GitHub org `coinc`. | One `base_name()` helper with a ccTLD rule |
| F28 | well-known | `$(basename "$path")` mapped both `/security.txt` and `/.well-known/security.txt` to the same filename — the RFC 9116 location silently overwrote the legacy one. | Full path with `/`→`_` |
| F29 | JS bundles | Files addressed by `basename`; `app.js`/`main.js`/`vendor.js` overwrote each other, so the "max 50" download kept far fewer. Source maps used `basename` *without* query stripping → a file literally named `app.js?v=1.map`. | Digest-addressed names + a `.urlmap` the `.map` probe reuses |
| F30 | wordlist | `list(words)[:100]` over a `set` — order depends on hash randomisation, so the "top 100 most relevant" changed every run. | `sorted(words, key=lambda w: (-len(w), w))[:100]` |
| F31 | cert counter | `grep "^YYYY" \| grep -v "^YYYY-MM"` — the second grep removes exactly what the first selected, so the count was always 0 and the finding never fired. | `awk` counting distinct certs this year excluding this month |
| F32 | NVD | Comment said "5 req/30s", code slept 1.5s (20/30s) → NVD 403'd partway and `except: continue` hid it. Report looked complete but was truncated. | 6.2s unauth / 0.7s with `NVD_API_KEY`; HTTP 403/429 sets an explicit `_exhausted` flag and stamps the report **PARTIAL** |
| F33 | metadata | `r.read()` unbounded (a 2 GB "document" exhausted memory); PDF scanned only the first 64 KB. | `MAX_DOC_BYTES` 8 MB, TLS verification disabled to match the rest of the tool, full-buffer scan |
| F34 | EXIF | Hardcoded `<H`/`<I`; TIFF byte-order mark ignored, so big-endian (`MM`) files silently yielded nothing. Markers with no length field skipped using a bogus length. | BOM selects endianness; proper IFD walk with entry count; payload-less markers and SOS handled |
| F35 | deps | `whois` and `xxd` used but undeclared; `git` declared and never used. Missing `xxd` made LDAP/MQTT report "no anonymous bind"/"no open broker" as if checked. | Hard check for `curl dig jq python3`; **soft** check that warns and records DEGRADED for the rest; `hexdump()` falls back to `od` |
| F36 | monitor | Three state-diff blocks overwrote the previous baseline **unconditionally** — one failed collection erased the baseline and the next cycle reported the entire corpus as NEW. | `cp` only when the current collection is non-empty; otherwise warn and preserve |
| F37 | vhost | URL was the raw IP, so no SNI was sent; every request hit the default vhost on any SNI-multiplexed front end, then `-fs` discarded the results. Module reliably found zero. | Fuzzed name in the URL so SNI follows it; `--connect-to` for the baseline |
| F38 | APK | `find . -maxdepth 2 -name '*.apk'` searched the **cwd**, so a run from a downloads folder decompiled an unrelated APK and reported its endpoints and secrets as target findings. | Scoped to `${OUTPUT_DIR}`, `APK_PATH` override |
| F39 | `-h` | Generated from the header, which listed 11 modules while the default ran 22. | Full list, plus the tier/environment notes |
| F40 | `\047` | Recorded, not changed: the escape is correct, but three different idioms for the same intent invite a bad refactor. | Left alone, with a note |

---

## 5. Design findings

| # | Problem | Fix |
|---|---|---|
| D1 | Modules exchanged data only through files; the order of 23 `&&` lines *was* the contract. `-m auth` without `-m js` silently gave it empty input. | `MODULE_DEPS` graph + `resolve_modules()` computes the closure and records what it added. Order in `main` is now cosmetic. |
| D2 | `--passive-only` included `auth` (12 live credential POSTs per login URL) and `intelligence` (WAF-evasion payloads). | Both removed from the passive tier and gated behind `--authz-ref <ticket>`; a config error, not a mid-run discovery. |
| D3 | `-s SCOPE_FILE` consumed at exactly one place. Nothing validated that resolved IPs or CT-derived subdomains were in scope. | `apply_scope()` + `in_scope_ip()` consulted before IP-level probes; the manifest records `scope_authoritative`. |
| D4 | `crt.sh` was fetched **four times** per run with no reconciliation; politeness was a per-site `sleep` that scaled with module count. | `rate_limited_curl` gained an on-disk cache with TTL, a per-call deadline, and a shared request budget. `--no-cache` / `--refresh` / `--budget N`. |
| D5 | ~40 external tools' exit statuses discarded by construction; "0 findings" was indistinguishable from "everything failed". | `run_tool()` records `{label, rc, ms, bytes}` to `state/tool_calls.jsonl`; `tool_errors` appears in the report. |
| D6 | A missing ffuf/naabu/alterx silently reduced coverage while the module still printed "complete". | Three-valued module state (`RAN`/`DEGRADED`/`SKIPPED`) with a mandatory reason, surfaced as a table. |
| D7 | `--resume` and `-w` were parsed and never read by anything. | `--resume` implemented via per-module input-digest sentinels; `-w` is now a real content-discovery wordlist. Both are also fixed in the header. |
| D8 | The report was counts with no denominator: `CIDRs discovered: 0` read the same whether skipped, CDN-masked, or genuinely empty. | `coverage_table()` renders per-module state into the report; `coverage.json` is a machine-readable roll-up; the header carries provenance (requested vs resolved modules, tier, authz, scope, budget). |
| D9 | Everything except waybackurls/gau was a serial `curl` loop. | Request budget + per-call deadline + `FETCH_TIMEOUT`/`FETCH_DEADLINE`/`MAX_RUNTIME` knobs. **Partial** — a full worker pool was not introduced; see *Not done* below. |
| D10 | TLS/SNMP/LDAP/MQTT implemented as inline byte strings, with no record of how a result was obtained. | JARM and SNMP now parse to spec with self-tests and prefer `tlsx`/`ldapsearch` when present; LDAP/MQTT comments name the RFC. **Partial** — see *Not done*. |
| D11 | No module could be exercised without running the whole recon. | 14 Python payloads compile-tested and 3 are behaviourally tested against synthetic inputs; the argv convention the Python blocks already used is now the documented model. **Partial** — no signature refactor. |
| D12 | Four env vars changed behaviour but were invisible; not one API key was configurable, so the keyless calls were guaranteed no-ops. | `-c config` file + env overlay, parsed once; all six credentials read from the environment and reported in the manifest; `--help` documents them. |

---

## 6. Not done, and why

- **Bounded worker pool (D9).** Every per-host loop is still sequential. Adding
  parallelism to ~15 call sites risks rate-limit and correctness regressions
  that I cannot test here; the budget/deadline knobs give the operator control
  without it. This is the largest remaining item.
- **Full module signature refactor (D11).** Modules still read globals. The
  Python payloads are argv-parameterised and tested; the bash side is not.
- **`dnsx -ptr` output layout** and **httpx `-silent` output format** remain
  unverified. Mitigations shipped anyway: `discover` pins `httpx -json` and
  post-normalises the inventory, and the rdns filters degrade to empty rather
  than erroring. I did not assert a fix for a schema I could not confirm.
- **BufferOver `cut -d',' -f5`** (L~600) is left as-is. The record shape is
  unconfirmed, so the field index is unchanged and the empty result falls
  through to the next CT source exactly as before.
- **ARIN RDAP route/shape** (L~700) left as-is for the same reason.
- **`bgrepview.io` availability** unverified; if the endpoint is dark the CIDR
  chain is empty and the report now says so through the coverage table.

---

## 7. Verification

`bash -n` clean. 11 inline Python payloads byte-compile. 66 static invariants
pass (each asserts a fixed defect is gone *in code*, with comments stripped so
an explanatory comment quoting the old bug cannot mask a regression).

Behavioural: 9/9 SNMP packets byte-exact against an RFC-derived reference;
13/13 JARM parser and hash checks including three session-id lengths; 15/15
metadata checks on genuinely deflated OOXML and Flate-compressed PDF streams;
6/6 coverage-table rendering checks; 6/6 CLI-surface checks including the
`--authz-ref` gate, the corrected `--passive-only` tier, and dependency
closure.

End-to-end smoke runs produced a report whose coverage table reads:

```
| Module | State | Time | Tool errors | Note |
|---|---|---:|---:|---|
| discover | **DEGRADED** | 0s | 0 | dnsx missing — falling back to dig; only the apex host resolved … |
| ct        | **RAN**      | 23s | 0 |  |
| wayback   | **RAN**      | 65s | 0 |  |
```

which is exactly the distinction the original script could not make.
