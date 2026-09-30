# deep-recon

Automated skipped-layer recon for bug bounty, built for Termux (ARM64 / Android, no root). One script (`deep_recon.sh`, ~5,300 lines, bash) that chains the recon layers most hunters skip — ASN/IP space, reverse DNS, CT deep mining, Wayback intelligence, cloud buckets, email security, favicon hashing, non-standard ports, vhosts, JS mining, protocol intelligence, OSINT, CVE mapping, and a target-specific testing playbook.

## Why this exists

Most recon stops at `subfinder + httpx`. The findings live in the layers people skip:

- IPs and CIDRs outside `*.target.com`
- Old API versions and backup files in Wayback
- S3/GCP/Azure buckets named after the company
- SPF/DMARC gaps, CAA gaps, weak headers
- Source maps, JS secrets, GraphQL endpoints
- Auth surface, SSRF params, smuggling surface

`deep_recon.sh` automates all of that into one `./recon_<target>_<date>/` directory with a Markdown report.

## Modules (23)

| # | Key | What it does |
|---|-----|--------------|
| 1 | `asn` | ASN + IPv4/IPv6 CIDR enum (BGPView, MX-IP CDN bypass, org search, HackerTarget, Team Cymru, ARIN RDAP, ipinfo) |
| 2 | `rdns` | Reverse DNS sweep over discovered CIDRs (dnsx, dig fallback), flags dev/staging/admin names |
| 3 | `ct` | CT deep mining (crt.sh + Certspotter + BufferOver fallback), org-name search, service/env naming analysis |
| 4 | `wayback` | Wayback + gau in parallel, param extraction, backup/config patterns, API versions, admin paths |
| 5 | `cloud` | S3 / GCS / Azure bucket permutation + anonymous-access check (~40 name variants) |
| 6 | `email` | SPF / DMARC / DKIM / MX analysis, vendor extraction, `mail.` host check |
| 7 | `favicon` | MurmurHash3 favicon hash for Shodan pivoting |
| 8 | `ports` | High-value port scan (naabu / nmap / bash-TCP fallback): Docker, Redis, ES, Mongo, Kibana, etc. |
| 9 | `vhost` | Virtual-host fuzzing (ffuf) with CT + env-wordlist candidates |
| 10 | `params` | Param wordlist (Wayback + sensitive list), arjun hook |
| 11 | `js` | JS URL harvest, bundle download, endpoint + secret + GraphQL quick pass, OMEGA hook |
| 12 | `correlation` | Master subdomain list, takeover candidates (CNAME), JS↔infra cross-ref |
| 13 | `monitor` | Continuous monitor: new subs / ports / certs, Termux notifications, cron hook |
| 14 | `supplemental` | CAA/SOA, robots/sitemap/security.txt, header audit (CORS/CSP/HSTS/cookies/OPTIONS), source maps, alterx permutations, SPF chain walk, URLScan, SaaS/Firebase detection, GitHub dorks, npm/Docker hints |
| 15 | `protocol` | WAF/CDN fingerprint, JARM, GraphQL introspection, API version enum, WebSocket discovery, SMTP banner, cache + smuggling indicators |
| 16 | `intelligence` | APK static analysis, passive→active priority scoring, WAF-evasion validation, VirusTotal passive lookup |
| 17 | `auth` | Login/OAuth/JWT/SAML/session endpoint discovery + rate-limit probes |
| 18 | `cve` | Tech-stack fingerprint → NVD/OSV mapping, high-severity report |
| 19 | `osint` | GitHub org/employee mapping, email patterns, breach/paste hints, acquisitions |
| 20 | `content` | Target-specific wordlists + per-host ffuf, backup + API path discovery |
| 21 | `metadata` | PDF/Office/EXIF metadata: authors, tools, internal paths/hostnames |
| 22 | `deepproto` | Smuggling surface, SOAP/WSDL, LDAP/SNMP, MQTT/AMQP, webhook/SSRF param map |
| 23 | `playbook` | Generates `playbook/playbook.md` — target-specific checklist (IDOR, auth, logic, race, GraphQL, WS, SSRF, multi-tenant) |

## Requirements

Core (must exist): `curl`, `dig`, `jq`, `python3`, `whois`

Go tools (recommended): `subfinder`, `httpx`, `waybackurls`, `gau`, `dnsx`, `alterx`, `naabu`

Optional: `ffuf`, `nmap`, `arjun`

Termux install:

```bash
pkg install curl dnsutils jq python whois git -y
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/ffuf/ffuf/v2@latest
pip install arjun --break-system-packages
```

Every module degrades gracefully — missing tools are skipped with a warning, never a hard failure.

## Usage

```bash
chmod +x deep_recon.sh
./deep_recon.sh -d target.com [OPTIONS]
```

Options:

```
-d  DOMAIN       Target domain (required)
-o  OUTPUT_DIR   Output directory (default: ./recon_TARGET_DATE)
-w  WORDLIST     Custom subdomain wordlist
-t  THREADS      Threads for ffuf/httpx (default: 50)
-s  SCOPE_FILE   File with in-scope CIDR ranges (optional)
-m  MODULES      Comma-separated modules (default: all)
--skip-ports     Skip port scanning (faster, less noise)
--passive-only   Zero-noise passive modules only
--resume         Resume previous run
-v               Verbose output
-h, --help       Show help
```

Examples:

```bash
# Full recon
./deep_recon.sh -d target.com

# Passive only (safe, no active scanning)
./deep_recon.sh -d target.com --passive-only

# Fast: skip ports, selected modules
./deep_recon.sh -d target.com --skip-ports -m asn,ct,wayback,cloud,email,js

# With program scope file + verbose
./deep_recon.sh -d target.com -s scope.txt -v

# Continuous monitor (single cycle, or LOOP=true for loop)
./deep_recon.sh -d target.com -m monitor
LOOP=true ./deep_recon.sh -d target.com -m monitor
MONITOR_CRON=true ./deep_recon.sh -d target.com -m monitor
```

Full integration run (VanguardScanner / nuclei-go / OMEGA hooks):

```bash
RUN_INTEGRATIONS=true ./deep_recon.sh -d target.com
```

## Output

```
recon_target.com_20240101_1200/
├── asn/           ASN, CIDR blocks, IP list
├── dns/           Reverse DNS results
├── ct/            Certificate transparency mining
├── wayback/       Historical URLs, params, sensitive files, API versions
├── cloud/         S3 / GCS / Azure findings
├── email/         SPF / DMARC / DKIM / MX
├── ports/         Port scan results
├── vhost/         Vhost candidates + results
├── js/            Live hosts, JS URLs, bundles, endpoints, secrets
├── params/        Parameter wordlist (+ arjun results)
├── correlation/   Master subs, takeover candidates
├── supplemental/  Headers, source maps, SPF chain, URLScan, SaaS, dorks
├── protocol/      WAF, JARM, GraphQL, API, WebSocket, SMTP, cache
├── intelligence/  Mobile, priority scores, evasion, VirusTotal
├── auth/          Login / OAuth / JWT / SAML / session / rate-limit
├── cve/           Tech stack + NVD high-severity matches
├── osint/         GitHub, email, breach, paste, acquisitions
├── content/       Wordlists + ffuf results + backups + APIs
├── metadata/      Document URLs + EXIF/author leaks
├── deepproto/     Smuggling, SOAP, LDAP/SNMP, MQTT, SSRF map
├── playbook/      playbook.md — what to test next
└── reports/       RECON_REPORT_<target>_<date>.md + favicon hash
```

Key files to check first after a run:

1. `reports/RECON_REPORT_*.md` — executive summary
2. `correlation/takeover_candidates.txt` — verify immediately
3. `wayback/sensitive_files.txt` — backups/configs/dumps
4. `js/potential_secrets.txt` — manual review required
5. `js/omega_run_command.sh` — full OMEGA JS analysis
6. `ct/ct_analysis.txt` — forgotten infra / acquisitions
7. `playbook/playbook.md` — your testing checklist

## Toolchain hooks

- **VanguardScanner**: live hosts exported to `reports/vanguard_targets.txt` + `run_vanguard.sh`
- **nuclei-go**: command template at `reports/run_nuclei_go.sh`
- **OMEGA / JS Decoder**: bundle dir at `js/bundles/`, trigger via `js/omega_run_command.sh`

Set `RUN_INTEGRATIONS=true` to generate these automatically.

## Notes for Termux

- No root required. Uses `nmap -sT`-style / naabu / bash-TCP fallbacks.
- Wayback fetch runs `waybackurls + gau` in parallel with a 5-minute safety cap.
- curl calls use retry + backoff; rate-limited APIs (crt.sh, BGPView) are retried before falling back.
- `set -u -o pipefail` without `errexit` — pipelines use explicit `|| true` guards so one bad API response never kills a run.

## Legal

Only run against targets you are authorized to test (your bug bounty scope, your own assets, or explicit permission). Active modules (ports, vhost, content, protocol) send traffic to the target — use `--passive-only` when in doubt, and always respect the program's rules of engagement.
