#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# deep_recon.sh — Automated Skipped-Layer Recon for Bug Bounty (Termux ARM64)
# =============================================================================
# Covers: ASN/CIDR, Reverse DNS, CT logs, GitHub OSINT hints, Wayback mining,
#         Cloud buckets, Email security, Favicon hashing, Non-standard ports,
#         Virtual host discovery, Parameter extraction, JS endpoint mining
#
# Usage:
#   ./deep_recon.sh -d target.com [OPTIONS]
#
# Options:
#   -d  DOMAIN       Target domain (required)
#   -o  OUTPUT_DIR   Output directory (default: ./recon_TARGET_DATE)
#   -w  WORDLIST     Custom subdomain wordlist
#   -t  THREADS      Threads for ffuf/httpx (default: 50)
#   -s  SCOPE_FILE   File containing in-scope CIDR ranges (optional)
#   -m  MODULES      Comma-separated modules to run (default: all)
#                    Options: asn,rdns,ct,wayback,cloud,email,favicon,
#                             ports,vhost,params,js,correlation
#   --skip-ports     Skip port scanning (faster, less noise)
#   --passive-only   Run only zero-noise passive modules
#   --resume         Resume previous run (reads existing output files)
#   -v               Verbose output
#
# Dependencies (install via pkg/go install):
#   Required:  curl, dig, whois, jq, python, git
#   Go tools:  subfinder, httpx, waybackurls, gau, dnsx, alterx, naabu
#   Optional:  ffuf, nmap, masscan, arjun
#
# Author: Built for your Termux ARM64 recon workflow
# =============================================================================

set -uo pipefail
# Note: -e (errexit) intentionally omitted — this script uses explicit || true
# guards on all critical pipelines. errexit causes silent death when jq/grep
# receive unexpected input (e.g. HTML error pages from rate-limited APIs).

# ─── Color palette ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Defaults ─────────────────────────────────────────────────────────────────
DOMAIN=""
OUTPUT_DIR=""
WORDLIST="${HOME}/.wordlists/subdomains-top1million-5000.txt"
THREADS=50
SCOPE_FILE=""
MODULES="asn,rdns,ct,wayback,cloud,email,favicon,ports,vhost,params,js,correlation,supplemental,protocol,intelligence,auth,cve,osint,content,metadata,deepproto,playbook"
SKIP_PORTS=false
PASSIVE_ONLY=false
RESUME=false
VERBOSE=false
START_TIME=$(date +%s)

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE=""

log()      { echo -e "${DIM}[$(date '+%H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"; }
success()  { echo -e "${GREEN}[✔]${NC} $*" | tee -a "$LOG_FILE"; }
warn()     { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
error()    { echo -e "${RED}[✘]${NC} $*" | tee -a "$LOG_FILE"; }
section()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${NC}"; \
             echo -e "${BOLD}${CYAN}  $*${NC}"; \
             echo -e "${BOLD}${CYAN}══════════════════════════════════════${NC}\n" | tee -a "$LOG_FILE"; }
info()     { echo -e "${BLUE}[i]${NC} $*" | tee -a "$LOG_FILE"; }
finding()  { echo -e "${MAGENTA}[★ FINDING]${NC} $*" | tee -a "$LOG_FILE"; \
             echo "$*" >> "${OUTPUT_DIR}/findings_summary.txt"; }
verbose()  { [[ "$VERBOSE" == true ]] && echo -e "${DIM}[v]${NC} $*" | tee -a "$LOG_FILE" || true; }

# ─── Arg parsing ──────────────────────────────────────────────────────────────
usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \?//' | head -40
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="$2"; shift 2 ;;
    -o) OUTPUT_DIR="$2"; shift 2 ;;
    -w) WORDLIST="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -s) SCOPE_FILE="$2"; shift 2 ;;
    -m) MODULES="$2"; shift 2 ;;
    --skip-ports) SKIP_PORTS=true; shift ;;
    --passive-only) PASSIVE_ONLY=true; MODULES="asn,rdns,ct,wayback,cloud,email,favicon,js,supplemental,intelligence,auth,cve,osint,metadata,playbook"; shift ;;
    --resume) RESUME=true; shift ;;
    -v) VERBOSE=true; shift ;;
    -h|--help) usage ;;
    *) error "Unknown option: $1"; exit 1 ;;
  esac
done

[[ -z "$DOMAIN" ]] && { error "Domain required. Use: $0 -d target.com"; exit 1; }

# ─── Setup output directory ───────────────────────────────────────────────────
DATE=$(date '+%Y%m%d_%H%M')
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="./recon_${DOMAIN}_${DATE}"
mkdir -p "$OUTPUT_DIR"/{asn,dns,ct,wayback,cloud,email,ports,vhost,content,js,params,correlation,reports}
LOG_FILE="${OUTPUT_DIR}/deep_recon.log"
touch "${OUTPUT_DIR}/findings_summary.txt"

# ─── Banner ───────────────────────────────────────────────────────────────────
banner() {
  echo -e "${BOLD}${CYAN}"
  cat << 'EOF'
  ██████╗ ███████╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗
  ██╔══██╗██╔════╝██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗
  ██║  ██║█████╗  █████╗  ██████╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗
  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗
  ██████╔╝███████╗███████╗██║         ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚██╗
  ╚═════╝ ╚══════╝╚══════╝╚═╝         ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
EOF
  echo -e "${NC}${DIM}  Skipped-Layer Bug Bounty Recon Automation | Termux ARM64 Edition${NC}\n"
  echo -e "  ${BOLD}Target:${NC}  ${GREEN}${DOMAIN}${NC}"
  echo -e "  ${BOLD}Output:${NC}  ${OUTPUT_DIR}"
  echo -e "  ${BOLD}Modules:${NC} ${MODULES}"
  echo -e "  ${BOLD}Mode:${NC}    $([ "$PASSIVE_ONLY" == true ] && echo 'Passive Only' || echo 'Full')"
  echo ""
}

# ─── Tool check helpers ───────────────────────────────────────────────────────
has_tool() { command -v "$1" &>/dev/null; }

require_tool() {
  if ! has_tool "$1"; then
    warn "Optional tool '$1' not found — skipping related checks."
    return 1
  fi
  return 0
}

check_core_deps() {
  local missing=()
  for t in curl dig jq python3; do
    has_tool "$t" || missing+=("$t")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Missing required tools: ${missing[*]}"
    error "Install with: pkg install ${missing[*]}"
    exit 1
  fi
}

module_enabled() {
  [[ ",$MODULES," == *",$1,"* ]]
}

# ─── Utility functions ────────────────────────────────────────────────────────
count_lines() { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }

dedupe_file() {
  [[ -f "$1" ]] && sort -u "$1" -o "$1"
}

rate_limited_curl() {
  # Polite curl with retry and backoff
  local url="$1"; shift
  local max_retries=3
  local delay=2
  for i in $(seq 1 $max_retries); do
    if curl -sL --max-time 15 --retry 2 "$@" "$url" 2>/dev/null; then
      return 0
    fi
    verbose "Retry $i/$max_retries for $url"
    sleep $((delay * i))
  done
  verbose "Failed after $max_retries attempts: $url"
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1: ASN & IP SPACE ENUMERATION
# Skipped by: ~95% of hunters who only look at *.target.com
# ─────────────────────────────────────────────────────────────────────────────
module_asn() {
  section "MODULE 1: ASN & IP Space Enumeration"
  local asn_dir="${OUTPUT_DIR}/asn"

  # 1a. Resolve the domain to IPs
  info "Resolving domain to IPs..."
  dig +short "$DOMAIN" A 2>/dev/null | grep -E '^[0-9]+\.' > "${asn_dir}/domain_ips.txt" || true
  dig +short "$DOMAIN" AAAA 2>/dev/null >> "${asn_dir}/domain_ips.txt" || true
  dedupe_file "${asn_dir}/domain_ips.txt"

  if [[ ! -s "${asn_dir}/domain_ips.txt" ]]; then
    warn "Could not resolve $DOMAIN to any IPs"
    return
  fi

  local first_ip
  first_ip=$(head -1 "${asn_dir}/domain_ips.txt")
  info "Primary IP: $first_ip"

  # ── CDN detection ─────────────────────────────────────────────────────────
  # If the resolved IP belongs to a CDN (Cloudflare/Akamai/Fastly/etc),
  # looking up ASN by IP returns the CDN's ASN, not the target's.
  # Detect this and switch to org-name based lookup instead.
  local CDN_ASNS="AS13335 AS20940 AS16625 AS54113 AS209242 AS394536 AS200814"  # CF, Akamai, Fastly
  local CDN_RANGES="104.16. 104.17. 104.18. 104.19. 104.20. 104.21. 172.64. 172.65. 172.66. 162.158. 198.41."
  local is_cdn=false

  for cdn_prefix in $CDN_RANGES; do
    if [[ "$first_ip" == ${cdn_prefix}* ]]; then
      is_cdn=true
      warn "Primary IP ${first_ip} is a CDN/Cloudflare address — switching to org-name ASN lookup"
      echo "CDN_MASKED: $first_ip" > "${asn_dir}/cdn_detected.txt"
      break
    fi
  done

  # 1b. ASN lookup — IP-based or org-name fallback for CDN targets
  local asn_number="" asn_name=""

  if [[ "$is_cdn" == false ]]; then
    info "Looking up ASN via BGPView (IP-based)..."
    local asn_data
    asn_data=$(rate_limited_curl "https://api.bgpview.io/ip/${first_ip}" \
      -H "Accept: application/json") || true

    if [[ -n "$asn_data" ]]; then
      echo "$asn_data" | jq '.' > "${asn_dir}/bgpview_ip_response.json" 2>/dev/null || true
      # BGPView returns prefixes array — take the most specific (last) not the CDN catch-all (first)
      asn_number=$(echo "$asn_data" | jq -r '
        .data.prefixes
        | sort_by(.prefix | split("/")[1] | tonumber)
        | reverse
        | .[0].asn.asn // empty' 2>/dev/null || echo "")
      asn_name=$(echo "$asn_data" | jq -r '
        .data.prefixes
        | sort_by(.prefix | split("/")[1] | tonumber)
        | reverse
        | .[0].asn.name // empty' 2>/dev/null || echo "")
    fi
  fi

  # ── CDN bypass 1: MX record IP — mail servers almost never sit behind CDN ──
  if [[ -z "$asn_number" ]]; then
    info "Trying MX record IP (mail servers bypass CDN)..."
    local mx_host
    mx_host=$(dig +short MX "$DOMAIN" 2>/dev/null \
      | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
    if [[ -n "$mx_host" ]]; then
      local mx_ip
      mx_ip=$(dig +short A "$mx_host" 2>/dev/null | grep -v '^\s*$' | head -1)
      verbose "MX: $mx_host → $mx_ip"
      if [[ -n "$mx_ip" ]]; then
        local mx_asn_data
        mx_asn_data=$(rate_limited_curl "https://api.bgpview.io/ip/${mx_ip}") || true
        asn_number=$(echo "$mx_asn_data" | jq -r \
          '.data.prefixes | sort_by(.prefix | split("/")[1] | tonumber) | reverse | .[0].asn.asn // empty' \
          2>/dev/null || echo "")
        asn_name=$(echo "$mx_asn_data" | jq -r \
          '.data.prefixes | sort_by(.prefix | split("/")[1] | tonumber) | reverse | .[0].asn.name // empty' \
          2>/dev/null || echo "")
        [[ -n "$asn_number" ]] && verbose "ASN via MX IP: AS${asn_number} — ${asn_name}"
      fi
    fi
  fi

  # ── CDN bypass 2: BGPView org name search ─────────────────────────────────
  if [[ -z "$asn_number" ]]; then
    local company_name
    company_name=$(echo "$DOMAIN" | rev | cut -d. -f2 | rev)
    info "Searching BGPView by org name: '${company_name}'..."
    local search_data
    search_data=$(rate_limited_curl "https://api.bgpview.io/search?query=${company_name}") || true
    if [[ -n "$search_data" ]]; then
      echo "$search_data" > "${asn_dir}/bgpview_search.json" 2>/dev/null || true
      asn_number=$(echo "$search_data" | jq -r --arg q "$company_name" \
        '.data.asns[] | select(.name | ascii_downcase | contains($q | ascii_downcase)) | .asn' \
        2>/dev/null | head -1 || echo "")
      asn_name=$(echo "$search_data" | jq -r --arg q "$company_name" \
        '.data.asns[] | select(.name | ascii_downcase | contains($q | ascii_downcase)) | .name' \
        2>/dev/null | head -1 || echo "")
      if [[ -z "$asn_number" ]]; then
        asn_number=$(echo "$search_data" | jq -r '.data.asns[0].asn // empty' 2>/dev/null || echo "")
        asn_name=$(echo "$search_data" | jq -r '.data.asns[0].name // empty' 2>/dev/null || echo "")
      fi
    fi
  fi

  # ── CDN bypass 3: HackerTarget findasn (domain-based query) ───────────────
  if [[ -z "$asn_number" ]]; then
    info "Trying HackerTarget findasn..."
    local ht_data
    ht_data=$(rate_limited_curl "https://api.hackertarget.com/findasn/?q=${DOMAIN}") || true
    if [[ -n "$ht_data" ]] && ! echo "$ht_data" | grep -qi "error\|API count\|<html"; then
      echo "$ht_data" > "${asn_dir}/hackertarget_findasn.txt" 2>/dev/null || true
      asn_number=$(echo "$ht_data" | grep -oP 'AS\K[0-9]+' | head -1 || echo "")
      asn_name=$(echo "$ht_data" | awk -F',' 'NR==1{gsub(/"/,"",$3); print $3}' || echo "")
      verbose "HackerTarget raw: $ht_data"
    fi
  fi

  # ── CDN bypass 4: Team Cymru whois (domain → ASN direct mapping) ──────────
  local cdn_asns="13335 20940 16625 54113 209242"
  local is_cdn_asn=false
  echo "$cdn_asns" | grep -qw "${asn_number:-0}" && is_cdn_asn=true

  if [[ -z "$asn_number" ]] || [[ "$is_cdn_asn" == true ]]; then
    info "Trying Team Cymru whois (domain-based ASN lookup)..."
    local cymru_result
    cymru_result=$(whois -h whois.cymru.com " -v ${DOMAIN}" 2>/dev/null \
      | grep -v "^AS\|^Bulk\|^Error\|^$" | tail -1)
    verbose "Cymru raw: $cymru_result"
    if [[ -n "$cymru_result" ]]; then
      local cymru_asn
      cymru_asn=$(echo "$cymru_result" | awk '{print $1}' | grep -oP '^[0-9]+$')
      local cymru_name
      cymru_name=$(echo "$cymru_result" | cut -d'|' -f3- | sed 's/^[[:space:]]*//' | cut -d'|' -f1)
      if [[ -n "$cymru_asn" ]] && ! echo "$cdn_asns" | grep -qw "$cymru_asn"; then
        asn_number="$cymru_asn"
        asn_name="$cymru_name"
        is_cdn_asn=false
      fi
    fi
  fi

  # ── CDN bypass 5: ARIN RDAP org name search ───────────────────────────────
  if [[ -z "$asn_number" ]] || [[ "$is_cdn_asn" == true ]]; then
    local company_name2
    company_name2=$(echo "$DOMAIN" | rev | cut -d. -f2 | rev)
    info "Trying ARIN RDAP org search: '${company_name2}'..."
    local arin_data
    arin_data=$(rate_limited_curl \
      "https://rdap.arin.net/registry/entities?fn=${company_name2}*&role=registrant") || true
    if [[ -n "$arin_data" ]]; then
      local arin_asn
      arin_asn=$(echo "$arin_data" | jq -r \
        '.entitySearchResults[]? | select(.handle | test("^AS[0-9]")) | .handle' \
        2>/dev/null | grep -oP 'AS\K[0-9]+' | head -1 || echo "")
      if [[ -n "$arin_asn" ]] && ! echo "$cdn_asns" | grep -qw "$arin_asn"; then
        asn_number="$arin_asn"
        asn_name="${company_name2}"
        is_cdn_asn=false
        info "ARIN RDAP result: AS${asn_number}"
      fi
    fi
  fi

  # ── Last resort: ipinfo.io by IP ──────────────────────────────────────────
  if [[ -z "$asn_number" ]]; then
    info "Last resort: ipinfo.io by IP..."
    local ipinfo
    ipinfo=$(rate_limited_curl "https://ipinfo.io/${first_ip}/json") || true
    if [[ -n "$ipinfo" ]]; then
      local raw_asn
      raw_asn=$(echo "$ipinfo" | jq -r '.org // empty' 2>/dev/null | grep -oP 'AS\K[0-9]+')
      if ! echo "$cdn_asns" | grep -qw "${raw_asn:-0}"; then
        asn_number="$raw_asn"
        asn_name=$(echo "$ipinfo" | jq -r '.org // empty' 2>/dev/null | sed 's/^AS[0-9]* //')
      fi
    fi
  fi

  # ── Surface CDN masking clearly ───────────────────────────────────────────
  if [[ -z "$asn_number" ]] || [[ "$is_cdn_asn" == true ]]; then
    warn "Target is fully CDN-masked — could not resolve org ASN"
    warn "All lookups returned a CDN network. Options:"
    warn "  1. Provide known CIDRs: dr -d ${DOMAIN} -s scope.txt"
    warn "  2. Check program scope for declared IP ranges"
    warn "  3. Look for origin IP leaks in MX/TXT/historical DNS"
    asn_number=""
    asn_name=""
  fi

  if [[ -n "$asn_number" ]]; then
    finding "ASN: AS${asn_number} — ${asn_name}"
    echo "AS${asn_number}" > "${asn_dir}/asn_number.txt"

    # Fetch all CIDR prefixes for this ASN
    info "Fetching all prefixes for AS${asn_number}..."
    local prefix_data
    prefix_data=$(rate_limited_curl "https://api.bgpview.io/asn/${asn_number}/prefixes") || true

    if [[ -n "$prefix_data" ]]; then
      echo "$prefix_data" | jq -r '.data.ipv4_prefixes[].prefix // empty' 2>/dev/null \
        > "${asn_dir}/ipv4_cidrs.txt" || true
      echo "$prefix_data" | jq -r '.data.ipv6_prefixes[].prefix // empty' 2>/dev/null \
        > "${asn_dir}/ipv6_cidrs.txt" || true

      local cidr_count
      cidr_count=$(count_lines "${asn_dir}/ipv4_cidrs.txt")
      finding "Found ${cidr_count} IPv4 CIDR blocks for AS${asn_number}"
      [[ "$VERBOSE" == true ]] && cat "${asn_dir}/ipv4_cidrs.txt"
    fi
  fi

  # If scope file provided, use those CIDRs directly (always honoured)
  if [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]]; then
    cp "$SCOPE_FILE" "${asn_dir}/scope_cidrs.txt"
    finding "Loaded $(count_lines "${asn_dir}/scope_cidrs.txt") CIDRs from scope file"
  fi

  success "ASN module complete — CIDRs saved to ${asn_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2: REVERSE DNS SWEEP
# Skipped by: ~90% of hunters
# ─────────────────────────────────────────────────────────────────────────────
module_rdns() {
  section "MODULE 2: Reverse DNS Sweep"
  local rdns_dir="${OUTPUT_DIR}/dns"
  local cidr_file="${OUTPUT_DIR}/asn/ipv4_cidrs.txt"

  [[ ! -s "$cidr_file" ]] && cidr_file="${OUTPUT_DIR}/asn/scope_cidrs.txt"
  if [[ ! -s "$cidr_file" ]]; then
    warn "No CIDRs found — skipping reverse DNS. Run ASN module first."
    return
  fi

  # Try dnsx first (fastest), fall back to host command
  if require_tool dnsx; then
    info "Running reverse DNS via dnsx..."
    # Generate IP list from CIDRs
    # dnsx supports CIDR input directly with -ptr flag
    dnsx -ptr -l "$cidr_file" -silent -o "${rdns_dir}/rdns_results.txt" \
      -t "$THREADS" 2>/dev/null || true
  else
    info "dnsx not found — using dig PTR (slower)..."
    # Fallback: only scan /24 of primary IP
    local primary_ip
    primary_ip=$(head -1 "${OUTPUT_DIR}/asn/domain_ips.txt" 2>/dev/null || echo "")
    if [[ -n "$primary_ip" ]]; then
      local base_ip
      base_ip=$(echo "$primary_ip" | cut -d. -f1-3)
      for i in $(seq 1 254); do
        local ptr
        ptr=$(dig +short -x "${base_ip}.${i}" 2>/dev/null | tr -d '\n')
        [[ -n "$ptr" ]] && echo "${base_ip}.${i} → $ptr" >> "${rdns_dir}/rdns_results.txt"
      done
    fi
  fi

  if [[ -s "${rdns_dir}/rdns_results.txt" ]]; then
    local rdns_count
    rdns_count=$(count_lines "${rdns_dir}/rdns_results.txt")
    finding "Reverse DNS: ${rdns_count} PTR records discovered"

    # Extract hostnames and add to subdomain pool
    grep -oP '[a-zA-Z0-9._-]+\.'$(echo "$DOMAIN" | sed 's/\./\\./g') \
      "${rdns_dir}/rdns_results.txt" 2>/dev/null \
      >> "${rdns_dir}/rdns_subdomains.txt" || true
    dedupe_file "${rdns_dir}/rdns_subdomains.txt"

    # Flag internal-looking hostnames
    grep -iE "(internal|staging|dev|test|admin|backup|vpn|mail|infra|mgmt)" \
      "${rdns_dir}/rdns_results.txt" 2>/dev/null \
      > "${rdns_dir}/rdns_interesting.txt" || true

    local interesting_count
    interesting_count=$(count_lines "${rdns_dir}/rdns_interesting.txt")
    [[ $interesting_count -gt 0 ]] && \
      finding "Reverse DNS: ${interesting_count} INTERESTING hostnames (dev/staging/admin/etc)"
  fi

  success "Reverse DNS module complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3: CERTIFICATE TRANSPARENCY DEEP MINING
# Most hunters just do basic crt.sh — this goes much deeper
# ─────────────────────────────────────────────────────────────────────────────
module_ct() {
  section "MODULE 3: Certificate Transparency Deep Mining"
  local ct_dir="${OUTPUT_DIR}/ct"

  # 3a. Standard wildcard query — with retry and certspotter fallback
  info "Querying crt.sh for *.${DOMAIN}..."
  local ct_attempts=0
  until [[ $ct_attempts -ge 3 ]]; do
    rate_limited_curl "https://crt.sh/?q=%.${DOMAIN}&output=json" \
      | jq -r '.[].name_value // empty' 2>/dev/null \
      | tr ',' '\n' \
      | sed 's/\*\.//g' \
      | grep -v '^$' \
      | sort -u > "${ct_dir}/ct_subdomains_raw.txt" || true
    [[ -s "${ct_dir}/ct_subdomains_raw.txt" ]] && break
    (( ct_attempts++ ))
    warn "crt.sh returned empty (attempt ${ct_attempts}/3) — retrying in 5s..."
    sleep 5
  done

  # Certspotter fallback if crt.sh still empty after retries
  if [[ ! -s "${ct_dir}/ct_subdomains_raw.txt" ]]; then
    info "crt.sh rate-limited — trying Certspotter API..."
    rate_limited_curl \
      "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" \
      | jq -r '.[].dns_names[]' 2>/dev/null \
      | grep -v '^\*\.' \
      | sort -u > "${ct_dir}/ct_subdomains_raw.txt" || true
  fi

  # BufferOver.run as second fallback
  if [[ ! -s "${ct_dir}/ct_subdomains_raw.txt" ]]; then
    info "Trying BufferOver DNS dataset..."
    rate_limited_curl "https://tls.bufferover.run/dns?q=.${DOMAIN}" \
      | jq -r '.Results[]' 2>/dev/null \
      | cut -d',' -f5 \
      | grep -i "\.${DOMAIN}\$" \
      | sort -u > "${ct_dir}/ct_subdomains_raw.txt" || true
  fi

  local raw_count
  raw_count=$(count_lines "${ct_dir}/ct_subdomains_raw.txt")
  info "CT raw results: ${raw_count} entries"

  # 3b. Organization name query (catches acquired companies' certs)
  local org_name=""
  if [[ -f "${OUTPUT_DIR}/asn/cdn_detected.txt" ]]; then
    info "CDN detected — mining org name from crt.sh issuer fields..."
    org_name=$(rate_limited_curl "https://crt.sh/?q=${DOMAIN}&output=json" 2>/dev/null \
      | jq -r '.[].issuer_name // empty' 2>/dev/null \
      | grep -oP '(?<=O=)[^,/]+' \
      | grep -iv "cloudflare\|let.s encrypt\|digicert\|sectigo\|amazon\|comodo\|google\|globalsign\|entrust\|geotrust\|rapidssl\|thawte\|trustwave\|godaddy\|network solutions" \
      | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
      | sort | uniq -c | sort -rn \
      | head -1 | awk '{$1=""; print $0}' \
      | sed 's/^ //;s/ /%20/g' \
      || echo "")
    org_name="${org_name:-}"
    [[ -n "$org_name" ]] && \
      info "Org name from CT issuer: $(echo "$org_name" | sed 's/%20/ /g')"
  else
    info "Extracting org name from TLS certificate..."
    org_name=$(
      timeout 8 bash -c \
        "echo | openssl s_client -connect '${DOMAIN}:443' \
         -servername '${DOMAIN}' 2>/dev/null \
         | openssl x509 -noout -subject 2>/dev/null" \
        2>/dev/null \
      | grep -oP '(?<=O = )[^,]+' \
      | head -1 \
      | sed 's/ /%20/g' \
      || echo "")
    org_name="${org_name:-}"
  fi
  if [[ -n "$org_name" ]]; then
    info "Found org name: $(echo $org_name | sed 's/%20/ /g')"
    rate_limited_curl "https://crt.sh/?q=${org_name}&output=json" \
      | jq -r '.[].name_value // empty' 2>/dev/null \
      | tr ',' '\n' \
      | sed 's/\*\.//g' \
      | grep -v '^$' \
      | sort -u > "${ct_dir}/ct_org_certs.txt" || true

    local org_ct_count
    org_ct_count=$(count_lines "${ct_dir}/ct_org_certs.txt")
    [[ $org_ct_count -gt 0 ]] && \
      finding "CT org search: ${org_ct_count} entries (may include acquisitions)"
  fi

  # 3c. Merge and deduplicate all CT results
  cat "${ct_dir}/ct_subdomains_raw.txt" \
      "${ct_dir}/ct_org_certs.txt" 2>/dev/null \
    | grep -v '^\*\.' \
    | sort -u > "${ct_dir}/ct_all_domains.txt"

  local total_ct
  total_ct=$(count_lines "${ct_dir}/ct_all_domains.txt")
  finding "CT logs: ${total_ct} unique domains/subdomains"

  # 3d. Extract naming convention patterns
  info "Analyzing naming conventions..."
  {
    echo "# Environment prefixes found:"
    grep -oiP '^(dev|staging|stage|test|qa|uat|sandbox|preprod|beta|demo|old|legacy|v[0-9]+|api-v[0-9]+)\.' \
      "${ct_dir}/ct_all_domains.txt" 2>/dev/null | sort | uniq -c | sort -rn

    echo -e "\n# Service names found (potential forgotten infra):"
    grep -oiP '^(jenkins|grafana|kibana|jira|confluence|vault|consul|prometheus|gitlab|bitbucket|sonar|nexus|artifactory|jupyter|airflow|rancher|portainer)\.' \
      "${ct_dir}/ct_all_domains.txt" 2>/dev/null | sort | uniq -c | sort -rn

    echo -e "\n# Domains NOT matching *.${DOMAIN} (possible acquisitions):"
    grep -v "\.${DOMAIN}\$" "${ct_dir}/ct_all_domains.txt" 2>/dev/null \
      | grep -v "^${DOMAIN}\$" | sort -u
  } > "${ct_dir}/ct_analysis.txt"

  # Flag interesting service names
  # Use grep -iP | wc -l instead of grep -c — wc -l always exits 0, grep -c
  # exits 1 on zero matches which triggers || echo 0, producing "0\n0"
  local interesting_services
  interesting_services=$(grep -iP \
    '^(jenkins|grafana|kibana|vault|jupyter|portainer|airflow)' \
    "${ct_dir}/ct_all_domains.txt" 2>/dev/null | wc -l)
  interesting_services="${interesting_services//[^0-9]/}"
  interesting_services="${interesting_services:-0}"
  [[ $interesting_services -gt 0 ]] && \
    finding "CT: ${interesting_services} high-value service subdomains (jenkins/grafana/kibana etc)"

  success "CT module complete — ${total_ct} domains, analysis at ${ct_dir}/ct_analysis.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4: WAYBACK MACHINE DEEP MINING
# Most hunters just collect URLs — this extracts intelligence from them
# ─────────────────────────────────────────────────────────────────────────────
module_wayback() {
  section "MODULE 4: Wayback Machine Deep Mining"
  local wb_dir="${OUTPUT_DIR}/wayback"

  # 4a. Collect historical URLs — parallel fetch (waybackurls + gau simultaneously)
  info "Collecting historical URLs in parallel (waybackurls + gau)..."
  local wb_tmp_1="${wb_dir}/.wayback_tmp.txt"
  local wb_tmp_2="${wb_dir}/.gau_tmp.txt"
  local pids=()

  if require_tool waybackurls; then
    waybackurls "$DOMAIN" > "$wb_tmp_1" 2>/dev/null &
    pids+=($!)
    verbose "waybackurls PID: ${pids[-1]}"
  fi

  if require_tool gau; then
    gau --threads 5 --timeout 30 "$DOMAIN" > "$wb_tmp_2" 2>/dev/null &
    pids+=($!)
    verbose "gau PID: ${pids[-1]}"
  fi

  # Progress dots while waiting (phone-friendly — shows it's alive)
  if [[ ${#pids[@]} -gt 0 ]]; then
    local waited=0
    while kill -0 "${pids[@]}" 2>/dev/null; do
      printf "." >&2
      sleep 5
      (( waited += 5 ))
      # Safety cap: kill if takes more than 5 minutes
      if [[ $waited -ge 300 ]]; then
        warn "\nWayback fetch timeout (5m) — killing background jobs"
        kill "${pids[@]}" 2>/dev/null || true
        break
      fi
    done
    printf "\n" >&2
    wait "${pids[@]}" 2>/dev/null || true
  fi

  # Merge parallel results
  cat "$wb_tmp_1" "$wb_tmp_2" 2>/dev/null > "${wb_dir}/wayback_raw.txt" || true
  rm -f "$wb_tmp_1" "$wb_tmp_2"

  # Fallback: CDX API directly if both tools failed or not installed
  if [[ ! -s "${wb_dir}/wayback_raw.txt" ]]; then
    info "Falling back to CDX API (limit 5000 URLs)..."
    rate_limited_curl \
      "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey&limit=5000" \
      > "${wb_dir}/wayback_raw.txt" || true
  fi

  dedupe_file "${wb_dir}/wayback_raw.txt"
  local url_count
  url_count=$(count_lines "${wb_dir}/wayback_raw.txt")
  info "Collected ${url_count} historical URLs"

  if [[ ! -s "${wb_dir}/wayback_raw.txt" ]]; then
    warn "No historical URLs collected"
    return
  fi

  # 4b. Extract unique parameters (often still valid server-side)
  info "Extracting unique parameter names..."
  grep "?" "${wb_dir}/wayback_raw.txt" 2>/dev/null \
    | cut -d '?' -f2 \
    | tr '&' '\n' \
    | cut -d '=' -f1 \
    | grep -v '^$' \
    | sort -u > "${wb_dir}/unique_params.txt" || true

  local param_count
  param_count=$(count_lines "${wb_dir}/unique_params.txt")
  finding "Wayback: ${param_count} unique parameter names extracted (for use with arjun/x8)"

  # 4c. Find backup/config/sensitive file patterns
  info "Mining for sensitive file patterns..."
  grep -iE '\.(bak|backup|old|orig|copy|sql|dump|tar|gz|zip|7z|rar|env|config|cfg|conf|ini|yml|yaml|json|xml|log|txt|swp|~)(\?.*)?$' \
    "${wb_dir}/wayback_raw.txt" 2>/dev/null \
    | sort -u > "${wb_dir}/sensitive_files.txt" || true

  local sensitive_count
  sensitive_count=$(count_lines "${wb_dir}/sensitive_files.txt")
  [[ $sensitive_count -gt 0 ]] && \
    finding "Wayback: ${sensitive_count} potential sensitive file URLs (backups/configs/dumps)"

  # 4d. Find old API version patterns
  info "Extracting API version patterns..."
  grep -oiP 'https?://[^/]+/api/v[0-9]+' "${wb_dir}/wayback_raw.txt" 2>/dev/null \
    | sort -u > "${wb_dir}/api_versions.txt" || true

  local api_ver_count
  api_ver_count=$(count_lines "${wb_dir}/api_versions.txt")
  [[ $api_ver_count -gt 0 ]] && \
    finding "Wayback: ${api_ver_count} distinct API version paths (check for older, less-secured versions)"

  # 4e. Find admin/debug paths
  grep -iE '/(admin|administrator|dashboard|panel|control|manage|backend|debug|test|dev|internal|staff|superuser)' \
    "${wb_dir}/wayback_raw.txt" 2>/dev/null \
    | grep -v '\.js\|\.css\|\.png\|\.jpg\|\.gif' \
    | sort -u > "${wb_dir}/admin_paths.txt" || true

  local admin_count
  admin_count=$(count_lines "${wb_dir}/admin_paths.txt")
  [[ $admin_count -gt 0 ]] && \
    finding "Wayback: ${admin_count} historical admin/debug path URLs"

  # 4f. Extract subdomains from historical URLs
  grep -oP 'https?://\K[a-zA-Z0-9._-]+(?=/)' "${wb_dir}/wayback_raw.txt" 2>/dev/null \
    | grep -i "${DOMAIN}\$" \
    | sort -u > "${wb_dir}/wayback_subdomains.txt" || true

  success "Wayback module complete — check ${wb_dir}/ for extracted intelligence"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5: CLOUD ASSET ENUMERATION
# Skipped by: ~85% of hunters
# ─────────────────────────────────────────────────────────────────────────────
module_cloud() {
  section "MODULE 5: Cloud Asset Enumeration"
  local cloud_dir="${OUTPUT_DIR}/cloud"

  # Extract company name variations from domain
  local base_name
  base_name=$(echo "$DOMAIN" | cut -d. -f1)

  # Build bucket name permutation list
  info "Generating bucket name permutations for: $base_name"
  cat > "${cloud_dir}/bucket_names.txt" << EOF
${base_name}
${base_name}-backup
${base_name}-backups
${base_name}-assets
${base_name}-static
${base_name}-media
${base_name}-files
${base_name}-uploads
${base_name}-images
${base_name}-data
${base_name}-dev
${base_name}-staging
${base_name}-prod
${base_name}-production
${base_name}-logs
${base_name}-log
${base_name}-archive
${base_name}-archives
${base_name}-public
${base_name}-private
${base_name}-api
${base_name}-app
${base_name}-web
${base_name}-cdn
${base_name}-content
${base_name}-config
${base_name}-configs
${base_name}-secret
${base_name}-secrets
${base_name}-tmp
${base_name}-temp
${base_name}-test
${base_name}-testing
${base_name}-qa
${base_name}-uat
${base_name}-release
${base_name}-builds
${base_name}-artifacts
${base_name}com
${DOMAIN}
${DOMAIN}-backup
${DOMAIN}-assets
EOF
  # Deduplicate in-place (e.g. when base_name.com == DOMAIN)
  dedupe_file "${cloud_dir}/bucket_names.txt"

  local checked=0
  local found_buckets=()

  # 5a. AWS S3 bucket enumeration
  info "Checking AWS S3 buckets..."
  while IFS= read -r bucket; do
    [[ -z "$bucket" ]] && continue

    # Check if bucket exists (no-sign-request = anonymous access check)
    local s3_url="https://${bucket}.s3.amazonaws.com"
    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
      --max-time 5 "$s3_url" 2>/dev/null || echo "000")

    case "$http_code" in
      200)
        finding "S3 BUCKET PUBLICLY READABLE: s3://${bucket} — ${s3_url}"
        found_buckets+=("s3_public: $bucket")
        ;;
      403)
        # Bucket exists but access denied — still useful (confirms existence)
        echo "EXISTS_FORBIDDEN: s3://${bucket}" >> "${cloud_dir}/s3_exists.txt"
        verbose "S3 exists (403): $bucket"
        ;;
      301|302)
        echo "EXISTS_REDIRECT: s3://${bucket}" >> "${cloud_dir}/s3_exists.txt"
        ;;
    esac

    ((checked++))
    [[ $((checked % 10)) -eq 0 ]] && verbose "Checked ${checked} bucket names..."
    sleep 0.2  # Polite delay

  done < "${cloud_dir}/bucket_names.txt"

  local s3_exists_count
  s3_exists_count=$(count_lines "${cloud_dir}/s3_exists.txt" 2>/dev/null || echo 0)
  [[ $s3_exists_count -gt 0 ]] && \
    finding "S3: ${s3_exists_count} buckets confirmed to EXIST (even if access-denied — useful for naming patterns)"

  # 5b. GCP Storage buckets
  info "Checking GCP Storage buckets..."
  while IFS= read -r bucket; do
    [[ -z "$bucket" ]] && continue
    local gcp_url="https://storage.googleapis.com/${bucket}"
    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
      --max-time 5 "$gcp_url" 2>/dev/null || echo "000")

    case "$http_code" in
      200) finding "GCP BUCKET PUBLICLY READABLE: gs://${bucket} — ${gcp_url}" ;;
      403) echo "EXISTS_FORBIDDEN: gs://${bucket}" >> "${cloud_dir}/gcp_exists.txt" ;;
    esac
    sleep 0.2
  done < "${cloud_dir}/bucket_names.txt"

  # 5c. Azure Blob Storage
  info "Checking Azure Blob Storage..."
  while IFS= read -r bucket; do
    [[ -z "$bucket" ]] && continue
    local azure_url="https://${bucket}.blob.core.windows.net"
    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
      --max-time 5 "$azure_url" 2>/dev/null || echo "000")

    case "$http_code" in
      200|400) # 400 = account exists but request malformed
        echo "EXISTS: azure://${bucket}" >> "${cloud_dir}/azure_exists.txt"
        verbose "Azure storage account exists: $bucket"
        ;;
    esac
    sleep 0.2
  done < "${cloud_dir}/bucket_names.txt"

  success "Cloud module complete — check ${cloud_dir}/ for results"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 6: EMAIL SECURITY ANALYSIS
# Skipped by: ~80% of hunters (easy wins)
# ─────────────────────────────────────────────────────────────────────────────
module_email() {
  section "MODULE 6: Email Security Analysis"
  local email_dir="${OUTPUT_DIR}/email"

  # 6a. SPF record analysis
  info "Checking SPF record..."
  local spf_record
  spf_record=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i "v=spf" || echo "NONE")

  echo "SPF: $spf_record" > "${email_dir}/email_security.txt"

  if [[ "$spf_record" == "NONE" ]]; then
    finding "EMAIL: No SPF record found — email spoofing likely possible"
  elif echo "$spf_record" | grep -qiE '~all|\\?all'; then
    finding "EMAIL: SPF uses soft-fail (~all) or neutral (?all) — email spoofing MAY be possible"
  elif echo "$spf_record" | grep -qi '\-all'; then
    info "SPF: Strict (-all) — properly configured"
  fi

  # Extract third-party services from SPF includes
  info "Extracting third-party vendors from SPF..."
  echo "$spf_record" | grep -oP 'include:[^\s]+' 2>/dev/null \
    | cut -d: -f2 >> "${email_dir}/spf_includes.txt" || true
  local vendor_count
  vendor_count=$(count_lines "${email_dir}/spf_includes.txt")
  [[ $vendor_count -gt 0 ]] && {
    finding "EMAIL: SPF reveals ${vendor_count} third-party vendors (attack surface expansion)"
    cat "${email_dir}/spf_includes.txt"
  }

  # 6b. DMARC analysis
  info "Checking DMARC record..."
  local dmarc_record
  dmarc_record=$(dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null | grep -i "v=DMARC" || echo "NONE")

  echo "DMARC: $dmarc_record" >> "${email_dir}/email_security.txt"

  if [[ "$dmarc_record" == "NONE" ]]; then
    finding "EMAIL: No DMARC record found — email spoofing reportable finding on most programs"
  elif echo "$dmarc_record" | grep -qi 'p=none'; then
    finding "EMAIL: DMARC policy=none — monitoring only, spoofed emails delivered"
  elif echo "$dmarc_record" | grep -qi 'p=quarantine'; then
    info "DMARC: Quarantine policy — partial protection"
  elif echo "$dmarc_record" | grep -qi 'p=reject'; then
    info "DMARC: Reject policy — properly configured"
  fi

  # 6c. DKIM selectors (common ones)
  info "Checking common DKIM selectors..."
  local selectors=("default" "google" "k1" "k2" "mail" "email" "dkim" "selector1" "selector2" "s1" "s2" "key1" "key2" "mimecast" "proofpoint" "mandrill" "mailchimp" "sendgrid" "amazonses")
  for selector in "${selectors[@]}"; do
    local dkim_result
    dkim_result=$(dig +short TXT "${selector}._domainkey.${DOMAIN}" 2>/dev/null | head -1)
    if [[ -n "$dkim_result" ]]; then
      echo "DKIM_SELECTOR: ${selector} — ${dkim_result:0:80}..." >> "${email_dir}/dkim_selectors.txt"
      verbose "DKIM selector found: $selector"
    fi
  done

  local dkim_count
  dkim_count=$(count_lines "${email_dir}/dkim_selectors.txt")
  [[ $dkim_count -gt 0 ]] && \
    info "Found ${dkim_count} DKIM selectors — reveals mail providers"

  # 6d. MX record analysis
  info "Analyzing MX records..."
  dig +short MX "$DOMAIN" 2>/dev/null > "${email_dir}/mx_records.txt" || true
  local mx_count
  mx_count=$(count_lines "${email_dir}/mx_records.txt")
  [[ $mx_count -gt 0 ]] && \
    info "Found ${mx_count} MX records — mail infrastructure identified"

  # Check for mail subdomain
  local mail_ip
  mail_ip=$(dig +short A "mail.${DOMAIN}" 2>/dev/null | head -1 || echo "")
  [[ -n "$mail_ip" ]] && \
    finding "EMAIL: mail.${DOMAIN} resolves to ${mail_ip} — dedicated mail server (often less patched)"

  success "Email security module complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 7: FAVICON HASH FINGERPRINTING
# Used to find hidden/related assets on Shodan — skipped by 95% of hunters
# ─────────────────────────────────────────────────────────────────────────────
module_favicon() {
  section "MODULE 7: Favicon Hash Fingerprinting"
  local fav_dir="${OUTPUT_DIR}/reports"

  # Common favicon locations
  local favicon_paths=("/favicon.ico" "/favicon.png" "/images/favicon.ico" "/assets/favicon.ico" "/static/favicon.ico")

  for fav_path in "${favicon_paths[@]}"; do
    local fav_url="https://${DOMAIN}${fav_path}"
    local http_code
    http_code=$(curl -sk -o "${fav_dir}/favicon_tmp" -w "%{http_code}" \
      --max-time 10 "$fav_url" 2>/dev/null || echo "000")

    if [[ "$http_code" == "200" && -s "${fav_dir}/favicon_tmp" ]]; then
      info "Favicon found at: $fav_path"

      # Calculate MurmurHash3 (Shodan's favicon hash algorithm)
      # Pass file path as argv[1] — heredoc owns stdin so < redirect never lands
      local favicon_hash
      favicon_hash=$(python3 - "${fav_dir}/favicon_tmp" << 'PYEOF'
import sys, base64

def mmh3_hash(data):
    seed = 0
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xFFFFFFFC)
    for i in range(0, roundedEnd, 4):
        k1 = (data[i] & 0xFF) | ((data[i+1] & 0xFF) << 8) | \
             ((data[i+2] & 0xFF) << 16) | (data[i+3] << 24)
        k1 &= 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    k1 = 0
    val = length & 0x03
    if val == 3: k1 ^= (data[roundedEnd+2] & 0xFF) << 16
    if val >= 2: k1 ^= (data[roundedEnd+1] & 0xFF) << 8
    if val >= 1:
        k1 ^= data[roundedEnd] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1

# Read from argv[1] (file path) — not stdin which is consumed by heredoc
with open(sys.argv[1], 'rb') as f:
    raw = f.read()

if not raw:
    print("ERROR_EMPTY")
    sys.exit(1)

# Shodan base64 method: encodebytes adds newlines every 76 chars
b64 = base64.encodebytes(raw).decode()
encoded = b64.encode()
print(mmh3_hash(encoded))
PYEOF
      ) 2>/dev/null || favicon_hash="ERROR"

      rm -f "${fav_dir}/favicon_tmp"

      if [[ "$favicon_hash" != "ERROR" && -n "$favicon_hash" ]]; then
        finding "FAVICON HASH: ${favicon_hash}"
        echo "Favicon hash: ${favicon_hash}" > "${fav_dir}/favicon_hash.txt"
        echo "Shodan query: http.favicon.hash:${favicon_hash}" >> "${fav_dir}/favicon_hash.txt"
        echo "Censys query: services.http.response.favicons.md5_hash" >> "${fav_dir}/favicon_hash.txt"
        echo "" >> "${fav_dir}/favicon_hash.txt"
        echo "Use this hash to find ALL servers running the same application on Shodan." >> "${fav_dir}/favicon_hash.txt"
        echo "This includes dev/staging servers, partner deployments, and forgotten instances." >> "${fav_dir}/favicon_hash.txt"
      fi
      break
    fi
  done

  success "Favicon module complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 8: NON-STANDARD PORT SCANNING
# Skipped by: ~70% of hunters who only check 80/443
# ─────────────────────────────────────────────────────────────────────────────
module_ports() {
  section "MODULE 8: Non-Standard Port Scanning"
  local port_dir="${OUTPUT_DIR}/ports"

  [[ "$SKIP_PORTS" == true ]] && { warn "Port scanning skipped (--skip-ports)"; return; }

  # Target IPs: primary domain IPs + any interesting IPs from earlier modules
  cat "${OUTPUT_DIR}/asn/domain_ips.txt" 2>/dev/null > "${port_dir}/scan_targets.txt" || true

  # Also resolve interesting subdomains found so far
  if [[ -s "${OUTPUT_DIR}/ct/ct_all_domains.txt" ]]; then
    # Only scan the interesting service subdomains
    grep -iP '^(jenkins|grafana|kibana|vault|consul|prometheus|gitlab|jira|confluence|jupyter|airflow|portainer|sonarqube|nexus|artifactory|rancher)\.' \
      "${OUTPUT_DIR}/ct/ct_all_domains.txt" 2>/dev/null \
      | head -20 \
      | while read -r subdomain; do
          local ip
          ip=$(dig +short A "$subdomain" 2>/dev/null | head -1)
          [[ -n "$ip" ]] && echo "$ip" >> "${port_dir}/scan_targets.txt"
        done
  fi

  dedupe_file "${port_dir}/scan_targets.txt"
  local target_count
  target_count=$(count_lines "${port_dir}/scan_targets.txt")

  [[ $target_count -eq 0 ]] && { warn "No scan targets found"; return; }
  info "Scanning ${target_count} targets for non-standard ports..."

  # The forgotten sysadmin port list — services that should never be internet-facing
  local HIGH_VALUE_PORTS="22,80,443,2375,2376,3000,4848,5000,5601,5900,6379,7474,8000,8080,8081,8443,8888,9000,9090,9092,9200,9300,10250,27017,28017,50070,61616"

  if require_tool naabu; then
    # naabu is much faster and Termux-compatible
    naabu -list "${port_dir}/scan_targets.txt" \
      -p "$HIGH_VALUE_PORTS" \
      -silent \
      -o "${port_dir}/naabu_results.txt" \
      2>/dev/null || true

  elif require_tool nmap; then
    while IFS= read -r target; do
      [[ -z "$target" ]] && continue
      info "Scanning: $target"
      nmap -sV -Pn --open \
        -p "$HIGH_VALUE_PORTS" \
        --max-retries 1 \
        --host-timeout 30s \
        -oG - "$target" 2>/dev/null \
        | grep "Ports:" >> "${port_dir}/nmap_results.txt" || true
      sleep 1
    done < "${port_dir}/scan_targets.txt"
  else
    # Pure bash TCP check (slow but no dependencies)
    info "Using bash TCP fallback (slow)..."
    local interesting_ports=(2375 3000 4848 5601 6379 8080 8443 8888 9090 9200 27017)
    while IFS= read -r target; do
      [[ -z "$target" ]] && continue
      for port in "${interesting_ports[@]}"; do
        if timeout 3 bash -c "echo >/dev/tcp/${target}/${port}" 2>/dev/null; then
          echo "${target}:${port} OPEN" | tee -a "${port_dir}/bash_tcp_results.txt"
        fi
      done
    done < "${port_dir}/scan_targets.txt"
  fi

  # Analyze results and flag high-value open ports
  local results_file=""
  [[ -f "${port_dir}/naabu_results.txt" ]] && results_file="${port_dir}/naabu_results.txt"
  [[ -f "${port_dir}/nmap_results.txt" ]] && results_file="${port_dir}/nmap_results.txt"
  [[ -f "${port_dir}/bash_tcp_results.txt" ]] && results_file="${port_dir}/bash_tcp_results.txt"

  if [[ -n "$results_file" && -s "$results_file" ]]; then
    # Flag critical services
    local critical_ports=(2375 6379 9200 27017 5601 8080)
    for cport in "${critical_ports[@]}"; do
      if grep -q ":${cport}" "$results_file" 2>/dev/null; then
        case $cport in
          2375) finding "CRITICAL PORT: Docker API (2375) — potentially unauthenticated RCE" ;;
          6379) finding "HIGH PORT: Redis (6379) — often auth-free, check for data exposure" ;;
          9200) finding "HIGH PORT: Elasticsearch (9200) — often auth-free, check for data exposure" ;;
          27017) finding "HIGH PORT: MongoDB (27017) — often auth-free, check for data exposure" ;;
          5601) finding "HIGH PORT: Kibana (5601) — check for unauthenticated access" ;;
          8080) finding "PORT: 8080 open — check for admin panels, Jenkins, Tomcat" ;;
        esac
      fi
    done
  fi

  success "Port scanning module complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 9: VIRTUAL HOST DISCOVERY
# Skipped by: ~85% of hunters
# ─────────────────────────────────────────────────────────────────────────────
module_vhost() {
  section "MODULE 9: Virtual Host Discovery"
  local vhost_dir="${OUTPUT_DIR}/vhost"

  # Get IPs to probe
  local primary_ip
  primary_ip=$(head -1 "${OUTPUT_DIR}/asn/domain_ips.txt" 2>/dev/null || \
    dig +short A "$DOMAIN" 2>/dev/null | head -1 || echo "")

  [[ -z "$primary_ip" ]] && { warn "No IP to probe for vhosts"; return; }

  if ! require_tool ffuf; then
    warn "ffuf not found — skipping vhost discovery (install: go install github.com/ffuf/ffuf/v2@latest)"
    return
  fi

  # Build vhost wordlist from CT results + environment patterns
  {
    # From CT results
    cat "${OUTPUT_DIR}/ct/ct_all_domains.txt" 2>/dev/null | \
      grep "\.${DOMAIN}\$" | sed "s/\.${DOMAIN}\$//"

    # Standard environment prefixes
    for prefix in dev staging stage test qa uat sandbox beta alpha preview demo old legacy backup internal intranet; do
      echo "$prefix"
      echo "${prefix}-api"
      echo "api-${prefix}"
      echo "${prefix}.api"
    done

    # Service names
    for svc in jenkins grafana kibana jira confluence gitlab vault consul prometheus admin portal dashboard manage control panel; do
      echo "$svc"
    done
  } | sort -u > "${vhost_dir}/vhost_candidates.txt"

  local candidate_count
  candidate_count=$(count_lines "${vhost_dir}/vhost_candidates.txt")
  info "Testing ${candidate_count} virtual host candidates against ${primary_ip}..."

  # Get baseline response size for filtering
  local baseline_size
  baseline_size=$(curl -sk -o /dev/null -w "%{size_download}" \
    -H "Host: nonexistent-vhost-xyz.${DOMAIN}" \
    "https://${primary_ip}/" 2>/dev/null || echo "0")

  verbose "Baseline response size: ${baseline_size} bytes"

  ffuf -w "${vhost_dir}/vhost_candidates.txt" \
    -u "https://${primary_ip}/" \
    -H "Host: FUZZ.${DOMAIN}" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    -fs "$baseline_size" \
    -mc "200,201,301,302,401,403" \
    -t "$THREADS" \
    -o "${vhost_dir}/vhost_results.json" \
    -of json \
    -silent \
    2>/dev/null || true

  if [[ -s "${vhost_dir}/vhost_results.json" ]]; then
    local vhost_count
    vhost_count=$(jq '.results | length' "${vhost_dir}/vhost_results.json" 2>/dev/null || echo 0)
    [[ $vhost_count -gt 0 ]] && \
      finding "VHOST: ${vhost_count} virtual hosts discovered on ${primary_ip} — potentially hidden apps"
  fi

  success "Virtual host module complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 10: PARAMETER DISCOVERY
# Most hunters never enumerate hidden parameters
# ─────────────────────────────────────────────────────────────────────────────
module_params() {
  section "MODULE 10: Parameter Discovery"
  local param_dir="${OUTPUT_DIR}/params"

  # Merge parameter names from all sources
  {
    cat "${OUTPUT_DIR}/wayback/unique_params.txt" 2>/dev/null
    # Common security-sensitive params
    cat << 'PARAMS'
id
user
username
email
token
key
api_key
secret
password
redirect
url
next
return
callback
file
path
page
action
type
format
debug
test
admin
role
access
auth
session
csrf
nonce
PARAMS
  } | sort -u > "${param_dir}/param_wordlist.txt"

  local param_count
  param_count=$(count_lines "${param_dir}/param_wordlist.txt")
  info "Built parameter wordlist with ${param_count} entries"

  if require_tool arjun; then
    info "Running arjun parameter discovery on main domain..."
    arjun -u "https://${DOMAIN}/" \
      -w "${param_dir}/param_wordlist.txt" \
      -oJ "${param_dir}/arjun_results.json" \
      --stable \
      2>/dev/null || true

    [[ -s "${param_dir}/arjun_results.json" ]] && \
      finding "PARAMS: arjun found hidden parameters on https://${DOMAIN}/ — check results"
  else
    info "arjun not found — parameter wordlist saved for manual use"
    info "Install: pip install arjun --break-system-packages"
  fi

  success "Parameter module complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 11: JAVASCRIPT DEEP ANALYSIS
# Your OMEGA pipeline integration point
# ─────────────────────────────────────────────────────────────────────────────
module_js() {
  section "MODULE 11: JavaScript Analysis & OMEGA Integration"
  local js_dir="${OUTPUT_DIR}/js"

  # Collect all live hosts for JS analysis
  # Always seed with apex domain — httpx results are additive
  echo "https://${DOMAIN}" > "${js_dir}/live_hosts.txt"

  # From CT subdomains (resolve and check live)
  if [[ -s "${OUTPUT_DIR}/ct/ct_all_domains.txt" ]]; then
    info "Resolving CT subdomains for JS analysis targets..."
    if require_tool httpx; then
      httpx -l "${OUTPUT_DIR}/ct/ct_all_domains.txt" \
        -silent \
        -timeout 10 \
        -threads "$THREADS" \
        2>/dev/null >> "${js_dir}/live_hosts.txt" || true
    fi
  fi

  # Deduplicate and ensure file always exists with at least the apex
  sort -u "${js_dir}/live_hosts.txt" -o "${js_dir}/live_hosts.txt" 2>/dev/null || true
  local live_count
  live_count=$(count_lines "${js_dir}/live_hosts.txt")
  info "JS analysis targets: ${live_count} live hosts"

  # Extract JS URLs from each live host
  info "Extracting JavaScript URLs from live hosts..."
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    verbose "Extracting JS from: $host"

    # Get main page and extract JS src attributes
    curl -skL --max-time 15 "$host" 2>/dev/null \
      | grep -oP '(?<=src=")[^"]+\.js[^"]*' \
      | while read -r js_path; do
          if [[ "$js_path" =~ ^https?:// ]]; then
            echo "$js_path"
          elif [[ "$js_path" =~ ^/ ]]; then
            echo "${host}${js_path}"
          else
            echo "${host}/${js_path}"
          fi
        done >> "${js_dir}/all_js_urls.txt"
  done < "${js_dir}/live_hosts.txt"

  dedupe_file "${js_dir}/all_js_urls.txt"
  touch "${js_dir}/all_js_urls.txt"  # guarantee file exists even if curl found nothing
  local js_url_count
  js_url_count=$(count_lines "${js_dir}/all_js_urls.txt")
  info "Found ${js_url_count} JavaScript file URLs"

  # Download JS files for analysis
  mkdir -p "${js_dir}/bundles"
  info "Downloading JS bundles (max 50 files)..."
  if [[ -s "${js_dir}/all_js_urls.txt" ]]; then
    head -50 "${js_dir}/all_js_urls.txt" | while IFS= read -r js_url; do
      local filename
      filename=$(basename "$js_url" | cut -c1-60 | tr '?' '_' | tr '&' '_')
      [[ -z "$filename" ]] && continue
      curl -skL --max-time 20 "$js_url" 2>/dev/null \
        > "${js_dir}/bundles/${filename}" || true
    done
  else
    warn "No JS URLs collected — bundles dir will be empty"
  fi

  # Basic endpoint extraction (your OMEGA does this better — this is the quick pass)
  info "Quick endpoint extraction from JS bundles..."
  grep -rhoP '(?:"|'"'"')(/(?:api|v[0-9]+|rest|graphql|admin|internal|auth|user|account)[^"'"'"'<>\s]{0,100})(?:"|'"'"')' \
    "${js_dir}/bundles/" 2>/dev/null \
    | tr -d '"'"'" \
    | sort -u > "${js_dir}/extracted_endpoints.txt" || true

  local endpoint_count
  endpoint_count=$(count_lines "${js_dir}/extracted_endpoints.txt")
  [[ $endpoint_count -gt 0 ]] && \
    finding "JS: ${endpoint_count} API endpoint paths extracted from JavaScript bundles"

  # Look for hardcoded secrets (quick regex pass)
  info "Scanning for hardcoded secrets in JS bundles..."
  grep -rnoiP '(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer|password|passwd|private[_-]?key)\s*[:=]\s*["\047][a-zA-Z0-9+/=_\-]{16,}["\047]' \
    "${js_dir}/bundles/" 2>/dev/null \
    | grep -v "example\|placeholder\|your_\|INSERT\|REPLACE\|xxxxxxx" \
    > "${js_dir}/potential_secrets.txt" || true

  local secret_count
  secret_count=$(count_lines "${js_dir}/potential_secrets.txt")
  [[ $secret_count -gt 0 ]] && \
    finding "JS: ${secret_count} potential hardcoded secrets found — MANUAL REVIEW REQUIRED"

  # GraphQL detection
  grep -rl "graphql\|__schema\|introspection" "${js_dir}/bundles/" 2>/dev/null \
    | head -5 > "${js_dir}/graphql_likely.txt" || true
  [[ -s "${js_dir}/graphql_likely.txt" ]] && \
    finding "JS: GraphQL references detected — try /graphql?query={__schema{types{name}}} for introspection"

  # OMEGA integration point
  echo ""
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  info "OMEGA INTEGRATION: Run JS Decoder OMEGA against:"
  info "  Input dir:  ${js_dir}/bundles/"
  info "  URL list:   ${js_dir}/all_js_urls.txt"
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # If OMEGA is in PATH or known location, invoke it
  for omega_path in \
    "${HOME}/omega-pipeline/omega_scan.py" \
    "${HOME}/bb-omega-suite/omega_pipeline/omega_scan.py" \
    "${HOME}/js-decoder-omega/omega.py"; do
    if [[ -f "$omega_path" ]]; then
      info "Found OMEGA at: $omega_path"
      info "Queuing OMEGA analysis..."
      echo "python3 ${omega_path} --input-dir ${js_dir}/bundles/ --output ${js_dir}/omega_report/" \
        > "${js_dir}/omega_run_command.sh"
      chmod +x "${js_dir}/omega_run_command.sh"
      finding "JS OMEGA: Run ${js_dir}/omega_run_command.sh to trigger full OMEGA analysis"
      break
    fi
  done

  success "JS module complete — bundles at ${js_dir}/bundles/, endpoints at ${js_dir}/extracted_endpoints.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 12: CORRELATION & CHAIN ANALYSIS
# The most skipped thing of all — connecting findings across layers
# ─────────────────────────────────────────────────────────────────────────────
module_correlation() {
  section "MODULE 12: Cross-Layer Correlation Analysis"
  local corr_dir="${OUTPUT_DIR}/correlation"

  info "Correlating findings across all modules..."

  # Build master subdomain list from all sources
  {
    cat "${OUTPUT_DIR}/ct/ct_all_domains.txt" 2>/dev/null
    cat "${OUTPUT_DIR}/dns/rdns_subdomains.txt" 2>/dev/null
    cat "${OUTPUT_DIR}/wayback/wayback_subdomains.txt" 2>/dev/null
  } | grep -i "${DOMAIN}" | sort -u > "${corr_dir}/master_subdomains.txt"

  local total_subs
  total_subs=$(count_lines "${corr_dir}/master_subdomains.txt")
  info "Master subdomain list: ${total_subs} unique entries"

  # Identify acquisition candidates (domains in CT logs that don't match primary domain)
  if [[ -s "${OUTPUT_DIR}/ct/ct_all_domains.txt" ]]; then
    grep -v "\.${DOMAIN}\$\|^${DOMAIN}\$" \
      "${OUTPUT_DIR}/ct/ct_all_domains.txt" 2>/dev/null \
      > "${corr_dir}/acquisition_candidates.txt" || true
    local acq_count
    acq_count=$(count_lines "${corr_dir}/acquisition_candidates.txt")
    [[ $acq_count -gt 0 ]] && \
      finding "CORRELATION: ${acq_count} external domains in CT logs — possible acquisitions/subsidiaries"
  fi

  # Subdomain takeover candidates (CNAME chains to external services)
  info "Checking CNAME chains for takeover candidates..."
  local takeover_services="github.io|amazonaws.com|cloudfront.net|azurewebsites.net|s3.amazonaws.com|herokuapp.com|ghost.io|pages.io|helpscoutdocs.com|freshdesk.com|statuspage.io|cargocollective.com|tumblr.com|surge.sh|bitbucket.io|strikingly.com|uberflip.com|desk.com|tictail.com|campaignmonitor.com|cname.hubspot.com|zendesk.com|uservoice.com"

  while IFS= read -r subdomain; do
    local cname_chain
    cname_chain=$(dig +short CNAME "$subdomain" 2>/dev/null | tail -1)
    if [[ -n "$cname_chain" ]]; then
      if echo "$cname_chain" | grep -qiP "($takeover_services)"; then
        # Check if the target service is actually claimed
        local http_code
        http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
          --max-time 10 "https://${subdomain}" 2>/dev/null || echo "000")
        if echo "$http_code" | grep -qE "^(404|410)"; then
          finding "TAKEOVER CANDIDATE: ${subdomain} → ${cname_chain} (HTTP ${http_code})"
          echo "${subdomain} CNAME ${cname_chain} HTTP:${http_code}" \
            >> "${corr_dir}/takeover_candidates.txt"
        fi
      fi
    fi
  done < "${corr_dir}/master_subdomains.txt" 2>/dev/null

  local takeover_count
  takeover_count=$(count_lines "${corr_dir}/takeover_candidates.txt" 2>/dev/null || echo 0)
  [[ $takeover_count -gt 0 ]] && \
    finding "CORRELATION: ${takeover_count} subdomain takeover candidates identified"

  # Chain analysis: correlate JS endpoints with discovered subdomains
  if [[ -s "${OUTPUT_DIR}/js/extracted_endpoints.txt" && \
        -s "${corr_dir}/master_subdomains.txt" ]]; then
    info "Cross-referencing JS endpoints with discovered infrastructure..."
    # Look for internal hostnames referenced in JS that match discovered subdomains
    grep -f "${corr_dir}/master_subdomains.txt" \
      "${OUTPUT_DIR}/js/extracted_endpoints.txt" 2>/dev/null \
      > "${corr_dir}/js_infra_correlation.txt" || true
    local corr_count
    corr_count=$(count_lines "${corr_dir}/js_infra_correlation.txt")
    [[ $corr_count -gt 0 ]] && \
      finding "CORRELATION: ${corr_count} JS endpoints reference discovered infrastructure"
  fi

  success "Correlation module complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 14: MISSING-LAYER SUPPLEMENTAL RECON
# Covers all high-ROI gaps identified in the gap analysis:
#   robots/sitemap/security.txt, CAA/SOA, URLScan, GitHub dork gen,
#   source map detection, CORS/CSP/cookie/HSTS/OPTIONS header audit,
#   alterx subdomain permutation, SPF include-chain deep walk,
#   Firebase/Heroku/Netlify/Vercel/SaaS detection, crossdomain.xml,
#   Postman/npm/Docker public asset hints
# ─────────────────────────────────────────────────────────────────────────────
module_supplemental() {
  section "MODULE 14: Supplemental Recon (Gap Coverage)"
  local sup_dir="${OUTPUT_DIR}/supplemental"
  mkdir -p "${sup_dir}"/{headers,dns,urlscan,dorks,sourcemaps,saas,spf}

  # ── 14a. DNS: CAA + SOA records ──────────────────────────────────────────
  info "Fetching CAA and SOA records..."
  {
    echo "=== CAA (authorized certificate authorities) ==="
    dig +short CAA "$DOMAIN" 2>/dev/null || echo "none"
    echo ""
    echo "=== SOA (zone admin email, serial, DNS provider) ==="
    dig +short SOA "$DOMAIN" 2>/dev/null || echo "none"
    echo ""
    echo "=== NS (nameserver provider) ==="
    dig +short NS "$DOMAIN" 2>/dev/null || echo "none"
  } > "${sup_dir}/dns/caa_soa_ns.txt"

  # Flag interesting CAA findings
  local caa_result
  caa_result=$(dig +short CAA "$DOMAIN" 2>/dev/null)
  if [[ -z "$caa_result" ]]; then
    finding "SUPP: No CAA record — any CA can issue certs for ${DOMAIN}"
  else
    info "CAA: $(echo "$caa_result" | tr '\n' ' ')"
  fi

  # Extract SOA admin email (often reveals internal contact)
  local soa_email
  soa_email=$(dig +short SOA "$DOMAIN" 2>/dev/null | awk '{print $2}' | sed 's/\.$//;s/\./@ /1')
  [[ -n "$soa_email" ]] && \
    finding "SUPP: SOA admin contact: ${soa_email} (DNS zone owner)"

  # ── 14b. Well-known paths per live host ──────────────────────────────────
  info "Fetching well-known paths from live hosts..."
  local live_hosts_file="${OUTPUT_DIR}/js/live_hosts.txt"
  [[ ! -s "$live_hosts_file" ]] && echo "https://${DOMAIN}" > "$live_hosts_file"

  local well_known_paths=(
    "/robots.txt"
    "/sitemap.xml"
    "/sitemap_index.xml"
    "/security.txt"
    "/.well-known/security.txt"
    "/.well-known/change-password"
    "/.well-known/openid-configuration"
    "/.well-known/oauth-authorization-server"
    "/.well-known/assetlinks.json"
    "/.well-known/apple-app-site-association"
    "/crossdomain.xml"
    "/clientaccesspolicy.xml"
    "/.well-known/host-meta"
  )

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local host_slug
    host_slug=$(echo "$host" | sed 's|https\?://||;s|/|_|g')
    mkdir -p "${sup_dir}/wellknown/${host_slug}"

    for wk_path in "${well_known_paths[@]}"; do
      local url="${host}${wk_path}"
      local http_code
      http_code=$(curl -skL --max-time 8 -o \
        "${sup_dir}/wellknown/${host_slug}/$(basename "${wk_path}").txt" \
        -w "%{http_code}" "$url" 2>/dev/null || echo "000")

      if [[ "$http_code" == "200" ]]; then
        local file_size
        file_size=$(wc -c < \
          "${sup_dir}/wellknown/${host_slug}/$(basename "${wk_path}").txt" \
          2>/dev/null || echo 0)
        if [[ $file_size -gt 10 ]]; then
          finding "SUPP: ${wk_path} found at ${host} (${file_size} bytes)"
          # Mine robots.txt for hidden paths
          if [[ "$wk_path" == "/robots.txt" ]]; then
            grep -i "^Disallow:\|^Allow:" \
              "${sup_dir}/wellknown/${host_slug}/$(basename "${wk_path}").txt" \
              2>/dev/null | grep -v "^Disallow: /$\|^Disallow: $" \
              >> "${sup_dir}/dns/robots_paths.txt" || true
          fi
          # Mine OpenID config for auth endpoints
          if echo "$wk_path" | grep -q "openid\|oauth"; then
            jq -r 'to_entries[] | select(.value | type == "string") | .value' \
              "${sup_dir}/wellknown/${host_slug}/$(basename "${wk_path}").txt" \
              2>/dev/null | grep "^http" \
              >> "${sup_dir}/dns/oidc_endpoints.txt" || true
          fi
        fi
      fi
      sleep 0.1
    done
  done < "$live_hosts_file"

  local robots_paths_count
  robots_paths_count=$(count_lines "${sup_dir}/dns/robots_paths.txt")
  [[ $robots_paths_count -gt 0 ]] && \
    finding "SUPP: ${robots_paths_count} paths in robots.txt Disallow/Allow rules"

  local oidc_count
  oidc_count=$(count_lines "${sup_dir}/dns/oidc_endpoints.txt")
  [[ $oidc_count -gt 0 ]] && \
    finding "SUPP: ${oidc_count} OIDC/OAuth endpoints discovered via .well-known"

  # ── 14c. HTTP header security audit per host ─────────────────────────────
  info "Auditing HTTP security headers per live host..."
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local headers_raw
    headers_raw=$(curl -skI --max-time 10 \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      "$host" 2>/dev/null || echo "")

    [[ -z "$headers_raw" ]] && continue

    local host_label
    host_label=$(echo "$host" | sed 's|https\?://||')

    {
      echo "=== ${host} ==="

      # CORS
      local cors
      cors=$(echo "$headers_raw" | grep -i "access-control-allow-origin:" | head -1)
      if [[ -n "$cors" ]]; then
        echo "CORS: $cors"
        if echo "$cors" | grep -q "\*"; then
          finding "SUPP HEADER: CORS wildcard (*) on ${host} — any origin allowed"
        elif echo "$cors" | grep -qi "null"; then
          finding "SUPP HEADER: CORS: null origin on ${host} — sandbox bypass possible"
        fi
      else
        echo "CORS: not set"
      fi

      # CSP
      local csp
      csp=$(echo "$headers_raw" | grep -i "content-security-policy:" | head -1)
      if [[ -n "$csp" ]]; then
        echo "CSP: $csp"
        # Flag weak CSP directives
        if echo "$csp" | grep -qiE "unsafe-inline|unsafe-eval|\*\."; then
          finding "SUPP HEADER: Weak CSP on ${host} (unsafe-inline/eval or wildcard)"
        fi
      else
        finding "SUPP HEADER: No CSP on ${host}"
      fi

      # HSTS
      local hsts
      hsts=$(echo "$headers_raw" | grep -i "strict-transport-security:" | head -1)
      if [[ -z "$hsts" ]]; then
        finding "SUPP HEADER: No HSTS on ${host}"
      else
        echo "HSTS: $hsts"
        # Flag short max-age
        local maxage
        maxage=$(echo "$hsts" | grep -oP 'max-age=\K[0-9]+')
        if [[ -n "$maxage" && $maxage -lt 31536000 ]]; then
          finding "SUPP HEADER: HSTS max-age=${maxage} on ${host} (< 1 year)"
        fi
      fi

      # X-Frame-Options (clickjacking)
      local xfo
      xfo=$(echo "$headers_raw" | grep -i "x-frame-options:" | head -1)
      [[ -z "$xfo" ]] && echo "X-Frame-Options: MISSING — potential clickjacking" \
        || echo "X-Frame-Options: $xfo"

      # Cookie flags (from Set-Cookie headers)
      local cookies
      cookies=$(echo "$headers_raw" | grep -i "set-cookie:" | head -5)
      if [[ -n "$cookies" ]]; then
        echo "$cookies" | while IFS= read -r cookie_line; do
          local missing_flags=""
          echo "$cookie_line" | grep -qi "secure" || missing_flags="${missing_flags}Secure "
          echo "$cookie_line" | grep -qi "httponly" || missing_flags="${missing_flags}HttpOnly "
          echo "$cookie_line" | grep -qi "samesite" || missing_flags="${missing_flags}SameSite "
          [[ -n "$missing_flags" ]] && \
            finding "SUPP HEADER: Cookie missing flags [${missing_flags}] on ${host}"
        done
      fi

      # Server version disclosure
      local server_hdr
      server_hdr=$(echo "$headers_raw" | grep -i "^server:" | head -1)
      if echo "$server_hdr" | grep -qiP 'apache/[0-9]|nginx/[0-9]|iis/[0-9]|php/|tomcat/'; then
        finding "SUPP HEADER: Version disclosure: ${server_hdr} on ${host}"
      fi

      # X-Powered-By disclosure
      local xpb
      xpb=$(echo "$headers_raw" | grep -i "x-powered-by:" | head -1)
      [[ -n "$xpb" ]] && finding "SUPP HEADER: Tech disclosure: ${xpb} on ${host}"

    } >> "${sup_dir}/headers/header_audit.txt"

    # OPTIONS method check
    local options_response
    options_response=$(curl -sk --max-time 8 -X OPTIONS \
      -o /dev/null -w "%{http_code}" \
      -D "${sup_dir}/headers/options_${host_label//\//_}.txt" \
      "$host" 2>/dev/null || echo "000")

    if [[ "$options_response" == "200" ]]; then
      local allowed_methods
      allowed_methods=$(grep -i "^Allow:\|^Access-Control-Allow-Methods:" \
        "${sup_dir}/headers/options_${host_label//\//_}.txt" 2>/dev/null | head -2)
      if echo "$allowed_methods" | grep -qiE "PUT|DELETE|PATCH|TRACE|CONNECT"; then
        finding "SUPP HEADER: Dangerous HTTP methods on ${host}: ${allowed_methods}"
      fi
    fi

    sleep 0.3
  done < "$live_hosts_file"

  # ── 14d. Source map discovery from downloaded JS bundles ─────────────────
  info "Checking for exposed source maps (.js.map)..."
  local js_bundles_dir="${OUTPUT_DIR}/js/bundles"
  if [[ -d "$js_bundles_dir" ]]; then
    while IFS= read -r js_url; do
      [[ -z "$js_url" ]] && continue
      local map_url="${js_url}.map"
      local http_code
      http_code=$(curl -sk --max-time 8 -o \
        "${sup_dir}/sourcemaps/$(basename "${js_url}").map" \
        -w "%{http_code}" "$map_url" 2>/dev/null || echo "000")
      if [[ "$http_code" == "200" ]]; then
        local map_size
        map_size=$(wc -c < "${sup_dir}/sourcemaps/$(basename "${js_url}").map" 2>/dev/null || echo 0)
        if [[ $map_size -gt 100 ]]; then
          finding "SUPP SOURCEMAP: ${map_url} (${map_size} bytes) — original source recoverable"
          # Extract original file paths from source map
          jq -r '.sources[]?' \
            "${sup_dir}/sourcemaps/$(basename "${js_url}").map" \
            2>/dev/null | head -20 \
            >> "${sup_dir}/sourcemaps/original_paths.txt" || true
        fi
      fi
      sleep 0.1
    done < "${OUTPUT_DIR}/js/all_js_urls.txt" 2>/dev/null
  fi

  local sourcemap_count
  sourcemap_count=$(count_lines "${sup_dir}/sourcemaps/original_paths.txt" 2>/dev/null || echo 0)
  [[ $sourcemap_count -gt 0 ]] && \
    finding "SUPP SOURCEMAP: ${sourcemap_count} original source file paths recovered"

  # ── 14e. Subdomain permutation via alterx ────────────────────────────────
  info "Running alterx subdomain permutation on discovered names..."
  local ct_subs="${OUTPUT_DIR}/ct/ct_all_domains.txt"
  if [[ -s "$ct_subs" ]] && require_tool alterx; then
    # Feed only subdomains (not apex) into alterx
    grep "\.${DOMAIN}\$" "$ct_subs" 2>/dev/null \
      | grep -v "^${DOMAIN}\$" \
      | head -50 \
      | alterx -silent 2>/dev/null \
      | grep -v "^${DOMAIN}\$" \
      | sort -u > "${sup_dir}/dns/alterx_permutations.txt" || true

    local perm_count
    perm_count=$(count_lines "${sup_dir}/dns/alterx_permutations.txt")
    info "alterx generated ${perm_count} permutations"

    # Resolve permutations to find live ones
    if [[ $perm_count -gt 0 ]] && require_tool dnsx; then
      dnsx -l "${sup_dir}/dns/alterx_permutations.txt" \
        -silent -a -resp \
        -o "${sup_dir}/dns/alterx_live.txt" \
        2>/dev/null || true
      local live_perm_count
      live_perm_count=$(count_lines "${sup_dir}/dns/alterx_live.txt")
      [[ $live_perm_count -gt 0 ]] && \
        finding "SUPP ALTERX: ${live_perm_count} permutation subdomains resolve — new attack surface"
    fi
  else
    info "alterx not found or no CT data — skipping permutation"
    info "Install: go install github.com/projectdiscovery/alterx/cmd/alterx@latest"
  fi

  # ── 14f. SPF include-chain deep walker ───────────────────────────────────
  info "Walking SPF include chain..."
  local spf_walk_output="${sup_dir}/spf/spf_chain.txt"
  local visited_spf=()

  walk_spf() {
    local domain_to_walk="$1"
    local depth="${2:-0}"
    local indent
    indent=$(printf '%*s' $((depth * 2)) '')

    # Avoid infinite loops
    for v in "${visited_spf[@]}"; do
      [[ "$v" == "$domain_to_walk" ]] && return
    done
    visited_spf+=("$domain_to_walk")

    local spf_txt
    spf_txt=$(dig +short TXT "$domain_to_walk" 2>/dev/null | grep -i "v=spf" | head -1)
    [[ -z "$spf_txt" ]] && return

    echo "${indent}${domain_to_walk}: ${spf_txt}" >> "$spf_walk_output"

    # Walk includes recursively (max depth 5)
    if [[ $depth -lt 5 ]]; then
      echo "$spf_txt" | grep -oP 'include:[^\s]+' | cut -d: -f2 | while read -r inc; do
        walk_spf "$inc" $((depth + 1))
      done
      # Also extract redirect modifier
      local redirect
      redirect=$(echo "$spf_txt" | grep -oP 'redirect=[^\s]+' | cut -d= -f2)
      [[ -n "$redirect" ]] && walk_spf "$redirect" $((depth + 1))
    fi
  }

  walk_spf "$DOMAIN"

  local spf_vendor_count
  spf_vendor_count=$(count_lines "$spf_walk_output" 2>/dev/null || echo 0)
  if [[ $spf_vendor_count -gt 1 ]]; then
    finding "SUPP SPF: Full include chain has ${spf_vendor_count} entries — see ${spf_walk_output}"
    # Extract all IPs and ranges authorized by SPF chain
    grep -oP 'ip[46]:[^\s]+' "$spf_walk_output" 2>/dev/null \
      | cut -d: -f2 \
      >> "${sup_dir}/spf/spf_authorized_ips.txt" || true
    local spf_ip_count
    spf_ip_count=$(count_lines "${sup_dir}/spf/spf_authorized_ips.txt")
    [[ $spf_ip_count -gt 0 ]] && \
      info "SPF chain authorizes ${spf_ip_count} explicit IP ranges"
  fi

  # ── 14g. URLScan.io lookup ────────────────────────────────────────────────
  info "Querying URLScan.io for domain history..."
  local urlscan_data
  urlscan_data=$(rate_limited_curl \
    "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=10") || true

  if [[ -n "$urlscan_data" ]]; then
    echo "$urlscan_data" | jq '.' > "${sup_dir}/urlscan/urlscan_results.json" \
      2>/dev/null || true

    local scan_count
    scan_count=$(echo "$urlscan_data" | jq '.total // 0' 2>/dev/null || echo 0)
    info "URLScan.io: ${scan_count} historical scans found"

    # Extract unique IPs observed serving the domain
    echo "$urlscan_data" | jq -r \
      '.results[].page.ip // empty' 2>/dev/null \
      | sort -u > "${sup_dir}/urlscan/observed_ips.txt" || true

    # Extract related domains observed in same scan
    echo "$urlscan_data" | jq -r \
      '.results[].page.domain // empty' 2>/dev/null \
      | sort -u > "${sup_dir}/urlscan/observed_domains.txt" || true

    # Extract ASN seen by URLScan (bypasses CDN for historical data)
    local urlscan_asn
    urlscan_asn=$(echo "$urlscan_data" | jq -r \
      '.results[].page | select(.asnname != null) | "\(.asn) \(.asnname)"' \
      2>/dev/null | sort | uniq -c | sort -rn | head -3 || echo "")

    if [[ -n "$urlscan_asn" ]]; then
      echo "$urlscan_asn" >> "${sup_dir}/urlscan/asn_history.txt"
      # If we still have no ASN from Module 1, URLScan may have the real one
      if [[ ! -s "${OUTPUT_DIR}/asn/asn_number.txt" ]]; then
        local us_asn_num
        us_asn_num=$(echo "$urlscan_asn" | head -1 | awk '{print $2}' | grep -oP '[0-9]+')
        [[ -n "$us_asn_num" ]] && \
          finding "SUPP URLSCAN: Historical ASN: $(echo "$urlscan_asn" | head -1) — use for rDNS"
      fi
    fi

    local obs_ip_count
    obs_ip_count=$(count_lines "${sup_dir}/urlscan/observed_ips.txt")
    [[ $obs_ip_count -gt 0 ]] && \
      finding "SUPP URLSCAN: ${obs_ip_count} IPs historically observed serving ${DOMAIN}"
  fi

  # ── 14h. SaaS / hosted platform detection ────────────────────────────────
  info "Detecting SaaS and hosted platform fingerprints..."
  local saas_targets=(
    "firebase.${DOMAIN}"
    "${DOMAIN%-*}.firebaseio.com"
    "$(echo "$DOMAIN" | cut -d. -f1).firebaseio.com"
    "$(echo "$DOMAIN" | cut -d. -f1).firebaseapp.com"
    "$(echo "$DOMAIN" | cut -d. -f1).web.app"
    "$(echo "$DOMAIN" | cut -d. -f1).herokuapp.com"
    "$(echo "$DOMAIN" | cut -d. -f1).netlify.app"
    "$(echo "$DOMAIN" | cut -d. -f1).vercel.app"
    "$(echo "$DOMAIN" | cut -d. -f1).pages.dev"
    "$(echo "$DOMAIN" | cut -d. -f1).github.io"
    "$(echo "$DOMAIN" | cut -d. -f1).azurewebsites.net"
    "$(echo "$DOMAIN" | cut -d. -f1).ondigitalocean.app"
  )

  for saas_target in "${saas_targets[@]}"; do
    local http_code
    http_code=$(curl -sk --max-time 6 \
      -o /dev/null -w "%{http_code}" \
      "https://${saas_target}" 2>/dev/null || echo "000")

    case "$http_code" in
      200|301|302|401|403)
        finding "SUPP SAAS: ${saas_target} responds (${http_code}) — hosted platform surface"
        echo "${saas_target} HTTP:${http_code}" >> "${sup_dir}/saas/detected.txt"
        ;;
    esac
    sleep 0.2
  done

  # Firebase realtime DB check (open rules = critical)
  local base_name
  base_name=$(echo "$DOMAIN" | rev | cut -d. -f2 | rev)
  local firebase_url="https://${base_name}-default-rtdb.firebaseio.com/.json"
  local fb_code
  fb_code=$(curl -sk --max-time 8 \
    -o "${sup_dir}/saas/firebase_db.json" \
    -w "%{http_code}" "$firebase_url" 2>/dev/null || echo "000")

  if [[ "$fb_code" == "200" ]]; then
    local fb_size
    fb_size=$(wc -c < "${sup_dir}/saas/firebase_db.json" 2>/dev/null || echo 0)
    [[ $fb_size -gt 5 ]] && \
      finding "SUPP CRITICAL: Firebase DB publicly readable: ${firebase_url} (${fb_size} bytes)"
  fi

  # ── 14i. GitHub dork list generator ──────────────────────────────────────
  info "Generating GitHub dork list for manual use..."
  local company_name
  company_name=$(echo "$DOMAIN" | rev | cut -d. -f2 | rev)

  cat > "${sup_dir}/dorks/github_dorks.txt" << DORKEOF
# GitHub Dorks for: ${DOMAIN} / ${company_name}
# Use at: https://github.com/search?type=code&q=DORK
# Each finds different leak categories — search manually

## Secrets and credentials
"${DOMAIN}" "api_key"
"${DOMAIN}" "secret_key"
"${DOMAIN}" "client_secret"
"${DOMAIN}" "access_token"
"${DOMAIN}" "password"
"${DOMAIN}" "BEGIN RSA PRIVATE KEY"
"${DOMAIN}" "BEGIN OPENSSH PRIVATE KEY"
"${DOMAIN}" "AWS_SECRET_ACCESS_KEY"
"${DOMAIN}" "DB_PASSWORD"
"${DOMAIN}" ".env"
org:${company_name} "aws_access_key_id"
org:${company_name} "client_secret"
org:${company_name} "private_key"
org:${company_name} "jdbc:"
org:${company_name} "mongodb://"
org:${company_name} "redis://"

## Internal infrastructure references
"${DOMAIN}" "internal"
"${DOMAIN}" "staging"
"${DOMAIN}" "dev."
"${DOMAIN}" "localhost"
org:${company_name} "staging"
org:${company_name} "internal"
org:${company_name} extension:env
org:${company_name} extension:pem
org:${company_name} extension:key
org:${company_name} filename:.env
org:${company_name} filename:config.yml
org:${company_name} filename:secrets.yml
org:${company_name} filename:database.yml
org:${company_name} filename:credentials

## Infrastructure as code
org:${company_name} filename:terraform.tfvars
org:${company_name} filename:*.tf "secret"
org:${company_name} filename:Jenkinsfile
org:${company_name} filename:.travis.yml "secret"
org:${company_name} filename:docker-compose.yml "password"

## Bearer tokens and JWT
"${DOMAIN}" "bearer"
"${DOMAIN}" "Authorization:"
"api.${DOMAIN}" "token"
DORKEOF

  finding "SUPP DORKS: GitHub dork list: ${sup_dir}/dorks/github_dorks.txt ($(wc -l < "${sup_dir}/dorks/github_dorks.txt") dorks)"

  # ── 14j. Public package / container registry hints ───────────────────────
  info "Checking public package registries for target packages..."
  local company_lower
  company_lower=$(echo "$company_name" | tr '[:upper:]' '[:lower:]')

  # npm registry
  local npm_data
  npm_data=$(rate_limited_curl "https://registry.npmjs.org/-/v1/search?text=${company_lower}&size=5") || true
  if [[ -n "$npm_data" ]]; then
    local npm_count
    npm_count=$(echo "$npm_data" | jq '.total // 0' 2>/dev/null || echo 0)
    if [[ "$npm_count" -gt 0 ]]; then
      echo "$npm_data" | jq -r '.objects[].package | "\(.name) v\(.version) — \(.description // "")"' \
        2>/dev/null > "${sup_dir}/dorks/npm_packages.txt" || true
      finding "SUPP REGISTRY: ${npm_count} npm packages matching '${company_lower}' — check for internal package naming"
    fi
  fi

  # Docker Hub
  local docker_data
  docker_data=$(rate_limited_curl \
    "https://hub.docker.com/v2/search/repositories/?query=${company_lower}&page_size=5") || true
  if [[ -n "$docker_data" ]]; then
    local docker_count
    docker_count=$(echo "$docker_data" | jq '.count // 0' 2>/dev/null || echo 0)
    if [[ "$docker_count" -gt 0 ]]; then
      echo "$docker_data" | jq -r \
        '.results[] | "\(.repo_name) — \(.short_description // "")"' \
        2>/dev/null > "${sup_dir}/dorks/docker_images.txt" || true
      finding "SUPP REGISTRY: ${docker_count} Docker Hub images matching '${company_lower}' — check for secrets in layers"
    fi
  fi

  # ── 14k. Postman public workspace hint ───────────────────────────────────
  info "Generating Postman search hint..."
  cat >> "${sup_dir}/dorks/github_dorks.txt" << POSTEOF

## Postman public workspaces (search manually)
# https://www.postman.com/search?q=${company_name}&scope=public&type=workspace
# https://www.postman.com/search?q=${DOMAIN}&scope=public&type=collection

## Google dorks (run in browser)
# site:${DOMAIN} filetype:env
# site:${DOMAIN} inurl:swagger
# site:${DOMAIN} inurl:api
# site:${DOMAIN} intitle:"index of /"
# site:${DOMAIN} ext:log
# site:${DOMAIN} ext:sql
# site:${DOMAIN} "internal use only"
POSTEOF

  success "Module 14 complete — see ${sup_dir}/"
  info "Key outputs:"
  info "  Headers audit:  ${sup_dir}/headers/header_audit.txt"
  info "  Source maps:    ${sup_dir}/sourcemaps/"
  info "  Well-known:     ${sup_dir}/wellknown/"
  info "  GitHub dorks:   ${sup_dir}/dorks/github_dorks.txt"
  info "  SPF chain:      ${sup_dir}/spf/spf_chain.txt"
  info "  URLScan:        ${sup_dir}/urlscan/"
  info "  SaaS detection: ${sup_dir}/saas/detected.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# FINAL REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
generate_report() {
  section "Generating Final Report"
  local report_file="${OUTPUT_DIR}/reports/RECON_REPORT_${DOMAIN}_${DATE}.md"
  local end_time
  end_time=$(date +%s)
  local duration=$(( end_time - START_TIME ))
  local duration_min=$(( duration / 60 ))
  local duration_sec=$(( duration % 60 ))

  cat > "$report_file" << REPORT_EOF
# Deep Recon Report: ${DOMAIN}
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Duration:** ${duration_min}m ${duration_sec}s
**Modules:** ${MODULES}

---

## Executive Summary

$(cat "${OUTPUT_DIR}/findings_summary.txt" 2>/dev/null || echo "No findings recorded.")

---

## Module Results

### ASN & Infrastructure
- CIDRs discovered: $(count_lines "${OUTPUT_DIR}/asn/ipv4_cidrs.txt" 2>/dev/null || echo 0)
- ASN: $(cat "${OUTPUT_DIR}/asn/asn_number.txt" 2>/dev/null || echo "Not found")

### Certificate Transparency
- Total domains in CT logs: $(count_lines "${OUTPUT_DIR}/ct/ct_all_domains.txt" 2>/dev/null || echo 0)
- Naming analysis: see ${OUTPUT_DIR}/ct/ct_analysis.txt

### Historical Data (Wayback)
- Historical URLs collected: $(count_lines "${OUTPUT_DIR}/wayback/wayback_raw.txt" 2>/dev/null || echo 0)
- Unique parameters extracted: $(count_lines "${OUTPUT_DIR}/wayback/unique_params.txt" 2>/dev/null || echo 0)
- Sensitive file patterns: $(count_lines "${OUTPUT_DIR}/wayback/sensitive_files.txt" 2>/dev/null || echo 0)
- Old API versions found: $(count_lines "${OUTPUT_DIR}/wayback/api_versions.txt" 2>/dev/null || echo 0)

### Cloud Assets
- S3 buckets (exist/public): $(count_lines "${OUTPUT_DIR}/cloud/s3_exists.txt" 2>/dev/null || echo 0) exist
- GCP buckets: $(count_lines "${OUTPUT_DIR}/cloud/gcp_exists.txt" 2>/dev/null || echo 0) exist

### Email Security
$(cat "${OUTPUT_DIR}/email/email_security.txt" 2>/dev/null || echo "Not run")

### JavaScript Analysis
- JS URLs discovered: $(count_lines "${OUTPUT_DIR}/js/all_js_urls.txt" 2>/dev/null || echo 0)
- Endpoints extracted: $(count_lines "${OUTPUT_DIR}/js/extracted_endpoints.txt" 2>/dev/null || echo 0)
- Potential secrets: $(count_lines "${OUTPUT_DIR}/js/potential_secrets.txt" 2>/dev/null || echo 0)

### Supplemental (Module 14)
- Header audit: $(count_lines "${OUTPUT_DIR}/supplemental/headers/header_audit.txt" 2>/dev/null || echo 0) lines
- Source maps found: $(count_lines "${OUTPUT_DIR}/supplemental/sourcemaps/original_paths.txt" 2>/dev/null || echo 0) original paths
- alterx live permutations: $(count_lines "${OUTPUT_DIR}/supplemental/dns/alterx_live.txt" 2>/dev/null || echo 0)
- SPF chain depth: $(count_lines "${OUTPUT_DIR}/supplemental/spf/spf_chain.txt" 2>/dev/null || echo 0) entries
- URLScan historical IPs: $(count_lines "${OUTPUT_DIR}/supplemental/urlscan/observed_ips.txt" 2>/dev/null || echo 0)
- SaaS platforms detected: $(count_lines "${OUTPUT_DIR}/supplemental/saas/detected.txt" 2>/dev/null || echo 0)
- GitHub dorks generated: $(grep -c "^\"" "${OUTPUT_DIR}/supplemental/dorks/github_dorks.txt" 2>/dev/null || echo 0)

### Correlation
- Master subdomain list: $(count_lines "${OUTPUT_DIR}/correlation/master_subdomains.txt" 2>/dev/null || echo 0)
- Takeover candidates: $(count_lines "${OUTPUT_DIR}/correlation/takeover_candidates.txt" 2>/dev/null || echo 0)

---

## Next Steps

1. **Run OMEGA** on JS bundles: \`${OUTPUT_DIR}/js/omega_run_command.sh\`
2. **Verify takeover candidates** in: \`${OUTPUT_DIR}/correlation/takeover_candidates.txt\`
3. **Check sensitive files** from Wayback: \`${OUTPUT_DIR}/wayback/sensitive_files.txt\`
4. **Review potential secrets** in JS: \`${OUTPUT_DIR}/js/potential_secrets.txt\`
5. **Manually probe** interesting services from CT analysis: \`${OUTPUT_DIR}/ct/ct_analysis.txt\`
6. **Run arjun** with: \`${OUTPUT_DIR}/params/param_wordlist.txt\` ($(count_lines "${OUTPUT_DIR}/params/param_wordlist.txt" 2>/dev/null || echo 0) params)

---

## Output Directory Structure
\`\`\`
${OUTPUT_DIR}/
├── asn/           — ASN, CIDR blocks, IP list
├── dns/           — Reverse DNS results
├── ct/            — Certificate transparency mining
├── wayback/       — Historical URL intelligence
├── cloud/         — S3/GCS/Azure bucket enumeration
├── email/         — SPF/DMARC/DKIM analysis
├── ports/         — Non-standard port scan results
├── vhost/         — Virtual host discovery
├── js/            — JavaScript analysis + OMEGA input
├── params/        — Parameter wordlist
├── correlation/   — Cross-layer correlation
└── reports/       — This report + favicon hash
\`\`\`
REPORT_EOF

  success "Report written to: $report_file"
  echo ""
  echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
  echo -e "${BOLD}${GREEN}  RECON COMPLETE${NC}"
  echo -e "${BOLD}${GREEN}  Target:   ${DOMAIN}${NC}"
  echo -e "${BOLD}${GREEN}  Duration: ${duration_min}m ${duration_sec}s${NC}"
  echo -e "${BOLD}${GREEN}  Output:   ${OUTPUT_DIR}${NC}"
  echo -e "${BOLD}${GREEN}  Report:   ${report_file}${NC}"
  echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
  echo ""
  echo -e "${BOLD}Key Findings:${NC}"
  cat "${OUTPUT_DIR}/findings_summary.txt" 2>/dev/null | head -20 || echo "  (none)"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 13: CONTINUOUS ASSET MONITOR
# Merged from monitor.sh — detects new subdomains/certs/ports between runs
# Usage: deep_recon.sh -d target.com -m monitor
#        LOOP=true deep_recon.sh -d target.com -m monitor   (infinite loop)
# ─────────────────────────────────────────────────────────────────────────────
module_monitor() {
  section "MODULE 13: Continuous Asset Monitor"
  local mon_dir="${HOME}/bounty/monitor/${DOMAIN}"
  local state_dir="${mon_dir}/state"
  local alert_dir="${mon_dir}/alerts"
  mkdir -p "$state_dir" "$alert_dir"

  local interval="${MONITOR_INTERVAL:-21600}"  # Default 6h

  monitor_alert() {
    local type="$1" content="$2"
    local ts; ts=$(date '+%Y%m%d_%H%M%S')
    echo "$content" > "${alert_dir}/${ts}_${type}.txt"
    finding "MONITOR ALERT [${type}]: $(echo "$content" | wc -l) new items"
    echo "$content"
    # Termux push notification (requires termux-api pkg)
    command -v termux-notification &>/dev/null && \
      termux-notification \
        --title "DeepRecon: ${DOMAIN}" \
        --content "${type}: $(echo "$content" | wc -l) new" \
        --priority high 2>/dev/null || true
  }

  monitor_cycle() {
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    info "Monitor cycle: $ts"

    # ── New subdomains ──────────────────────────────────────────────
    local curr="${state_dir}/current_subs.txt"
    local prev="${state_dir}/previous_subs.txt"
    if require_tool subfinder; then
      subfinder -d "$DOMAIN" -all -silent 2>/dev/null | sort -u > "$curr"
      if [[ -f "$prev" ]]; then
        local new_subs; new_subs=$(comm -23 "$curr" "$prev")
        if [[ -n "$new_subs" ]]; then
          monitor_alert "NEW_SUBDOMAINS" "$new_subs"
          # Auto-probe new subdomains and feed into VanguardScanner if available
          echo "$new_subs" | httpx -silent -status-code -title -threads 5 \
            >> "${alert_dir}/new_subs_probed.txt" 2>/dev/null || true
          # Feed to VanguardScanner if present
          for vanguard_path in \
            "${HOME}/vanguard/vanguard.py" \
            "${HOME}/VanguardScanner/vanguard.py"; do
            if [[ -f "$vanguard_path" ]]; then
              echo "$new_subs" | while read -r sub; do
                echo "https://${sub}" >> "${alert_dir}/vanguard_queue.txt"
              done
              info "New subdomains queued for VanguardScanner: ${alert_dir}/vanguard_queue.txt"
              break
            fi
          done
        else
          info "Subdomains: no change ($(wc -l < "$curr") total)"
        fi
      fi
      cp "$curr" "$prev"
    fi

    # ── New open ports on apex IP ───────────────────────────────────
    local apex_ip; apex_ip=$(dig +short A "$DOMAIN" 2>/dev/null | head -1 || true)
    if [[ -n "$apex_ip" ]] && require_tool naabu; then
      local curr_ports="${state_dir}/current_ports.txt"
      local prev_ports="${state_dir}/previous_ports.txt"
      naabu -host "$apex_ip" \
        -p "80,443,2375,3000,5601,6379,8080,8443,9090,9200,27017" \
        -silent 2>/dev/null > "$curr_ports"
      if [[ -f "$prev_ports" ]]; then
        local new_ports; new_ports=$(comm -23 <(sort "$curr_ports") <(sort "$prev_ports"))
        [[ -n "$new_ports" ]] && monitor_alert "NEW_OPEN_PORTS" "$new_ports"
      fi
      cp "$curr_ports" "$prev_ports"
    fi

    # ── New CT certificates ─────────────────────────────────────────
    local curr_certs="${state_dir}/current_certs.txt"
    local prev_certs="${state_dir}/previous_certs.txt"
    curl -s --max-time 20 "https://crt.sh/?q=%.${DOMAIN}&output=json" \
      | jq -r '.[].name_value // empty' 2>/dev/null \
      | sed 's/\*\.//g' | sort -u > "$curr_certs"
    if [[ -f "$prev_certs" ]]; then
      local new_certs; new_certs=$(comm -23 "$curr_certs" "$prev_certs")
      [[ -n "$new_certs" ]] && monitor_alert "NEW_CERTIFICATES" "$new_certs"
    fi
    cp "$curr_certs" "$prev_certs"

    info "Cycle complete. Alerts: ${alert_dir}/"
  }

  # Setup cron if requested
  if [[ "${MONITOR_CRON:-false}" == "true" ]]; then
    local script_path; script_path=$(realpath "$0")
    local cron_line="0 */6 * * * DOMAIN=${DOMAIN} ${script_path} -d ${DOMAIN} -m monitor >> ${mon_dir}/cron.log 2>&1"
    (crontab -l 2>/dev/null | grep -v "DOMAIN=${DOMAIN}"; echo "$cron_line") | crontab - 2>/dev/null && \
      success "Cron job installed (every 6h)" || \
      warn "crontab not available. Run manually: LOOP=true deep_recon.sh -d ${DOMAIN} -m monitor"
    return
  fi

  # Run cycle(s)
  if [[ "${LOOP:-false}" == "true" ]]; then
    info "Monitor loop started (interval: $((interval/3600))h). Ctrl+C to stop."
    while true; do
      monitor_cycle
      sleep "$interval"
    done
  else
    monitor_cycle
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# TOOLCHAIN INTEGRATION HOOKS
# Connects deep_recon output to VanguardScanner, nuclei-go, OMEGA
# ─────────────────────────────────────────────────────────────────────────────
run_integrations() {
  [[ "${RUN_INTEGRATIONS:-false}" != "true" ]] && return
  section "Toolchain Integration"

  local live_hosts="${OUTPUT_DIR}/js/live_hosts.txt"
  local js_files="${OUTPUT_DIR}/js/all_js_urls.txt"
  local endpoints="${OUTPUT_DIR}/js/extracted_endpoints.txt"

  # ── VanguardScanner v11 ─────────────────────────────────────────
  for vanguard in \
    "${HOME}/vanguard/vanguard.py" \
    "${HOME}/VanguardScanner/vanguard.py" \
    "${HOME}/tools/vanguard.py"; do
    if [[ -f "$vanguard" && -s "$live_hosts" ]]; then
      info "Feeding live hosts into VanguardScanner..."
      grep -oP 'https?://[^\s]+' "$live_hosts" \
        > "${OUTPUT_DIR}/reports/vanguard_targets.txt" 2>/dev/null || true
      info "VanguardScanner input: ${OUTPUT_DIR}/reports/vanguard_targets.txt"
      info "Run: python3 ${vanguard} --targets ${OUTPUT_DIR}/reports/vanguard_targets.txt --mode full"
      echo "python3 ${vanguard} --targets ${OUTPUT_DIR}/reports/vanguard_targets.txt --mode full" \
        > "${OUTPUT_DIR}/reports/run_vanguard.sh"
      chmod +x "${OUTPUT_DIR}/reports/run_vanguard.sh"
      break
    fi
  done

  # ── nuclei-go ───────────────────────────────────────────────────
  for nuclei_go in \
    "${HOME}/nuclei-go/nuclei-go" \
    "${HOME}/tools/nuclei-go"; do
    if [[ -f "$nuclei_go" && -s "$live_hosts" ]]; then
      info "Preparing nuclei-go command..."
      cat > "${OUTPUT_DIR}/reports/run_nuclei_go.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
${nuclei_go} \\
  -l ${live_hosts} \\
  -t ~/nuclei-templates/ \\
  -severity medium,high,critical \\
  -o ${OUTPUT_DIR}/reports/nuclei_go_results.txt
EOF
      chmod +x "${OUTPUT_DIR}/reports/run_nuclei_go.sh"
      info "nuclei-go command: ${OUTPUT_DIR}/reports/run_nuclei_go.sh"
      break
    fi
  done

  # ── JS Decoder OMEGA / omega_lite ──────────────────────────────
  for omega in \
    "${HOME}/omega-pipeline/omega_scan.py" \
    "${HOME}/bb-omega-suite/omega_pipeline/omega_scan.py" \
    "${HOME}/omega_pipeline/omega_lite.py" \
    "${HOME}/js-decoder-omega/omega.py"; do
    if [[ -f "$omega" && -s "$js_files" ]]; then
      cat > "${OUTPUT_DIR}/js/omega_run_command.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
python3 ${omega} \\
  --input ${OUTPUT_DIR}/js/bundles/ \\
  --output ${OUTPUT_DIR}/js/omega_report/
EOF
      chmod +x "${OUTPUT_DIR}/js/omega_run_command.sh"
      finding "OMEGA ready: ${OUTPUT_DIR}/js/omega_run_command.sh"
      break
    fi
  done

  success "Integration scripts written to ${OUTPUT_DIR}/reports/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 15: ACTIVE PROTOCOL INTELLIGENCE
# WAF/CDN fingerprinting, JARM, GraphQL introspection, API version enum,
# WebSocket discovery, SMTP banner, CDN origin discovery, cache surface,
# HTTP smuggling indicators, historical DNS via free sources
# ─────────────────────────────────────────────────────────────────────────────
module_protocol() {
  section "MODULE 15: Active Protocol Intelligence"
  local proto_dir="${OUTPUT_DIR}/protocol"
  mkdir -p "${proto_dir}"/{waf,jarm,graphql,api,websocket,smtp,origin,cache,dns_history}

  local live_hosts="${OUTPUT_DIR}/js/live_hosts.txt"
  [[ ! -s "$live_hosts" ]] && echo "https://${DOMAIN}" > "$live_hosts"

  # ── 15a. WAF / CDN fingerprinting ────────────────────────────────────────
  info "Fingerprinting WAF and CDN on live hosts..."

  waf_fingerprint() {
    local target="$1"
    local result_file="${proto_dir}/waf/$(echo "$target" | sed 's|https\?://||;s|/|_|g').txt"
    local headers_raw
    headers_raw=$(curl -skI --max-time 10 \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      "$target" 2>/dev/null || echo "")

    {
      echo "=== WAF/CDN Fingerprint: ${target} ==="

      # CDN detection via headers
      local cdn=""
      echo "$headers_raw" | grep -qi "cf-ray\|cf-cache\|cloudflare" && cdn="Cloudflare"
      echo "$headers_raw" | grep -qi "x-cache.*akamai\|akamai-cache" && cdn="Akamai"
      echo "$headers_raw" | grep -qi "x-amz-cf-id\|cloudfront" && cdn="CloudFront"
      echo "$headers_raw" | grep -qi "fastly-restarts\|x-served-by.*cache" && cdn="Fastly"
      echo "$headers_raw" | grep -qi "x-azure-ref\|arr-disable" && cdn="Azure CDN"
      echo "$headers_raw" | grep -qi "x-sucuri-id" && cdn="Sucuri"
      echo "$headers_raw" | grep -qi "x-cdn.*imperva\|incap_ses" && cdn="Imperva/Incapsula"

      # WAF detection via headers
      local waf=""
      echo "$headers_raw" | grep -qi "x-waf-\|x-fw-\|x-firewall" && waf="Generic WAF"
      echo "$headers_raw" | grep -qi "x-amzn-waf\|x-amzn-requestid" && waf="AWS WAF"
      echo "$headers_raw" | grep -qi "x-sucuri-cache\|sucuri" && waf="Sucuri WAF"
      echo "$headers_raw" | grep -qi "x-protected-by.*snapchat\|x-datacenter" && waf="Custom WAF"

      [[ -n "$cdn" ]] && echo "CDN: $cdn" || echo "CDN: not detected"
      [[ -n "$waf" ]] && echo "WAF: $waf" || echo "WAF: not detected"

      # Probe for WAF with a known-bad request (harmless marker)
      local waf_test_code
      waf_test_code=$(curl -sk --max-time 8 \
        -o /dev/null -w "%{http_code}" \
        -H "User-Agent: Mozilla/5.0" \
        "${target}/?waf_test_param=<script>alert(1)</script>" \
        2>/dev/null || echo "000")

      echo "WAF probe response (XSS marker): HTTP ${waf_test_code}"
      if [[ "$waf_test_code" == "403" || "$waf_test_code" == "406" || \
            "$waf_test_code" == "429" || "$waf_test_code" == "412" ]]; then
        echo "WAF ACTIVE: blocked probe (${waf_test_code})"
        finding "PROTO WAF: Active WAF detected on ${target} (${waf_test_code} on probe)"
      elif [[ "$waf_test_code" == "200" ]]; then
        echo "WAF BYPASS: probe passed through (200) — WAF may be absent or misconfigured"
        finding "PROTO WAF: No WAF block on ${target} — XSS probe returned 200"
      fi

      # X-Forwarded-For trust check
      local xff_test_code
      xff_test_code=$(curl -sk --max-time 8 \
        -o /dev/null -w "%{http_code}" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Real-IP: 127.0.0.1" \
        -H "True-Client-IP: 127.0.0.1" \
        "${target}/admin" 2>/dev/null || echo "000")
      echo "X-Forwarded-For: 127.0.0.1 → /admin = HTTP ${xff_test_code}"
      [[ "$xff_test_code" == "200" || "$xff_test_code" == "301" || \
         "$xff_test_code" == "302" ]] && \
        finding "PROTO WAF: XFF spoofing to 127.0.0.1 bypasses /admin check on ${target}"

    } > "$result_file"

    # wafw00f integration
    if require_tool wafw00f; then
      wafw00f "$target" -o "${proto_dir}/waf/wafw00f_$(echo "$target" | \
        sed 's|https\?://||;s|/|_|g').txt" 2>/dev/null || true
    fi
  }

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    waf_fingerprint "$host"
    sleep 0.5
  done < "$live_hosts"

  # ── 15b. JARM TLS fingerprinting ─────────────────────────────────────────
  info "Computing JARM fingerprints for TLS correlation..."

  python3 - "${DOMAIN}" "${proto_dir}/jarm/jarm_results.txt" << 'JARMEOF'
import sys, socket, struct, hashlib, random, string

def jarm_hash(fingerprint):
    """Compute JARM hash from raw fingerprint string"""
    if fingerprint == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
        return "0" * 62
    fuzzy = hashlib.sha256(fingerprint.encode()).hexdigest()
    return fuzzy[:62]

def read_packet(sock, timeout=3):
    sock.settimeout(timeout)
    try:
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 5:
                break
    except Exception:
        pass
    return data

def send_hello(host, port, tls_version, ciphers, extensions=""):
    """Send a TLS ClientHello and return server response"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))

        # Minimal TLS ClientHello
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id = b"\x00"
        cipher_bytes = b"".join([c.to_bytes(2, 'big') for c in ciphers])
        cipher_len = len(cipher_bytes).to_bytes(2, 'big')
        compression = b"\x01\x00"  # no compression

        hello_body = (
            tls_version.to_bytes(2, 'big') +
            random_bytes + session_id +
            cipher_len + cipher_bytes +
            compression
        )

        hello_len = len(hello_body).to_bytes(3, 'big')
        handshake = b"\x01" + hello_len + hello_body
        record = b"\x16" + tls_version.to_bytes(2, 'big') + \
                 len(handshake).to_bytes(2, 'big') + handshake
        s.send(record)
        resp = read_packet(s)
        s.close()
        return resp
    except Exception:
        return b""

def extract_cipher_and_version(data):
    """Extract selected cipher suite and version from ServerHello"""
    if not data or len(data) < 10:
        return "|||"
    try:
        # TLS record: type(1) ver(2) len(2) | handshake: type(1) len(3) body
        if data[0] != 0x16 or data[5] != 0x02:
            return "|||"
        server_version = struct.unpack('>H', data[9:11])[0]
        cipher = struct.unpack('>H', data[43:45])[0]
        return f"{server_version:04x}|{cipher:04x}|"
    except Exception:
        return "|||"

# JARM probe configurations: (version, cipher_list)
PROBES = [
    (0x0303, [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f]),  # TLS 1.3 modern
    (0x0303, [0xc02b, 0xc02f, 0x009e, 0xcc14, 0xcc13]),  # TLS 1.2
    (0x0301, [0x0035, 0x002f, 0x000a]),                   # TLS 1.0
    (0x0302, [0xc013, 0xc014, 0x002f, 0x0035]),           # TLS 1.1
    (0x0303, [0xc02c, 0xc030, 0x009f, 0xcc15]),           # TLS 1.2 alt
]

domain = sys.argv[1]
out_file = sys.argv[2]
port = 443

results = []
for ver, ciphers in PROBES:
    resp = send_hello(domain, port, ver, ciphers)
    results.append(extract_cipher_and_version(resp))

fingerprint = ",".join(results)
jarm = jarm_hash(fingerprint)

output = f"Domain: {domain}\nFingerprint: {fingerprint}\nJARM: {jarm}\n"
output += f"\nShodan query: ssl.jarm:{jarm}\n"
output += f"Censys query: services.tls.ja3s_fingerprint:{jarm}\n"

with open(out_file, 'w') as f:
    f.write(output)

print(f"JARM: {jarm}")
JARMEOF

  if [[ -s "${proto_dir}/jarm/jarm_results.txt" ]]; then
    local jarm_hash
    jarm_hash=$(grep "^JARM:" "${proto_dir}/jarm/jarm_results.txt" | awk '{print $2}')
    [[ -n "$jarm_hash" && "$jarm_hash" != "0000000000000000000000000000000000000000000000000000000000000000" ]] && \
      finding "PROTO JARM: ${jarm_hash} — use Shodan: ssl.jarm:${jarm_hash} to find related servers"
  fi

  # ── 15c. GraphQL introspection ───────────────────────────────────────────
  info "Testing GraphQL endpoints for introspection..."

  local graphql_paths=(
    "/graphql"
    "/api/graphql"
    "/v1/graphql"
    "/query"
    "/api/query"
    "/graph"
    "/gql"
    "/graphiql"
    "/playground"
    "/api"
  )

  local introspection_query
  introspection_query='{"query":"{__schema{types{name fields{name}}}}"}'
  local batch_query
  batch_query='[{"query":"{__schema{queryType{name}}}"},{"query":"{__schema{mutationType{name}}}"}]'

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    for gql_path in "${graphql_paths[@]}"; do
      local gql_url="${host}${gql_path}"

      # Standard introspection
      local gql_code gql_body
      gql_body=$(curl -sk --max-time 10 \
        -X POST "$gql_url" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "$introspection_query" \
        -o "${proto_dir}/graphql/$(echo "${gql_url}" | \
          sed 's|https\?://||;s|/|_|g').json" \
        -w "%{http_code}" 2>/dev/null || echo "000")

      local gql_resp
      gql_resp=$(cat "${proto_dir}/graphql/$(echo "${gql_url}" | \
        sed 's|https\?://||;s|/|_|g').json" 2>/dev/null || echo "")

      if echo "$gql_resp" | grep -q '"__schema"'; then
        # Introspection enabled
        local type_count
        type_count=$(echo "$gql_resp" | jq '.data.__schema.types | length' 2>/dev/null || echo "?")
        finding "PROTO GRAPHQL: Introspection ENABLED at ${gql_url} — ${type_count} types exposed"

        # Extract type and field names
        echo "$gql_resp" | jq -r \
          '.data.__schema.types[] | select(.name | startswith("__") | not) |
           "\(.name): \([.fields[]?.name] | join(", "))"' \
          2>/dev/null > "${proto_dir}/graphql/schema_$(echo "${host}" | \
            sed 's|https\?://||').txt" || true

      elif echo "$gql_resp" | grep -q '"errors"'; then
        # GraphQL exists but introspection disabled
        local error_msg
        error_msg=$(echo "$gql_resp" | jq -r '.errors[0].message' 2>/dev/null | head -1)
        if echo "$error_msg" | grep -qi "introspection\|disabled\|not allowed"; then
          finding "PROTO GRAPHQL: Endpoint at ${gql_url} — introspection disabled (try batching)"
          # Try batch bypass
          local batch_resp
          batch_resp=$(curl -sk --max-time 10 \
            -X POST "$gql_url" \
            -H "Content-Type: application/json" \
            -d "$batch_query" 2>/dev/null || echo "")
          echo "$batch_resp" | grep -q '"data"' && \
            finding "PROTO GRAPHQL: Batch query BYPASS works at ${gql_url}"
        fi
      fi
      sleep 0.3
    done
  done < "$live_hosts"

  # ── 15d. API version enumeration ─────────────────────────────────────────
  info "Enumerating API versions..."
  local api_versions=("v0" "v1" "v2" "v3" "v4" "v5"
                      "api/v1" "api/v2" "api/v3"
                      "internal" "private" "admin"
                      "beta" "alpha" "dev" "test"
                      "rest" "service" "services"
                      "api/internal" "api/admin"
                      "api/beta" "api/private")

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local api_results_file="${proto_dir}/api/versions_$(echo "$host" | \
      sed 's|https\?://||;s|/|_|g').txt"

    for ver in "${api_versions[@]}"; do
      local api_url="${host}/${ver}"
      local code
      code=$(curl -sk --max-time 8 \
        -H "Accept: application/json" \
        -o /dev/null -w "%{http_code}" "$api_url" 2>/dev/null || echo "000")

      case "$code" in
        200|201)
          echo "LIVE ${code}: ${api_url}" | tee -a "$api_results_file"
          finding "PROTO API: Live endpoint ${api_url} (${code})"
          ;;
        401|403)
          echo "EXISTS_AUTH ${code}: ${api_url}" >> "$api_results_file"
          # Auth-required is still valuable — confirms path exists
          [[ "$ver" == "internal" || "$ver" == "private" || \
             "$ver" == "admin" || "$ver" == "api/admin" ]] && \
            finding "PROTO API: Protected internal endpoint: ${api_url} (${code})"
          ;;
        301|302)
          local location
          location=$(curl -skI --max-time 8 "$api_url" 2>/dev/null | \
            grep -i "^location:" | head -1 | awk '{print $2}')
          echo "REDIRECT ${code}: ${api_url} → ${location}" >> "$api_results_file"
          ;;
        405)
          # Method Not Allowed = endpoint exists but GET rejected
          echo "EXISTS_405: ${api_url}" >> "$api_results_file"
          finding "PROTO API: ${api_url} exists (405 Method Not Allowed — try POST)"
          ;;
      esac
      sleep 0.15
    done
  done < "$live_hosts"

  local api_live_count
  api_live_count=$(grep -rl "^LIVE\|^EXISTS" "${proto_dir}/api/" 2>/dev/null | \
    xargs grep -h "^LIVE\|^EXISTS" 2>/dev/null | wc -l || echo 0)
  [[ $api_live_count -gt 0 ]] && \
    finding "PROTO API: ${api_live_count} API version paths discovered across all hosts"

  # ── 15e. WebSocket endpoint discovery ────────────────────────────────────
  info "Probing for WebSocket endpoints..."
  local ws_paths=("/ws" "/websocket" "/socket" "/socket.io"
                  "/ws/v1" "/ws/v2" "/live" "/stream"
                  "/realtime" "/events" "/notifications"
                  "/cable" "/sockjs" "/push")

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local ws_host
    ws_host=$(echo "$host" | sed 's/^https:/wss:/;s/^http:/ws:/')

    for ws_path in "${ws_paths[@]}"; do
      # Send HTTP Upgrade request — check for 101 Switching Protocols
      local upgrade_resp
      upgrade_resp=$(curl -sk --max-time 6 \
        -o /dev/null -w "%{http_code}" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        "${host}${ws_path}" 2>/dev/null || echo "000")

      case "$upgrade_resp" in
        101)
          finding "PROTO WS: WebSocket endpoint at ${host}${ws_path} (101 Switching Protocols)"
          echo "${host}${ws_path}" >> "${proto_dir}/websocket/ws_endpoints.txt"
          ;;
        200|400)
          # 400 on socket.io = endpoint exists, wrong handshake
          echo "${host}${ws_path} HTTP:${upgrade_resp}" >> \
            "${proto_dir}/websocket/ws_candidates.txt"
          ;;
      esac
      sleep 0.1
    done
  done < "$live_hosts"

  local ws_count
  ws_count=$(count_lines "${proto_dir}/websocket/ws_endpoints.txt" 2>/dev/null || echo 0)
  [[ $ws_count -gt 0 ]] && \
    finding "PROTO WS: ${ws_count} confirmed WebSocket endpoints — map message flow manually"

  # ── 15f. SMTP banner grab and open relay check ───────────────────────────
  info "Grabbing SMTP banner from mail server..."
  local mx_host
  mx_host=$(dig +short MX "$DOMAIN" 2>/dev/null | sort -n | \
    head -1 | awk '{print $2}' | sed 's/\.$//')

  if [[ -n "$mx_host" ]]; then
    local mx_ip
    mx_ip=$(dig +short A "$mx_host" 2>/dev/null | head -1)
    info "MX: ${mx_host} (${mx_ip})"

    # Grab SMTP banner via nc or bash TCP
    local smtp_banner
    smtp_banner=$(timeout 8 bash -c \
      "exec 3<>/dev/tcp/${mx_ip}/25; cat <&3" \
      2>/dev/null | head -3 || echo "")

    if [[ -n "$smtp_banner" ]]; then
      echo "$smtp_banner" > "${proto_dir}/smtp/banner.txt"
      finding "PROTO SMTP: Banner: $(echo "$smtp_banner" | head -1 | tr -d '\r')"

      # Extract mail server software and version
      local smtp_sw
      smtp_sw=$(echo "$smtp_banner" | grep -oiP '(postfix|exim|sendmail|exchange|zimbra|haraka|dovecot)[^\s]*' | head -1)
      [[ -n "$smtp_sw" ]] && \
        finding "PROTO SMTP: Software: ${smtp_sw} — check for version-specific CVEs"

      # SMTP EHLO to get capabilities
      local ehlo_resp
      ehlo_resp=$(timeout 8 bash -c \
        "exec 3<>/dev/tcp/${mx_ip}/25
         echo 'EHLO test.com' >&3
         sleep 1; cat <&3" 2>/dev/null | head -20 || echo "")
      echo "$ehlo_resp" > "${proto_dir}/smtp/ehlo.txt"

      # Check for STARTTLS
      echo "$ehlo_resp" | grep -qi "STARTTLS" || \
        finding "PROTO SMTP: No STARTTLS on ${mx_host} — mail in cleartext"

      # VRFY user enumeration check
      local vrfy_resp
      vrfy_resp=$(timeout 8 bash -c \
        "exec 3<>/dev/tcp/${mx_ip}/25
         echo 'VRFY root' >&3
         sleep 1; cat <&3" 2>/dev/null | head -3 || echo "")
      if echo "$vrfy_resp" | grep -qP "^250|^252"; then
        finding "PROTO SMTP: VRFY user enumeration enabled on ${mx_host}"
      fi
    fi
  fi

  # ── 15g. CDN origin discovery via historical data ─────────────────────────
  info "Attempting CDN origin IP discovery..."

  # Source 1: Subdomain resolution without CDN (common patterns)
  local origin_candidates=()
  for bypass_sub in "direct" "origin" "origin-www" "backend" "server" \
                    "mail" "ftp" "cpanel" "whm" "webdisk" \
                    "smtp" "imap" "pop" "autodiscover"; do
    local bypass_ip
    bypass_ip=$(dig +short A "${bypass_sub}.${DOMAIN}" 2>/dev/null | \
      grep -v '^\s*$' | head -1)
    if [[ -n "$bypass_ip" ]]; then
      # Check if it's NOT a CDN IP
      local is_cdn=false
      for cdn_prefix in "104.16." "104.17." "104.18." "104.19." "172.64." \
                        "172.65." "162.158." "198.41." "104.21."; do
        [[ "$bypass_ip" == ${cdn_prefix}* ]] && is_cdn=true && break
      done
      if [[ "$is_cdn" == false ]]; then
        origin_candidates+=("${bypass_sub}.${DOMAIN} → ${bypass_ip}")
        finding "PROTO ORIGIN: ${bypass_sub}.${DOMAIN} resolves to ${bypass_ip} — possible non-CDN origin"
        echo "${bypass_sub}.${DOMAIN} ${bypass_ip}" >> \
          "${proto_dir}/origin/non_cdn_hosts.txt"
      fi
    fi
  done

  # Source 2: URLScan historical IPs (already fetched in Module 14)
  local urlscan_ips="${OUTPUT_DIR}/supplemental/urlscan/observed_ips.txt"
  if [[ -s "$urlscan_ips" ]]; then
    info "Cross-referencing URLScan historical IPs as origin candidates..."
    while IFS= read -r hist_ip; do
      [[ -z "$hist_ip" ]] && continue
      local is_cdn=false
      for cdn_prefix in "104.16." "104.17." "104.18." "104.19." "172.64." \
                        "172.65." "162.158." "198.41."; do
        [[ "$hist_ip" == ${cdn_prefix}* ]] && is_cdn=true && break
      done
      if [[ "$is_cdn" == false ]]; then
        finding "PROTO ORIGIN: Historical non-CDN IP from URLScan: ${hist_ip} — test direct access"
        echo "$hist_ip" >> "${proto_dir}/origin/historical_ips.txt"

        # Probe direct access
        local direct_code
        direct_code=$(curl -sk --max-time 8 \
          -H "Host: ${DOMAIN}" \
          -o /dev/null -w "%{http_code}" \
          "https://${hist_ip}/" 2>/dev/null || echo "000")
        [[ "$direct_code" != "000" ]] && \
          finding "PROTO ORIGIN: Direct origin access: https://${hist_ip}/ responds (${direct_code}) with Host: ${DOMAIN}"
      fi
    done < "$urlscan_ips"
  fi

  # ── 15h. Cache poisoning surface analysis ────────────────────────────────
  info "Analyzing cache poisoning surface..."

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local cache_file="${proto_dir}/cache/$(echo "$host" | \
      sed 's|https\?://||;s|/|_|g').txt"

    {
      echo "=== Cache Poisoning Surface: ${host} ==="

      # Get baseline response
      local baseline
      baseline=$(curl -sk --max-time 10 \
        -D - "$host" -o /dev/null 2>/dev/null || echo "")

      local cache_control xfh_reflect x_host_reflect vary_hdr
      cache_control=$(echo "$baseline" | grep -i "^cache-control:" | head -1)
      vary_hdr=$(echo "$baseline" | grep -i "^vary:" | head -1)

      echo "Cache-Control: ${cache_control:-not set}"
      echo "Vary: ${vary_hdr:-not set}"

      # Test X-Forwarded-Host reflection
      local xfh_resp
      xfh_resp=$(curl -sk --max-time 10 \
        -H "X-Forwarded-Host: evil.example.com" \
        "$host" 2>/dev/null | grep -oi "evil\.example\.com" | head -1 || echo "")
      if [[ -n "$xfh_resp" ]]; then
        echo "X-Forwarded-Host: REFLECTED in body"
        finding "PROTO CACHE: X-Forwarded-Host reflected in response at ${host} — cache poisoning candidate"
      else
        echo "X-Forwarded-Host: not reflected"
      fi

      # Test X-Host reflection
      local xhost_resp
      xhost_resp=$(curl -sk --max-time 10 \
        -H "X-Host: evil.example.com" \
        "$host" 2>/dev/null | grep -oi "evil\.example\.com" | head -1 || echo "")
      [[ -n "$xhost_resp" ]] && \
        finding "PROTO CACHE: X-Host header reflected at ${host} — cache poisoning candidate"

      # Check if response is cacheable with dangerous Vary
      if echo "$vary_hdr" | grep -qi "X-Forwarded-Host\|X-Host\|User-Agent"; then
        finding "PROTO CACHE: Vary includes attacker-controlled header at ${host}"
      fi

      # Age header = cached response
      echo "$baseline" | grep -qi "^Age:" && echo "Response is cached (Age: header present)"

    } > "$cache_file"
    sleep 0.5
  done < "$live_hosts"

  # ── 15i. Historical DNS via free APIs ────────────────────────────────────
  info "Querying historical DNS records..."

  # HackerTarget DNS history (free, no key)
  local ht_dns
  ht_dns=$(rate_limited_curl \
    "https://api.hackertarget.com/dnslookup/?q=${DOMAIN}") || true
  if [[ -n "$ht_dns" ]] && ! echo "$ht_dns" | grep -qi "error\|API count"; then
    echo "$ht_dns" > "${proto_dir}/dns_history/hackertarget_dns.txt"
    info "HackerTarget DNS records saved"
  fi

  # ViewDNS.info historical IPs (scrape public endpoint)
  local viewdns
  viewdns=$(rate_limited_curl \
    "https://api.hackertarget.com/reverseiplookup/?q=${DOMAIN}") || true
  if [[ -n "$viewdns" ]] && ! echo "$viewdns" | grep -qi "error\|API count"; then
    echo "$viewdns" > "${proto_dir}/dns_history/reverse_ip_peers.txt"
    local peer_count
    peer_count=$(echo "$viewdns" | wc -l)
    [[ $peer_count -gt 1 ]] && \
      finding "PROTO DNS: ${peer_count} domains share same IP as ${DOMAIN} — check for related assets"
  fi

  # Subdomain history via crt.sh timing data
  info "Extracting subdomain first-seen dates from CT logs..."
  rate_limited_curl "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null \
    | jq -r '.[] | "\(.not_before[:10]) \(.name_value)"' 2>/dev/null \
    | sort | uniq \
    | grep -v '^\*\.' \
    > "${proto_dir}/dns_history/ct_timeline.txt" || true

  # Flag recently issued certs (new infrastructure = less hardened)
  local recent_certs
  recent_certs=$(grep "^$(date +%Y)" \
    "${proto_dir}/dns_history/ct_timeline.txt" 2>/dev/null | \
    grep -v "^$(date +%Y-%m)" | wc -l || echo 0)
  [[ $recent_certs -gt 0 ]] && \
    finding "PROTO DNS: ${recent_certs} certs issued this year — new infrastructure, likely less hardened"

  success "Module 15 complete — see ${proto_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 16: MOBILE RECON + PRIORITY SCORING + EVASION VALIDATION
# APK static analysis, passive-to-active priority engine,
# WAF evasion control validation, VirusTotal passive lookup
# ─────────────────────────────────────────────────────────────────────────────
module_intelligence() {
  section "MODULE 16: Intelligence — Mobile, Priority Scoring, Evasion Validation"
  local intel_dir="${OUTPUT_DIR}/intelligence"
  mkdir -p "${intel_dir}"/{mobile,priority,evasion,virustotal}

  local live_hosts="${OUTPUT_DIR}/js/live_hosts.txt"
  [[ ! -s "$live_hosts" ]] && echo "https://${DOMAIN}" > "$live_hosts"

  # ── 16a. APK static analysis ─────────────────────────────────────────────
  info "Checking for mobile app assets (APK static analysis)..."

  # Try to find APK from common URLs / Play Store
  local base_name
  base_name=$(echo "$DOMAIN" | rev | cut -d. -f2 | rev)

  # Google Play Store lookup (scrape app listing for package name)
  local play_data
  play_data=$(rate_limited_curl \
    "https://play.google.com/store/search?q=${base_name}&c=apps" \
    2>/dev/null | grep -oP 'com\.[a-z0-9._]+' | \
    grep -i "$base_name" | head -5 || echo "")

  if [[ -n "$play_data" ]]; then
    echo "$play_data" > "${intel_dir}/mobile/package_names.txt"
    finding "MOBILE: Possible package names: $(echo "$play_data" | tr '\n' ' ')"
  fi

  # APKPure / APKCombo (public mirrors) download hint
  {
    echo "# APK Analysis Hints for: ${DOMAIN}"
    echo ""
    echo "## Find and download APK:"
    echo "# 1. Search: https://apkpure.com/search?q=${base_name}"
    echo "# 2. Search: https://apkcombo.com/search/${base_name}"
    echo ""
    echo "## Once you have the APK, run:"
    echo "apktool d target.apk -o ${intel_dir}/mobile/decompiled/"
    echo ""
    echo "## Extract endpoints:"
    echo "grep -rhoP 'https?://[a-zA-Z0-9._/-]+' ${intel_dir}/mobile/decompiled/ | sort -u"
    echo ""
    echo "## Extract hardcoded strings:"
    echo "grep -rh 'api_key\|secret\|token\|password\|client_id' ${intel_dir}/mobile/decompiled/res/values/"
    echo ""
    echo "## Check AndroidManifest.xml for exported activities:"
    echo "grep -i 'exported=\"true\"\|android:exported' ${intel_dir}/mobile/decompiled/AndroidManifest.xml"
    echo ""
    echo "## Check Firebase config:"
    echo "cat ${intel_dir}/mobile/decompiled/res/values/google-services.xml 2>/dev/null"
    echo "grep -r 'firebaseio\|googleapis.com' ${intel_dir}/mobile/decompiled/ | head -20"
    echo ""
    echo "## Deep link handlers:"
    echo "grep -A3 'intent-filter' ${intel_dir}/mobile/decompiled/AndroidManifest.xml | grep 'scheme\|host'"
  } > "${intel_dir}/mobile/apk_analysis_guide.sh"
  chmod +x "${intel_dir}/mobile/apk_analysis_guide.sh"

  # If apktool is installed and an APK is in the working directory, auto-run
  local found_apk
  found_apk=$(find . -maxdepth 2 -name "*.apk" 2>/dev/null | head -1)
  if [[ -n "$found_apk" ]] && require_tool apktool; then
    info "APK found: $found_apk — decompiling..."
    apktool d "$found_apk" \
      -o "${intel_dir}/mobile/decompiled/" \
      --force 2>/dev/null || true

    if [[ -d "${intel_dir}/mobile/decompiled/" ]]; then
      # Extract endpoints
      grep -rhoP 'https?://[a-zA-Z0-9._/\-]+'  \
        "${intel_dir}/mobile/decompiled/" 2>/dev/null \
        | grep -v "schemas\.android\|w3\.org\|example\.com" \
        | sort -u > "${intel_dir}/mobile/apk_endpoints.txt" || true

      # Extract potential secrets
      grep -rhoiP '(?:api[_-]?key|secret|token|password|client_id)\s*[=:]\s*["\047][^"'\'']{8,}' \
        "${intel_dir}/mobile/decompiled/res/" 2>/dev/null \
        >> "${intel_dir}/mobile/apk_secrets.txt" || true

      # Firebase project ID
      grep -rh "google_app_id\|project_id\|api_key" \
        "${intel_dir}/mobile/decompiled/res/values/" 2>/dev/null \
        >> "${intel_dir}/mobile/apk_firebase.txt" || true

      local apk_ep_count
      apk_ep_count=$(count_lines "${intel_dir}/mobile/apk_endpoints.txt")
      [[ $apk_ep_count -gt 0 ]] && \
        finding "MOBILE APK: ${apk_ep_count} endpoints extracted from decompiled APK"

      local apk_secret_count
      apk_secret_count=$(count_lines "${intel_dir}/mobile/apk_secrets.txt")
      [[ $apk_secret_count -gt 0 ]] && \
        finding "MOBILE APK: ${apk_secret_count} potential hardcoded secrets in APK"
    fi
  fi

  # ── 16b. Passive-to-active priority scoring engine ───────────────────────
  info "Computing passive-to-active priority scores..."
  # Formula from document section 4:
  # ActivePriority = PassiveConfidence * ForgottenScore * AssetValue
  #                  * ExposureLikelihood / ActiveCost

  python3 - "${OUTPUT_DIR}" "${DOMAIN}" \
    "${intel_dir}/priority/priority_report.txt" << 'PYEOF'
import sys, os, json, re
from pathlib import Path

output_dir = Path(sys.argv[1])
domain     = sys.argv[2]
report     = sys.argv[3]

findings = []

def read_file(p):
    try:
        return Path(p).read_text(errors='ignore')
    except:
        return ""

def count_lines(p):
    try:
        return len([l for l in Path(p).read_text(errors='ignore').split('\n') if l.strip()])
    except:
        return 0

# ── Score each asset type ────────────────────────────────────────────────────

# 1. Subdomain takeover candidates
takeover_file = output_dir / "correlation/takeover_candidates.txt"
for line in read_file(takeover_file).splitlines():
    if line.strip():
        host = line.split()[0]
        score = round(0.95 * 0.90 * 0.85 * 0.90 / 0.10, 1)
        findings.append({
            "asset": host, "type": "SUBDOMAIN_TAKEOVER",
            "score": score, "priority": "CRITICAL",
            "reason": "Dangling CNAME to claimable service",
            "action": f"Claim the service the CNAME points to, prove takeover"
        })

# 2. High-value service subdomains from CT
ct_file = output_dir / "ct/ct_analysis.txt"
ct_text = read_file(ct_file)
for svc in ["jenkins", "grafana", "kibana", "vault", "jupyter",
            "portainer", "airflow", "sonar", "nexus", "gitlab"]:
    if svc.lower() in ct_text.lower():
        score = round(0.80 * 0.85 * 0.90 * 0.80 / 0.30, 1)
        findings.append({
            "asset": f"{svc}.{domain}", "type": "FORGOTTEN_SERVICE",
            "score": score, "priority": "HIGH",
            "reason": f"Service name '{svc}' found in CT logs — often default creds",
            "action": f"Probe https://{svc}.{domain} for default credentials and unauth access"
        })

# 3. S3 buckets that exist (even 403)
s3_file = output_dir / "cloud/s3_exists.txt"
for line in read_file(s3_file).splitlines():
    if "EXISTS" in line:
        bucket = line.split("s3://")[-1].strip() if "s3://" in line else line.strip()
        score = round(0.70 * 0.75 * 0.80 * 0.75 / 0.20, 1)
        findings.append({
            "asset": bucket, "type": "S3_BUCKET",
            "score": score, "priority": "MEDIUM",
            "reason": "S3 bucket exists — check for list/write permissions",
            "action": f"aws s3 ls s3://{bucket} --no-sign-request"
        })

# 4. GraphQL endpoints found
gql_dir = output_dir / "protocol/graphql"
if gql_dir.exists():
    for f in gql_dir.glob("*.json"):
        content = read_file(f)
        if "__schema" in content:
            score = round(0.95 * 0.60 * 0.85 * 0.90 / 0.25, 1)
            findings.append({
                "asset": f.stem.replace("_", "/"),
                "type": "GRAPHQL_INTROSPECTION",
                "score": score, "priority": "HIGH",
                "reason": "GraphQL introspection enabled — full schema exposed",
                "action": "Map all queries/mutations, test for IDOR and auth bypass"
            })

# 5. Historical sensitive file URLs from Wayback
sens_file = output_dir / "wayback/sensitive_files.txt"
sens_count = count_lines(sens_file)
if sens_count > 0:
    score = round(0.75 * 0.80 * 0.70 * 0.65 / 0.15, 1)
    findings.append({
        "asset": f"{sens_count} URLs", "type": "WAYBACK_SENSITIVE_FILES",
        "score": score, "priority": "HIGH",
        "reason": f"{sens_count} historical sensitive file URLs in Wayback",
        "action": f"Probe each URL — server may still serve deleted files: {sens_file}"
    })

# 6. Potential JS secrets
js_secrets = output_dir / "js/potential_secrets.txt"
secret_count = count_lines(js_secrets)
if secret_count > 0:
    score = round(0.80 * 0.70 * 0.90 * 0.85 / 0.10, 1)
    findings.append({
        "asset": f"{secret_count} matches", "type": "JS_HARDCODED_SECRETS",
        "score": score, "priority": "CRITICAL",
        "reason": f"{secret_count} potential secrets in JS bundles",
        "action": f"Review {js_secrets} — validate each key, check permissions"
    })

# 7. Source maps
sourcemap_paths = output_dir / "supplemental/sourcemaps/original_paths.txt"
sm_count = count_lines(sourcemap_paths)
if sm_count > 0:
    score = round(0.90 * 0.65 * 0.80 * 0.85 / 0.15, 1)
    findings.append({
        "asset": f"{sm_count} source files", "type": "SOURCE_MAP_EXPOSED",
        "score": score, "priority": "HIGH",
        "reason": "Source maps expose original source code",
        "action": "Run: npx source-map-explorer on downloaded .map files"
    })

# 8. CORS issues from header audit
header_audit = output_dir / "supplemental/headers/header_audit.txt"
ha_text = read_file(header_audit)
cors_wildcard_count = ha_text.count("CORS wildcard")
if cors_wildcard_count > 0:
    score = round(0.95 * 0.50 * 0.80 * 0.90 / 0.20, 1)
    findings.append({
        "asset": f"{cors_wildcard_count} hosts", "type": "CORS_WILDCARD",
        "score": score, "priority": "HIGH",
        "reason": f"CORS wildcard (*) on {cors_wildcard_count} hosts",
        "action": "Test cross-origin data access with credentials from attacker origin"
    })

# 9. WebSocket endpoints
ws_file = output_dir / "protocol/websocket/ws_endpoints.txt"
ws_count = count_lines(ws_file)
if ws_count > 0:
    score = round(0.90 * 0.70 * 0.75 * 0.80 / 0.35, 1)
    findings.append({
        "asset": f"{ws_count} endpoints", "type": "WEBSOCKET_ENDPOINTS",
        "score": score, "priority": "MEDIUM",
        "reason": f"{ws_count} WebSocket endpoints — often less-tested surface",
        "action": f"Intercept WS messages with Burp, test auth and injection: {ws_file}"
    })

# 10. Non-CDN origin IPs found
origin_file = output_dir / "protocol/origin/non_cdn_hosts.txt"
origin_count = count_lines(origin_file)
if origin_count > 0:
    score = round(0.85 * 0.80 * 0.85 * 0.90 / 0.25, 1)
    findings.append({
        "asset": f"{origin_count} hosts", "type": "CDN_ORIGIN_EXPOSED",
        "score": score, "priority": "HIGH",
        "reason": "Non-CDN IPs found — direct origin access bypasses WAF/CDN",
        "action": f"Probe direct with Host header: curl -H 'Host: {domain}' https://ORIGIN_IP/"
    })

# ── Sort by score descending ─────────────────────────────────────────────────
findings.sort(key=lambda x: x['score'], reverse=True)

# ── Write report ─────────────────────────────────────────────────────────────
lines = [
    f"# Passive-to-Active Priority Report: {domain}",
    f"# Generated: {__import__('datetime').datetime.now().isoformat()[:19]}",
    f"# Formula: PassiveConfidence × ForgottenScore × AssetValue × Exposure / ActiveCost",
    "",
    f"{'SCORE':<8} {'PRIORITY':<10} {'TYPE':<30} {'ASSET'}",
    "-" * 90
]
for f in findings:
    lines.append(
        f"{f['score']:<8.1f} {f['priority']:<10} {f['type']:<30} {f['asset']}"
    )
    lines.append(f"         Reason: {f['reason']}")
    lines.append(f"         Action: {f['action']}")
    lines.append("")

Path(report).write_text('\n'.join(lines))
print(f"Scored {len(findings)} items")
PYEOF

  if [[ -s "${intel_dir}/priority/priority_report.txt" ]]; then
    local scored_count
    scored_count=$(grep -c "^[0-9]" "${intel_dir}/priority/priority_report.txt" || echo 0)
    finding "INTEL PRIORITY: ${scored_count} assets scored — report: ${intel_dir}/priority/priority_report.txt"
    # Print top 3
    echo ""
    info "Top priority targets:"
    grep "^[0-9]" "${intel_dir}/priority/priority_report.txt" | \
      head -3 | while IFS= read -r line; do
        info "  $line"
      done
    echo ""
  fi

  # ── 16c. WAF evasion control validation ──────────────────────────────────
  info "Running WAF evasion control validation (authorized targets only)..."

  # Only run if WAF was detected in Module 15
  local waf_detected=false
  if grep -rl "WAF ACTIVE\|WAF: AWS\|WAF: Sucuri\|WAF: Custom" \
      "${OUTPUT_DIR}/protocol/waf/" 2>/dev/null | grep -q .; then
    waf_detected=true
  fi

  if [[ "$waf_detected" == true ]]; then
    info "WAF detected — running control validation probes..."
  else
    info "No WAF confirmed — running baseline encoding tests..."
  fi

  local primary_host
  primary_host=$(head -1 "$live_hosts")

  {
    echo "# WAF Evasion Control Validation: ${primary_host}"
    echo "# Purpose: verify WAF normalizes and blocks equivalent payloads"
    echo "# Each probe uses a harmless marker — not a weaponized payload"
    echo ""

    local tests_passed=0 tests_blocked=0

    run_evasion_test() {
      local name="$1" url="$2" method="${3:-GET}" data="${4:-}"
      local response code

      if [[ "$method" == "GET" ]]; then
        code=$(curl -sk --max-time 8 \
          -H "User-Agent: Mozilla/5.0" \
          -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
      else
        code=$(curl -sk --max-time 8 \
          -X "$method" -d "$data" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -H "User-Agent: Mozilla/5.0" \
          -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
      fi

      local result
      if [[ "$code" == "403" || "$code" == "406" || \
            "$code" == "412" || "$code" == "429" ]]; then
        result="BLOCKED(${code})"
        ((tests_blocked++))
      elif [[ "$code" == "000" ]]; then
        result="TIMEOUT"
      else
        result="PASSED(${code}) — WAF did not block"
      fi
      echo "  ${name}: ${result}"

      # Flag bypass as finding
      if [[ "$result" == PASSED* ]]; then
        finding "EVASION: WAF bypass — ${name} not blocked on ${primary_host}"
      fi
    }

    echo "## Encoding normalization tests:"
    # URL encoding
    run_evasion_test "URL-encoded path traversal" \
      "${primary_host}/%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    # Double encoding
    run_evasion_test "Double-encoded traversal" \
      "${primary_host}/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    # Case variation
    run_evasion_test "Case-varied SQL keyword" \
      "${primary_host}/?id=1+UnIoN+SeLeCt+1,2,3--"
    # Unicode normalization
    run_evasion_test "Unicode path separator" \
      "${primary_host}/\u002e\u002e\u002fetc\u002fpasswd"
    # Null byte
    run_evasion_test "Null byte injection" \
      "${primary_host}/?file=../etc/passwd%00.jpg"

    echo ""
    echo "## IP spoofing header tests:"
    # X-Forwarded-For bypass
    local xff_bypass_code
    xff_bypass_code=$(curl -sk --max-time 8 \
      -H "X-Forwarded-For: 127.0.0.1" \
      -H "X-Real-IP: 127.0.0.1" \
      -H "X-Originating-IP: 127.0.0.1" \
      -o /dev/null -w "%{http_code}" \
      "${primary_host}/admin" 2>/dev/null || echo "000")
    echo "  XFF localhost → /admin: HTTP ${xff_bypass_code}"
    [[ "$xff_bypass_code" == "200" ]] && \
      finding "EVASION: XFF spoofing to 127.0.0.1 bypasses /admin (200)"

    echo ""
    echo "## HTTP method tests:"
    for method in "HEAD" "OPTIONS" "TRACE" "CONNECT" "PUT" "DELETE" "PATCH"; do
      local method_code
      method_code=$(curl -sk --max-time 8 \
        -X "$method" \
        -o /dev/null -w "%{http_code}" \
        "$primary_host" 2>/dev/null || echo "000")
      echo "  ${method}: HTTP ${method_code}"
      [[ "$method" == "TRACE" && "$method_code" == "200" ]] && \
        finding "EVASION: TRACE method enabled on ${primary_host} — XST possible"
    done

    echo ""
    echo "## Content-Type confusion:"
    # JSON payload with form Content-Type
    local ct_code
    ct_code=$(curl -sk --max-time 8 \
      -X POST \
      -H "Content-Type: text/plain" \
      -d '{"key":"<script>alert(1)</script>"}' \
      -o /dev/null -w "%{http_code}" \
      "${primary_host}/api" 2>/dev/null || echo "000")
    echo "  JSON body with text/plain Content-Type → /api: HTTP ${ct_code}"

    echo ""
    echo "## Summary: ${tests_blocked} blocked / $((tests_blocked + tests_passed)) tested"

  } > "${intel_dir}/evasion/waf_validation_report.txt"

  local evasion_finding_count
  evasion_finding_count=$(grep -c "EVASION:" "${OUTPUT_DIR}/findings_summary.txt" 2>/dev/null || echo 0)
  info "WAF validation complete — ${evasion_finding_count} bypass findings"

  # ── 16d. VirusTotal passive lookup ───────────────────────────────────────
  info "Querying VirusTotal for domain reputation and history..."

  # VT public API (no key needed for basic info)
  local vt_data
  vt_data=$(rate_limited_curl \
    "https://www.virustotal.com/api/v3/domains/${DOMAIN}" \
    -H "x-apikey: " 2>/dev/null || true)

  # Fallback: scrape VT community page (no API key)
  if [[ -z "$vt_data" ]] || echo "$vt_data" | grep -qi "forbidden\|unauthorized"; then
    vt_data=$(rate_limited_curl \
      "https://www.virustotal.com/vtapi/v2/domain/report?apikey=&domain=${DOMAIN}" \
      2>/dev/null || true)
  fi

  # Use urlscan as VirusTotal proxy (always free)
  local vt_urlscan
  vt_urlscan=$(rate_limited_curl \
    "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=5" \
    2>/dev/null || true)

  if [[ -n "$vt_urlscan" ]]; then
    echo "$vt_urlscan" | jq -r \
      '.results[] | "\(.task.time[:10]) \(.page.url) → \(.page.ip)"' \
      2>/dev/null > "${intel_dir}/virustotal/urlscan_timeline.txt" || true
    local vt_scan_count
    vt_scan_count=$(count_lines "${intel_dir}/virustotal/urlscan_timeline.txt")
    [[ $vt_scan_count -gt 0 ]] && \
      info "VT/URLScan: ${vt_scan_count} recent scans with IP timeline"
  fi

  # Generate VT manual lookup links
  {
    echo "# VirusTotal Manual Lookup Links: ${DOMAIN}"
    echo ""
    echo "Domain report:   https://www.virustotal.com/gui/domain/${DOMAIN}/relations"
    echo "IP report:       (use IPs from ${OUTPUT_DIR}/asn/domain_ips.txt)"
    echo "URL scan:        https://www.virustotal.com/gui/url/$(echo "https://${DOMAIN}" | \
      python3 -c "import sys,base64; print(base64.urlsafe_b64encode(sys.stdin.read().encode()).decode().rstrip('='))" 2>/dev/null || echo "encode_manually")"
    echo ""
    echo "# Key tabs to check:"
    echo "# Relations → linked domains, IPs, files, URLs"
    echo "# Community → notes from researchers"
    echo "# DNS Resolutions → historical A records (origin IP discovery)"
    echo "# Communicating Files → malware communicating with this domain"
  } > "${intel_dir}/virustotal/vt_lookup_links.txt"

  finding "INTEL VT: VirusTotal lookup links generated: ${intel_dir}/virustotal/vt_lookup_links.txt"

  # ── 16e. Final intelligence summary ──────────────────────────────────────
  {
    echo "# Intelligence Summary: ${DOMAIN}"
    echo "# $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "## Attack Surface Map"
    echo "Live hosts:           $(count_lines "${OUTPUT_DIR}/js/live_hosts.txt")"
    echo "Unique subdomains:    $(count_lines "${OUTPUT_DIR}/correlation/master_subdomains.txt")"
    echo "API endpoints (JS):  $(count_lines "${OUTPUT_DIR}/js/extracted_endpoints.txt")"
    echo "Historical URLs:     $(count_lines "${OUTPUT_DIR}/wayback/wayback_raw.txt")"
    echo "S3 buckets found:    $(count_lines "${OUTPUT_DIR}/cloud/s3_exists.txt")"
    echo "WS endpoints:        $(count_lines "${OUTPUT_DIR}/protocol/websocket/ws_endpoints.txt" 2>/dev/null || echo 0)"
    echo "GraphQL schemas:     $(ls "${OUTPUT_DIR}/protocol/graphql/"*.txt 2>/dev/null | wc -l)"
    echo ""
    echo "## Priority Queue (top items)"
    grep "^[0-9]" "${intel_dir}/priority/priority_report.txt" 2>/dev/null | head -10
  } > "${intel_dir}/attack_surface_map.txt"

  success "Module 16 complete — see ${intel_dir}/"
  success "Priority report: ${intel_dir}/priority/priority_report.txt"
  success "Evasion report:  ${intel_dir}/evasion/waf_validation_report.txt"
  success "Attack surface:  ${intel_dir}/attack_surface_map.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 17: AUTHENTICATION & SESSION INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
module_auth() {
  section "MODULE 17: Authentication & Session Intelligence"
  local auth_dir="${OUTPUT_DIR}/auth"
  mkdir -p "${auth_dir}"/{login,oauth,jwt,saml,session,ratelimit}

  local live_hosts="${OUTPUT_DIR}/js/live_hosts.txt"
  [[ ! -s "$live_hosts" ]] && echo "https://${DOMAIN}" > "$live_hosts"

  # 17a. Login endpoint discovery
  info "Discovering authentication endpoints..."
  local auth_paths=("/login" "/signin" "/sign-in" "/auth" "/authenticate"
    "/admin/login" "/api/login" "/api/auth" "/api/v1/auth" "/api/v1/login"
    "/api/token" "/oauth/token" "/oauth/authorize" "/oauth2/token"
    "/connect/token" "/identity/connect/token" "/auth/login" "/auth/token"
    "/sso" "/sso/login" "/saml/sso" "/saml2/sso"
    "/forgot-password" "/reset-password" "/password/reset"
    "/register" "/signup" "/sign-up"
    "/2fa" "/mfa" "/totp" "/otp" "/verify-otp"
    "/magic-link" "/passwordless" "/webauthn" "/logout")

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local auth_results="${auth_dir}/login/$(echo "$host" | sed 's|https\?://||;s|/|_|g').txt"
    echo "=== Auth Endpoints: ${host} ===" > "$auth_results"
    for auth_path in "${auth_paths[@]}"; do
      local url="${host}${auth_path}"
      local code
      code=$(curl -skL --max-time 8 \
        -o "${auth_dir}/login/.tmp_body" \
        -w "%{http_code}" "$url" 2>/dev/null || echo "000")
      case "$code" in
        200|301|302)
          local title
          title=$(grep -ioP '(?<=<title>)[^<]+' \
            "${auth_dir}/login/.tmp_body" 2>/dev/null | head -1 | tr -d '\r')
          echo "FOUND ${code}: ${url} — ${title}" | tee -a "$auth_results"
          echo "$auth_path" | grep -qiE "forgot|reset" && \
            finding "AUTH: Password reset endpoint: ${url} — test token entropy + reuse"
          echo "$auth_path" | grep -qiE "register|signup" && \
            finding "AUTH: Registration endpoint: ${url} — test email enumeration"
          echo "$auth_path" | grep -qiE "2fa|mfa|totp|otp" && \
            finding "AUTH: MFA endpoint: ${url} — test bypass and brute force"
          echo "$auth_path" | grep -qiE "admin|staff" && \
            finding "AUTH: Admin login surface: ${url} — test default credentials"
          grep -ioP 'name="[^"]+"' "${auth_dir}/login/.tmp_body" 2>/dev/null \
            | sort -u >> "${auth_dir}/login/form_fields.txt" || true
          ;;
        401|403)
          echo "PROTECTED ${code}: ${url}" >> "$auth_results"
          ;;
      esac
      sleep 0.15
    done
    rm -f "${auth_dir}/login/.tmp_body"
  done < "$live_hosts"

  local auth_found
  auth_found=$(grep -rl "^FOUND" "${auth_dir}/login/" 2>/dev/null | \
    xargs grep -h "^FOUND" 2>/dev/null | wc -l || echo 0)
  finding "AUTH: ${auth_found} authentication endpoints discovered"
  local field_count
  field_count=$(sort -u "${auth_dir}/login/form_fields.txt" 2>/dev/null | wc -l || echo 0)
  [[ $field_count -gt 0 ]] && \
    finding "AUTH: ${field_count} unique form field names — check for mass assignment"

  # 17b. OAuth/OIDC endpoint mapping
  info "Mapping OAuth/OIDC infrastructure..."
  local oauth_paths=("/.well-known/openid-configuration"
    "/.well-known/oauth-authorization-server"
    "/oauth/authorize" "/oauth/token" "/oauth2/authorize" "/oauth2/token"
    "/oauth2/revoke" "/oauth2/introspect"
    "/connect/authorize" "/connect/token" "/connect/revocation"
    "/connect/userinfo" "/connect/endsession"
    "/.well-known/jwks.json" "/jwks" "/jwks.json" "/public-keys")

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    for oauth_path in "${oauth_paths[@]}"; do
      local code body
      code=$(curl -skL --max-time 8 \
        -H "Accept: application/json" \
        -o "${auth_dir}/oauth/.tmp_oauth" \
        -w "%{http_code}" "${host}${oauth_path}" 2>/dev/null || echo "000")
      body=$(cat "${auth_dir}/oauth/.tmp_oauth" 2>/dev/null || echo "")
      if [[ "$code" == "200" ]]; then
        echo "${host}${oauth_path}" >> "${auth_dir}/oauth/endpoints.txt"
        if echo "$oauth_path" | grep -qi "jwks\|public-keys"; then
          local key_count alg_types
          key_count=$(echo "$body" | jq '.keys | length' 2>/dev/null || echo "?")
          alg_types=$(echo "$body" | jq -r '.keys[].alg // .keys[].kty' \
            2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || echo "unknown")
          finding "AUTH JWKS: ${host}${oauth_path} — ${key_count} keys, alg: ${alg_types}"
          cp "${auth_dir}/oauth/.tmp_oauth" \
            "${auth_dir}/jwt/jwks_$(echo "$host" | sed 's|https\?://||').json"
          echo "$alg_types" | grep -qiE "HS256|none" && \
            finding "AUTH JWKS: Weak JWT algorithm: ${alg_types} on ${host}"
        fi
        if echo "$oauth_path" | grep -qi "openid\|oauth-auth"; then
          echo "$body" | jq -r 'to_entries[] |
            select(.value | type == "string") |
            select(.value | startswith("http")) | "\(.key): \(.value)"' \
            2>/dev/null >> "${auth_dir}/oauth/oidc_endpoints.txt" || true
        fi
      fi
      rm -f "${auth_dir}/oauth/.tmp_oauth"
      sleep 0.1
    done
  done < "$live_hosts"

  local oidc_count
  oidc_count=$(count_lines "${auth_dir}/oauth/oidc_endpoints.txt")
  [[ $oidc_count -gt 0 ]] && \
    finding "AUTH OIDC: ${oidc_count} OIDC endpoints from discovery config"

  # 17c. JWT analysis from JS bundles
  info "Analyzing JWT tokens in JS bundles..."
  python3 - "${OUTPUT_DIR}/js/bundles" "${auth_dir}/jwt/analysis.txt" << 'JWTEOF'
import sys, re, base64, json
from pathlib import Path

bundles = Path(sys.argv[1])
out     = Path(sys.argv[2])
JWT_RE  = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')

def b64d(s):
    s += '=' * (4 - len(s) % 4)
    try: return json.loads(base64.urlsafe_b64decode(s))
    except: return {}

findings, seen = [], set()
if not bundles.exists():
    out.write_text("No bundles dir\n"); sys.exit(0)

for f in bundles.iterdir():
    try: content = f.read_text(errors='ignore')
    except: continue
    for jwt in JWT_RE.findall(content):
        if jwt in seen: continue
        seen.add(jwt)
        parts = jwt.split('.')
        if len(parts) < 2: continue
        header = b64d(parts[0])
        payload = b64d(parts[1]) if len(parts) > 1 else {}
        alg = header.get('alg', 'unknown')
        flags = []
        if alg.upper() in ('NONE', ''): flags.append('CRITICAL:alg=none')
        if alg.upper().startswith('HS'): flags.append('WEAK:symmetric-HMAC')
        if not payload.get('exp'): flags.append('NO-EXPIRY')
        if payload.get('role') or payload.get('roles'): flags.append(f"ROLE:{payload.get('role') or payload.get('roles')}")
        if payload.get('email'): flags.append(f"EMAIL:{payload['email']}")
        findings.append({'file': f.name, 'alg': alg, 'iss': payload.get('iss',''),
                         'flags': flags, 'jwt': jwt[:40]+'...'})

lines = [f"JWT Analysis: {len(findings)} tokens\n"]
for e in findings:
    lines += [f"File: {e['file']}", f"Alg:  {e['alg']}", f"ISS:  {e['iss']}",
              f"JWT:  {e['jwt']}"]
    if e['flags']: lines.append(f"!!    {' | '.join(e['flags'])}")
    lines.append("")
out.write_text('\n'.join(lines))
print(f"Analyzed {len(findings)} JWTs")
JWTEOF

  local jwt_count
  jwt_count=$(grep -c "^File:" "${auth_dir}/jwt/analysis.txt" 2>/dev/null || echo 0)
  [[ $jwt_count -gt 0 ]] && \
    finding "AUTH JWT: ${jwt_count} JWT tokens in JS bundles — ${auth_dir}/jwt/analysis.txt"
  grep -q "CRITICAL\|WEAK\|NO-EXPIRY" "${auth_dir}/jwt/analysis.txt" 2>/dev/null && \
    finding "AUTH JWT: Weak JWT configuration flags detected — review immediately"

  # 17d. SSO provider fingerprinting
  info "Fingerprinting SSO providers..."
  local primary_host; primary_host=$(head -1 "$live_hosts")
  local page; page=$(curl -skL --max-time 10 "$primary_host" 2>/dev/null || echo "")
  local sso_providers=()
  echo "$page" | grep -qi "accounts.google.com\|gsi/client"  && sso_providers+=("Google")
  echo "$page" | grep -qi "login.microsoftonline\|msal"      && sso_providers+=("Microsoft/AzureAD")
  echo "$page" | grep -qi "github.com/login/oauth"           && sso_providers+=("GitHub")
  echo "$page" | grep -qi "auth0\.com\|auth0"                && sso_providers+=("Auth0")
  echo "$page" | grep -qi "okta\.com\|okta"                  && sso_providers+=("Okta")
  echo "$page" | grep -qi "onelogin\.com"                    && sso_providers+=("OneLogin")
  echo "$page" | grep -qi "keycloak"                         && sso_providers+=("Keycloak")
  echo "$page" | grep -qi "cognito.*amazonaws\|aws.*cognito" && sso_providers+=("AWS Cognito")
  echo "$page" | grep -qi "firebase.*auth"                   && sso_providers+=("Firebase Auth")
  echo "$page" | grep -qi "clerk\.com\|clerk\.dev"           && sso_providers+=("Clerk")
  echo "$page" | grep -qi "supabase.*auth"                   && sso_providers+=("Supabase")
  if [[ ${#sso_providers[@]} -gt 0 ]]; then
    local pstr; pstr=$(printf '%s, ' "${sso_providers[@]}" | sed 's/, $//')
    finding "AUTH SSO: Providers: ${pstr}"
  fi
  echo "$page" | grep -qiE "totp|authenticator|2fa|mfa|two.factor" && \
    finding "AUTH MFA: MFA references found in page source"

  # 17e. Rate limit test on login
  info "Testing auth endpoint rate limiting..."
  local login_url
  login_url=$(grep -rh "^FOUND.*login\|^FOUND.*signin" \
    "${auth_dir}/login/" 2>/dev/null | \
    grep -oP 'https?://[^\s]+' | head -1 || echo "")
  if [[ -n "$login_url" ]]; then
    local throttled=false
    for i in $(seq 1 12); do
      local code
      code=$(curl -sk --max-time 5 -X POST "$login_url" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "email=test${i}@example.com&password=wrong${i}" \
        -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
      if [[ "$code" == "429" || "$code" == "423" ]]; then
        finding "AUTH RATELIMIT: Throttled at request ${i} (${code}) on ${login_url}"
        throttled=true; break
      fi
      sleep 0.3
    done
    [[ "$throttled" == false ]] && \
      finding "AUTH RATELIMIT: No throttling detected on ${login_url} — brute force possible"
  fi

  success "Module 17 complete — ${auth_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 18: TECHNOLOGY STACK CVE MAPPING
# ─────────────────────────────────────────────────────────────────────────────
module_cve() {
  section "MODULE 18: Technology Stack CVE Mapping"
  local cve_dir="${OUTPUT_DIR}/cve"
  mkdir -p "${cve_dir}"/{tech,nvd,osv,nuclei,deps}

  # 18a. Aggregate tech fingerprints
  info "Aggregating technology fingerprints..."
  python3 - "${OUTPUT_DIR}" "${cve_dir}/tech/stack.json" << 'TECHEOF'
import sys, re, json
from pathlib import Path
output_dir = Path(sys.argv[1])
out_file   = Path(sys.argv[2])
tech_stack = {}

def add(name, version="unknown", source=""):
    k = name.lower().replace(" ","_")
    if k not in tech_stack:
        tech_stack[k] = {"name":name,"versions":set(),"sources":set()}
    if version and version != "unknown":
        tech_stack[k]["versions"].add(version)
    tech_stack[k]["sources"].add(source)

def read(p):
    try: return Path(p).read_text(errors='ignore')
    except: return ""

# From HTTP headers
for m in re.finditer(r'Server:\s*([^\r\n]+)', read(output_dir/"supplemental/headers/header_audit.txt"), re.I):
    parts = m.group(1).strip().split('/')
    add(parts[0].strip(), parts[1].split()[0] if len(parts)>1 else "unknown", "server-header")
for m in re.finditer(r'X-Powered-By:\s*([^\r\n]+)', read(output_dir/"supplemental/headers/header_audit.txt"), re.I):
    parts = m.group(1).strip().split('/')
    add(parts[0].strip(), parts[1].split()[0] if len(parts)>1 else "unknown", "x-powered-by")

# From JS bundles
PATTERNS = [
    (r'"react":\s*"[~^]?([0-9.]+)"', "React"),
    (r'"vue":\s*"[~^]?([0-9.]+)"', "Vue.js"),
    (r'"next":\s*"[~^]?([0-9.]+)"', "Next.js"),
    (r'"express":\s*"[~^]?([0-9.]+)"', "Express"),
    (r'"jquery":\s*"[~^]?([0-9.]+)"', "jQuery"),
    (r'"lodash":\s*"[~^]?([0-9.]+)"', "Lodash"),
    (r'"axios":\s*"[~^]?([0-9.]+)"', "Axios"),
    (r'"graphql":\s*"[~^]?([0-9.]+)"', "GraphQL"),
    (r'"webpack":\s*"[~^]?([0-9.]+)"', "Webpack"),
    (r'"angular(?:core)?/core":\s*"[~^]?([0-9.]+)"', "Angular"),
    (r'React\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "React"),
    (r'jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "jQuery"),
    (r'Bootstrap\s+v?([0-9]+\.[0-9]+)', "Bootstrap"),
]
js_dir = output_dir/"js/bundles"
if js_dir.exists():
    for f in list(js_dir.iterdir())[:30]:
        try: content = f.read_text(errors='ignore')[:50000]
        except: continue
        for pat, name in PATTERNS:
            for m in re.finditer(pat, content, re.I):
                add(name, m.group(1), f"js:{f.name}")

# From wayback
wb = read(output_dir/"wayback/wayback_raw.txt")
for kw, name in [("wp-content","WordPress"),("joomla","Joomla"),
                  ("drupal","Drupal"),("magento","Magento"),
                  ("laravel","Laravel"),("springframework","Spring"),
                  ("django","Django"),("rails","Ruby on Rails")]:
    if kw in wb.lower(): add(name, "unknown", "wayback")

out = {k: {"name":v["name"],"versions":sorted(v["versions"]),"sources":sorted(v["sources"])}
       for k,v in tech_stack.items()}
out_file.write_text(json.dumps(out, indent=2))
print(f"Fingerprinted {len(out)} technologies")
TECHEOF

  local tech_count
  tech_count=$(jq 'keys | length' "${cve_dir}/tech/stack.json" 2>/dev/null || echo 0)
  info "Fingerprinted ${tech_count} technology components"

  # 18b. NVD CVE lookup
  info "Querying NVD API for CVEs..."
  python3 - "${cve_dir}/tech/stack.json" \
             "${cve_dir}/nvd/cve_results.json" \
             "${cve_dir}/nvd/high_severity.txt" << 'NVDEOF'
import sys, json, urllib.request, urllib.parse, time
from pathlib import Path

stack    = json.loads(Path(sys.argv[1]).read_text())
out_json = Path(sys.argv[2])
out_high = Path(sys.argv[3])
all_cves, high_sev = {}, []

for tech_key, tech_info in list(stack.items())[:12]:
    name    = tech_info["name"]
    version = tech_info["versions"][0] if tech_info["versions"] else "unknown"
    time.sleep(1.5)  # NVD: 5 req/30s unauthenticated
    try:
        q = f"{name} {version}" if version != "unknown" else name
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + \
              urllib.parse.urlencode({"keywordSearch": q, "resultsPerPage": "5"})
        req = urllib.request.Request(url,
              headers={"User-Agent": "deep_recon/1.0"})
        with urllib.request.urlopen(req, timeout=12) as r:
            data = json.loads(r.read())
    except Exception: continue

    tech_cves = []
    for item in data.get("vulnerabilities", []):
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc   = (cve.get("descriptions") or [{}])[0].get("value", "")[:100]
        metrics= cve.get("metrics", {})
        cvss, sev = 0.0, "UNKNOWN"
        for ver in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            if ver in metrics:
                m = metrics[ver][0]
                cvss = m.get("cvssData", {}).get("baseScore", 0.0)
                sev  = m.get("cvssData", {}).get("baseSeverity",
                       m.get("baseSeverity", "UNKNOWN"))
                break
        e = {"cve_id":cve_id,"cvss":cvss,"severity":sev,
             "desc":desc,"tech":name,"version":version}
        tech_cves.append(e)
        if cvss >= 7.0: high_sev.append(e)
    if tech_cves:
        all_cves[tech_key] = sorted(tech_cves, key=lambda x: x["cvss"], reverse=True)

out_json.write_text(json.dumps(all_cves, indent=2))
lines = ["# High-Severity CVEs (CVSS >= 7.0)", ""]
for e in sorted(high_sev, key=lambda x: x["cvss"], reverse=True):
    lines.append(f"[{e['severity']:<8} {e['cvss']:<5}] {e['cve_id']} — {e['tech']} {e['version']}")
    lines.append(f"  {e['desc']}")
    lines.append("")
out_high.write_text('\n'.join(lines))
print(f"Found {len(high_sev)} high-severity CVEs")
NVDEOF

  local high_cve_count
  high_cve_count=$(grep -c "^\[" "${cve_dir}/nvd/high_severity.txt" 2>/dev/null || echo 0)
  [[ $high_cve_count -gt 0 ]] && \
    finding "CVE: ${high_cve_count} HIGH/CRITICAL CVEs in tech stack — ${cve_dir}/nvd/high_severity.txt"

  # 18c. OSV dependency check
  info "Checking OSV.dev for npm vulnerabilities..."
  if [[ -d "${OUTPUT_DIR}/js/bundles" ]]; then
    grep -rhoP '"name":\s*"[^"@][^"]+"' \
      "${OUTPUT_DIR}/js/bundles/" 2>/dev/null | \
      grep -oP '(?<="name":\s*")[^"]+' | \
      sort -u | head -15 | while IFS= read -r pkg; do
        local osv
        osv=$(curl -sk --max-time 8 \
          -X POST "https://api.osv.dev/v1/query" \
          -H "Content-Type: application/json" \
          -d "{\"package\":{\"name\":\"${pkg}\",\"ecosystem\":\"npm\"}}" \
          2>/dev/null || echo "")
        if echo "$osv" | jq -e '.vulns | length > 0' 2>/dev/null | grep -q true; then
          local vc; vc=$(echo "$osv" | jq '.vulns | length' 2>/dev/null || echo 0)
          echo "$osv" | jq -r '.vulns[] | "\(.id) — \(.summary // .details[:60])"' \
            2>/dev/null >> "${cve_dir}/osv/npm_vulns.txt" || true
          finding "CVE OSV: ${pkg} has ${vc} known vulnerabilities"
        fi
        sleep 0.5
      done
  fi

  # 18d. Nuclei template recommendations
  info "Generating nuclei template recommendations..."
  {
    echo "# Nuclei Template Recommendations: ${DOMAIN}"
    jq -r 'keys[]' "${cve_dir}/tech/stack.json" 2>/dev/null | while IFS= read -r t; do
      case "$t" in
        *wordpress*) echo "nuclei -l live_hosts.txt -t technologies/wordpress/ -t cves/ -tags wordpress" ;;
        *apache*)    echo "nuclei -l live_hosts.txt -t technologies/apache/ -tags apache" ;;
        *nginx*)     echo "nuclei -l live_hosts.txt -t technologies/nginx/ -tags nginx" ;;
        *spring*)    echo "nuclei -l live_hosts.txt -t technologies/spring/ -tags springboot" ;;
        *laravel*)   echo "nuclei -l live_hosts.txt -t technologies/laravel/ -tags laravel" ;;
        *drupal*)    echo "nuclei -l live_hosts.txt -t cves/ -tags drupal" ;;
        *jenkins*)   echo "nuclei -l live_hosts.txt -t technologies/jenkins/ -tags jenkins" ;;
        *grafana*)   echo "nuclei -l live_hosts.txt -t technologies/grafana/ -tags grafana" ;;
        *jquery*)    echo "nuclei -l live_hosts.txt -t technologies/jquery/ -tags jquery" ;;
      esac
    done
    echo ""
    echo "# Always run:"
    echo "nuclei -l live_hosts.txt -t exposures/ -t misconfiguration/ -t default-logins/"
    echo "nuclei -l live_hosts.txt -t http/misconfiguration/cors/ -severity high,critical"
    echo ""
    echo "# live_hosts.txt = ${OUTPUT_DIR}/js/live_hosts.txt"
  } > "${cve_dir}/nuclei/recommendations.txt"
  finding "CVE: Nuclei guide: ${cve_dir}/nuclei/recommendations.txt"

  # 18e. Dependency confusion surface
  info "Checking dependency confusion attack surface..."
  if [[ -d "${OUTPUT_DIR}/js/bundles" ]]; then
    grep -rhoP '@[a-z][a-z0-9_-]+/[a-z][a-z0-9_-]+' \
      "${OUTPUT_DIR}/js/bundles/" 2>/dev/null | \
      sort -u | \
      grep -v "@angular\|@babel\|@types\|@jest\|@testing\|@emotion\|@mui" | \
      head -20 > "${cve_dir}/deps/scoped_packages.txt" || true
    local dep_count
    dep_count=$(count_lines "${cve_dir}/deps/scoped_packages.txt")
    [[ $dep_count -gt 0 ]] && \
      finding "CVE DEPS: ${dep_count} scoped packages — check npm for dependency confusion"
  fi

  success "Module 18 complete — ${cve_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 19: OSINT INTELLIGENCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
module_osint() {
  section "MODULE 19: OSINT Intelligence Engine"
  local osint_dir="${OUTPUT_DIR}/osint"
  mkdir -p "${osint_dir}"/{github,email,linkedin,breach,paste,acquisitions}

  local base_name
  base_name=$(echo "$DOMAIN" | rev | cut -d. -f2 | rev)

  # 19a. GitHub org and employee mapping
  info "Mapping GitHub organization..."
  local github_orgs=("$base_name" "${base_name}hq" "${base_name}inc"
                     "${base_name}corp" "${base_name}-inc" "${base_name}-hq")
  local found_org=""
  for org_try in "${github_orgs[@]}"; do
    local org_data
    org_data=$(rate_limited_curl "https://api.github.com/orgs/${org_try}") || true
    if echo "$org_data" | jq -e '.login' 2>/dev/null | grep -q '"'; then
      found_org="$org_try"
      echo "$org_data" > "${osint_dir}/github/org_profile.json"
      local public_repos
      public_repos=$(echo "$org_data" | jq '.public_repos // 0' 2>/dev/null || echo 0)
      finding "OSINT GITHUB: Org: github.com/${found_org} — ${public_repos} public repos"
      break
    fi
    sleep 0.5
  done

  if [[ -n "$found_org" ]]; then
    rate_limited_curl \
      "https://api.github.com/orgs/${found_org}/repos?per_page=100&sort=updated" \
      | jq -r '.[] | "\(.name) — \(.description // "") — \(.updated_at[:10])"' \
      2>/dev/null > "${osint_dir}/github/repos.txt" || true
    local repo_count
    repo_count=$(count_lines "${osint_dir}/github/repos.txt")
    info "GitHub: ${repo_count} public repos"

    rate_limited_curl \
      "https://api.github.com/orgs/${found_org}/members?per_page=100" \
      | jq -r '.[].login' 2>/dev/null \
      > "${osint_dir}/github/members.txt" || true
    local member_count
    member_count=$(count_lines "${osint_dir}/github/members.txt")
    [[ $member_count -gt 0 ]] && \
      finding "OSINT GITHUB: ${member_count} public members — check personal repos"

    grep -iE "terraform|infra|k8s|kubernetes|helm|ansible|deploy|secret|vault" \
      "${osint_dir}/github/repos.txt" 2>/dev/null \
      > "${osint_dir}/github/interesting_repos.txt" || true
    local iac_count
    iac_count=$(count_lines "${osint_dir}/github/interesting_repos.txt")
    [[ $iac_count -gt 0 ]] && \
      finding "OSINT GITHUB: ${iac_count} infra/IaC repos — check for secrets and topology"
  fi

  # 19b. Email pattern via Hunter.io
  info "Querying email patterns..."
  local hunter_data
  hunter_data=$(rate_limited_curl \
    "https://api.hunter.io/v2/domain-search?domain=${DOMAIN}&limit=10") || true
  if echo "$hunter_data" | jq -e '.data.emails | length > 0' 2>/dev/null | grep -q true; then
    local pattern
    pattern=$(echo "$hunter_data" | jq -r '.data.pattern // empty' 2>/dev/null || echo "")
    [[ -n "$pattern" ]] && \
      finding "OSINT EMAIL: Pattern: ${pattern}@${DOMAIN} — enables username prediction"
    echo "$hunter_data" | jq -r \
      '.data.emails[] | "\(.value) — \(.first_name) \(.last_name)"' \
      2>/dev/null > "${osint_dir}/email/discovered.txt" || true
    local email_count
    email_count=$(count_lines "${osint_dir}/email/discovered.txt")
    [[ $email_count -gt 0 ]] && \
      finding "OSINT EMAIL: ${email_count} addresses via Hunter.io"
  fi

  # 19c. LinkedIn dorks
  info "Generating LinkedIn dorks..."
  cat > "${osint_dir}/linkedin/linkedin_dorks.txt" << LKEOF
# LinkedIn Intelligence: ${DOMAIN} / ${base_name}
site:linkedin.com/in "${base_name}"
site:linkedin.com "${base_name}" "software engineer"
site:linkedin.com "${base_name}" "devops OR SRE OR platform engineer"
site:linkedin.com "${base_name}" "infrastructure"
site:linkedin.com/jobs "${base_name}" "kubernetes"
site:linkedin.com/jobs "${base_name}" "AWS"
site:linkedin.com/jobs "${base_name}" "terraform"
site:linkedin.com/in "formerly ${base_name}"
site:linkedin.com/in "ex-${base_name}"
https://www.linkedin.com/company/${base_name}/people/
https://www.linkedin.com/company/${base_name}/jobs/
LKEOF
  finding "OSINT LINKEDIN: Dorks: ${osint_dir}/linkedin/linkedin_dorks.txt"

  # 19d. HIBP breach check
  info "Checking HaveIBeenPwned domain exposure..."
  local hibp_data
  hibp_data=$(rate_limited_curl \
    "https://haveibeenpwned.com/api/v3/breacheddomain/${DOMAIN}" \
    -H "User-Agent: deep_recon/1.0 (authorized security research)" \
    2>/dev/null || true)
  if echo "$hibp_data" | jq -e 'type == "array"' 2>/dev/null | grep -q true; then
    local breach_count
    breach_count=$(echo "$hibp_data" | jq 'length' 2>/dev/null || echo 0)
    finding "OSINT BREACH: ${DOMAIN} in ${breach_count} HIBP breaches"
    echo "$hibp_data" | jq -r '.[]' 2>/dev/null \
      > "${osint_dir}/breach/hibp_breaches.txt" || true
  fi

  # 19e. Paste + grep.app hints
  cat > "${osint_dir}/paste/search_hints.txt" << PASTEEOF
# Paste Site Search: ${DOMAIN} / ${base_name}
site:pastebin.com "${DOMAIN}"
site:pastebin.com "${base_name}" "password"
site:pastebin.com "${base_name}" "api_key"
site:gist.github.com "${DOMAIN}"
site:gist.github.com "${base_name}" "secret"
https://grep.app/search?q=${DOMAIN}
https://grep.app/search?q=${base_name}+password
https://grep.app/search?q=${base_name}+api_key
https://intelx.io/?s=${DOMAIN}
https://publicwww.com/websites/%22${base_name}%22/
PASTEEOF
  finding "OSINT PASTE: Search hints: ${osint_dir}/paste/search_hints.txt"

  # 19f. Acquisition correlation
  local acq_file="${OUTPUT_DIR}/correlation/acquisition_candidates.txt"
  if [[ -s "$acq_file" ]]; then
    local acq_count; acq_count=$(count_lines "$acq_file")
    while IFS= read -r ext_domain; do
      [[ -z "$ext_domain" ]] && continue
      local lcode
      lcode=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
        "https://${ext_domain}" 2>/dev/null || echo "000")
      [[ "$lcode" != "000" && "$lcode" != "404" ]] && \
        echo "LIVE ${lcode}: ${ext_domain}" >> \
          "${osint_dir}/acquisitions/live_external.txt"
      sleep 0.2
    done < "$acq_file"
    local live_acq
    live_acq=$(count_lines "${osint_dir}/acquisitions/live_external.txt" 2>/dev/null || echo 0)
    [[ $live_acq -gt 0 ]] && \
      finding "OSINT ACQ: ${live_acq} live external domains — separate attack surfaces"
  fi

  # 19g. Engineering blog check
  for eng_blog in "engineering.${DOMAIN}" "tech.${DOMAIN}" "${base_name}.engineering"; do
    local blog_code
    blog_code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
      "https://${eng_blog}" 2>/dev/null || echo "000")
    [[ "$blog_code" != "000" && "$blog_code" != "404" ]] && \
      finding "OSINT: Engineering blog: https://${eng_blog} (${blog_code}) — architecture intel"
  done

  # 19h. Stack Overflow and conference dork sheet
  cat > "${osint_dir}/github/developer_intel.txt" << DEVEOF
# Developer Intelligence: ${DOMAIN}
site:stackoverflow.com "${DOMAIN}"
site:stackoverflow.com "${base_name}" "api"
https://stackoverflow.com/search?q=${base_name}
https://www.youtube.com/results?search_query=${base_name}+engineering
https://www.youtube.com/results?search_query=${base_name}+infrastructure
site:speakerdeck.com "${base_name}"
site:medium.com "${base_name}" engineering
site:dev.to "${base_name}"
https://www.crunchbase.com/organization/${base_name}/acquisitions
https://www.sec.gov/cgi-bin/browse-edgar?company=${base_name}&action=getcompany
DEVEOF
  finding "OSINT: Developer intel sheet: ${osint_dir}/github/developer_intel.txt"

  success "Module 19 complete — ${osint_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 20: CONTENT DISCOVERY ENGINE
# Target-specific wordlist generation from all collected data,
# comprehensive ffuf per live host, backup file discovery,
# API path brute-forcing from discovered patterns
# ─────────────────────────────────────────────────────────────────────────────
module_content() {
  section "MODULE 20: Content Discovery Engine"
  local cd_dir="${OUTPUT_DIR}/content"
  mkdir -p "${cd_dir}"/{wordlists,results,backups,apis}

  local live_hosts="${OUTPUT_DIR}/js/live_hosts.txt"
  [[ ! -s "$live_hosts" ]] && echo "https://${DOMAIN}" > "$live_hosts"

  # ── 20a. Build target-specific wordlist from all collected data ───────────
  info "Building target-specific wordlist from collected intelligence..."

  python3 - "${OUTPUT_DIR}" "${cd_dir}/wordlists/target_specific.txt" << 'WORDEOF'
import sys, re
from pathlib import Path

output_dir = Path(sys.argv[1])
out_file   = Path(sys.argv[2])

words = set()

def read(p):
    try: return Path(p).read_text(errors='ignore')
    except: return ""

def extract_path_words(text):
    """Extract meaningful path segments from URLs"""
    for url in re.findall(r'https?://[^\s"\'<>]+', text):
        path = re.sub(r'https?://[^/]+', '', url)
        path = re.sub(r'\?.*', '', path)
        for seg in path.split('/'):
            seg = re.sub(r'\.(php|html|js|css|json|xml|txt|asp|aspx|jsp)$', '', seg)
            seg = re.sub(r'[0-9]{4,}', '', seg)  # strip long numbers (IDs)
            if seg and 3 <= len(seg) <= 40 and not seg.startswith('.'):
                words.add(seg.lower())

# From Wayback URLs
extract_path_words(read(output_dir / "wayback/wayback_raw.txt"))

# From JS extracted endpoints
for line in read(output_dir / "js/extracted_endpoints.txt").splitlines():
    for seg in line.split('/'):
        if seg and 3 <= len(seg) <= 40:
            words.add(seg.lower().rstrip('?&='))

# From robots.txt disallow paths
for line in read(output_dir / "supplemental/dns/robots_paths.txt").splitlines():
    m = re.search(r'(?:Disallow|Allow):\s*(/[^\s]+)', line)
    if m:
        for seg in m.group(1).split('/'):
            if seg and 3 <= len(seg) <= 40:
                words.add(seg.lower())

# From CT subdomain naming (extract service/env prefixes)
for line in read(output_dir / "ct/ct_all_domains.txt").splitlines():
    parts = line.split('.')
    if parts:
        prefix = parts[0].lower()
        if 3 <= len(prefix) <= 25 and prefix not in ('www','api','mail','smtp'):
            words.add(prefix)

# From Wayback admin paths
for line in read(output_dir / "wayback/admin_paths.txt").splitlines():
    extract_path_words(line)

# From OIDC endpoints discovered
for line in read(output_dir / "supplemental/dns/oidc_endpoints.txt").splitlines():
    extract_path_words(line)

# From auth endpoints found
for line in read(output_dir / "auth/login/form_fields.txt").splitlines():
    m = re.search(r'name="([^"]+)"', line)
    if m:
        words.add(m.group(1).lower())

# Standard high-value additions
standard = [
    "admin","administrator","api","v1","v2","v3","internal","private","beta",
    "debug","test","dev","staging","backup","config","setup","install","logs",
    "console","dashboard","panel","manage","portal","staff","support","help",
    "auth","login","signin","logout","register","signup","password","reset",
    "user","users","account","accounts","profile","settings","preferences",
    "health","status","metrics","actuator","env","info","trace","version",
    "swagger","openapi","graphql","api-docs","redoc","docs","documentation",
    "upload","uploads","files","media","assets","static","images","download",
    "export","import","report","reports","data","bulk","batch","queue",
    "webhook","callback","notify","notification","event","events","feed",
    "search","query","filter","list","index","sitemap","robots",
    "phpinfo","phpmyadmin","adminer","wp-admin","wp-login","xmlrpc",
    ".env","web.config","config.json","config.yml","appsettings.json",
    ".git","Dockerfile","docker-compose","Makefile","requirements",
]
words.update(standard)

# Environment permutations of discovered paths
env_prefixes = ["dev","staging","stage","test","qa","uat","sandbox","beta","alpha"]
base_words   = list(words)[:100]  # permute top 100
for word in base_words:
    for prefix in env_prefixes:
        words.add(f"{prefix}-{word}")
        words.add(f"{word}-{prefix}")

# Write sorted
sorted_words = sorted(w for w in words if w and not w.startswith('//'))
Path(out_file).write_text('\n'.join(sorted_words))
print(f"Generated {len(sorted_words)} target-specific wordlist entries")
WORDEOF

  local wl_count
  wl_count=$(count_lines "${cd_dir}/wordlists/target_specific.txt")
  info "Target-specific wordlist: ${wl_count} entries"

  # Merge with a base wordlist if available
  local base_wl="${HOME}/.wordlists/raft-medium-directories.txt"
  if [[ -f "$base_wl" ]]; then
    cat "${cd_dir}/wordlists/target_specific.txt" "$base_wl" | \
      sort -u > "${cd_dir}/wordlists/merged.txt"
    local merged_count
    merged_count=$(count_lines "${cd_dir}/wordlists/merged.txt")
    info "Merged wordlist: ${merged_count} entries (target-specific + raft-medium)"
  else
    cp "${cd_dir}/wordlists/target_specific.txt" "${cd_dir}/wordlists/merged.txt"
    info "Base wordlist not found — using target-specific only"
    info "Download: curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o ~/.wordlists/raft-medium-directories.txt"
  fi

  # ── 20b. Content discovery per live host ─────────────────────────────────
  if ! require_tool ffuf; then
    warn "ffuf not found — skipping active content discovery"
    warn "Install: go install github.com/ffuf/ffuf/v2@latest"
  else
    info "Running content discovery on live hosts..."
    while IFS= read -r host; do
      [[ -z "$host" ]] && continue
      local host_slug
      host_slug=$(echo "$host" | sed 's|https\?://||;s|/|_|g')
      info "  Scanning: ${host}"

      # Get baseline 404 size for filtering
      local baseline_size
      baseline_size=$(curl -skL --max-time 8 \
        "${host}/definitely-does-not-exist-xyz-12345" \
        -o /dev/null -w "%{size_download}" 2>/dev/null || echo "0")

      # Main content discovery
      ffuf -w "${cd_dir}/wordlists/merged.txt" \
        -u "${host}/FUZZ" \
        -mc "200,201,204,301,302,401,403,405,500" \
        -fs "$baseline_size" \
        -t "$THREADS" \
        -timeout 8 \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
        -o "${cd_dir}/results/${host_slug}_dirs.json" \
        -of json \
        -s \
        2>/dev/null || true

      # Parse results
      if [[ -s "${cd_dir}/results/${host_slug}_dirs.json" ]]; then
        local found_count
        found_count=$(jq '.results | length' \
          "${cd_dir}/results/${host_slug}_dirs.json" 2>/dev/null || echo 0)
        if [[ $found_count -gt 0 ]]; then
          jq -r '.results[] | "\(.status) \(.length)b \(.url)"' \
            "${cd_dir}/results/${host_slug}_dirs.json" 2>/dev/null \
            > "${cd_dir}/results/${host_slug}_dirs.txt"
          finding "CONTENT: ${found_count} paths on ${host}"

          # Flag high-value discovered paths
          jq -r '.results[].url' \
            "${cd_dir}/results/${host_slug}_dirs.json" 2>/dev/null | \
            grep -iE "admin|debug|console|actuator|swagger|graphql|env|config|backup|\.git" | \
            while IFS= read -r sensitive_url; do
              finding "CONTENT SENSITIVE: ${sensitive_url}"
            done
        fi
      fi
      sleep 1
    done < "$live_hosts"
  fi

  # ── 20c. Backup file discovery ────────────────────────────────────────────
  info "Probing for backup and sensitive file extensions..."
  local backup_extensions=(".bak" ".backup" ".old" ".orig" ".copy" ".tmp"
    ".sql" ".sql.gz" ".dump" ".db" ".sqlite"
    ".tar.gz" ".tgz" ".zip" ".7z" ".rar" ".tar"
    ".env" ".env.backup" ".env.local" ".env.prod" ".env.production"
    ".config" ".conf" ".cfg" ".ini" ".yaml" ".yml"
    ".log" ".logs" ".txt" "~" ".swp" ".swo"
    ".php.bak" ".asp.bak" ".aspx.bak" ".jsp.bak"
    "/.git/config" "/.git/HEAD" "/.gitignore"
    "/web.config.bak" "/wp-config.php.bak" "/config.php.bak")

  # Files commonly targeted
  local target_filenames=("index" "config" "database" "db" "settings"
    "admin" "backup" "app" "web" "site" "application")

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local backup_results="${cd_dir}/backups/$(echo "$host" | sed 's|https\?://||;s|/|_|g').txt"

    for fname in "${target_filenames[@]}"; do
      for ext in "${backup_extensions[@]}"; do
        local url="${host}/${fname}${ext}"
        local code size
        code=$(curl -sk --max-time 6 \
          -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        if [[ "$code" == "200" ]]; then
          size=$(curl -sk --max-time 6 \
            -o /dev/null -w "%{size_download}" "$url" 2>/dev/null || echo "0")
          if [[ $size -gt 50 ]]; then
            echo "FOUND ${code} ${size}b: ${url}" | tee -a "$backup_results"
            finding "CONTENT BACKUP: ${url} (${size} bytes) — potential source/config leak"
          fi
        fi
        sleep 0.05
      done
    done

    # Specific high-value single checks
    for special in \
      "/.git/config" "/.git/HEAD" "/.git/COMMIT_EDITMSG" \
      "/.env" "/.env.example" "/web.config" \
      "/phpinfo.php" "/info.php" "/test.php" \
      "/server-status" "/server-info" \
      "/actuator/env" "/actuator/heapdump" "/actuator/mappings" \
      "/console" "/.htaccess" "/.htpasswd" \
      "/crossdomain.xml" "/clientaccesspolicy.xml"; do
      local code size
      code=$(curl -sk --max-time 6 \
        -o /dev/null -w "%{http_code}" "${host}${special}" 2>/dev/null || echo "000")
      if [[ "$code" == "200" ]]; then
        size=$(curl -sk --max-time 6 \
          -o /dev/null -w "%{size_download}" \
          "${host}${special}" 2>/dev/null || echo "0")
        [[ $size -gt 10 ]] && \
          finding "CONTENT CRITICAL: ${host}${special} (${code}, ${size}b)"
      fi
      sleep 0.05
    done
  done < "$live_hosts"

  # ── 20d. API path brute-force from discovered patterns ────────────────────
  info "Brute-forcing API paths from collected patterns..."

  # Build API-specific wordlist from discovered endpoint fragments
  {
    # From JS endpoints
    grep -hoP '/[a-zA-Z][a-zA-Z0-9_/-]{2,30}' \
      "${OUTPUT_DIR}/js/extracted_endpoints.txt" 2>/dev/null
    # From Wayback API version patterns
    cat "${OUTPUT_DIR}/wayback/api_versions.txt" 2>/dev/null | \
      grep -oP '/api/v[0-9]+' | sort -u
    # Standard API paths
    printf '/api\n/api/v1\n/api/v2\n/api/v3\n/api/internal\n/api/private\n'
    printf '/api/admin\n/api/beta\n/v1\n/v2\n/v3\n/internal\n/private\n'
    printf '/rest\n/rest/v1\n/rest/v2\n/service\n/services\n'
    printf '/graphql\n/query\n/gql\n/graph\n'
  } | sort -u > "${cd_dir}/wordlists/api_paths.txt"

  if require_tool ffuf; then
    while IFS= read -r host; do
      [[ -z "$host" ]] && continue
      local host_slug
      host_slug=$(echo "$host" | sed 's|https\?://||;s|/|_|g')

      ffuf -w "${cd_dir}/wordlists/api_paths.txt" \
        -u "${host}FUZZ" \
        -mc "200,201,204,401,403,405" \
        -t "$THREADS" \
        -timeout 8 \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        -o "${cd_dir}/apis/${host_slug}_api.json" \
        -of json -s \
        2>/dev/null || true

      if [[ -s "${cd_dir}/apis/${host_slug}_api.json" ]]; then
        local api_count
        api_count=$(jq '.results | length' \
          "${cd_dir}/apis/${host_slug}_api.json" 2>/dev/null || echo 0)
        [[ $api_count -gt 0 ]] && \
          finding "CONTENT API: ${api_count} API paths on ${host}"
      fi
      sleep 0.5
    done < "$live_hosts"
  fi

  success "Module 20 complete — ${cd_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 21: DOCUMENT & METADATA INTELLIGENCE
# PDF/Office/EXIF metadata extraction from publicly accessible documents,
# author/tool/path leakage, internal hostname discovery from metadata
# ─────────────────────────────────────────────────────────────────────────────
module_metadata() {
  section "MODULE 21: Document & Metadata Intelligence"
  local meta_dir="${OUTPUT_DIR}/metadata"
  mkdir -p "${meta_dir}"/{pdf,office,images,raw}

  # ── 21a. Find public documents from Wayback + current crawl ──────────────
  info "Discovering publicly accessible documents..."

  # From Wayback historical URLs
  local doc_urls_file="${meta_dir}/document_urls.txt"
  {
    grep -iE '\.(pdf|docx?|xlsx?|pptx?|csv|rtf)(\?|$)' \
      "${OUTPUT_DIR}/wayback/wayback_raw.txt" 2>/dev/null | head -50
  } > "$doc_urls_file" || true

  # Also crawl current live hosts for document links
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    curl -skL --max-time 15 "$host" 2>/dev/null | \
      grep -ioP '(?:href|src)="[^"]*\.(pdf|docx?|xlsx?|pptx?)(?:\?[^"]*)?(?:")' | \
      grep -oP '"[^"]*\.(?:pdf|docx?|xlsx?|pptx?)(?:\?[^"]*)?"' | \
      tr -d '"' | while IFS= read -r rel_url; do
        if echo "$rel_url" | grep -q "^http"; then
          echo "$rel_url"
        else
          echo "${host}${rel_url}"
        fi
      done >> "$doc_urls_file"
    sleep 0.3
  done < "${OUTPUT_DIR}/js/live_hosts.txt"

  dedupe_file "$doc_urls_file"
  local doc_count
  doc_count=$(count_lines "$doc_urls_file")
  info "Found ${doc_count} document URLs to analyze"

  # ── 21b. Download and extract metadata via Python ─────────────────────────
  info "Downloading and extracting document metadata..."

  python3 - "$doc_urls_file" "${meta_dir}" << 'METAEOF'
import sys, re, struct, urllib.request, urllib.error
from pathlib import Path

doc_urls_file = Path(sys.argv[1])
meta_dir      = Path(sys.argv[2])
findings      = []

if not doc_urls_file.exists():
    print("No document URLs file")
    sys.exit(0)

urls = [u.strip() for u in doc_urls_file.read_text().splitlines() if u.strip()][:30]

def fetch(url, timeout=12):
    try:
        req = urllib.request.Request(url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return b""

def extract_pdf_metadata(data, url):
    """Extract metadata from PDF binary without external tools"""
    meta = {"url": url, "type": "PDF", "fields": {}}
    if not data.startswith(b'%PDF'):
        return None

    text = data[:65536].decode('latin-1', errors='ignore')
    patterns = {
        "Author":   r'/Author\s*\(([^)]{1,100})\)',
        "Creator":  r'/Creator\s*\(([^)]{1,100})\)',
        "Producer": r'/Producer\s*\(([^)]{1,100})\)',
        "Title":    r'/Title\s*\(([^)]{1,100})\)',
        "Subject":  r'/Subject\s*\(([^)]{1,100})\)',
        "Keywords": r'/Keywords\s*\(([^)]{1,100})\)',
        "CreationDate": r'/CreationDate\s*\(([^)]{1,30})\)',
    }
    for field, pat in patterns.items():
        m = re.search(pat, text)
        if m:
            val = m.group(1).replace('\r','').replace('\n','').strip()
            if val:
                meta["fields"][field] = val

    # Look for internal paths and hostnames
    internal = re.findall(
        r'(?:C:\\|/home/|/var/|/usr/|\\\\[A-Z]{2,}\\)[^\s\)\"\'<>]{4,60}',
        text)
    if internal:
        meta["fields"]["InternalPaths"] = internal[:5]

    return meta if meta["fields"] else None

def extract_office_metadata(data, url):
    """Extract metadata from Office Open XML (docx/xlsx/pptx)"""
    meta = {"url": url, "type": "Office", "fields": {}}
    # OOXML is a ZIP — look for core.xml magic bytes
    if not data[:4] == b'PK\x03\x04':
        return None

    # Scan for XML metadata in ZIP content (without unzipping)
    text = data.decode('latin-1', errors='ignore')
    patterns = {
        "dc:creator":        r'<dc:creator>([^<]{1,80})</dc:creator>',
        "dc:title":          r'<dc:title>([^<]{1,80})</dc:title>',
        "dc:subject":        r'<dc:subject>([^<]{1,80})</dc:subject>',
        "cp:lastModifiedBy": r'<cp:lastModifiedBy>([^<]{1,80})</cp:lastModifiedBy>',
        "cp:revision":       r'<cp:revision>([^<]{1,10})</cp:revision>',
        "dc:description":    r'<dc:description>([^<]{1,120})</dc:description>',
    }
    for field, pat in patterns.items():
        m = re.search(pat, text)
        if m:
            val = m.group(1).strip()
            if val:
                meta["fields"][field.split(':')[1]] = val

    # Look for embedded paths
    paths = re.findall(r'[A-Za-z]:\\[^<>"]{4,60}', text)
    if paths:
        meta["fields"]["WindowsPaths"] = list(set(paths))[:5]

    return meta if meta["fields"] else None

all_meta = []
for url in urls:
    ext = url.lower().split('?')[0].split('.')[-1]
    data = fetch(url)
    if not data:
        continue

    meta = None
    if ext == 'pdf':
        meta = extract_pdf_metadata(data, url)
        if meta:
            (meta_dir / "pdf" / re.sub(r'[^a-z0-9]', '_', url[-40:])
             ).with_suffix('.txt').write_text(str(meta["fields"]))
    elif ext in ('docx','xlsx','pptx','doc','xls','ppt'):
        meta = extract_office_metadata(data, url)
        if meta:
            (meta_dir / "office" / re.sub(r'[^a-z0-9]', '_', url[-40:])
             ).with_suffix('.txt').write_text(str(meta["fields"]))

    if meta and meta["fields"]:
        all_meta.append(meta)

# Write consolidated report
report_lines = [f"Document Metadata Report — {len(all_meta)} documents analyzed\n"]
intel_found = []
for m in all_meta:
    report_lines.append(f"URL:  {m['url']}")
    for k, v in m["fields"].items():
        report_lines.append(f"  {k}: {v}")
        # Flag high-value intel
        if k in ("Author","Creator","cp:lastModifiedBy"):
            intel_found.append(f"AUTHOR: {v} — from {m['url']}")
        if k in ("InternalPaths","WindowsPaths"):
            intel_found.append(f"PATH LEAK: {v} — from {m['url']}")
    report_lines.append("")

(meta_dir / "metadata_report.txt").write_text('\n'.join(report_lines))

if intel_found:
    (meta_dir / "high_value_intel.txt").write_text('\n'.join(intel_found))
    for item in intel_found:
        print(f"FINDING: {item}")
else:
    print("No high-value metadata found")

print(f"Processed {len(all_meta)}/{len(urls)} documents")
METAEOF

  if [[ -s "${meta_dir}/high_value_intel.txt" ]]; then
    local intel_count
    intel_count=$(count_lines "${meta_dir}/high_value_intel.txt")
    finding "META: ${intel_count} high-value metadata items — ${meta_dir}/high_value_intel.txt"
    head -5 "${meta_dir}/high_value_intel.txt" | while IFS= read -r line; do
      finding "META: $line"
    done
  fi

  # ── 21c. Public image EXIF extraction ────────────────────────────────────
  info "Extracting EXIF from public images..."

  # Collect image URLs from main page and sitemaps
  local img_urls=()
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    while IFS= read -r img_url; do
      img_urls+=("$img_url")
    done < <(curl -skL --max-time 10 "$host" 2>/dev/null | \
      grep -ioP '(?:src|href)="([^"]*\.(?:jpg|jpeg|png|tiff|tif)(?:\?[^"]*)?)"' | \
      grep -oP '"[^"]+"' | tr -d '"' | \
      grep -v "^data:" | head -10)
    sleep 0.3
  done < "${OUTPUT_DIR}/js/live_hosts.txt"

  python3 - "${meta_dir}/images" "${img_urls[@]}" << 'EXIFEOF' 2>/dev/null
import sys, struct, urllib.request
from pathlib import Path

out_dir = Path(sys.argv[1])
out_dir.mkdir(parents=True, exist_ok=True)
urls = sys.argv[2:]

def fetch(url):
    try:
        req = urllib.request.Request(url,
            headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.read(65536)
    except: return b""

def extract_jpeg_exif(data):
    """Minimal EXIF parser for GPS and camera info"""
    meta = {}
    if data[:2] != b'\xff\xd8': return meta
    i = 2
    while i < len(data) - 4:
        if data[i] != 0xFF: break
        marker = data[i+1]
        length = struct.unpack('>H', data[i+2:i+4])[0]
        if marker == 0xE1:  # APP1 = EXIF
            exif = data[i+4:i+2+length]
            if exif[:6] in (b'Exif\x00\x00', b'Exif\x00\xff'):
                tiff = exif[6:]
                # Extract make/model strings (ASCII tags)
                for tag, name in [(0x010F,"Make"),(0x0110,"Model"),
                                   (0x0131,"Software"),(0x013B,"Artist"),
                                   (0x8298,"Copyright"),(0x0132,"DateTime")]:
                    for offset in range(0, min(len(tiff)-12, 4096), 2):
                        try:
                            t = struct.unpack_from('<H', tiff, offset)[0]
                            if t == tag:
                                val_len = struct.unpack_from('<I', tiff, offset+4)[0]
                                val_off = struct.unpack_from('<I', tiff, offset+8)[0]
                                val = tiff[val_off:val_off+val_len].decode('ascii',
                                      errors='ignore').strip('\x00')
                                if val: meta[name] = val
                        except: pass
        i += 2 + length
    return meta

findings = []
for url in urls[:15]:
    if not url.startswith('http'): continue
    data = fetch(url)
    if not data: continue
    meta = extract_jpeg_exif(data)
    if meta:
        findings.append(f"URL: {url}\n" +
                        '\n'.join(f"  {k}: {v}" for k,v in meta.items()))
        if "Artist" in meta or "Copyright" in meta:
            print(f"PERSON FOUND: {meta.get('Artist','')} {meta.get('Copyright','')} — {url}")

if findings:
    (out_dir / "exif_results.txt").write_text('\n\n'.join(findings))
    print(f"EXIF data from {len(findings)} images")
EXIFEOF

  [[ -s "${meta_dir}/images/exif_results.txt" ]] && \
    finding "META EXIF: GPS/camera/author data in public images — ${meta_dir}/images/exif_results.txt"

  success "Module 21 complete — ${meta_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 22: DEEP PROTOCOL RECON
# HTTP request smuggling surface, SOAP/WSDL discovery,
# LDAP/SNMP enumeration, MQTT/AMQP detection,
# webhook/SSRF parameter surface mapping
# ─────────────────────────────────────────────────────────────────────────────
module_deepproto() {
  section "MODULE 22: Deep Protocol Recon"
  local dp_dir="${OUTPUT_DIR}/deepproto"
  mkdir -p "${dp_dir}"/{smuggling,soap,ldap,snmp,mqtt,ssrf}

  local live_hosts="${OUTPUT_DIR}/js/live_hosts.txt"
  [[ ! -s "$live_hosts" ]] && echo "https://${DOMAIN}" > "$live_hosts"

  # ── 22a. HTTP request smuggling surface detection ─────────────────────────
  info "Probing HTTP request smuggling surface..."

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local smug_file="${dp_dir}/smuggling/$(echo "$host" | sed 's|https\?://||;s|/|_|g').txt"
    {
      echo "=== Smuggling Surface: ${host} ==="

      # CL.TE probe: Send ambiguous Content-Length + Transfer-Encoding
      # Using a harmless payload that won't cause damage
      local cl_te_code
      cl_te_code=$(curl -sk --max-time 10 \
        -X POST "$host" \
        -H "Content-Length: 6" \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-binary $'3\r\nabc\r\n0\r\n\r\n' \
        -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
      echo "CL.TE probe: HTTP ${cl_te_code}"

      # TE.CL probe
      local te_cl_code
      te_cl_code=$(curl -sk --max-time 10 \
        -X POST "$host" \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Length: 4" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-binary $'5\r\nhello\r\n0\r\n\r\n' \
        -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
      echo "TE.CL probe: HTTP ${te_cl_code}"

      # TE.TE obfuscation probe
      local te_te_code
      te_te_code=$(curl -sk --max-time 10 \
        -X POST "$host" \
        -H "Transfer-Encoding: chunked" \
        -H "Transfer-Encoding: x-obfuscated" \
        --data-binary $'0\r\n\r\n' \
        -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
      echo "TE.TE obfuscation probe: HTTP ${te_te_code}"

      # HTTP/2 downgrade check
      local h2_code
      h2_code=$(curl -sk --max-time 8 --http2 \
        -o /dev/null -w "%{http_code}" "$host" 2>/dev/null || echo "000")
      local h11_code
      h11_code=$(curl -sk --max-time 8 --http1.1 \
        -o /dev/null -w "%{http_code}" "$host" 2>/dev/null || echo "000")
      echo "HTTP/2: ${h2_code} | HTTP/1.1: ${h11_code}"

      # H2C upgrade attempt (cleartext HTTP/2)
      local h2c_code
      h2c_code=$(curl -sk --max-time 8 \
        -H "Upgrade: h2c" \
        -H "HTTP2-Settings: AAMAAABkAAQAAP__" \
        -H "Connection: Upgrade, HTTP2-Settings" \
        -o /dev/null -w "%{http_code}" "$host" 2>/dev/null || echo "000")
      echo "H2C upgrade: HTTP ${h2c_code}"
      [[ "$h2c_code" == "101" ]] && \
        finding "PROTO SMUG: H2C upgrade accepted on ${host} — potential h2c smuggling"

      # TRACE method (XST)
      local trace_resp
      trace_resp=$(curl -sk --max-time 8 \
        -X TRACE \
        -H "X-Custom-Header: smug-test" \
        "$host" 2>/dev/null | head -3)
      if echo "$trace_resp" | grep -qi "X-Custom-Header"; then
        finding "PROTO SMUG: TRACE method reflects headers on ${host} — XST (Cross-Site Tracing)"
      fi

    } > "$smug_file"
    sleep 0.5
  done < "$live_hosts"

  # ── 22b. SOAP/WSDL discovery ──────────────────────────────────────────────
  info "Probing for SOAP/WSDL endpoints..."
  local soap_paths=(
    "/soap" "/ws" "/wsdl" "/webservice" "/webservices"
    "/service" "/services" "/api/soap"
    "/axis" "/axis2" "/services/Service"
    "/?wsdl" "/?WSDL" "/service?wsdl"
    "/api/v1?wsdl" "/api?wsdl"
    "/soap/wsdl" "/ws/wsdl"
    "/xmlrpc" "/xmlrpc.php" "/RPC2"
  )

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    for soap_path in "${soap_paths[@]}"; do
      local code body
      body=$(curl -skL --max-time 8 \
        -H "Accept: text/xml,application/xml" \
        -o "${dp_dir}/soap/.tmp_soap" \
        -w "%{http_code}" "${host}${soap_path}" 2>/dev/null || echo "000")
      code=$(cat "${dp_dir}/soap/.tmp_soap" 2>/dev/null || echo "")
      local http_code="$body"

      if [[ "$http_code" == "200" ]]; then
        local resp_body
        resp_body=$(cat "${dp_dir}/soap/.tmp_soap" 2>/dev/null || echo "")
        if echo "$resp_body" | grep -qiE "wsdl|soap|envelope|porttype|binding|service"; then
          finding "PROTO SOAP: WSDL/SOAP endpoint: ${host}${soap_path}"
          cp "${dp_dir}/soap/.tmp_soap" \
            "${dp_dir}/soap/$(echo "${host}${soap_path}" | \
            sed 's|https\?://||;s|[/?]|_|g').xml"

          # Extract operations from WSDL
          grep -oP '(?<=operation name=")[^"]+' \
            "${dp_dir}/soap/.tmp_soap" 2>/dev/null | head -20 \
            >> "${dp_dir}/soap/operations.txt" || true
        fi
      fi
      rm -f "${dp_dir}/soap/.tmp_soap"
      sleep 0.1
    done
  done < "$live_hosts"

  local soap_op_count
  soap_op_count=$(count_lines "${dp_dir}/soap/operations.txt" 2>/dev/null || echo 0)
  [[ $soap_op_count -gt 0 ]] && \
    finding "PROTO SOAP: ${soap_op_count} SOAP operations discovered — see ${dp_dir}/soap/operations.txt"

  # ── 22c. LDAP enumeration (if port 389/636 open) ──────────────────────────
  info "Checking for LDAP exposure..."
  local ldap_ips=()

  # Gather IPs from port scan results
  for scan_file in $(ls "${OUTPUT_DIR}/ports/"*.txt 2>/dev/null); do
    [[ -f "$scan_file" ]] || continue
    grep -E ":389|:636|:3268|:3269" "$scan_file" 2>/dev/null | \
      grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
      while IFS= read -r ip; do ldap_ips+=("$ip"); done
  done

  if [[ ${#ldap_ips[@]} -gt 0 ]]; then
    for ldap_ip in "${ldap_ips[@]}"; do
      info "LDAP probe: ${ldap_ip}"
      {
        echo "=== LDAP Probe: ${ldap_ip} ==="
        # Anonymous bind test via bash TCP
        local ldap_resp
        ldap_resp=$(timeout 8 bash -c \
          "exec 3<>/dev/tcp/${ldap_ip}/389
           # Minimal LDAP anonymous bind request
           printf '\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' >&3
           sleep 1; cat <&3" 2>/dev/null | xxd | head -5 || echo "no response")

        echo "Anonymous bind response: ${ldap_resp}"
        if echo "$ldap_resp" | grep -q "0a 01 00"; then
          finding "PROTO LDAP: Anonymous bind SUCCESS on ${ldap_ip}:389 — CRITICAL"
        fi

        # ldapsearch if available
        if require_tool ldapsearch; then
          ldapsearch -x -h "$ldap_ip" -b "" \
            -s base namingContexts 2>/dev/null | head -20 \
            >> "${dp_dir}/ldap/namingcontexts_${ldap_ip}.txt" || true
          local nc_count
          nc_count=$(count_lines \
            "${dp_dir}/ldap/namingcontexts_${ldap_ip}.txt" 2>/dev/null || echo 0)
          [[ $nc_count -gt 0 ]] && \
            finding "PROTO LDAP: Naming contexts exposed on ${ldap_ip}"
        fi
      } >> "${dp_dir}/ldap/probe_${ldap_ip}.txt"
    done
  else
    info "No LDAP ports found in port scan results — skipping"
  fi

  # ── 22d. SNMP community string probing ────────────────────────────────────
  info "Probing SNMP on discovered IPs..."
  local scan_ips=()
  [[ -f "${OUTPUT_DIR}/asn/domain_ips.txt" ]] && \
    mapfile -t scan_ips < "${OUTPUT_DIR}/asn/domain_ips.txt"
  [[ -f "${OUTPUT_DIR}/asn/ipv4_cidrs.txt" ]] && \
    scan_ips+=($(head -1 "${OUTPUT_DIR}/asn/ipv4_cidrs.txt" | \
      cut -d'/' -f1 2>/dev/null || echo ""))

  local community_strings=("public" "private" "community" "manager"
                            "admin" "monitor" "snmp" "cisco" "default")

  for snmp_ip in "${scan_ips[@]}"; do
    [[ -z "$snmp_ip" ]] && continue
    for community in "${community_strings[@]}"; do
      # SNMP v1/v2c get-request via bash (OID 1.3.6.1.2.1.1.1.0 = sysDescr)
      local snmp_resp
      snmp_resp=$(timeout 3 bash -c \
        "exec 3<>/dev/udp/${snmp_ip}/161
         # Minimal SNMPv1 GetRequest for sysDescr
         printf '\x30\x26\x02\x01\x00\x04$(printf '\\x%02x' ${#community})${community}\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00' >&3
         sleep 1; cat <&3" 2>/dev/null | \
        strings | head -3 || echo "")
      if [[ -n "$snmp_resp" ]] && ! echo "$snmp_resp" | grep -q "^$"; then
        finding "PROTO SNMP: Community '${community}' works on ${snmp_ip} — info disclosure"
        echo "${snmp_ip} community:${community} — ${snmp_resp:0:80}" \
          >> "${dp_dir}/snmp/found.txt"
        break
      fi
    done
  done

  # ── 22e. MQTT/AMQP broker detection ──────────────────────────────────────
  info "Checking for MQTT/AMQP broker exposure..."
  for scan_ip in "${scan_ips[@]}"; do
    [[ -z "$scan_ip" ]] && continue

    # MQTT (1883 plaintext, 8883 TLS)
    for mqtt_port in 1883 8883; do
      if timeout 3 bash -c \
          "echo > /dev/tcp/${scan_ip}/${mqtt_port}" 2>/dev/null; then
        # Send MQTT CONNECT packet
        local mqtt_resp
        mqtt_resp=$(timeout 5 bash -c \
          "exec 3<>/dev/tcp/${scan_ip}/${mqtt_port}
           # MQTT CONNECT: fixed header + variable header + client ID
           printf '\x10\x12\x00\x04MQTT\x04\x00\x00\x3c\x00\x06recon' >&3
           sleep 1; cat <&3" 2>/dev/null | xxd | head -2 || echo "")
        # CONNACK with return code 0 = open broker
        if echo "$mqtt_resp" | grep -q "20 02 00 00"; then
          finding "PROTO MQTT: Open MQTT broker on ${scan_ip}:${mqtt_port} — unauthenticated"
          echo "${scan_ip}:${mqtt_port}" >> "${dp_dir}/mqtt/open_brokers.txt"
        fi
      fi
    done

    # AMQP (5672 plaintext, 5671 TLS)
    if timeout 3 bash -c \
        "echo > /dev/tcp/${scan_ip}/5672" 2>/dev/null; then
      local amqp_banner
      amqp_banner=$(timeout 5 bash -c \
        "exec 3<>/dev/tcp/${scan_ip}/5672; cat <&3" \
        2>/dev/null | head -1 | strings || echo "")
      if echo "$amqp_banner" | grep -qi "AMQP\|RabbitMQ"; then
        finding "PROTO AMQP: AMQP/RabbitMQ broker on ${scan_ip}:5672 — check auth"
        echo "${scan_ip}:5672 — ${amqp_banner:0:60}" \
          >> "${dp_dir}/mqtt/amqp_brokers.txt"
      fi
    fi
  done

  # ── 22f. Webhook / SSRF parameter surface mapping ─────────────────────────
  info "Mapping webhook and SSRF parameter attack surface..."

  python3 - "${OUTPUT_DIR}" "${dp_dir}/ssrf/ssrf_surface.txt" << 'SSRFEOF'
import sys, re
from pathlib import Path

output_dir = Path(sys.argv[1])
out_file   = Path(sys.argv[2])

# SSRF-prone parameter names
SSRF_PARAMS = {
    "url", "uri", "link", "src", "source", "href", "redirect",
    "return", "next", "callback", "file", "path", "load", "fetch",
    "target", "dest", "destination", "site", "html", "domain",
    "host", "page", "reference", "feed", "webhook", "endpoint",
    "proxy", "request", "image", "logo", "avatar", "picture",
    "thumbnail", "embed", "import", "to", "from", "resource",
}

def read(p):
    try: return Path(p).read_text(errors='ignore')
    except: return ""

findings = []

# From Wayback unique params
wayback_params = set(read(output_dir/"wayback/unique_params.txt").splitlines())
ssrf_from_wayback = wayback_params & SSRF_PARAMS
if ssrf_from_wayback:
    findings.append(f"WAYBACK SSRF PARAMS: {', '.join(sorted(ssrf_from_wayback))}")

# From JS endpoints — look for URL-accepting patterns
js_text = ""
js_dir = output_dir / "js/bundles"
if js_dir.exists():
    for f in list(js_dir.iterdir())[:20]:
        try: js_text += f.read_text(errors='ignore')[:20000]
        except: pass

# Find fetch/axios/XMLHttpRequest calls with variable URLs
url_patterns = re.findall(
    r'(?:fetch|axios\.get|axios\.post|\.open)\s*\(\s*([^)]{5,80})',
    js_text)
variable_fetches = [p for p in url_patterns
                    if re.search(r'[a-zA-Z_$]\w*\s*[\+\[]', p)]
if variable_fetches[:5]:
    findings.append(f"VARIABLE URL FETCHES IN JS ({len(variable_fetches)} found):")
    for vf in variable_fetches[:5]:
        findings.append(f"  {vf[:80]}")

# From API endpoints — flag ones with file/url params
api_eps = read(output_dir/"js/extracted_endpoints.txt").splitlines()
ssrf_endpoints = []
for ep in api_eps:
    for param in SSRF_PARAMS:
        if param in ep.lower():
            ssrf_endpoints.append(ep)
            break
if ssrf_endpoints:
    findings.append(f"\nSSRF-PRONE API ENDPOINTS ({len(ssrf_endpoints)}):")
    for ep in ssrf_endpoints[:10]:
        findings.append(f"  {ep}")

# Webhook paths from auth endpoints
auth_eps = read(output_dir/"supplemental/wellknown").replace('\x00','')
if "webhook" in auth_eps.lower() or "callback" in auth_eps.lower():
    findings.append("\nWEBHOOK PATHS FOUND in well-known/auth endpoints — probe for SSRF")

# Metadata SSRF test reminder
findings.append("""
## SSRF Test Payloads (use with discovered params):
http://169.254.169.254/latest/meta-data/          # AWS
http://metadata.google.internal/computeMetadata/v1/ # GCP (needs Metadata: true)
http://169.254.169.254/metadata/instance           # Azure (needs Metadata: true)
http://100.100.100.200/latest/meta-data/           # Alibaba Cloud
http://0.0.0.0/
http://localhost/
http://127.0.0.1/
http://[::1]/
http://0177.0.0.1/          # Octal bypass
http://2130706433/          # Decimal bypass for 127.0.0.1
""")

Path(out_file).write_text('\n'.join(findings))
print(f"SSRF surface: {len([f for f in findings if f.startswith('WAYBACK') or f.startswith('VARIABLE')])} source types mapped")
SSRFEOF

  if [[ -s "${dp_dir}/ssrf/ssrf_surface.txt" ]]; then
    local ssrf_params
    ssrf_params=$(grep "WAYBACK SSRF PARAMS:" \
      "${dp_dir}/ssrf/ssrf_surface.txt" 2>/dev/null | head -1)
    [[ -n "$ssrf_params" ]] && \
      finding "PROTO SSRF: ${ssrf_params}"
    finding "PROTO SSRF: Surface map at ${dp_dir}/ssrf/ssrf_surface.txt"
  fi

  success "Module 22 complete — ${dp_dir}/"
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 23: AUTHENTICATED RECON METHODOLOGY GENERATOR
# Generates a personalized, target-specific testing playbook based on
# all recon findings — auth flows, IDOR candidates, business logic,
# race condition surface, multi-tenant testing, role matrix
# ─────────────────────────────────────────────────────────────────────────────
module_playbook() {
  section "MODULE 23: Authenticated Recon Playbook Generator"
  local pb_dir="${OUTPUT_DIR}/playbook"
  mkdir -p "${pb_dir}"

  python3 - "${OUTPUT_DIR}" "${DOMAIN}" "${pb_dir}/playbook.md" << 'PBEOF'
import sys, json
from pathlib import Path
from datetime import datetime

output_dir = Path(sys.argv[1])
domain     = sys.argv[2]
out_file   = Path(sys.argv[3])

def read(p):
    try: return Path(p).read_text(errors='ignore')
    except: return ""

def count(p):
    try: return len([l for l in Path(p).read_text(errors='ignore').split('\n') if l.strip()])
    except: return 0

def load_json(p):
    try: return json.loads(Path(p).read_text())
    except: return {}

# Gather intelligence from all modules
findings_text  = read(output_dir/"findings_summary.txt")
auth_endpoints = read(output_dir/"auth/login/form_fields.txt")
oauth_eps      = read(output_dir/"auth/oauth/endpoints.txt")
jwt_analysis   = read(output_dir/"auth/jwt/analysis.txt")
sso_fp         = read(output_dir/"auth/session/sso_fingerprint.txt")
api_versions   = read(output_dir/"protocol/api")
ws_endpoints   = read(output_dir/"protocol/websocket/ws_endpoints.txt")
gql_schemas    = list((output_dir/"protocol/graphql").glob("schema_*.txt")) \
                  if (output_dir/"protocol/graphql").exists() else []
js_endpoints   = read(output_dir/"js/extracted_endpoints.txt")
wayback_params = read(output_dir/"wayback/unique_params.txt")
ssrf_surface   = read(output_dir/"deepproto/ssrf/ssrf_surface.txt")
tech_stack     = load_json(output_dir/"cve/tech/stack.json")
cve_report     = read(output_dir/"cve/nvd/high_severity.txt")
content_found  = list((output_dir/"content/results").glob("*.txt")) \
                  if (output_dir/"content/results").exists() else []
s3_buckets     = read(output_dir/"cloud/s3_exists.txt")
subdomain_list = read(output_dir/"correlation/master_subdomains.txt")
takeovers      = read(output_dir/"correlation/takeover_candidates.txt")
priority_rpt   = read(output_dir/"intelligence/priority/priority_report.txt")

# Build playbook
lines = [
f"# Authenticated Recon Playbook: {domain}",
f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
f"Based on: {count(output_dir/'findings_summary.txt')} passive findings",
"",
"---",
"",
"## Pre-Auth Checklist",
"",
"Before logging in, capture these baselines:",
"",
"- [ ] Intercept login page in Burp — note all form fields, hidden inputs, CSRF tokens",
"- [ ] Note session cookie names, flags (Secure/HttpOnly/SameSite), domain scope",
"- [ ] Record exact HTTP request/response for login — baseline for comparison",
"- [ ] Map all visible vs hidden roles (check page source for role hints)",
"",
]

# SSO/Auth specifics
if sso_fp and "SSO Providers:" in sso_fp:
    providers = [l for l in sso_fp.splitlines() if "SSO Providers:" in l]
    lines += ["## SSO/OAuth Testing", ""]
    for p in providers:
        lines.append(f"Detected: {p.strip()}")
    lines += [
"",
"- [ ] Test redirect_uri manipulation (open redirect → token theft)",
"  `?redirect_uri=https://evil.com` / `?redirect_uri=https://target.com.evil.com`",
"- [ ] Test state parameter absence/reuse (CSRF on OAuth flow)",
"- [ ] Test implicit flow token leakage in Referer headers",
"- [ ] Test code reuse (replay authorization code after exchange)",
"- [ ] Test account linking: link attacker account, pre-hijack victim",
"- [ ] Test `prompt=none` silent auth bypass",
"",
]

if jwt_analysis and "FLAGS:" in jwt_analysis:
    lines += ["## JWT Testing (flags detected in recon)", ""]
    for line in jwt_analysis.splitlines():
        if "FLAGS:" in line:
            lines.append(f"- {line.strip()}")
    lines += [
"",
"- [ ] Test `alg: none` bypass: strip signature, set alg to none",
"- [ ] Test algorithm confusion (RS256→HS256 with public key as secret)",
"- [ ] Test `kid` header injection (SQL injection, path traversal in kid)",
"- [ ] Test JWT expiry extension (modify exp claim, re-sign if key known)",
"- [ ] Test claim tampering: elevate role/scope claims",
"",
]

# IDOR surface
id_params = [p.strip() for p in wayback_params.splitlines()
             if p.strip().lower() in
             ("id","user_id","account_id","org_id","team_id","customer_id",
              "order_id","invoice_id","ticket_id","project_id","document_id",
              "report_id","file_id","message_id","thread_id","group_id")]
if id_params or js_endpoints:
    lines += ["## IDOR / Broken Object Level Authorization", ""]
    if id_params:
        lines.append(f"ID parameters found in historical URLs: `{'`, `'.join(id_params)}`")
        lines.append("")
    lines += [
"- [ ] Create two test accounts (A and B) in the same scope",
"- [ ] As A: create a resource, note its ID",
"- [ ] As B: attempt to access/modify/delete A's resource",
"- [ ] Test numeric ID prediction (sequential, UUID v1 timestamp)",
"- [ ] Test ID in path vs query string vs request body (different enforcement)",
"- [ ] Test IDOR on export/download endpoints (often missed)",
"- [ ] Test IDOR on bulk operations with mixed IDs",
"- [ ] Test indirect object references (hash/slug → underlying ID)",
"",
]

# GraphQL specifics
if gql_schemas:
    lines += ["## GraphQL Testing", ""]
    lines.append(f"Schemas discovered: {len(gql_schemas)} (see protocol/graphql/)")
    lines += [
"",
"- [ ] Map all queries and mutations from introspection schema",
"- [ ] Test IDOR on every ID argument in queries/mutations",
"- [ ] Test authentication on individual fields (field-level auth bypass)",
"- [ ] Test query depth/complexity limits (DoS via deep nesting)",
"- [ ] Test batch query abuse (N+1, rate limit bypass via batching)",
"- [ ] Test mutation IDOR (update/delete another user's objects)",
"- [ ] Test subscription endpoints for auth (WebSocket-based)",
"- [ ] Look for admin/internal mutations not exposed in UI",
"",
]

# WebSocket testing
if ws_endpoints.strip():
    ws_list = [l for l in ws_endpoints.splitlines() if l.strip()]
    lines += ["## WebSocket Testing", ""]
    lines.append(f"Endpoints: {', '.join(ws_list[:5])}")
    lines += [
"",
"- [ ] Intercept WS handshake — note auth mechanism (token in URL? header?)",
"- [ ] Test Cross-Site WebSocket Hijacking (CSWSH) — Origin header not validated?",
"- [ ] Map all message types (subscribe to all events, send all message types)",
"- [ ] Test IDOR in WS messages (change user/channel/room IDs)",
"- [ ] Test injection in WS message fields (SQLi, XSS, command injection)",
"- [ ] Test auth bypass: connect without token, reuse expired token",
"- [ ] Test race conditions via simultaneous WS message sends",
"",
]

# SSRF surface
if ssrf_surface and "SSRF PARAMS" in ssrf_surface:
    lines += ["## SSRF Testing", ""]
    ssrf_param_line = [l for l in ssrf_surface.splitlines() if "SSRF PARAMS:" in l]
    if ssrf_param_line:
        lines.append(f"Params: {ssrf_param_line[0]}")
    lines += [
"",
"- [ ] Test each SSRF-prone param with: http://169.254.169.254/ (AWS metadata)",
"- [ ] Test with internal hostnames from CT logs and rDNS results",
"- [ ] Test DNS rebinding: use Burp Collaborator/interactsh to confirm OOB",
"- [ ] Test protocol smuggling via URL schemes: file://, dict://, gopher://",
"- [ ] Test SSRF via redirect chains (server follows 302 to internal IP)",
"- [ ] Test SSRF in import/export, webhook, avatar/logo URL fields",
"- [ ] Test blind SSRF: no response but OOB DNS/HTTP via interactsh",
"",
]

# Business logic
lines += ["## Business Logic Testing", ""]
lines += [
"- [ ] Test price/quantity manipulation on payment flows",
"- [ ] Test negative quantities, zero prices, overflow values",
"- [ ] Test workflow step skipping (go directly to step 3 without step 2)",
"- [ ] Test state machine bypass (cancel a completed order, downgrade an upgraded plan)",
"- [ ] Test coupon/discount stacking and reuse",
"- [ ] Test role escalation via account type change during active session",
"- [ ] Test data isolation between tenants/organizations",
"- [ ] Test sharing/invitation link authorization (can non-member access shared link?)",
"- [ ] Test rate limits on business-critical actions (password reset, OTP, payments)",
"",
]

# Race conditions
lines += ["## Race Condition Testing", ""]
rc_candidates = []
if "payment" in findings_text.lower() or "checkout" in findings_text.lower():
    rc_candidates.append("Payment/checkout endpoints")
if "coupon" in findings_text.lower() or "discount" in findings_text.lower():
    rc_candidates.append("Coupon/discount redemption")
if "vote" in findings_text.lower() or "like" in findings_text.lower():
    rc_candidates.append("Vote/like/reaction endpoints")
if "transfer" in findings_text.lower() or "balance" in findings_text.lower():
    rc_candidates.append("Balance/transfer operations")
rc_candidates.append("Account creation / email verification")
rc_candidates.append("Password reset token generation")

lines.append("Race condition candidates (from recon):")
for rc in rc_candidates:
    lines.append(f"- [ ] {rc}")
lines += [
"",
"Technique: Burp Turbo Intruder or `curl` parallel requests:",
"```bash",
"# Send 20 parallel requests",
f"seq 20 | xargs -P20 -I{{}} curl -sk -X POST https://{domain}/api/redeem -d 'coupon=CODE'",
"```",
"",
]

# Multi-tenant testing
lines += ["## Multi-Tenant / Tenant Isolation Testing", ""]
lines += [
"- [ ] Register two accounts in different organizations/tenants",
"- [ ] Test cross-tenant object access (IDs from tenant A in tenant B session)",
"- [ ] Test subdomain isolation (tenantA.domain.com accessing tenantB data)",
"- [ ] Test API key/token scope (does tenant A's key work for tenant B endpoints?)",
"- [ ] Test admin endpoints: does org-admin escalate to platform-admin?",
"- [ ] Test data export: does export include only own tenant data?",
"",
]

# CVE-driven testing
if cve_report and "[CRITICAL" in cve_report or "[HIGH" in cve_report:
    lines += ["## CVE-Driven Testing (from detected tech stack)", ""]
    for line in cve_report.splitlines():
        if line.startswith("["):
            lines.append(f"- [ ] Validate: {line.strip()}")
    lines += ["", "See full report: cve/nvd/high_severity.txt", ""]

# Priority queue
if priority_rpt:
    lines += ["## Priority Queue (from scoring engine)", ""]
    lines.append("Attack in this order based on passive-to-active scoring:")
    lines.append("")
    scored = [l for l in priority_rpt.splitlines() if l[:1].isdigit()][:8]
    for i, item in enumerate(scored, 1):
        lines.append(f"{i}. {item.strip()}")
    lines.append("")

# Final tooling section
lines += [
"## Tooling for Each Phase",
"",
"```bash",
"# Session capture",
"# Set Burp as proxy: export https_proxy=http://127.0.0.1:8080",
"",
"# IDOR automation",
f"# arjun -u https://{domain}/api/endpoint -m GET -w {output_dir}/params/param_wordlist.txt",
"",
"# Race conditions",
"# Burp Turbo Intruder → Last-byte sync technique",
"",
"# WebSocket",
"# wscat -c wss://TARGET/ws -H 'Authorization: Bearer TOKEN'",
"",
"# GraphQL",
f"# graphql-cop -t https://{domain}/graphql -o {output_dir}/protocol/graphql/cop_report.json",
"",
"# SSRF OOB callback",
"# interactsh-client → get a unique URL for blind SSRF confirmation",
"```",
"",
f"Full recon output: {output_dir}/",
]

out_file.write_text('\n'.join(lines))
print(f"Playbook written: {len(lines)} lines")
PBEOF

  if [[ -s "${pb_dir}/playbook.md" ]]; then
    local pb_lines
    pb_lines=$(wc -l < "${pb_dir}/playbook.md")
    finding "PLAYBOOK: Target-specific testing playbook: ${pb_dir}/playbook.md (${pb_lines} lines)"
    info "Key sections generated:"
    grep "^## " "${pb_dir}/playbook.md" | while IFS= read -r section; do
      info "  ${section}"
    done
  fi

  success "Module 23 complete — ${pb_dir}/playbook.md"
}

# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
main() {
  banner
  check_core_deps

  log "Starting deep_recon.sh for target: $DOMAIN"
  log "Modules: $MODULES"
  log "Output:  $OUTPUT_DIR"

  # Run enabled modules
  module_enabled "asn"         && module_asn
  module_enabled "rdns"        && module_rdns
  module_enabled "ct"          && module_ct
  module_enabled "wayback"     && module_wayback
  module_enabled "cloud"       && module_cloud
  module_enabled "email"       && module_email
  module_enabled "favicon"     && module_favicon
  module_enabled "ports"       && module_ports
  module_enabled "vhost"       && module_vhost
  module_enabled "params"      && module_params
  module_enabled "js"          && module_js
  module_enabled "correlation" && module_correlation
  module_enabled "supplemental"  && module_supplemental
  module_enabled "protocol"      && module_protocol
  module_enabled "intelligence"  && module_intelligence
  module_enabled "auth"          && module_auth
  module_enabled "cve"           && module_cve
  module_enabled "osint"         && module_osint
  module_enabled "content"       && module_content
  module_enabled "metadata"      && module_metadata
  module_enabled "deepproto"     && module_deepproto
  module_enabled "playbook"      && module_playbook
  module_enabled "monitor"       && module_monitor

  run_integrations
  generate_report
}

main "$@"
