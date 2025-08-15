#!/usr/bin/env bash
# ns_takeover_check.sh
# Usage: ./ns_takeover_check.sh -f subdomains.txt
# Requires: dig, host, awk, sed, grep
set -u

if [[ "$1" != "-f" || -z "${2:-}" ]]; then
  echo "Usage: $0 -f <file_of_domains>"; exit 1
fi
FILE="$2"

have(){ command -v "$1" >/dev/null 2>&1; }
for t in dig host awk sed grep; do have "$t" || { echo "Missing: $t"; exit 2; }; done

# Heuristic: extract "registrable-ish" domain (last two labels). Not PSL-accurate.
registrable_domain() {
  awk -F. '{ if (NF>=2) printf("%s.%s\n", $(NF-1), $NF); else print $0 }'
}

# Heuristic: vendors commonly "claimable" by creating zones/services
is_claimable_vendor() {
  case "$1" in
    *awsdns.*|*route53.amazonaws.com*|*amazonaws.com*|*cloudfront.net|\
    *azure-dns.*|*trafficmanager.net|*azureedge.net|\
    *googlecloud.com|*googledomains.com|*gcloud-dns.*|\
    *digitalocean.com|*dnsimple.com|*cloudflare.com|*fastly.net|*nsone.net|*akamai.net)
      return 0 ;;
    *) return 1 ;;
  esac
}

# Optional: quick whois hint (very rough). Returns 0 if "seems unregistered"
whois_unregistered() {
  local d="$1"
  command -v whois >/dev/null 2>&1 || return 1
  whois "$d" 2>/dev/null | tr -d '\r' | grep -qiE 'no match|not found|available|no entries found'
}

check_domain() {
  local zone="$1"
  echo; echo "=== $zone ==="

  local ns_list
  ns_list="$(dig +short NS "$zone" 2>/dev/null | sed 's/\.$//' | sort -u)"

  if [[ -z "$ns_list" ]]; then
    echo "[i] No NS records (not delegated) -> Status: NOT VULNERABLE (NS takeover N/A)"
    return
  fi

  echo "$ns_list" | sed 's/^/NS: /'

  local good=0 bad=0
  local claimable=0

  # Pre-check claimability across NS hosts
  while read -r ns; do
    [[ -z "$ns" ]] && continue
    local base
    base="$(printf "%s\n" "$ns" | registrable_domain)"
    if is_claimable_vendor "$ns"; then
      claimable=1
      break
    fi
    if whois_unregistered "$base"; then
      claimable=1
      break
    fi
  done <<<"$ns_list"

  # Evaluate each NS
  while read -r ns; do
    [[ -z "$ns" ]] && continue

    local ns_ips
    ns_ips="$(host "$ns" 2>/dev/null | awk '/has address|has IPv6 address/{print $NF}')"
    if [[ -z "$ns_ips" ]]; then
      echo "  [X] $ns has no A/AAAA (dangling)"
      ((bad++))
      continue
    fi
    echo "$ns_ips" | sed "s/^/  IP: /"

    local dig_out status flags soa_line
    dig_out="$(dig @"$ns" "$zone" SOA +norecurse +noall +answer +authority +comments 2>/dev/null || true)"
    status="$(printf "%s\n" "$dig_out" | awk '/status:/{gsub(",","",$6);print $6}')"
    flags="$(printf "%s\n" "$dig_out" | awk -F'; ' '/flags:/{print $2}' | awk '{print $2}')"
    soa_line="$(printf "%s\n" "$dig_out" | awk '($4=="SOA"){print}' | head -n1)"

    if [[ "$status" == "NOERROR" && -n "$soa_line" && "$flags" == *"aa"* ]]; then
      echo "  [OK] @$ns authoritative SOA"
      ((good++))
    else
      echo "  [WARN] @$ns status=${status:-none} flags=${flags:-none} (no authoritative SOA)"
      ((bad++))
    fi
  done <<<"$ns_list"

  # Final classification
  if (( good == 0 && bad > 0 )); then
    if (( claimable == 1 )); then
      echo "=> Status: VULNERABLE (all NS failing; NS host appears claimable)"
    else
      echo "=> Status: BROKEN DELEGATION (likely non-exploitable; NS host not claimable)"
    fi
  elif (( good > 0 && bad > 0 )); then
    echo "=> Status: POTENTIALLY VULNERABLE (inconsistent NS; check if failing NS host is claimable)"
  elif (( good > 0 && bad == 0 )); then
    echo "=> Status: NOT VULNERABLE"
  else
    echo "=> Status: POTENTIALLY VULNERABLE"
  fi
}

# Read file (handle CRLF, skip blanks/comments)
while IFS= read -r line || [[ -n "$line" ]]; do
  zone="$(printf '%s' "$line" | tr -d '\r' | sed 's/#.*//' | xargs)"
  [[ -z "$zone" ]] && continue
  check_domain "$zone"
done < "$FILE"
