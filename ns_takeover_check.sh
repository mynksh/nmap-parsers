#use below to find who is pointed by the domain
#while read h; do host "$h" | awk '/has address/ {print $4}' | while read ip; do echo "$h - $ip - $(whois $ip | grep -i 'OrgName')"; done; done < hosts.txt


#!/usr/bin/env bash
# ns_takeover_check.sh
# Usage:
#   ./ns_takeover_check.sh sub.example.com
#   ./ns_takeover_check.sh -f subdomains.txt
#
# Requires: dig, host, awk, grep, sed, whois (optional)

set -euo pipefail

INPUT_FILE=""
if [[ "${1:-}" == "-f" && -n "${2:-}" ]]; then
  INPUT_FILE="$2"
elif [[ -n "${1:-}" ]]; then
  : # single domain via $1
else
  echo "Usage: $0 <subdomain> | -f <file_of_subdomains>"
  exit 1
fi

have() { command -v "$1" >/dev/null 2>&1; }

need_tools=(dig host awk grep sed)
for t in "${need_tools[@]}"; do
  if ! have "$t"; then
    echo "Missing required tool: $t" >&2
    exit 2
  fi
done

color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
GREEN="32"; YELLOW="33"; RED="31"; CYAN="36"

check_domain() {
  local zone="$1"
  echo
  echo "=========================="
  echo "Zone: $(color $CYAN "$zone")"

  # Get delegated NS set
  mapfile -t NS <<<"$(dig +short NS "$zone" 2>/dev/null | sed 's/\.$//' | sort -u)"
  if [[ ${#NS[@]} -eq 0 ]]; then
    echo "$(color $YELLOW "[!]") No NS delegation found (no NS records)."
    return
  fi

  echo "NS set:"
  for ns in "${NS[@]}"; do echo "  - $ns"; done

  # Resolve each NS and query SOA directly
  declare -A NS_IPS
  declare -A NS_STATUS
  declare -A NS_FLAGS

  for ns in "${NS[@]}"; do
    # Resolve NS hostname to IPs
    ns_ips="$(host "$ns" 2>/dev/null | awk '/has address|has IPv6 address/ {print $NF}')"
    if [[ -z "$ns_ips" ]]; then
      echo "  $(color $RED "[X]") NS $(color $CYAN "$ns") does not resolve to an IP (dangling?)."
      NS_IPS["$ns"]=""
      NS_STATUS["$ns"]="NO_IP"
      continue
    fi

    NS_IPS["$ns"]="$ns_ips"
    echo "  $(color $GREEN "[✓]") NS $(color $CYAN "$ns") resolves to:"
    while read -r ip; do [[ -n "$ip" ]] && echo "      - $ip"; done <<<"$ns_ips"

    # Query SOA from this NS
    # Capture status line and flags; prefer authoritative NOERROR with SOA in ANSWER
    dig_out="$(dig @"$ns" "$zone" SOA +norecurse +noall +answer +authority +comments 2>/dev/null)"
    status="$(printf "%s\n" "$dig_out" | awk '/status:/{print $6}' | sed 's/,//')"
    flags="$(printf "%s\n" "$dig_out" | awk -F'; ' '/flags:/{print $2}' | awk '{print $2}')"
    # Check if we got SOA in ANSWER
    soa_answer="$(printf "%s\n" "$dig_out" | awk '($4=="SOA"){print}' | head -n1)"

    NS_STATUS["$ns"]="${status:-UNK}"
    NS_FLAGS["$ns"]="${flags:-}"

    case "${status:-}" in
      NOERROR)
        if [[ -n "$soa_answer" && "$flags" == *"aa"* ]]; then
          echo "    $(color $GREEN "[OK]") @$ns returned authoritative SOA."
        else
          echo "    $(color $YELLOW "[WARN]") @$ns NOERROR but not authoritative SOA (flags: $flags)."
        fi
        ;;
      NXDOMAIN|SERVFAIL|REFUSED)
        echo "    $(color $RED "[BAD]") @$ns status: $status (flags: $flags)."
        ;;
      *)
        echo "    $(color $YELLOW "[WARN]") @$ns unknown/empty response (status: ${status:-none}, flags: ${flags:-none})."
        ;;
    esac
  done

  # Simple consistency heuristic
  bad=0; good=0
  for ns in "${NS[@]}"; do
    case "${NS_STATUS[$ns]:-}" in
      NO_IP|NXDOMAIN|SERVFAIL|REFUSED|UNK) ((bad++)) ;;
      NOERROR) ((good++)) ;;
    esac
  done

  if (( bad > 0 && good > 0 )); then
    echo "$(color $YELLOW "[!]") Inconsistent delegation: some NS fail while others answer. Caching may intermittently serve attacker-controlled data if a failing NS is (re)claimable."
  elif (( bad == ${#NS[@]} )); then
    echo "$(color $RED "[!]") All NS failed to serve authoritative SOA. Zone appears unserved at delegated NS. If any NS domain can be registered/claimed, takeover is likely."
  else
    echo "$(color $GREEN "[✓]") Delegation looks consistent (at least one NS authoritative; no failing NS)."
  fi

  # Optional: quick whois hint for NS base domain (requires whois)
  if have whois; then
    echo "Whois quick check on NS base domains (heuristic):"
    for ns in "${NS[@]}"; do
      base="${ns#*.}"           # drop leftmost label (ns1.example.com -> example.com)
      base="${base#*.}"         # try to get registrable-ish (com -> risky; best effort)
      [[ -z "$base" ]] && continue
      out="$(whois "$ns" 2>/dev/null | tr -d '\r' | head -n 30 || true)"
      if echo "$out" | grep -qiE 'no match|not found|available|no entries found'; then
        echo "  $(color $RED "[X]") Possible unregistered NS host: $ns  (check manually!)"
      fi
    done
  fi
}

if [[ -n "$INPUT_FILE" ]]; then
  while IFS= read -r line; do
    zone="$(echo "$line" | sed 's/#.*//' | xargs)"
    [[ -z "$zone" ]] && continue
    check_domain "$zone"
  done < "$INPUT_FILE"
else
  check_domain "$1"
fi
