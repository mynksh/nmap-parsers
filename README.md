# 🕵️‍♂️ GNMAP One-Liner Extractor

A tiny Bash one-liner to pull **IP addresses** and **open ports** from Nmap `.gnmap` files.  
No scripts, no dependencies — just copy, paste, and run.

---

## 📦 Usage

### Parse all `.gnmap` files in the current directory
```
grep "Ports:" *.gnmap | awk '{ip=$2; for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") p=p?a[1]","p:a[1]} print ip, p; p=""}'
```
**Example output:**
```
192.168.1.10 22,80
192.168.1.11 443
```

---

### IP:PORT format (for piping into other tools)
```
grep "Ports:" *.gnmap | awk '{ip=$2; for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") print ip":"a[1]}}'
```
**Example output:**
```
192.168.1.10:22
192.168.1.10:80
192.168.1.11:443
```

---

## 💡 Tip
Run Nmap with grepable output to generate `.gnmap`:
```
nmap -p- -oG scan.gnmap 192.168.1.0/24
```

# Check Subdomain takeover
## One liner to check if a sub-domain is vulnerable
No scripts, no dependencies — just copy, paste, and run.


```bash
while IFS= read -r l || [[ -n "$l" ]]; do z=$(printf '%s' "$l" | tr -d '\r' | sed 's/#.*//' | xargs); [[ -z "$z" ]]&&continue; ns=$(dig +short NS "$z" | sed 's/\.$//' | sort -u); if [[ -z "$ns" ]]; then echo "$z => NOT VULNERABLE (no delegation)"; continue; fi; g=0; b=0; claim=0; while read -r n; do [[ -z "$n" ]]&&continue; base=$(awk -F. '{if(NF>=2)printf("%s.%s\n",$(NF-1),$NF);else print $0}'<<<"$n"); [[ "$n" =~ (awsdns|route53|amazonaws|cloudfront|azure-dns|trafficmanager|azureedge|googlecloud|googledomains|gcloud-dns|digitalocean|dnsimple|cloudflare|fastly|nsone|akamai) ]]&&claim=1; command -v whois >/dev/null&&whois "$base" 2>/dev/null|grep -qiE 'no match|not found|available|no entries found'&&claim=1; ips=$(host "$n" 2>/dev/null|awk '/has address|has IPv6 address/{print $NF}'); if [[ -z "$ips" ]]; then ((b++)); continue; fi; o=$(dig @"$n" "$z" SOA +norecurse +noall +answer +authority +comments 2>/dev/null||true); s=$(awk '/status:/{gsub(",","",$6);print $6}'<<<"$o"); f=$(awk -F'; ' '/flags:/{print $2}'<<<"$o"|awk '{print $2}'); so=$(awk '($4=="SOA"){print}'<<<"$o"|head -n1); [[ "$s"=="NOERROR" && -n "$so" && "$f" == *"aa"* ]]&&((g++))||((b++)); done<<<"$ns"; ((g==0&&b>0))&&{ ((claim==1))&&echo "$z => VULNERABLE"||echo "$z => BROKEN DELEGATION (non-exploitable)"; } || { ((g>0&&b>0))&&echo "$z => POTENTIALLY VULNERABLE"||{ ((g>0&&b==0))&&echo "$z => NOT VULNERABLE"||echo "$z => POTENTIALLY VULNERABLE"; }; }; done < subdomains.txt
```
