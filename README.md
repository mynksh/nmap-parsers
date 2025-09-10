# 🕵️‍♂️ GNMAP One-Liner Extractor

A tiny Bash one-liner to pull **IP addresses** and **open ports** from Nmap `.gnmap` files.  
No scripts, no dependencies — just copy, paste, and run.

---

## 📦 Usage

### Parse all `.gnmap` files in the current directory
In bash
```bash
grep "Ports:" *.gnmap | awk '{ip=$2; for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") p=p?a[1]","p:a[1]} print ip, p; p=""}'
```
PowerShell one-liner
```bash
Get-ChildItem *.gnmap | % { Get-Content $_ | % { if ($_ -match "Ports:") { $f=$_ -split "\s+"; $ip=$f[1]; $ports=@(); for ($i=3; $i -lt $f.Count; $i++) { $p=$f[$i] -split "/"; if ($p.Count -ge 2 -and $p[1] -eq "open") { $ports+=$p[0] } } if ($ports.Count -gt 0) { "$ip $($ports -join ',')" } } } }
```
**Example output:**
```
192.168.1.10 22,80
192.168.1.11 443
```

---

### IP:PORT format (for piping into other tools)
In bash
```bash
grep "Ports:" *.gnmap | awk '{ip=$2; for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") print ip":"a[1]}}'
```
PowerShell one-liner
```bash
Get-ChildItem *.gnmap | ForEach-Object { Get-Content $_ | ForEach-Object { if ($_ -match "Ports:") { $f = ($_ -split "\s+"); $ip = $f[1]; for ($i=3; $i -lt $f.Count; $i++) { $p = $f[$i] -split "/"; if ($p.Count -ge 2 -and $p[1] -eq "open") { "$ip`:$($p[0])" }}}}}
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
