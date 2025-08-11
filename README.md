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
