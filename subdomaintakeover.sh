#use below to find who is pointed by the domain
while read h; do host "$h" | awk '/has address/ {print $4}' | while read ip; do echo "$h - $ip - $(whois $ip | grep -i 'OrgName')"; done; done < hosts.txt
