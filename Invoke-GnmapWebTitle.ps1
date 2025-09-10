#(Get-ChildItem *.gnmap | ForEach-Object { Get-Content $_ | ForEach-Object { if ($_ -match "Ports:") { $f = ($_ -split "\s+"); $ip = $f[1]; for ($i=3; $i -lt $f.Count; $i++) { $p = $f[$i] -split "/"; if ($p.Count -ge 2 -and $p[1] -eq "open") { "$ip`:$($p[0])" }}}}}) | ForEach-Object { try { $url="http://$_"; $resp=Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5; if($resp.Content -match '<title>(.*?)</title>'){ "$url [$($matches[1])]" } } catch { try { $url="https://$_"; $resp=Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5; if($resp.Content -match '<title>(.*?)</title>'){ "$url [$($matches[1])]" } } catch {} } }

Get-ChildItem *.gnmap | ForEach-Object {
    Get-Content $_ | ForEach-Object {
        if ($_ -match "Ports:") {
            $fields = $_ -split "\s+"
            $ip = $fields[1]
            for ($i=3; $i -lt $fields.Count; $i++) {
                $parts = $fields[$i] -split "/"
                if ($parts.Count -ge 2 -and $parts[1] -eq "open") {
                    Write-Output "$ip`:$($parts[0])"
                }
            }
        }
    }
}
