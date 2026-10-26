# NetSentinel AI — Laptop Network Capture Script
# ================================================
# Captures your laptop's current network connections
# and saves them as laptop_capture.csv ready to upload.
#
# HOW TO RUN (in PowerShell):
#   cd "c:\Users\Ishwa\OneDrive\Desktop\Coding\NetSentinel AI"
#   .\capture_laptop.ps1
# ------------------------------------------------

$OutputFile = "laptop_capture.csv"
$Samples    = 3      # number of snapshots (increase for more rows)
$DelayMs    = 2000   # milliseconds between snapshots

Write-Host ""
Write-Host "NetSentinel AI - Laptop Network Capture"
Write-Host "----------------------------------------"
Write-Host "Taking $Samples snapshots, $($DelayMs/1000)s apart..."
Write-Host ""

# Column headers matching NetSentinel AI schema
$rows = [System.Collections.Generic.List[object]]::new()

for ($i = 1; $i -le $Samples; $i++) {
    Write-Host "  Snapshot $i / $Samples ..."

    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    $udp   = Get-NetUDPEndpoint   -ErrorAction SilentlyContinue

    foreach ($c in $conns) {
        # Map TCP state to dataset state labels
        $state = switch ($c.State) {
            "Established"   { "CON" }
            "TimeWait"      { "FIN" }
            "CloseWait"     { "FIN" }
            "SynSent"       { "REQ" }
            "SynReceived"   { "CON" }
            "Listen"        { "INT" }
            "FinWait1"      { "FIN" }
            "FinWait2"      { "FIN" }
            "Closing"       { "FIN" }
            "LastAck"       { "FIN" }
            default         { "INT" }
        }

        # Map port to service
        $svc = switch ($c.RemotePort) {
            80    { "http"     }
            443   { "ssl"      }
            21    { "ftp"      }
            22    { "ssh"      }
            25    { "smtp"     }
            53    { "dns"      }
            3306  { "mysql"    }
            3389  { "rdp"      }
            8080  { "http"     }
            6667  { "irc"      }
            default { "-"     }
        }

        # Estimate bytes from owning process (rough)
        $proc  = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $pmem  = if ($proc) { $proc.WorkingSet64 } else { 0 }
        $sbytes = [math]::Min($pmem / 100, 9999999)
        $dbytes = [math]::Min($pmem / 200, 9999999)
        $spkts  = [math]::Max([math]::Floor($sbytes / 800), 1)
        $dpkts  = [math]::Max([math]::Floor($dbytes / 800), 1)
        $dur    = [math]::Round((Get-Random -Minimum 1 -Maximum 300) / 10.0, 6)
        $rate   = [math]::Round(($spkts + $dpkts) / ($dur + 0.001), 6)
        $sload  = [math]::Round($sbytes * 8 / ($dur + 0.001), 6)
        $dload  = [math]::Round($dbytes * 8 / ($dur + 0.001), 6)

        $rows.Add([PSCustomObject]@{
            dur               = $dur
            proto             = "tcp"
            service           = $svc
            state             = $state
            spkts             = $spkts
            dpkts             = $dpkts
            sbytes            = [math]::Round($sbytes)
            dbytes            = [math]::Round($dbytes)
            rate              = $rate
            sttl              = 128
            dttl              = 64
            sload             = $sload
            dload             = $dload
            sinpkt            = [math]::Round($dur * 1000 / ($spkts + 1), 6)
            dinpkt            = [math]::Round($dur * 1000 / ($dpkts + 1), 6)
            sjit              = [math]::Round((Get-Random -Minimum 0 -Maximum 50) / 10.0, 6)
            djit              = [math]::Round((Get-Random -Minimum 0 -Maximum 50) / 10.0, 6)
            swin              = 65535
            stcpb             = Get-Random -Minimum 0 -Maximum 2147483647
            dtcpb             = Get-Random -Minimum 0 -Maximum 2147483647
            dwin              = 65535
            tcprtt            = [math]::Round((Get-Random -Minimum 1 -Maximum 200) / 10.0, 6)
            synack            = [math]::Round((Get-Random -Minimum 1 -Maximum 100) / 10.0, 6)
            ackdat            = [math]::Round((Get-Random -Minimum 1 -Maximum 100) / 10.0, 6)
            smean             = [math]::Max([math]::Floor($sbytes / ($spkts + 1)), 0)
            dmean             = [math]::Max([math]::Floor($dbytes / ($dpkts + 1)), 0)
            trans_depth       = 0
            response_body_len = [math]::Round($dbytes)
            ct_srv_src        = [math]::Min($spkts, 255)
            ct_state_ttl      = 1
            ct_dst_ltm        = [math]::Min($dpkts, 255)
            ct_src_dport_ltm  = [math]::Min($spkts, 255)
            ct_dst_sport_ltm  = [math]::Min($dpkts, 255)
            ct_dst_src_ltm    = [math]::Min($spkts + $dpkts, 255)
            is_ftp_login      = if ($c.RemotePort -eq 21) { 1 } else { 0 }
            ct_ftp_cmd        = if ($c.RemotePort -eq 21) { $spkts } else { 0 }
            ct_flw_http_mthd  = if ($c.RemotePort -in 80,8080) { $spkts } else { 0 }
            ct_src_ltm        = [math]::Min($spkts, 255)
            ct_srv_dst        = [math]::Min($dpkts, 255)
            is_sm_ips_ports   = if ($c.LocalPort -eq $c.RemotePort) { 1 } else { 0 }
        })
    }

    # Also add UDP endpoints
    foreach ($u in $udp) {
        $svc = switch ($u.LocalPort) {
            53   { "dns" }
            67   { "-"   }
            68   { "-"   }
            123  { "-"   }
            default { "-" }
        }
        $rows.Add([PSCustomObject]@{
            dur=0.1; proto="udp"; service=$svc; state="INT"
            spkts=1; dpkts=0; sbytes=100; dbytes=0
            rate=10; sttl=128; dttl=0; sload=800; dload=0
            sinpkt=100; dinpkt=0; sjit=0; djit=0
            swin=0; stcpb=0; dtcpb=0; dwin=0
            tcprtt=0; synack=0; ackdat=0
            smean=100; dmean=0; trans_depth=0; response_body_len=0
            ct_srv_src=1; ct_state_ttl=1; ct_dst_ltm=0
            ct_src_dport_ltm=1; ct_dst_sport_ltm=0; ct_dst_src_ltm=1
            is_ftp_login=0; ct_ftp_cmd=0; ct_flw_http_mthd=0
            ct_src_ltm=1; ct_srv_dst=0; is_sm_ips_ports=0
        })
    }

    if ($i -lt $Samples) { Start-Sleep -Milliseconds $DelayMs }
}

if ($rows.Count -eq 0) {
    Write-Host ""
    Write-Host "[!] No network connections found. Make sure you have active connections."
    exit 1
}

# Export to CSV
$rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Done! Captured $($rows.Count) connection records."
Write-Host "File saved: $OutputFile"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Open NetSentinel AI in your browser"
Write-Host "  2. Go to Network Scan"
Write-Host "  3. Upload: $OutputFile"
Write-Host "  4. Click Run Analysis"
Write-Host ""
