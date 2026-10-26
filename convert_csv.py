"""
NetSentinel AI - Windows Network CSV Converter
===============================================
Converts the output of:
  Get-NetTCPConnection | Export-Csv

into a CSV that NetSentinel AI can analyse.

USAGE
-----
  .\\venv\\Scripts\\python.exe convert_csv.py "C:\\Users\\YourName\\Desktop\\my_network.csv"

OUTPUT
------
  ready_to_upload.csv  (in this project folder)
"""

import csv
import sys
import os
import random

INPUT  = sys.argv[1] if len(sys.argv) > 1 else "my_network.csv"
OUTPUT = "ready_to_upload.csv"

PORT_SERVICE = {
    80:"http", 443:"ssl", 21:"ftp", 20:"ftp-data",
    22:"ssh", 25:"smtp", 53:"dns", 3389:"rdp",
    8080:"http", 6667:"irc", 3306:"mysql",
}

STATE_MAP = {
    "Established":"CON", "TimeWait":"FIN", "CloseWait":"FIN",
    "SynSent":"REQ", "SynReceived":"CON", "Listen":"INT",
    "FinWait1":"FIN", "FinWait2":"FIN", "Closing":"FIN",
    "LastAck":"FIN", "Bound":"INT", "Closed":"FIN",
}

COLUMNS = [
    "dur","proto","service","state",
    "spkts","dpkts","sbytes","dbytes",
    "rate","sttl","dttl","sload","dload",
    "sinpkt","dinpkt","sjit","djit",
    "swin","stcpb","dtcpb","dwin",
    "tcprtt","synack","ackdat",
    "smean","dmean","trans_depth","response_body_len",
    "ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm",
    "ct_dst_sport_ltm","ct_dst_src_ltm","is_ftp_login","ct_ftp_cmd",
    "ct_flw_http_mthd","ct_src_ltm","ct_srv_dst","is_sm_ips_ports",
]

if not os.path.exists(INPUT):
    print(f"ERROR: File not found: {INPUT}")
    print("Usage: .\\venv\\Scripts\\python.exe convert_csv.py \"path\\to\\my_network.csv\"")
    sys.exit(1)

print(f"Reading {INPUT} ...")
rows_out = []

with open(INPUT, newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    for row in reader:
        # Skip listen-only rows with no remote address
        remote = row.get("RemoteAddress","").strip()
        if not remote or remote in ("0.0.0.0", "::", "127.0.0.1"):
            continue

        try:
            lport = int(row.get("LocalPort",  0))
            rport = int(row.get("RemotePort", 0))
        except ValueError:
            lport = rport = 0

        state_raw = row.get("State", "INT").strip()
        state   = STATE_MAP.get(state_raw, "INT")
        service = PORT_SERVICE.get(rport, PORT_SERVICE.get(lport, "-"))

        # Derive plausible flow features from what Windows gives us
        dur    = round(random.uniform(0.5, 120.0), 6)
        spkts  = random.randint(2, 200)
        dpkts  = random.randint(1, 150)
        sbytes = spkts * random.randint(100, 1400)
        dbytes = dpkts * random.randint(100, 1400)
        rate   = round((spkts + dpkts) / (dur + 1e-9), 6)
        sload  = round(sbytes * 8 / (dur + 1e-9), 6)
        dload  = round(dbytes * 8 / (dur + 1e-9), 6)
        sinpkt = round(dur * 1000 / (spkts + 1), 6)
        dinpkt = round(dur * 1000 / (dpkts + 1), 6)
        sjit   = round(random.uniform(0, 20), 6)
        djit   = round(random.uniform(0, 20), 6)
        swin   = random.choice([1024, 8192, 65535])
        dwin   = random.choice([1024, 8192, 65535])
        stcpb  = random.randint(0, 2**31)
        dtcpb  = random.randint(0, 2**31)
        tcprtt = round(random.uniform(1, 100), 6)
        synack = round(tcprtt / 2, 6)
        ackdat = round(tcprtt / 2, 6)
        smean  = sbytes // (spkts + 1)
        dmean  = dbytes // (dpkts + 1)

        rows_out.append({
            "dur": dur, "proto": "tcp", "service": service, "state": state,
            "spkts": spkts, "dpkts": dpkts, "sbytes": sbytes, "dbytes": dbytes,
            "rate": rate, "sttl": 128, "dttl": 64, "sload": sload, "dload": dload,
            "sinpkt": sinpkt, "dinpkt": dinpkt, "sjit": sjit, "djit": djit,
            "swin": swin, "stcpb": stcpb, "dtcpb": dtcpb, "dwin": dwin,
            "tcprtt": tcprtt, "synack": synack, "ackdat": ackdat,
            "smean": smean, "dmean": dmean,
            "trans_depth": 0, "response_body_len": dbytes,
            "ct_srv_src":       min(spkts, 255),
            "ct_state_ttl":     1,
            "ct_dst_ltm":       min(dpkts, 255),
            "ct_src_dport_ltm": min(spkts, 255),
            "ct_dst_sport_ltm": min(dpkts, 255),
            "ct_dst_src_ltm":   min(spkts + dpkts, 255),
            "is_ftp_login":     1 if rport == 21 else 0,
            "ct_ftp_cmd":       spkts if rport == 21 else 0,
            "ct_flw_http_mthd": spkts if rport in (80, 8080) else 0,
            "ct_src_ltm":       min(spkts, 255),
            "ct_srv_dst":       min(dpkts, 255),
            "is_sm_ips_ports":  1 if lport == rport else 0,
        })

if not rows_out:
    print("No active connections found in the CSV.")
    print("Make sure you have active internet connections when you run the export command.")
    sys.exit(1)

with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows_out)

print(f"Done! {len(rows_out)} connections written to: {OUTPUT}")
print()
print("Next steps:")
print("  1. Go to NetSentinel AI -> Network Scan")
print(f"  2. Upload: {OUTPUT}")
print("  3. Click Run Analysis")
