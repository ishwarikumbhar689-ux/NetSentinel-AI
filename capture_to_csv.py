"""
NetSentinel AI -- Laptop Network Capture to CSV Converter
==========================================================
Converts a Wireshark .pcap / .pcapng capture file into a CSV
that NetSentinel AI can analyse.

REQUIREMENTS
------------
  pip install scapy

HOW TO USE
----------
1. Capture traffic in Wireshark for 1-5 minutes, then:
   File -> Save As -> choose .pcap format -> save as  capture.pcap

2. Place capture.pcap in this project folder.

3. Run:
   .\\venv\\Scripts\\python.exe capture_to_csv.py

4. Upload the generated  laptop_capture.csv  in NetSentinel AI -> Network Scan.

NOTE: Run as Administrator (or with sudo on Linux/Mac) if scapy
      cannot read the capture file due to permissions.
"""

import os
import sys
import csv
import time
import hashlib
from collections import defaultdict

# ── Check scapy is installed ──────────────────────────────────────────────────
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except ImportError:
    print("\n[!] scapy is not installed.")
    print("    Run:  .\\venv\\Scripts\\pip.exe install scapy")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
INPUT_FILE  = "capture.pcap"     # change if your file has a different name
OUTPUT_FILE = "laptop_capture.csv"

# ── Column order must match NetSentinel AI's required schema ──────────────────
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

# Map destination port -> service name
PORT_TO_SERVICE = {
    80: "http", 443: "ssl", 21: "ftp", 20: "ftp-data",
    22: "ssh",  25: "smtp", 53: "dns", 110: "pop3",
    143: "imap", 3306: "mysql", 3389: "rdp", 8080: "http",
    6667: "irc", 6697: "irc",
}

def port_to_service(port):
    return PORT_TO_SERVICE.get(port, "-")

def proto_name(pkt):
    if pkt.haslayer(TCP):  return "tcp"
    if pkt.haslayer(UDP):  return "udp"
    if pkt.haslayer(ICMP): return "icmp"
    return "other"

def flow_key(pkt):
    """Canonical 5-tuple key (src always < dst for bidirectional grouping)."""
    if not pkt.haslayer(IP): return None
    ip = pkt[IP]
    proto = proto_name(pkt)
    sport, dport = 0, 0
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    a = (ip.src, sport)
    b = (ip.dst, dport)
    if a > b: a, b = b, a
    return (a[0], b[0], a[1], b[1], proto)

def tcp_state(flags_int):
    """Very rough TCP state from flags."""
    SYN = 0x02; ACK = 0x10; FIN = 0x01; RST = 0x04
    if flags_int & RST: return "RST"
    if flags_int & FIN: return "FIN"
    if (flags_int & SYN) and not (flags_int & ACK): return "REQ"
    if (flags_int & SYN) and (flags_int & ACK): return "CON"
    return "INT"

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if not os.path.exists(INPUT_FILE):
        print(f"\n[!] File not found: {INPUT_FILE}")
        print("    Capture traffic in Wireshark and save as 'capture.pcap'")
        print("    in this project folder, then run this script again.")
        sys.exit(1)

    print(f"\nReading {INPUT_FILE} ...")
    try:
        packets = rdpcap(INPUT_FILE)
    except Exception as e:
        print(f"[!] Could not read capture file: {e}")
        sys.exit(1)

    print(f"  Loaded {len(packets):,} packets")

    # ── Group packets into flows ───────────────────────────────────────────────
    flows = defaultdict(lambda: {
        "pkts": [], "src": None, "dst": None,
        "sport": 0, "dport": 0, "proto": "other"
    })

    for pkt in packets:
        if not pkt.haslayer(IP): continue
        key = flow_key(pkt)
        if key is None: continue
        f = flows[key]
        f["pkts"].append(pkt)
        if f["src"] is None:
            f["src"]   = pkt[IP].src
            f["dst"]   = pkt[IP].dst
            f["proto"] = proto_name(pkt)
            if pkt.haslayer(TCP):
                f["sport"] = pkt[TCP].sport
                f["dport"] = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                f["sport"] = pkt[UDP].sport
                f["dport"] = pkt[UDP].dport

    print(f"  Grouped into {len(flows):,} flows")

    # ── Build one CSV row per flow ─────────────────────────────────────────────
    print(f"  Building features ...")
    records = []

    for key, f in flows.items():
        pkts   = f["pkts"]
        proto  = f["proto"]
        dport  = f["dport"]
        sport  = f["sport"]

        times  = [float(p.time) for p in pkts]
        t_start, t_end = min(times), max(times)
        dur    = round(t_end - t_start, 6) if len(times) > 1 else 0.0

        # Split src/dst packets by direction
        src_ip = f["src"]
        spkts_list = [p for p in pkts if p.haslayer(IP) and p[IP].src == src_ip]
        dpkts_list = [p for p in pkts if p.haslayer(IP) and p[IP].src != src_ip]

        spkts  = len(spkts_list)
        dpkts  = len(dpkts_list)
        sbytes = sum(len(p) for p in spkts_list)
        dbytes = sum(len(p) for p in dpkts_list)

        total_pkts = spkts + dpkts
        rate   = round(total_pkts / (dur + 1e-9), 6)
        sload  = round(sbytes * 8 / (dur + 1e-9), 6)
        dload  = round(dbytes * 8 / (dur + 1e-9), 6)

        # TTL
        sttl = pkts[0][IP].ttl if pkts else 64
        dttl = dpkts_list[0][IP].ttl if dpkts_list else 0

        # Inter-packet time (mean, ms)
        if len(times) > 1:
            gaps  = [(times[i+1]-times[i])*1000 for i in range(len(times)-1)]
            sinpkt = round(sum(gaps)/len(gaps), 6)
            djit   = round(max(gaps) - min(gaps), 6)
        else:
            sinpkt = 0.0; djit = 0.0
        dinpkt = sinpkt; sjit = djit

        # Window sizes & TCP info
        swin = stcpb = dtcpb = dwin = 0
        tcprtt = synack = ackdat = 0.0
        state = "CON"
        if proto == "tcp" and pkts[0].haslayer(TCP):
            tcp0 = pkts[0][TCP]
            swin  = tcp0.window
            stcpb = tcp0.seq
            dwin  = dpkts_list[0][TCP].window if dpkts_list and dpkts_list[0].haslayer(TCP) else 0
            dtcpb = dpkts_list[0][TCP].seq    if dpkts_list and dpkts_list[0].haslayer(TCP) else 0
            state = tcp_state(int(tcp0.flags))
            if len(times) > 1:
                tcprtt = round((times[1] - times[0]) * 1000, 6)
                synack = round(tcprtt / 2, 6)
                ackdat = round(tcprtt / 2, 6)
        elif proto == "udp":
            state = "INT"

        smean = sbytes // spkts if spkts else 0
        dmean = dbytes // dpkts if dpkts else 0

        service = port_to_service(dport)

        # Connection tracking counters (simplified — single-file capture)
        ct_srv_src       = min(spkts, 255)
        ct_state_ttl     = 1 if sttl in [64, 128, 255] else 0
        ct_dst_ltm       = min(dpkts, 255)
        ct_src_dport_ltm = min(spkts, 255)
        ct_dst_sport_ltm = min(dpkts, 255)
        ct_dst_src_ltm   = min(total_pkts, 255)
        is_ftp_login     = 1 if dport == 21 else 0
        ct_ftp_cmd       = spkts if dport == 21 else 0
        ct_flw_http_mthd = spkts if dport in (80, 8080) else 0
        ct_src_ltm       = min(spkts, 255)
        ct_srv_dst       = min(dpkts, 255)
        is_sm_ips_ports  = 1 if sport == dport else 0

        records.append({
            "dur": dur, "proto": proto, "service": service, "state": state,
            "spkts": spkts, "dpkts": dpkts, "sbytes": sbytes, "dbytes": dbytes,
            "rate": rate, "sttl": sttl, "dttl": dttl, "sload": sload, "dload": dload,
            "sinpkt": sinpkt, "dinpkt": dinpkt, "sjit": sjit, "djit": djit,
            "swin": swin, "stcpb": stcpb, "dtcpb": dtcpb, "dwin": dwin,
            "tcprtt": tcprtt, "synack": synack, "ackdat": ackdat,
            "smean": smean, "dmean": dmean,
            "trans_depth": 0, "response_body_len": dbytes,
            "ct_srv_src": ct_srv_src, "ct_state_ttl": ct_state_ttl,
            "ct_dst_ltm": ct_dst_ltm, "ct_src_dport_ltm": ct_src_dport_ltm,
            "ct_dst_sport_ltm": ct_dst_sport_ltm, "ct_dst_src_ltm": ct_dst_src_ltm,
            "is_ftp_login": is_ftp_login, "ct_ftp_cmd": ct_ftp_cmd,
            "ct_flw_http_mthd": ct_flw_http_mthd, "ct_src_ltm": ct_src_ltm,
            "ct_srv_dst": ct_srv_dst, "is_sm_ips_ports": is_sm_ips_ports,
        })

    # ── Write CSV ──────────────────────────────────────────────────────────────
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(records)

    print(f"\n  Done! Written {len(records):,} flow records to: {OUTPUT_FILE}")
    print(f"\nNext step:")
    print(f"  1. Open NetSentinel AI -> Network Scan")
    print(f"  2. Upload:  {OUTPUT_FILE}")
    print(f"  3. Click Run Analysis")

if __name__ == "__main__":
    main()
