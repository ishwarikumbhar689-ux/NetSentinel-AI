"""
NetSentinel AI — Synthetic Dataset Generator
=============================================
Generates a realistic synthetic network traffic dataset for training
the Random Forest model when you don't have UNSW-NB15 or CIC-IDS2017.

The data is statistically modelled to match real network traffic patterns:
  - Normal traffic: typical port/packet/byte/duration distributions
  - Attack traffic: port scans, DoS floods, data exfiltration, C2 beacons

OUTPUT
------
  synthetic_train.csv  —  80% of rows  (used for training)
  synthetic_test.csv   —  20% of rows  (used for evaluation)
  sample_network.csv   —  30 rows      (replaces the static sample in static/)

HOW TO RUN
----------
  .\\venv\\Scripts\\python.exe generate_dataset.py
"""

import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# ── Reproducibility ───────────────────────────────────────────────────────────
SEED = 42
rng  = np.random.default_rng(SEED)

# ── Dataset size ──────────────────────────────────────────────────────────────
N_NORMAL  = 70_000   # 70% normal traffic
N_ATTACK  = 30_000   # 30% attack traffic  (realistic imbalance)
TOTAL     = N_NORMAL + N_ATTACK

print(f"\nGenerating {TOTAL:,} rows ({N_NORMAL:,} normal + {N_ATTACK:,} attack)...")

# ── Shared categorical pools ──────────────────────────────────────────────────
PROTOS   = ["tcp", "udp", "icmp", "arp", "ospf", "pim", "igmp"]
PROTO_W  = [0.55,  0.30,  0.08,   0.03,  0.02,   0.01,  0.01]   # normal weights

SERVICES = ["http", "ftp", "smtp", "ssh", "dns", "-", "ssl", "ftp-data", "irc"]
SERVICE_W= [0.30,   0.05,  0.06,   0.04,  0.15,  0.28,  0.08,  0.03,     0.01]

STATES   = ["FIN", "CON", "REQ", "RST", "INT", "ECO", "CLO", "no"]
STATE_W  = [0.30,  0.30,  0.15,  0.10,  0.07,  0.04,  0.03,  0.01]


# ═════════════════════════════════════════════════════════════════════════════
# NORMAL TRAFFIC GENERATOR
# ═════════════════════════════════════════════════════════════════════════════

def gen_normal(n):
    """Generate realistic normal network traffic records."""

    # Duration: most sessions 0.01s – 120s, log-normal
    dur = rng.lognormal(mean=1.5, sigma=1.8, size=n).clip(0.001, 3600)

    # Packet counts: small for most sessions
    spkts = rng.integers(1, 500,  size=n)
    dpkts = rng.integers(0, 800,  size=n)

    # Bytes: correlated with packets
    sbytes = (spkts * rng.integers(40, 1500, size=n)).clip(0, 10_000_000)
    dbytes = (dpkts * rng.integers(40, 1500, size=n)).clip(0, 10_000_000)

    # Rates
    rate  = (spkts + dpkts) / (dur + 1e-9)
    sload = sbytes * 8 / (dur + 1e-9)
    dload = dbytes * 8 / (dur + 1e-9)

    # TTL values: typical OS defaults
    sttl  = rng.choice([64, 128, 255, 32], size=n, p=[0.45, 0.35, 0.15, 0.05])
    dttl  = rng.choice([64, 128, 255, 32], size=n, p=[0.40, 0.40, 0.15, 0.05])

    # Inter-packet times (ms)
    sinpkt = rng.exponential(scale=50, size=n).clip(0.1, 5000)
    dinpkt = rng.exponential(scale=60, size=n).clip(0.1, 5000)

    # Jitter (ms)
    sjit  = rng.exponential(scale=5,  size=n).clip(0, 500)
    djit  = rng.exponential(scale=6,  size=n).clip(0, 500)

    # Window sizes
    swin  = rng.choice([0, 255, 512, 1024, 8192, 65535], size=n,
                       p=[0.10, 0.05, 0.10, 0.15, 0.30, 0.30])
    dwin  = rng.choice([0, 255, 512, 1024, 8192, 65535], size=n,
                       p=[0.10, 0.05, 0.10, 0.15, 0.30, 0.30])

    # TCP base sequence numbers
    stcpb = rng.integers(0, 2**32, size=n)
    dtcpb = rng.integers(0, 2**32, size=n)

    # TCP handshake timings (ms)
    tcprtt = rng.exponential(scale=20, size=n).clip(0, 5000)
    synack = rng.exponential(scale=10, size=n).clip(0, 2000)
    ackdat = rng.exponential(scale=8,  size=n).clip(0, 2000)

    # Mean segment sizes
    smean = (sbytes / (spkts + 1)).astype(int).clip(0, 65535)
    dmean = (dbytes / (dpkts + 1)).astype(int).clip(0, 65535)

    # Application-layer features
    trans_depth        = rng.integers(0, 5,   size=n)
    response_body_len  = rng.integers(0, 50000, size=n)

    # Connection tracking counters
    ct_srv_src        = rng.integers(1, 50,  size=n)
    ct_state_ttl      = rng.integers(0, 6,   size=n)
    ct_dst_ltm        = rng.integers(1, 100, size=n)
    ct_src_dport_ltm  = rng.integers(1, 50,  size=n)
    ct_dst_sport_ltm  = rng.integers(1, 50,  size=n)
    ct_dst_src_ltm    = rng.integers(1, 100, size=n)
    ct_ftp_cmd        = rng.integers(0, 3,   size=n)
    ct_flw_http_mthd  = rng.integers(0, 5,   size=n)
    ct_src_ltm        = rng.integers(1, 100, size=n)
    ct_srv_dst        = rng.integers(1, 50,  size=n)

    # Binary flags
    is_ftp_login    = rng.choice([0, 1], size=n, p=[0.97, 0.03])
    is_sm_ips_ports = rng.choice([0, 1], size=n, p=[0.95, 0.05])

    # Categorical
    proto   = rng.choice(PROTOS,   size=n, p=PROTO_W)
    service = rng.choice(SERVICES, size=n, p=SERVICE_W)
    state   = rng.choice(STATES,   size=n, p=STATE_W)

    return dict(
        dur=dur, proto=proto, service=service, state=state,
        spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
        rate=rate, sttl=sttl, dttl=dttl, sload=sload, dload=dload,
        sinpkt=sinpkt, dinpkt=dinpkt, sjit=sjit, djit=djit,
        swin=swin, stcpb=stcpb, dtcpb=dtcpb, dwin=dwin,
        tcprtt=tcprtt, synack=synack, ackdat=ackdat,
        smean=smean, dmean=dmean,
        trans_depth=trans_depth, response_body_len=response_body_len,
        ct_srv_src=ct_srv_src, ct_state_ttl=ct_state_ttl,
        ct_dst_ltm=ct_dst_ltm, ct_src_dport_ltm=ct_src_dport_ltm,
        ct_dst_sport_ltm=ct_dst_sport_ltm, ct_dst_src_ltm=ct_dst_src_ltm,
        is_ftp_login=is_ftp_login, ct_ftp_cmd=ct_ftp_cmd,
        ct_flw_http_mthd=ct_flw_http_mthd, ct_src_ltm=ct_src_ltm,
        ct_srv_dst=ct_srv_dst, is_sm_ips_ports=is_sm_ips_ports,
        label=np.zeros(n, dtype=int)
    )


# ═════════════════════════════════════════════════════════════════════════════
# ATTACK TRAFFIC GENERATOR
# Attack types: port scan, DoS flood, data exfiltration, C2 beacon, brute-force
# ═════════════════════════════════════════════════════════════════════════════

def gen_attacks(n):
    """Generate synthetic attack traffic with distinct statistical signatures."""

    # Split attacks across 5 types
    n_scan   = n // 5        # Port scan
    n_dos    = n // 5        # DoS/DDoS flood
    n_exfil  = n // 5        # Data exfiltration
    n_c2     = n // 5        # C2 beacon
    n_brute  = n - 4*(n//5)  # Brute-force (remainder)

    parts = []

    # ── Port scan: many short SYN-only packets, high rate, tiny bytes ──
    def port_scan(k):
        dur    = rng.uniform(0.0001, 0.01, size=k)
        spkts  = rng.integers(1, 4, size=k)
        dpkts  = rng.integers(0, 2, size=k)
        sbytes = spkts * rng.integers(40, 80, size=k)
        dbytes = dpkts * rng.integers(0,  60, size=k)
        return dict(
            dur=dur, proto=np.full(k, "tcp"), service=np.full(k, "-"),
            state=rng.choice(["REQ","RST","CON"], size=k, p=[0.6,0.3,0.1]),
            spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
            rate=(spkts+dpkts)/(dur+1e-9),
            sttl=rng.choice([64,128], size=k),
            dttl=rng.choice([64,128,0], size=k, p=[0.4,0.4,0.2]),
            sload=sbytes*8/(dur+1e-9), dload=dbytes*8/(dur+1e-9),
            sinpkt=rng.uniform(0.01, 1, size=k),
            dinpkt=rng.uniform(0.01, 1, size=k),
            sjit=rng.uniform(0, 2, size=k),  djit=rng.uniform(0, 2, size=k),
            swin=rng.choice([0,1024], size=k, p=[0.7,0.3]),
            dwin=rng.choice([0,1024], size=k, p=[0.8,0.2]),
            stcpb=rng.integers(0,2**32,size=k), dtcpb=rng.integers(0,2**32,size=k),
            tcprtt=rng.uniform(0,0.5,size=k), synack=rng.uniform(0,0.3,size=k),
            ackdat=rng.uniform(0,0.3,size=k),
            smean=(sbytes/(spkts+1)).astype(int),
            dmean=(dbytes/(dpkts+1)).astype(int),
            trans_depth=np.zeros(k,dtype=int), response_body_len=np.zeros(k,dtype=int),
            ct_srv_src=rng.integers(1,5,size=k), ct_state_ttl=rng.integers(0,2,size=k),
            ct_dst_ltm=rng.integers(50,255,size=k),
            ct_src_dport_ltm=rng.integers(50,255,size=k),
            ct_dst_sport_ltm=rng.integers(50,255,size=k),
            ct_dst_src_ltm=rng.integers(50,255,size=k),
            is_ftp_login=np.zeros(k,dtype=int), ct_ftp_cmd=np.zeros(k,dtype=int),
            ct_flw_http_mthd=np.zeros(k,dtype=int),
            ct_src_ltm=rng.integers(50,255,size=k),
            ct_srv_dst=rng.integers(1,5,size=k),
            is_sm_ips_ports=rng.choice([0,1],size=k,p=[0.3,0.7]),
            label=np.ones(k,dtype=int)
        )

    # ── DoS flood: massive packets/bytes in very short time ──
    def dos_flood(k):
        dur    = rng.uniform(0.01, 2.0, size=k)
        spkts  = rng.integers(5000, 100000, size=k)
        dpkts  = rng.integers(0, 100, size=k)
        sbytes = spkts * rng.integers(60, 1500, size=k)
        dbytes = dpkts * rng.integers(0,  200,  size=k)
        return dict(
            dur=dur, proto=rng.choice(["tcp","udp","icmp"],size=k,p=[0.4,0.4,0.2]),
            service=rng.choice(["-","http"],size=k,p=[0.6,0.4]),
            state=rng.choice(["INT","CON","FIN"],size=k,p=[0.5,0.3,0.2]),
            spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
            rate=(spkts+dpkts)/(dur+1e-9),
            sttl=rng.choice([64,128,255],size=k),
            dttl=rng.choice([0,64],size=k,p=[0.6,0.4]),
            sload=sbytes*8/(dur+1e-9), dload=dbytes*8/(dur+1e-9),
            sinpkt=rng.uniform(0.0001,0.01,size=k),
            dinpkt=rng.uniform(0.0001,5,size=k),
            sjit=rng.uniform(0,0.5,size=k), djit=rng.uniform(0,10,size=k),
            swin=rng.choice([0,65535],size=k,p=[0.4,0.6]),
            dwin=rng.choice([0,255],size=k,p=[0.7,0.3]),
            stcpb=rng.integers(0,2**32,size=k), dtcpb=rng.integers(0,2**32,size=k),
            tcprtt=rng.uniform(0,0.1,size=k), synack=rng.uniform(0,0.05,size=k),
            ackdat=rng.uniform(0,0.05,size=k),
            smean=(sbytes/(spkts+1)).astype(int),
            dmean=(dbytes/(dpkts+1)).astype(int),
            trans_depth=np.zeros(k,dtype=int), response_body_len=np.zeros(k,dtype=int),
            ct_srv_src=rng.integers(100,255,size=k), ct_state_ttl=rng.integers(0,3,size=k),
            ct_dst_ltm=rng.integers(100,255,size=k),
            ct_src_dport_ltm=rng.integers(100,255,size=k),
            ct_dst_sport_ltm=rng.integers(100,255,size=k),
            ct_dst_src_ltm=rng.integers(100,255,size=k),
            is_ftp_login=np.zeros(k,dtype=int), ct_ftp_cmd=np.zeros(k,dtype=int),
            ct_flw_http_mthd=np.zeros(k,dtype=int),
            ct_src_ltm=rng.integers(100,255,size=k),
            ct_srv_dst=rng.integers(1,10,size=k),
            is_sm_ips_ports=rng.choice([0,1],size=k,p=[0.5,0.5]),
            label=np.ones(k,dtype=int)
        )

    # ── Data exfiltration: long sessions, large bytes dst→src, rare ──
    def exfiltration(k):
        dur    = rng.uniform(30, 3600, size=k)
        spkts  = rng.integers(10, 500, size=k)
        dpkts  = rng.integers(500, 50000, size=k)
        sbytes = spkts * rng.integers(200, 800, size=k)
        dbytes = dpkts * rng.integers(800, 9000, size=k)  # high outbound
        return dict(
            dur=dur, proto=rng.choice(["tcp","udp"],size=k,p=[0.7,0.3]),
            service=rng.choice(["ftp","ftp-data","ssl","-"],size=k,p=[0.3,0.3,0.2,0.2]),
            state=rng.choice(["FIN","CON"],size=k,p=[0.5,0.5]),
            spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
            rate=(spkts+dpkts)/(dur+1e-9),
            sttl=rng.choice([64,128],size=k),
            dttl=rng.choice([64,128],size=k),
            sload=sbytes*8/(dur+1e-9), dload=dbytes*8/(dur+1e-9),
            sinpkt=rng.uniform(50,5000,size=k),
            dinpkt=rng.uniform(1,100,size=k),
            sjit=rng.uniform(1,100,size=k), djit=rng.uniform(0.5,50,size=k),
            swin=rng.choice([8192,65535],size=k),
            dwin=rng.choice([8192,65535],size=k),
            stcpb=rng.integers(0,2**32,size=k), dtcpb=rng.integers(0,2**32,size=k),
            tcprtt=rng.uniform(5,500,size=k), synack=rng.uniform(2,200,size=k),
            ackdat=rng.uniform(2,200,size=k),
            smean=(sbytes/(spkts+1)).astype(int),
            dmean=(dbytes/(dpkts+1)).astype(int),
            trans_depth=rng.integers(1,10,size=k),
            response_body_len=rng.integers(100000,5000000,size=k),
            ct_srv_src=rng.integers(1,20,size=k), ct_state_ttl=rng.integers(2,6,size=k),
            ct_dst_ltm=rng.integers(1,30,size=k),
            ct_src_dport_ltm=rng.integers(1,10,size=k),
            ct_dst_sport_ltm=rng.integers(1,10,size=k),
            ct_dst_src_ltm=rng.integers(1,30,size=k),
            is_ftp_login=rng.choice([0,1],size=k,p=[0.3,0.7]),
            ct_ftp_cmd=rng.integers(1,20,size=k),
            ct_flw_http_mthd=rng.integers(0,3,size=k),
            ct_src_ltm=rng.integers(1,30,size=k),
            ct_srv_dst=rng.integers(1,10,size=k),
            is_sm_ips_ports=np.zeros(k,dtype=int),
            label=np.ones(k,dtype=int)
        )

    # ── C2 beacon: periodic very regular short sessions ──
    def c2_beacon(k):
        dur    = rng.uniform(0.1, 5.0, size=k)
        spkts  = rng.integers(2, 20, size=k)
        dpkts  = rng.integers(1, 15, size=k)
        sbytes = spkts * rng.integers(50, 400, size=k)
        dbytes = dpkts * rng.integers(50, 400, size=k)
        return dict(
            dur=dur, proto=rng.choice(["tcp","udp"],size=k,p=[0.8,0.2]),
            service=rng.choice(["-","ssl","irc"],size=k,p=[0.5,0.3,0.2]),
            state=rng.choice(["FIN","CON","REQ"],size=k,p=[0.4,0.4,0.2]),
            spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
            rate=(spkts+dpkts)/(dur+1e-9),
            sttl=rng.choice([64,128],size=k),
            dttl=rng.choice([64,128],size=k),
            sload=sbytes*8/(dur+1e-9), dload=dbytes*8/(dur+1e-9),
            sinpkt=rng.uniform(10,200,size=k),
            dinpkt=rng.uniform(10,200,size=k),
            sjit=rng.uniform(0.1,5,size=k), djit=rng.uniform(0.1,5,size=k),
            swin=rng.choice([8192,65535],size=k),
            dwin=rng.choice([8192,65535],size=k),
            stcpb=rng.integers(0,2**32,size=k), dtcpb=rng.integers(0,2**32,size=k),
            tcprtt=rng.uniform(10,200,size=k), synack=rng.uniform(5,100,size=k),
            ackdat=rng.uniform(5,100,size=k),
            smean=(sbytes/(spkts+1)).astype(int),
            dmean=(dbytes/(dpkts+1)).astype(int),
            trans_depth=rng.integers(0,3,size=k), response_body_len=rng.integers(0,5000,size=k),
            ct_srv_src=rng.integers(1,5,size=k), ct_state_ttl=rng.integers(1,4,size=k),
            ct_dst_ltm=rng.integers(1,10,size=k),
            ct_src_dport_ltm=rng.integers(1,5,size=k),
            ct_dst_sport_ltm=rng.integers(1,5,size=k),
            ct_dst_src_ltm=rng.integers(1,10,size=k),
            is_ftp_login=np.zeros(k,dtype=int), ct_ftp_cmd=np.zeros(k,dtype=int),
            ct_flw_http_mthd=np.zeros(k,dtype=int),
            ct_src_ltm=rng.integers(1,10,size=k),
            ct_srv_dst=rng.integers(1,5,size=k),
            is_sm_ips_ports=np.zeros(k,dtype=int),
            label=np.ones(k,dtype=int)
        )

    # ── Brute-force: rapid repeated connection attempts ──
    def brute_force(k):
        dur    = rng.uniform(0.001, 0.5, size=k)
        spkts  = rng.integers(2, 10, size=k)
        dpkts  = rng.integers(1, 8, size=k)
        sbytes = spkts * rng.integers(50, 300, size=k)
        dbytes = dpkts * rng.integers(50, 300, size=k)
        return dict(
            dur=dur, proto=np.full(k,"tcp"),
            service=rng.choice(["ssh","ftp","ssl"],size=k,p=[0.5,0.3,0.2]),
            state=rng.choice(["FIN","RST","CON"],size=k,p=[0.4,0.4,0.2]),
            spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
            rate=(spkts+dpkts)/(dur+1e-9),
            sttl=rng.choice([64,128],size=k),
            dttl=rng.choice([64,128],size=k),
            sload=sbytes*8/(dur+1e-9), dload=dbytes*8/(dur+1e-9),
            sinpkt=rng.uniform(0.5,50,size=k),
            dinpkt=rng.uniform(0.5,50,size=k),
            sjit=rng.uniform(0,10,size=k), djit=rng.uniform(0,10,size=k),
            swin=rng.choice([1024,8192],size=k),
            dwin=rng.choice([1024,8192],size=k),
            stcpb=rng.integers(0,2**32,size=k), dtcpb=rng.integers(0,2**32,size=k),
            tcprtt=rng.uniform(1,100,size=k), synack=rng.uniform(0.5,50,size=k),
            ackdat=rng.uniform(0.5,50,size=k),
            smean=(sbytes/(spkts+1)).astype(int),
            dmean=(dbytes/(dpkts+1)).astype(int),
            trans_depth=np.zeros(k,dtype=int), response_body_len=np.zeros(k,dtype=int),
            ct_srv_src=rng.integers(10,100,size=k), ct_state_ttl=rng.integers(0,4,size=k),
            ct_dst_ltm=rng.integers(10,100,size=k),
            ct_src_dport_ltm=rng.integers(10,100,size=k),
            ct_dst_sport_ltm=rng.integers(10,100,size=k),
            ct_dst_src_ltm=rng.integers(10,100,size=k),
            is_ftp_login=rng.choice([0,1],size=k,p=[0.4,0.6]),
            ct_ftp_cmd=rng.integers(0,5,size=k),
            ct_flw_http_mthd=np.zeros(k,dtype=int),
            ct_src_ltm=rng.integers(10,100,size=k),
            ct_srv_dst=rng.integers(1,20,size=k),
            is_sm_ips_ports=rng.choice([0,1],size=k,p=[0.5,0.5]),
            label=np.ones(k,dtype=int)
        )

    for fn, k in [(port_scan,n_scan),(dos_flood,n_dos),(exfiltration,n_exfil),
                  (c2_beacon,n_c2),(brute_force,n_brute)]:
        parts.append(pd.DataFrame(fn(k)))

    return pd.concat(parts, ignore_index=True)


# ═════════════════════════════════════════════════════════════════════════════
# BUILD & SAVE
# ═════════════════════════════════════════════════════════════════════════════

# Column order must match what app.py / train_model.py expect
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
    "label"
]

print("  Building normal traffic...")
df_normal  = pd.DataFrame(gen_normal(N_NORMAL))

print("  Building attack traffic...")
df_attack  = pd.DataFrame(gen_attacks(N_ATTACK))

df = pd.concat([df_normal, df_attack], ignore_index=True)
df = df[COLUMNS]

# Shuffle
df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)

# Round floats to 6 decimal places to keep CSV files smaller
float_cols = ["dur","rate","sload","dload","sinpkt","dinpkt","sjit","djit",
              "tcprtt","synack","ackdat"]
df[float_cols] = df[float_cols].round(6)

# ── Train / test split ───────────────────────────────────────────────────────
train_df, test_df = train_test_split(df, test_size=0.20,
                                     random_state=SEED, stratify=df["label"])

train_df.to_csv("synthetic_train.csv", index=False)
test_df.to_csv("synthetic_test.csv",   index=False)
print(f"\n  synthetic_train.csv  ->  {len(train_df):,} rows")
print(f"  synthetic_test.csv   ->  {len(test_df):,} rows")

# ── Update static/sample_network.csv ─────────────────────────────────────────
# 20 normal + 10 attack, no label column (app uploads don't have labels)
sample = pd.concat([
    df[df["label"]==0].head(20),
    df[df["label"]==1].head(10),
]).sample(frac=1, random_state=SEED).reset_index(drop=True)

sample_no_label = sample.drop(columns=["label"])
os.makedirs("static", exist_ok=True)
sample_no_label.to_csv("static/sample_network.csv", index=False)
print(f"  static/sample_network.csv  ->  {len(sample_no_label)} rows (no label column)")

print("\nDone! Now run:")
print("  .\\venv\\Scripts\\python.exe train_model.py")
print()
