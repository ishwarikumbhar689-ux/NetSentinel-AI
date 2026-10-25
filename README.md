# NetSentinel AI — Intelligent Network Intrusion Detection System

A full-stack cybersecurity web application that uses a **Random Forest machine learning model** to classify network traffic records as *Normal* or *Potentially Suspicious*.

---

## Tech Stack

| Layer      | Technology                              |
|------------|-----------------------------------------|
| Backend    | Python 3.10+, Flask 3                   |
| ML Model   | scikit-learn Random Forest, joblib      |
| Database   | SQLite (auto-created on first run)      |
| Frontend   | HTML5, Tailwind CSS (CDN), Chart.js (CDN) |
| Auth       | Werkzeug password hashing, Flask session |

---

## Pages

| Page             | URL               | Description                                      |
|------------------|-------------------|--------------------------------------------------|
| Landing          | `/`               | Public hero page — overview and feature list     |
| Login            | `/login`          | Email + password authentication                  |
| Register         | `/register`       | Create a new account                             |
| Dashboard        | `/dashboard`      | Summary stats, charts, recent scans              |
| Network Scan     | `/network-scan`   | Upload a CSV to run an AI-powered analysis       |
| Scan Results     | `/scan-results/<id>` | Record-level results with filter + chart      |
| Scan History     | `/scan-history`   | All past scans with flag-rate bars               |
| Reports          | `/reports`        | Download CSV reports for completed scans         |
| Settings/Profile | `/settings`       | Update profile, change password, system info     |

---

## Quick Start

### 1 — Install dependencies

```bash
pip install -r requirements.txt
```

### 2 — Train the model (required before scanning)

Download one of the following free datasets and place the CSV file(s) in the project root:

- **UNSW-NB15** — https://research.unsw.edu.au/projects/unsw-nb15-dataset  
  Download any of the four CSV part files.
- **CIC-IDS2017** — https://www.unb.ca/cic/datasets/ids-2017.html  
  Download any day's traffic CSV (e.g. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`).

Then run:

```bash
python train_model.py
```

The script will:
- Auto-detect whether you have UNSW-NB15 or CIC-IDS2017 data
- Train a Random Forest classifier
- Print precision, recall, F1, and a confusion matrix
- Save `model.pkl` in the project root

### 3 — Start the server

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### 4 — Register and log in

Go to `/register` to create your account — there are no pre-seeded demo users.

### 5 — Run a scan

1. Go to **Network Scan** in the sidebar.
2. Upload a CSV file with the required columns (listed on the Network Scan page).
3. View results, download the CSV report, or browse your scan history.

---

## Required CSV Columns

Your uploaded CSV must contain these columns (case-insensitive, spaces/underscores interchangeable):

```
dur, proto, service, state, spkts, dpkts, sbytes, dbytes,
rate, sttl, dttl, sload, dload, sinpkt, dinpkt, sjit, djit,
swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
smean, dmean, trans_depth, response_body_len,
ct_srv_src, ct_state_ttl, ct_dst_ltm, ct_src_dport_ltm,
ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login, ct_ftp_cmd,
ct_flw_http_mthd, ct_src_ltm, ct_srv_dst, is_sm_ips_ports
```

A sample file with 20 rows is included at `static/sample_network.csv`.

---

## Project Structure

```
NetSentinel AI/
├── app.py                  # Flask application
├── train_model.py          # Model training script
├── model.pkl               # Trained model bundle (created by train_model.py)
├── requirements.txt
├── netsentinel.db          # SQLite database (auto-created)
├── uploads/                # Uploaded CSV files (auto-created)
├── static/
│   └── sample_network.csv  # 20-row sample CSV
└── templates/
    ├── base.html
    ├── landing.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── network_scan.html
    ├── scan_results.html
    ├── scan_history.html
    ├── reports.html
    └── settings.html
```

---

## How the Model Works

`train_model.py` builds a `scikit-learn` pipeline:

1. **Imputation** — median for numeric, constant `"missing"` for categorical
2. **Encoding** — `OrdinalEncoder` for categorical features
3. **Classification** — `RandomForestClassifier(n_estimators=100)`

The trained pipeline is saved as a `joblib` bundle (`model.pkl`) containing the pipeline, feature lists, label encoders, and dataset metadata. `app.py` loads this on startup. If the file is missing, all upload attempts return HTTP 503 with a clear message.

---

## Notes

- All data is stored locally — nothing is sent to external servers.
- Passwords are hashed with `werkzeug.security.generate_password_hash`.
- Uploaded CSV files are stored in `uploads/` and referenced in the database.
- The `uploads/` folder is not served publicly.
