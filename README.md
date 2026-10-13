# 🛡️ CyberShield: AI-Powered Network Intrusion Detection System (AI-NIDS)

An intelligent, real-time Network Intrusion Detection System that combines **Heuristic Threat Detection** and **Machine Learning (Isolation Forest Anomaly Detection)** to identify and score malicious network activity.

---

## 🚀 Key Capabilities

- **Port Scanning Detection**: Identifies rapid SYN connection probes and multi-port scanning attempts.
- **Denial-of-Service (DoS) Detection**: Detects volumetric packet floods, SYN floods, and abnormal packet frequency.
- **Machine Learning Anomaly Detection**: Uses **Scikit-learn's Isolation Forest** to detect zero-day or statistical outliers in packet size, protocol distributions, and TCP flag anomalies.
- **Dynamic 0–100 Risk Scoring**: Fuses heuristic confidence with ML outlier scores to assign threat levels (**LOW**, **MEDIUM**, **HIGH**, **CRITICAL**).
- **Real-Time SOC Dashboard**: Built with **React 19**, **Tailwind CSS**, and **Recharts**, featuring live packet telemetry, attack charts, and WebSocket event streaming.
- **Built-in Attack Simulator**: Allows one-click testing of port scans, DoS floods, and anomalies directly in VS Code.
- **Live Scapy Sniffing**: Supports live packet capture from real network interfaces.

---

## 📂 Project Structure

```text
ai-nids/
├── .vscode/
│   ├── settings.json            # VS Code Python environment configuration
│   └── launch.json              # F5 debug launcher for FastAPI
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes.py        # REST API endpoints (alerts, stats, simulation)
│   │   ├── engine/
│   │   │   ├── alert_manager.py # In-memory aggregator & WebSocket broadcaster
│   │   │   ├── packet_sniffer.py# Scapy real-time packet capture
│   │   │   └── traffic_simulator.py # Simulation generator for attacks & normal flows
│   │   ├── ml/
│   │   │   ├── features.py      # Flow & packet feature extraction
│   │   │   ├── detector.py      # Hybrid Isolation Forest + Heuristic detection engine
│   │   │   ├── train_baseline.py# Baseline Isolation Forest training script
│   │   │   └── isolation_forest.joblib # Saved trained model & scaler
│   │   ├── config.py            # Thresholds and application configuration
│   │   ├── database.py          # SQLAlchemy SQLite / PostgreSQL setup
│   │   ├── models.py            # Database models (PacketRecord, AlertRecord)
│   │   ├── schemas.py           # Pydantic schemas
│   │   └── main.py              # FastAPI app and WebSocket endpoint (/ws/traffic)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Cyber SOC Dashboard UI
│   │   ├── index.css            # Tailwind CSS styling
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── venv/                        # Pre-configured Python virtual environment
└── start.bat                    # One-click Windows launcher
```

---

## 🛠️ Step-by-Step Instructions to Run in VS Code

### Step 1: Open the Project in VS Code
1. Open VS Code.
2. Click **File** > **Open Folder...**
3. Select `C:\Users\shiva\OneDrive\Desktop\ai-nids`.

---

### Step 2: Start the Backend (Terminal 1)
1. In VS Code, open a terminal (<kbd>Ctrl</kbd> + <kbd>`</kbd>).
2. Activate the virtual environment and start FastAPI:
   ```powershell
   cd backend
   ..\venv\Scripts\activate
   uvicorn app.main:app --reload --port 8000
   ```
3. You will see:
   ```text
   AI-POWERED NETWORK INTRUSION DETECTION SYSTEM (NIDS)
   Isolation Forest Anomaly Detector successfully loaded.
   Uvicorn running on http://127.0.0.1:8000
   ```
4. Check Swagger API documentation at: **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**.

---

### Step 3: Start the React Frontend (Terminal 2)
1. In VS Code, open a **second terminal tab** (click the `+` icon in the terminal panel).
2. Run:
   ```powershell
   cd frontend
   npm run dev
   ```
3. Open your browser at: **[http://localhost:5173](http://localhost:5173)**.

---

### Step 4: Test Attacks with the Built-in Simulator
On the SOC dashboard, click the attack simulation buttons:
- **Port Scan (SYN)**: Triggers rapid multi-port scan targeting ports 21, 22, 23, 80, 443, 3389...
- **DoS Flood**: Triggers high-frequency packet flood (>50 pps) to test volumetric detection.
- **ML Anomaly**: Generates non-standard packets (TCP NULL/XMAS scans, abnormal lengths).
- **Normal Traffic**: Simulates standard legitimate web and DNS flows.

Observe the **Live Threat Feed**, **Average Risk Score Gauge**, and **Charts** update in real-time via WebSockets!

---

## 🌐 Real Packet Sniffing with Scapy on Windows

To capture real physical network packets from your Wi-Fi or Ethernet card:
1. Download and install **Npcap for Windows**: [https://npcap.com/#download](https://npcap.com/#download) (enable the *"WinPcap API-compatible mode"* checkbox during installation).
2. Run VS Code as **Administrator**.
3. On the dashboard, click **"Start Live Sniffer"**.

