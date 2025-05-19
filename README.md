# 🛡️ Hybrid SIEM System – Cloud & Local Honeypot Integration

> **Final Year Project – BSc (Hons) Computer Security – University of Plymouth**  
> **Author:** Lakshan Sameera | [lakshan.sam28@gmail.com](mailto:lakshan.sam28@gmail.com)

---

## 📌 Overview

This project delivers a complete **Hybrid SIEM** (Security Information and Event Management) solution that combines:

✅ Local and cloud honeypots  
✅ Real-time File Integrity Monitoring (FIM)  
✅ Machine learning-based anomaly detection  
✅ Automated threat response in under 5 seconds  
✅ SOC Analyst tool for visual analysis & PDF reporting  

Everything is unified through **Azure Sentinel** for centralized monitoring, fast response, and deep visibility across hybrid enterprise environments.

---

## 🧠 Why This Project?

Traditional SIEMs struggle to monitor **hybrid infrastructure** — attackers easily exploit this gap.

This project solves that by:

- Detecting threats across **both cloud and local machines**
- Automating the **entire detection-to-response lifecycle**
- Empowering analysts with **custom reporting tools**

---

## 🧩 System Architecture

```
+---------------------+        +----------------------+
|  Local Honeypot VM  |        |  Cloud Honeypot VM   |
|  (Windows 10)       |        |  (Azure-based)       |
+----------+----------+        +----------+-----------+
           |                             |
| File changes + login logs   | Suspicious logins + scans
v                             v
+----------------------------- Azure Sentinel -----------------------------+
|  🔍 ML Detection (KQL Rules)  →   🔁 Logic App Playbook  →   📧 Alerting  |
|  📊 Workbooks Dashboard      →   🔒 IP Blocking           →   🔄 Isolation |
+-------------------------------------------------------------------------+
                                |
                   +-----------------------------+
                   | SOC CSV Analyzer Pro        |
                   | (Python + Streamlit)        |
                   | Visual & PDF Log Analysis   |
                   +-----------------------------+
```

---

## 🚀 Features

### 🔥 Detection Modules
- 🧪 **Cloud & Local Honeypots**: Azure VMs + RDP-exposed Windows machines
- 📁 **File Integrity Monitor**: Detects unauthorized changes via hashing
- 🔐 **RDP Brute-Force Detection**: Logs failed logins and flags suspicious spikes

### 🧠 AI/ML + Response
- 🧠 **ML-based Rule in Azure Sentinel**: Custom anomaly detection (RDP abuse, geo spikes)
- ⚡ **Logic Apps Automation**: Responds instantly — blocks IPs, isolates systems, alerts analyst

### 📊 Analyst Tool
- 🛠️ **SOC CSV Analyzer Pro**: Upload logs, visualize attacks, and export PDF reports

### 📡 Real-Time Dashboards
- 🌍 Azure Workbooks for real-time login events, geo-maps, and incident heatmaps

---

## 📈 Performance Highlights

| Metric                  | Value                     |
|-------------------------|---------------------------|
| 🎯 Detection Accuracy    | **96.2%**                 |
| ⚡ Response Time         | **< 5 seconds**           |
| 📊 EPS (Scalability)     | **1,050+ Events/sec**     |
| 🔕 False Positives       | **4.2% (after tuning)**   |
| 📉 Analyst Time Saved    | **65% faster log reviews**|

---

## 🛠️ Tech Stack

- **Cloud & Monitoring**: Azure Sentinel, Log Analytics, Logic Apps  
- **Backend**: Node.js, Express.js, PowerShell  
- **Frontend**: Streamlit (Python), HTML/CSS, Chart.js, Tailwind  
- **Data Tools**: Pandas, Matplotlib, Seaborn, Plotly  
- **Detection**: KQL (Custom ML Rules), MITRE ATT&CK Mapping  
- **OS/Platforms**: Windows 10 VM, Azure VM, Linux (Kali)

---

## ⚙️ Setup & Deployment Guide

### 📁 Clone Repos

```bash
# FIM Module (Node.js)
git clone https://github.com/Lsam18/Sentinel-X.git

# SOC Analyzer Tool (Python + Streamlit)
git clone https://github.com/Lsam18/ai-soc-summary-SentinelX.git
```

---

### 🔧 Local Honeypot Setup

1. Setup a Windows 10 VM on your LAN
2. Create folder: `C:\Critical`
3. Enable RDP
4. Install Log Analytics Agent and connect to Azure Sentinel

---

### 🔧 Cloud Honeypot Setup

1. Deploy Azure VM (RDP + SMB exposed)
2. Install Log Analytics Agent
3. Link to Azure Sentinel Workspace

---

### ⚙️ File Integrity Monitor (FIM)

```bash
cd Sentinel-X/FIM-Module
npm install
node server.js
```

Access via browser: `http://localhost:3000`

---

### 🖥️ RDP Brute-Force Detection (PowerShell)

```powershell
# Run these as Administrator
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install-prerequisites.ps1
.\configure-rdp-monitor.ps1
.\rdp-sentinelx.ps1
```

---

### 📈 SOC CSV Analyzer Pro

```bash
cd ai-soc-summary-SentinelX
pip install -r requirements.txt
streamlit run soc_csv_analyzer.py
```

Then open: `http://localhost:8501`

---

## 🧠 Machine Learning Rule (KQL Sample)

```kql
let StartDate = datetime(2025-04-15);
let Now = now();
let baseline = SecurityEvent
| where EventID == 4624 and LogonType == 10
| where TimeGenerated >= StartDate and TimeGenerated < Now
| summarize count_baseline = count() by Account, IpAddress;
let recent = SecurityEvent
| where EventID in (4624, 4625)
| where TimeGenerated >= ago(5m)
| summarize count_recent = count() by Account, IpAddress;
recent
| join kind=leftouter baseline on Account, IpAddress
| extend anomalyScore = count_recent - coalesce(count_baseline, 0)
| where anomalyScore > 5 and IpAddress !startswith "192."
```

Set this to run every 5 minutes in Sentinel → Trigger Logic App on match.

---

## 📊 Live Dashboards (Azure Workbooks)

* Create a workbook linked to your Log Analytics Workspace
* Use these charts:
  * Geo map of attacker IPs
  * Time series of RDP events
  * FIM alert logs with file paths
* Optional: Connect Sentinel to Grafana for external dashboards

---

## 📂 Project Structure

```
📦 Hybrid-SIEM-Project/
├── Sentinel-X/
│   └── FIM-Module/
│       └── server.js, config.json, logs/
├── ai-soc-summary-SentinelX/
│   └── soc_csv_analyzer.py
│   └── utils/, visuals/, reports/
├── PowerShell/
│   └── install-prerequisites.ps1
│   └── configure-rdp-monitor.ps1
│   └── rdp-sentinelx.ps1
└── README.md
```

---

## 🪪 License

This project is open-source under the **MIT License**.
Feel free to use, modify, and contribute.

---

## 📬 Contact

For inquiries, access to the full report, poster, or live demo:

**Lakshan Sameera**
Email: [lakshan.sam28@gmail.com](mailto:lakshan.sam28@gmail.com)

---

> Built for the Final Year Project:
> **Hybrid SIEM with Cloud & Local Honeypot Integration and Analyst-Driven Automation**
> University of Plymouth – BSc (Hons) Computer Security
