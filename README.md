
# 🛰️ Network Traffic Analyzer

This project captures live network packets, engineers features, and uses an
**Isolation Forest** model to perform unsupervised anomaly detection on network
traffic. It includes:

- A reusable Python pipeline (`src/` modules)
- A command-line entry point (`python -m src.app_main`)
- A Streamlit dashboard (`dashboard_streamlit.py`)
- Basic visualizations and CSV exports
- A report template under `reports/`

## 📂 Project Structure

```text
network_traffic_analyzer/
├─ src/
│  ├─ __init__.py
│  ├─ capture.py
│  ├─ features.py
│  ├─ ml_anomaly.py
│  ├─ visualization.py
│  └─ app_main.py
├─ data/
│  ├─ raw/
│  └─ processed/
├─ reports/
│  └─ Network_Traffic_Analyzer_Report.md
├─ tests/
├─ dashboard_streamlit.py
├─ requirements.txt
└─ README.md
```

## 🚀 Getting Started

1. Create and activate a virtual environment (recommended).
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the command-line pipeline:

   ```bash
   python -m src.app_main
   ```

   This will:
   - Capture packets
   - Engineer features
   - Train an Isolation Forest
   - Save CSVs and plots under `data/processed/`

4. Run the Streamlit dashboard:

   ```bash
   streamlit run dashboard_streamlit.py
   ```

   Then open the URL Streamlit prints (typically `http://localhost:8501`).

## ⚠️ Permissions & Ethics

- Live packet capture often **requires administrator or root privileges**.
- Only use this tool on networks you **own** or have explicit permission to monitor.
- This project is for **educational purposes** and should not be used for any
  malicious or intrusive activity.

## 🧠 How It Works (High Level)

1. `capture.py` uses **scapy** to sniff packets and builds a pandas DataFrame.
2. `features.py` adds numeric features such as protocol encoding, ports, length,
   and time since the start of capture.
3. `ml_anomaly.py` wraps an **Isolation Forest** model for unsupervised anomaly
   detection.
4. `visualization.py` uses **matplotlib** to generate:
   - Packet length distribution
   - Protocol distribution
   - Correlation heatmap of numeric features
5. `dashboard_streamlit.py` provides an interactive UI to:
   - Configure capture settings
   - View raw and processed data
   - Inspect anomalies
   - See plots
   - Download results as CSV

## 📘 Report

See `reports/Network_Traffic_Analyzer_Report.md` for a written explanation you can
adapt for assignments or documentation.
