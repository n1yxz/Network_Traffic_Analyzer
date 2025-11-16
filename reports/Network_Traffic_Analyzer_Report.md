
# Network Traffic Analyzer with Isolation Forest Anomaly Detection

## 1. Introduction

Modern computer networks generate large volumes of traffic, making it difficult
for security analysts to manually inspect packets and detect suspicious activity.
This project implements a **Network Traffic Analyzer** that captures live packets,
extracts useful features, and applies an **unsupervised Isolation Forest model**
to highlight anomalous traffic patterns.

The goal is to provide a lightweight, educational prototype that demonstrates how
machine learning can be integrated into basic network monitoring.

## 2. Objectives

- Capture live packets from a chosen network interface.
- Convert raw packets into structured tabular data.
- Engineer simple numeric features suitable for machine learning.
- Train an Isolation Forest model for anomaly detection.
- Visualize traffic patterns and anomalies.
- Provide both a command-line workflow and an interactive dashboard.

## 3. System Design

The system is organized into modular Python components:

- `capture.py`:
  Uses scapy to sniff network packets and converts them into a pandas DataFrame
  containing source/destination IPs, ports, protocol, timestamp, and packet length.

- `features.py`:
  Encodes protocol types as numeric codes, normalizes ports and lengths, and
  computes `time_since_start` as a simple temporal feature.

- `ml_anomaly.py`:
  Wraps an Isolation Forest model from scikit-learn to perform unsupervised
  anomaly detection on the engineered features.

- `visualization.py`:
  Generates basic matplotlib plots such as packet length distribution, protocol
  distribution, and a correlation heatmap of numeric features.

- `app_main.py`:
  Provides an end-to-end pipeline (capture → features → anomaly detection →
  save outputs → generate plots).

- `dashboard_streamlit.py`:
  Implements a Streamlit-based dashboard for configuring capture parameters,
  running the analysis, exploring results, and downloading CSV files.

## 4. Implementation Details

### 4.1 Data Capture

Packet capture is performed using the `sniff` function from scapy. For each
packet, the tool extracts:

- Timestamp
- Source IP (`src_ip`)
- Destination IP (`dst_ip`)
- Source port (`src_port`)
- Destination port (`dst_port`)
- Protocol (e.g. TCP, UDP, or numeric identifier)
- Packet length in bytes

These fields are appended to a list of dictionaries and converted into a
pandas DataFrame at the end of the capture phase.

### 4.2 Feature Engineering

For anomaly detection, the following numeric features are derived:

- `length`: Packet length (bytes)
- `protocol_code`: Encoded integer representing the protocol
- `src_port`: Numeric source port (0 if missing)
- `dst_port`: Numeric destination port (0 if missing)
- `time_since_start`: Seconds elapsed since the first captured packet

This simple feature set is intentionally lightweight and easy to compute, while
still capturing basic structural and temporal information about the traffic.

### 4.3 Anomaly Detection

The Isolation Forest algorithm is used in an unsupervised setting:

- It is fit on the engineered feature matrix.
- It outputs `1` for normal points and `-1` for anomalies.
- The `contamination` parameter controls the expected proportion of anomalies.

The project labels each packet as either:

- `is_anomaly = "Yes"` for predicted anomalies
- `is_anomaly = "No"` for normal traffic

### 4.4 Visualization

The visualizations include:

- **Packet Length Distribution**: Histogram showing the spread of packet sizes.
- **Protocol Distribution**: Bar chart of counts per protocol.
- **Feature Correlation Heatmap**: Matrix showing correlations between numeric
  features such as length, ports, and time_since_start.

These plots help users quickly understand overall traffic behavior and investigate
whether anomalies differ significantly from normal traffic.

## 5. Results & Observations

In typical testing scenarios on a small local network, most captured packets
are classified as normal, while a small fraction may be flagged as anomalous.
These anomalies can correspond to rare protocols, unusual port combinations,
or packets with sizes that deviate from the bulk of traffic.

Since the model is unsupervised and trained on relatively small samples, it is
important to interpret anomalies as *unusual* rather than automatically
*malicious*. In a production-grade system, additional context and labeled data
would be necessary.

## 6. Limitations

- Only a minimal set of features is used; deeper payload inspection is out of
  scope for this project.
- Live capture requires appropriate permissions and may not work in restricted
  environments.
- Unsupervised anomaly detection does not distinguish between benign and
  malicious anomalies.
- The prototype is not optimized for high-throughput or large-scale deployments.

## 7. Future Work

- Incorporate labeled datasets (e.g., CICIDS2017, UNSW-NB15) for supervised
  attack classification.
- Add protocol-specific parsers for HTTP, DNS, etc. to extract richer features.
- Extend the dashboard with real-time streaming views and alerting.
- Containerize the application for easier deployment.
- Integrate the analyzer into a broader SIEM or log management platform.

## 8. Conclusion

This project demonstrates an end-to-end workflow for applying machine learning
to network traffic analysis:

- Data capture
- Feature engineering
- Unsupervised anomaly detection
- Visualization and interactive exploration

It serves as a solid educational example and a starting point for building more
sophisticated intrusion detection or network monitoring tools.
