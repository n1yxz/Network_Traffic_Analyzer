
"""Streamlit dashboard for the Network Traffic Analyzer."""

import streamlit as st
import pandas as pd

from src.capture import capture_packets
from src.features import engineer_features
from src.ml_anomaly import TrafficAnomalyDetector
from src.visualization import (
    plot_packet_length_distribution,
    plot_protocol_distribution,
    plot_feature_correlation,
)


st.set_page_config(
    page_title="Network Traffic Analyzer",
    layout="wide",
)

st.title("🛰️ Network Traffic Analyzer")
st.write(
    """Capture live network packets, engineer features, and detect anomalies
    using an Isolation Forest model."""
)

with st.sidebar:
    st.header("Capture Settings")
    packet_count = st.number_input(
        "Number of packets",
        min_value=20,
        max_value=5000,
        value=200,
        step=20,
    )
    interface = st.text_input(
        "Network interface (optional)",
        help="Leave blank for default interface. Example: eth0, wlan0, en0",
    )
    contamination = st.slider(
        "Expected anomaly proportion",
        min_value=0.01,
        max_value=0.3,
        value=0.1,
        step=0.01,
    )
    run_button = st.button("🚀 Capture & Analyze", type="primary")

if run_button:
    st.info("Capturing packets... This may require admin/root privileges.", icon="ℹ️")
    try:
        df_raw = capture_packets(count=int(packet_count), interface=interface or None)
    except Exception as exc:
        st.error(f"Error during capture: {exc}")
        st.stop()

    if df_raw.empty:
        st.warning("No packets were captured. Try again with a different interface or more packets.")
        st.stop()

    st.success(f"Captured {len(df_raw)} packets.")

    st.subheader("Raw Captured Packets")
    st.dataframe(df_raw.head(200))

    st.subheader("Feature Engineering")
    df_feat, feature_cols = engineer_features(df_raw)
    st.write("Using features:", feature_cols)

    detector = TrafficAnomalyDetector(contamination=float(contamination))
    preds = detector.fit_predict(df_feat, feature_cols)
    df_feat["prediction"] = preds
    df_feat["is_anomaly"] = df_feat["prediction"].apply(lambda x: "Yes" if x == -1 else "No")

    st.subheader("Anomalous Packets")
    anomalies = df_feat[df_feat["is_anomaly"] == "Yes"]
    if anomalies.empty:
        st.info("No strong anomalies detected with current settings.")
    else:
        st.write(f"Detected {len(anomalies)} anomalous packets.")
        st.dataframe(anomalies.head(200))

    st.subheader("Processed Data (With Features & Labels)")
    st.dataframe(df_feat.head(200))

    # Visualizations
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("**Packet Length Distribution**")
        path_len = plot_packet_length_distribution(df_raw)
        if path_len:
            st.image(str(path_len))

    with col2:
        st.markdown("**Protocol Distribution**")
        path_proto = plot_protocol_distribution(df_raw)
        if path_proto:
            st.image(str(path_proto))

    with col3:
        st.markdown("**Feature Correlation Heatmap**")
        path_corr = plot_feature_correlation(df_feat)
        if path_corr:
            st.image(str(path_corr))

    # Downloads
    st.subheader("Download Results")
    csv_raw = df_raw.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Raw Packets CSV",
        data=csv_raw,
        file_name="raw_packets.csv",
        mime="text/csv",
    )

    csv_proc = df_feat.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Processed Packets CSV",
        data=csv_proc,
        file_name="packets_with_anomalies.csv",
        mime="text/csv",
    )
