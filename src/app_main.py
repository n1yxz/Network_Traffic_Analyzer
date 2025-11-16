
"""Command-line entry point for the Network Traffic Analyzer."""

import os
from pathlib import Path

import pandas as pd

from .capture import capture_packets
from .features import engineer_features
from .ml_anomaly import TrafficAnomalyDetector
from .visualization import (
    plot_packet_length_distribution,
    plot_protocol_distribution,
    plot_feature_correlation,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
MODEL_PATH = ROOT / "model_isolation_forest.joblib"


def ensure_dirs() -> None:
    os.makedirs(DATA_RAW, exist_ok=True)
    os.makedirs(DATA_PROCESSED, exist_ok=True)


def run_capture_and_analyze(
    packet_count: int = 200,
    interface: str | None = None,
    contamination: float = 0.1,
) -> pd.DataFrame:
    """End-to-end pipeline: capture, feature-engineer, detect anomalies, save outputs."""
    ensure_dirs()

    print(f"[+] Capturing approximately {packet_count} packets...")
    df_raw = capture_packets(count=packet_count, interface=interface)
    print(f"[+] Captured {len(df_raw)} packets.")

    if df_raw.empty:
        print("[!] No packets captured. Exiting.")
        return df_raw

    raw_path = DATA_RAW / "packets_raw.csv"
    df_raw.to_csv(raw_path, index=False)
    print(f"[+] Raw packets saved to {raw_path}")

    df_feat, feature_cols = engineer_features(df_raw)

    detector = TrafficAnomalyDetector(contamination=contamination)
    preds = detector.fit_predict(df_feat, feature_cols)
    df_feat["prediction"] = preds
    df_feat["is_anomaly"] = df_feat["prediction"].apply(lambda x: "Yes" if x == -1 else "No")

    detector.save(str(MODEL_PATH))
    print(f"[+] Model saved to {MODEL_PATH}")

    processed_path = DATA_PROCESSED / "packets_with_anomalies.csv"
    df_feat.to_csv(processed_path, index=False)
    print(f"[+] Processed packets saved to {processed_path}")

    # Visualizations
    print("[+] Generating visualizations...")
    plot_packet_length_distribution(df_raw, out_path=str(DATA_PROCESSED / "packet_length_distribution.png"))
    plot_protocol_distribution(df_raw, out_path=str(DATA_PROCESSED / "protocol_distribution.png"))
    plot_feature_correlation(df_feat, out_path=str(DATA_PROCESSED / "feature_correlation.png"))
    print(f"[+] Plots saved under {DATA_PROCESSED}")

    return df_feat


if __name__ == "__main__":
    # Basic default run for manual testing
    df_result = run_capture_and_analyze(packet_count=200, interface=None)
    if not df_result.empty:
        print(df_result.head())
