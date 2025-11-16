
"""Feature engineering for network traffic records."""

import pandas as pd


def engineer_features(df: pd.DataFrame):
    """Add numeric features required for anomaly detection.

    Returns a tuple of (features_dataframe, feature_columns_list).
    """
    df = df.copy()

    # Ensure required columns exist
    for col in ["protocol", "length", "src_port", "dst_port", "timestamp"]:
        if col not in df.columns:
            df[col] = None

    # Protocol encoding
    df["protocol"] = df["protocol"].fillna("OTHER")
    proto_map = {name: idx for idx, name in enumerate(df["protocol"].unique())}
    df["protocol_code"] = df["protocol"].map(proto_map)

    # Length and ports: missing -> 0
    df["length"] = df["length"].fillna(0)
    df["src_port"] = df["src_port"].fillna(0)
    df["dst_port"] = df["dst_port"].fillna(0)

    # Time since start in seconds
    if not df["timestamp"].isna().all():
        first_ts = df["timestamp"].min()
        df["time_since_start"] = (df["timestamp"] - first_ts).dt.total_seconds()
    else:
        df["time_since_start"] = 0.0

    feature_cols = [
        "length",
        "protocol_code",
        "src_port",
        "dst_port",
        "time_since_start",
    ]

    return df, feature_cols
