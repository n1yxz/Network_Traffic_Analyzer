
"""Matplotlib-based visualizations for network traffic."""

from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import pandas as pd


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def plot_packet_length_distribution(df: pd.DataFrame, out_path: Optional[str] = None):
    """Plot histogram of packet lengths.

    Returns a Path to the saved image.
    """
    if df.empty:
        return None

    lengths = df["length"].fillna(0)

    fig, ax = plt.subplots()
    ax.hist(lengths, bins=30)
    ax.set_title("Packet Length Distribution")
    ax.set_xlabel("Length (bytes)")
    ax.set_ylabel("Frequency")

    out = Path(out_path) if out_path else Path("data/processed/packet_length_distribution.png")
    _ensure_dir(out)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_protocol_distribution(df: pd.DataFrame, out_path: Optional[str] = None):
    """Plot bar chart of protocol counts."""
    if df.empty or "protocol" not in df.columns:
        return None

    counts = df["protocol"].fillna("UNKNOWN").value_counts()

    fig, ax = plt.subplots()
    ax.bar(counts.index.astype(str), counts.values)
    ax.set_title("Protocol Distribution")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Count")
    fig.autofmt_xdate(rotation=45)

    out = Path(out_path) if out_path else Path("data/processed/protocol_distribution.png")
    _ensure_dir(out)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_feature_correlation(df: pd.DataFrame, out_path: Optional[str] = None):
    """Plot correlation heatmap for numeric features."""
    if df.empty:
        return None

    numeric_df = df.select_dtypes(include=["number"])
    if numeric_df.empty:
        return None

    corr = numeric_df.corr()

    fig, ax = plt.subplots()
    cax = ax.imshow(corr.values)
    ax.set_xticks(range(len(corr.columns)))
    ax.set_yticks(range(len(corr.columns)))
    ax.set_xticklabels(corr.columns, rotation=45, ha="right")
    ax.set_yticklabels(corr.columns)
    fig.colorbar(cax)
    ax.set_title("Feature Correlation Heatmap")

    out = Path(out_path) if out_path else Path("data/processed/feature_correlation.png")
    _ensure_dir(out)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    return out
