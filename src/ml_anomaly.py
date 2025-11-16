
"""Unsupervised anomaly detection using Isolation Forest."""

from dataclasses import dataclass
from typing import List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


@dataclass
class TrafficAnomalyDetector:
    """Wrapper around IsolationForest for network traffic data."""

    contamination: float = 0.1
    random_state: int = 42

    def __post_init__(self):
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.fitted: bool = False
        self.feature_cols: List[str] = []

    def fit(self, df: pd.DataFrame, feature_cols: List[str]) -> None:
        self.feature_cols = feature_cols
        X = df[feature_cols].values
        self.model.fit(X)
        self.fitted = True

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            raise ValueError("Model is not fitted. Call fit() first.")
        X = df[self.feature_cols].values
        return self.model.predict(X)  # 1 = normal, -1 = anomaly

    def fit_predict(self, df: pd.DataFrame, feature_cols: List[str]) -> pd.Series:
        self.fit(df, feature_cols)
        preds = self.predict(df)
        return pd.Series(preds, index=df.index)

    def save(self, path: str) -> None:
        joblib.dump(
            {"model": self.model, "feature_cols": self.feature_cols},
            path,
        )

    def load(self, path: str) -> None:
        obj = joblib.load(path)
        self.model = obj["model"]
        self.feature_cols = obj["feature_cols"]
        self.fitted = True
