from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from detector.training.features import FEATURE_NAMES


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on DNS features")
    parser.add_argument("--input", required=True, help="Parquet file from generate_training_data.py")
    parser.add_argument("--output", required=True, help="Output joblib model path")
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.01,
        help="Expected fraction of outliers in training data (default 0.01)",
    )
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of trees (default 100)")
    args = parser.parse_args()

    dataframe = pd.read_parquet(args.input)
    print(f"loaded {len(dataframe)} rows")
    assert list(dataframe.columns) == FEATURE_NAMES, (
        f"Column mismatch. Expected {FEATURE_NAMES}, got {list(dataframe.columns)}"
    )
    assert not dataframe.isnull().any().any(), "NaN values found in training data"

    zero_variance_features = dataframe.columns[dataframe.var() == 0].tolist()
    if zero_variance_features:
        print(f"zero-variance features: {zero_variance_features}")

    feature_matrix = dataframe.values.astype(np.float32)
    train_matrix, validation_matrix = train_test_split(feature_matrix, test_size=0.1, random_state=42)
    print(f"train rows={len(train_matrix)} val rows={len(validation_matrix)}")

    model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(train_matrix)

    train_scores = model.score_samples(train_matrix)
    validation_scores = model.score_samples(validation_matrix)
    print(f"train score mean={train_scores.mean():.4f} std={train_scores.std():.4f}")
    print(f"val score mean={validation_scores.mean():.4f} std={validation_scores.std():.4f}")

    score_gap = abs(train_scores.mean() - validation_scores.mean())
    if score_gap > train_scores.std():
        print(f"train/val mean gap {score_gap:.4f} is larger than train std")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    print(f"saved model to {output_path}")


if __name__ == "__main__":
    main()
