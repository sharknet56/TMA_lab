#!/usr/bin/env python3
"""
train_baseline.py

Baseline RandomForest training on aggregated or per-pcap flow CSVs.

Supports:
    --dataset <aggregated.parquet or aggregated.csv>
    OR
    --csv <file1> --csv <file2> ...
    OR
    --csv-dir <directory-of-pcap-subdirs>

Outputs:
    outputs/<exp-name>/ml/
        metrics.csv
        confusion_matrix.png
        model.pkl
"""

import argparse
from pathlib import Path
import pickle

import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
import matplotlib.pyplot as plt
import seaborn as sns


# ---------------- FEATURE SELECTION ---------------- #

def extract_feature_columns(df: pd.DataFrame):
    """Select numeric columns used for ML."""
    candidate = [
        "duration",
        "total_bytes",
        "total_pkts",
        "fwd_bytes",
        "bwd_bytes",
        "fwd_pkts",
        "bwd_pkts",
        "mean_pkt_len",
        "min_pkt_len",
        "max_pkt_len",
        "mean_iat",
        "min_iat",
        "max_iat",
        "syn_count",
        "fin_count",
        "rst_count",
    ]
    return [c for c in candidate if c in df.columns]


# ---------------- DATA LOADING ---------------- #

def load_dataset(args):
    """
    Handles all ways of providing training data.
    """

    # New single aggregated dataset mode
    if args.dataset:
        path = Path(args.dataset)
        print(f"Loading aggregated dataset: {path}")
        if path.suffix == ".parquet":
            df = pd.read_parquet(path)
        elif path.suffix == ".csv":
            df = pd.read_csv(path)
        else:
            raise SystemExit("Unsupported dataset file format. Use CSV or Parquet.")
        return df

    # Original multiple --csv mode
    if args.csv:
        dfs = []
        for csv_file in args.csv:
            df = pd.read_csv(csv_file)
            dfs.append(df)
        return pd.concat(dfs, ignore_index=True)

    # New --csv-dir mode (all flows_labeled.csv under subdirs)
    if args.csv_dir:
        root = Path(args.csv_dir)
        subdirs = [p for p in root.iterdir() if p.is_dir()]
        dfs = []
        for sd in subdirs:
            csv_path = sd / args.csv_name
            if csv_path.is_file():
                dfs.append(pd.read_csv(csv_path))
        if not dfs:
            raise SystemExit(f"No CSVs found under {root}")
        return pd.concat(dfs, ignore_index=True)

    raise SystemExit("No dataset input provided.")


# ---------------- TRAINING ---------------- #

def train_baseline(df: pd.DataFrame, exp_name="baseline_experiment", outdir="outputs"):
    if "device_type" not in df.columns:
        raise SystemExit("Dataset must contain a 'device_type' column.")

    feature_cols = extract_feature_columns(df)
    print(f"Using {len(feature_cols)} features:", feature_cols)

    X = df[feature_cols]
    y = df["device_type"].astype(str)

    # Encode device_type
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Train-val split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y_enc,
        test_size=0.3,
        random_state=42,
        stratify=y_enc,
    )

    # Model
    clf = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_val)
    acc = accuracy_score(y_val, y_pred)

    report = classification_report(
        y_val, y_pred, target_names=le.classes_, output_dict=True
    )

    cm = confusion_matrix(y_val, y_pred)

    # Output directory
    exp_root = Path(outdir) / exp_name / "ml"
    exp_root.mkdir(parents=True, exist_ok=True)

    # Save metrics
    metrics_path = exp_root / "metrics.csv"
    metrics_df = pd.DataFrame(report).transpose()
    metrics_df.loc["accuracy", "f1-score"] = acc
    metrics_df.to_csv(metrics_path)
    print(f"Saved metrics: {metrics_path}")

    # Confusion matrix
    cm_path = exp_root / "confusion_matrix.png"
    plt.figure(figsize=(7, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=le.classes_,
                yticklabels=le.classes_)
    plt.title(f"Confusion Matrix (Acc={acc:.3f})")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.tight_layout()
    plt.savefig(cm_path)
    plt.close()
    print(f"Saved confusion matrix: {cm_path}")

    # Save model
    model_path = exp_root / "model.pkl"
    with open(model_path, "wb") as f:
        pickle.dump({
            "model": clf,
            "label_encoder": le,
            "features": feature_cols,
        }, f)
    print(f"Saved model: {model_path}")

    print("\n=== TRAINING COMPLETE ===")
    print(f"Accuracy: {acc:.4f}")
    print(f"Classes: {list(le.classes_)}")
    print(f"Results in: {exp_root}")


# ---------------- MAIN ---------------- #

def main():
    parser = argparse.ArgumentParser(description="Train baseline RandomForest classifier.")

    # NEW dataset mode
    parser.add_argument("--dataset",
                        help="Single aggregated dataset file (.csv or .parquet)")

    # OLD modes
    parser.add_argument("--csv", action="append",
                        help="One or more flow CSVs (repeatable)")
    parser.add_argument("--csv-dir",
                        help="Directory containing per-pcap subdirectories with flow CSVs")
    parser.add_argument("--csv-name", default="flows_labeled.csv",
                        help="Filename to load from each subdirectory (default: flows_labeled.csv)")

    # Experiment info
    parser.add_argument("--exp-name", default="baseline_experiment")
    parser.add_argument("--outdir", default="outputs")

    args = parser.parse_args()

    df = load_dataset(args)
    train_baseline(df, args.exp_name, args.outdir)


if __name__ == "__main__":
    main()
