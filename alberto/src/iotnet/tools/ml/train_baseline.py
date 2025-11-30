"""
train_baseline.py

Baseline RandomForest training on aggregated (or per-PCAP) flow CSVs.

Library-style module (no CLI here). Typical usage:

    from pathlib import Path
    from src.iotnet.tools.ml import train_baseline

    # Option 1: load df yourself
    df = train_baseline.load_dataset_from_path(Path("outputs/aggregated_flows.parquet"))
    train_baseline.train_baseline(
        df,
        exp_name="rf_baseline",
        outdir="outputs",
        model_name="rf",
        test_size=0.3,
        random_state=42,
        max_rows=None,
    )

    # Option 2: one-shot from dataset path
    train_baseline.train_from_dataset(
        dataset_path=Path("outputs/aggregated_flows.parquet"),
        exp_name="rf_baseline",
        outdir="outputs",
        model_name="rf",
        test_size=0.3,
        random_state=42,
        max_rows=None,
    )

Outputs:
    <outdir>/<exp-name>/ml/
        metrics.csv
        confusion_matrix.png
        model.pkl
"""

from __future__ import annotations

from pathlib import Path
import pickle
from typing import List, Union, Optional

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    HistGradientBoostingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


# ---------------- FEATURE SELECTION ---------------- #


def extract_feature_columns(df: pd.DataFrame) -> List[str]:
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


def load_dataset_from_path(dataset_path: Path) -> pd.DataFrame:
    """
    Load a dataset given a single file path.

    Supports:
        - CSV (.csv)
        - Parquet (.parquet)

    Args:
        dataset_path: Path to the dataset file.

    Returns:
        DataFrame containing the dataset.
    """
    dataset_path = Path(dataset_path)
    print(f"Loading dataset from: {dataset_path}")

    if not dataset_path.is_file():
        raise SystemExit(f"Dataset path does not exist or is not a file: {dataset_path}")

    if dataset_path.suffix == ".parquet":
        df = pd.read_parquet(dataset_path)
    elif dataset_path.suffix == ".csv":
        df = pd.read_csv(dataset_path)
    else:
        raise SystemExit("Unsupported dataset file format. Use CSV or Parquet.")

    print(f"Loaded {len(df)} rows with {len(df.columns)} columns.")
    return df


# ---------------- MODEL FACTORY ---------------- #


def _make_model(model_name: str, random_state: int):
    """
    Simple model factory.

    Currently supported model_name values:

        - "rf"   : RandomForestClassifier
        - "et"   : ExtraTreesClassifier
        - "gb"   : GradientBoostingClassifier
        - "hgb"  : HistGradientBoostingClassifier
        - "mlp"  : MLPClassifier
        - "logreg": LogisticRegression

    All models use sensible defaults; you can add model-specific
    hyperparameters here later if desired.
    """
    name = model_name.lower()

    if name == "rf":
        return RandomForestClassifier(
            n_estimators=200,
            random_state=random_state,
            n_jobs=-1,
        )

    if name == "et":
        return ExtraTreesClassifier(
            n_estimators=200,
            random_state=random_state,
            n_jobs=-1,
        )

    if name == "gb":
        return GradientBoostingClassifier(
            random_state=random_state,
        )

    if name == "hgb":
        return HistGradientBoostingClassifier(
            random_state=random_state,
        )

    if name == "mlp":
        # Simple MLP; you can tune later
        return MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation="relu",
            solver="adam",
            random_state=random_state,
            max_iter=200,
        )

    if name == "logreg":
        # "lbfgs" usually fine; multi_class="auto" handles multi-class
        return LogisticRegression(
            max_iter=1000,
            n_jobs=-1,
            random_state=random_state,
        )

    raise SystemExit(
        f"Unknown model '{model_name}'. Currently supported: "
        "'rf', 'et', 'gb', 'hgb', 'mlp', 'logreg'."
    )


# ---------------- TRAINING ---------------- #


def train_baseline(
    df: pd.DataFrame,
    exp_name: str = "baseline_experiment",
    outdir: Union[str, Path] = "outputs",
    model_name: str = "rf",
    test_size: float = 0.3,
    random_state: int = 42,
    max_rows: Optional[int] = None,
) -> None:
    """
    Train a baseline classifier on the given DataFrame.

    Args:
        df:
            DataFrame containing flow-level features and a 'device_type' column.
        exp_name:
            Name of the experiment (used to create the output subdirectory).
        outdir:
            Base output directory. Results are written to:
                <outdir>/<exp_name>/ml/
        model_name:
            Which model to use. Currently supported: 'rf' (RandomForest).
        test_size:
            Fraction of data used as validation set (0 < test_size < 1).
        random_state:
            Random seed for sampling and train/val split.
        max_rows:
            Optional maximum number of rows to use. If None, uses all rows.
            If set and df is larger, a random sample of size max_rows is used.
    """
    if "device_type" not in df.columns:
        raise SystemExit("Dataset must contain a 'device_type' column.")

    # Optional subsampling
    if max_rows is not None and len(df) > max_rows:
        print(f"Subsampling dataset from {len(df)} to {max_rows} rows (random_state={random_state})")
        df = df.sample(n=max_rows, random_state=random_state).reset_index(drop=True)

    feature_cols = extract_feature_columns(df)
    if not feature_cols:
        raise SystemExit("No usable feature columns found in dataset.")

    print(f"Using {len(feature_cols)} features: {feature_cols}")

    X = df[feature_cols]
    y = df["device_type"].astype(str)

    # Encode device_type
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Train-val split
    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y_enc,
        test_size=test_size,
        random_state=random_state,
        stratify=y_enc,
    )

    print(f"Training set size: {len(X_train)}, Validation set size: {len(X_val)}")

    # Model
    clf = _make_model(model_name=model_name, random_state=random_state)
    print(f"Training model '{model_name}'...")
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_val)
    acc = accuracy_score(y_val, y_pred)

    report = classification_report(
        y_val,
        y_pred,
        target_names=le.classes_,
        output_dict=True,
        zero_division=0,
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

    # Confusion matrix plot (matplotlib only)
    cm_path = exp_root / "confusion_matrix.png"
    plt.figure(figsize=(7, 5))
    im = plt.imshow(cm, interpolation="nearest")
    plt.colorbar(im, fraction=0.046, pad=0.04)

    num_classes = len(le.classes_)
    tick_positions = np.arange(num_classes)

    plt.xticks(tick_positions, le.classes_, rotation=45, ha="right")
    plt.yticks(tick_positions, le.classes_)

    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.title(f"Confusion Matrix (model={model_name}, Acc={acc:.3f})")

    # Annotate cells
    for i in range(num_classes):
        for j in range(num_classes):
            plt.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center",
            )

    plt.tight_layout()
    plt.savefig(cm_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved confusion matrix: {cm_path}")

    # Save model
    model_path = exp_root / "model.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(
            {
                "model": clf,
                "label_encoder": le,
                "features": feature_cols,
                "model_name": model_name,
                "test_size": test_size,
                "random_state": random_state,
                "max_rows": max_rows,
            },
            f,
        )
    print(f"Saved model: {model_path}")

    print("\n=== TRAINING COMPLETE ===")
    print(f"Accuracy: {acc:.4f}")
    print(f"Classes: {list(le.classes_)}")
    print(f"Results in: {exp_root}")


def train_from_dataset(
    dataset_path: Path,
    exp_name: str = "baseline_experiment",
    outdir: Union[str, Path] = "outputs",
    model_name: str = "rf",
    test_size: float = 0.3,
    random_state: int = 42,
    max_rows: Optional[int] = None,
) -> None:
    """
    Convenience wrapper: load a dataset from a single file path and train.

    Args:
        dataset_path:
            Path to a CSV or Parquet dataset file.
        exp_name:
            Experiment name (used in output path).
        outdir:
            Base output directory.
        model_name:
            Which model to use (currently: 'rf').
        test_size:
            Fraction of data used as validation set.
        random_state:
            Random seed.
        max_rows:
            Optional maximum number of rows to use.
    """
    df = load_dataset_from_path(dataset_path)
    train_baseline(
        df,
        exp_name=exp_name,
        outdir=outdir,
        model_name=model_name,
        test_size=test_size,
        random_state=random_state,
        max_rows=max_rows,
    )
