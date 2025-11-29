#!/usr/bin/env python3
"""
src/main.py

Unified CLI wrapper around the project tools.

Example usage:

    # Single PCAP full pipeline (flows + pcap EDA + flows EDA)
    python -m src.main pipeline \
        --pcap dataset/pcapIoT/52093085_IoT_2023-07-12.pcap \
        --mac-csv dataset/CSVs/macAddresses.csv

    # Just generate labeled flows for one PCAP
    python -m src.main flows \
        --pcap dataset/pcapIoT/52093085_IoT_2023-07-12.pcap \
        --mac-csv dataset/CSVs/macAddresses.csv

    # Batch generate labeled flows for all PCAPs in a directory
    python -m src.main batch-flows \
        --pcap-dir kk-prueba-pcap_to_flows_dir \
        --mac-csv dataset/CSVs/macAddresses.csv

    # Aggregate all flows_labeled.csv under outputs/ into one dataset
    python -m src.main aggregate \
        --root outputs \
        --csv-name flows_labeled.csv \
        --out-prefix aggregated_flows_all \
        --skip-unknown

    # Train baseline model from aggregated dataset
    python -m src.main train \
        --dataset outputs/aggregated_flows_all.parquet \
        --exp-name rf_on_aggregated
"""

import argparse
from pathlib import Path
import time

# Local imports of your existing tools
from .tools.pcap_to_labeled_flows import process_single_pcap as pcap_to_labeled_flows_single
from .tools.plotting.pcap_eda import process_single_pcap as pcap_eda_single
from .tools.plotting.flows_eda import process_single_csv as flows_eda_single
from .tools.ml.aggregate_flows import aggregate_flows
from .tools.ml.train_baseline import load_dataset, train_baseline


# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------

def cmd_flows(args: argparse.Namespace) -> None:
    """Generate labeled flows for a single pcap."""
    pcap_path = Path(args.pcap)
    pcap_to_labeled_flows_single(pcap_path, args.mac_csv, out_csv=args.out)


def cmd_pcap_eda(args: argparse.Namespace) -> None:
    """Run EDA on a single pcap."""
    pcap_eda_single(Path(args.pcap), args.mac_csv, args.outdir)


def cmd_flows_eda(args: argparse.Namespace) -> None:
    """Run EDA on a single flows_labeled.csv corresponding to a pcap."""
    pcap_stem = Path(args.pcap_name).stem
    csv_path = Path(args.csv) if args.csv else Path(args.outdir) / pcap_stem / "flows_labeled.csv"
    flows_eda_single(csv_path, args.pcap_name, args.outdir)


def cmd_pipeline(args: argparse.Namespace) -> None:
    """
    Run the full pipeline for a single pcap:
      - labeled flows
      - pcap EDA
      - flows EDA
    """
    pcap = Path(args.pcap)
    mac_csv = args.mac_csv
    outdir = args.outdir

    print(f"[PIPELINE] PCAP = {pcap}")
    start = time.time()

    print("[1/3] Generating labeled flows...")
    pcap_to_labeled_flows_single(pcap, mac_csv, out_csv=None)

    print("[2/3] Running PCAP EDA...")
    pcap_eda_single(pcap, mac_csv, outdir)

    print("[3/3] Running flows EDA...")
    pcap_name = str(pcap)  # flows_eda expects the original pcap filename
    pcap_stem = pcap.stem
    csv_path = Path(outdir) / pcap_stem / "flows_labeled.csv"
    flows_eda_single(csv_path, pcap_name, outdir)

    elapsed = time.time() - start
    print(f"[PIPELINE] Completed in {elapsed:.2f}s")


def cmd_batch_flows(args: argparse.Namespace) -> None:
    """Generate labeled flows for all pcaps in a directory (non-recursive)."""
    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.is_dir():
        raise SystemExit(f"{pcap_dir} is not a directory")

    pcaps = sorted(p for p in pcap_dir.iterdir() if p.suffix.lower() == ".pcap")
    if not pcaps:
        raise SystemExit(f"No .pcap files found in {pcap_dir}")

    print(f"[batch-flows] Found {len(pcaps)} pcaps in {pcap_dir}")
    batch_start = time.time()
    for pcap_path in pcaps:
        pcap_to_labeled_flows_single(pcap_path, args.mac_csv, out_csv=None)
    elapsed = time.time() - batch_start
    print(f"[batch-flows] Completed in {elapsed:.2f}s")


def cmd_batch_pcap_eda(args: argparse.Namespace) -> None:
    """Run pcap EDA for all pcaps in a directory."""
    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.is_dir():
        raise SystemExit(f"{pcap_dir} is not a directory")

    pcaps = sorted(p for p in pcap_dir.iterdir() if p.suffix.lower() == ".pcap")
    if not pcaps:
        raise SystemExit(f"No .pcap files found in {pcap_dir}")

    print(f"[batch-pcap-eda] Found {len(pcaps)} pcaps in {pcap_dir}")
    batch_start = time.time()
    for pcap_path in pcaps:
        pcap_eda_single(pcap_path, args.mac_csv, args.outdir)
    elapsed = time.time() - batch_start
    print(f"[batch-pcap-eda] Completed in {elapsed:.2f}s")


def cmd_batch_flows_eda(args: argparse.Namespace) -> None:
    """
    Run flows EDA for all subdirectories under --root (typically outputs/),
    expecting each subdir to have a flows_labeled.csv.
    """
    root = Path(args.root)
    if not root.is_dir():
        raise SystemExit(f"{root} is not a directory")

    subdirs = [d for d in root.iterdir() if d.is_dir()]
    print(f"[batch-flows-eda] Found {len(subdirs)} candidate subdirs in {root}")

    batch_start = time.time()
    processed = 0
    for subdir in sorted(subdirs):
        csv_path = subdir / args.csv_name
        if not csv_path.is_file():
            print(f"[WARN] No {args.csv_name} in {subdir}, skipping.")
            continue

        pcap_name = f"{subdir.name}.pcap"
        flows_eda_single(csv_path, pcap_name, args.outdir)
        processed += 1

    elapsed = time.time() - batch_start
    print(f"[batch-flows-eda] Processed {processed} subdirs in {elapsed:.2f}s")


def cmd_aggregate(args: argparse.Namespace) -> None:
    """Aggregate flows_labeled.csv files into a single ML-ready dataset."""
    aggregate_flows(
        root=args.root,
        csv_name=args.csv_name,
        out_prefix=args.out_prefix,
        skip_unknown=args.skip_unknown,
        outdir=args.outdir,
    )


def cmd_train(args: argparse.Namespace) -> None:
    """Train baseline RandomForest classifier."""
    df = load_dataset(args)
    train_baseline(df, exp_name=args.exp_name, outdir=args.outdir)


def cmd_batch_all(args: argparse.Namespace) -> None:
    """
    Full batch pipeline:
      - batch-flows
      - aggregate
      - train
    """
    # 1) batch flows
    cmd_batch_flows(args)

    # 2) aggregate
    agg_args = argparse.Namespace(
        root=args.outdir,
        csv_name=args.csv_name,
        out_prefix=args.out_prefix,
        skip_unknown=args.skip_unknown,
        outdir=args.outdir,
    )
    cmd_aggregate(agg_args)

    # 3) train
    dataset_path = Path(args.outdir) / f"{args.out_prefix}.parquet"
    train_args = argparse.Namespace(
        dataset=str(dataset_path),
        csv=None,
        csv_dir=None,
        csv_name=args.csv_name,
        exp_name=args.exp_name,
        outdir=args.outdir,
    )
    cmd_train(train_args)


# --------------------------------------------------------------------
# Main CLI setup
# --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Unified CLI for IoT flow/ML pipeline.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- flows ----
    p_flows = subparsers.add_parser("flows", help="Generate labeled flows for a single pcap.")
    p_flows.add_argument("--pcap", required=True, help="Path to PCAP file")
    p_flows.add_argument("--mac-csv", required=True, help="Path to macAddresses.csv")
    p_flows.add_argument("--out", help="Optional explicit output CSV path")
    p_flows.set_defaults(func=cmd_flows)

    # ---- pcap-eda ----
    p_pcap_eda = subparsers.add_parser("pcap-eda", help="Run EDA on a single PCAP.")
    p_pcap_eda.add_argument("--pcap", required=True, help="Path to PCAP file")
    p_pcap_eda.add_argument("--mac-csv", help="Path to macAddresses.csv", default=None)
    p_pcap_eda.add_argument("--outdir", default="outputs", help="Base output directory")
    p_pcap_eda.set_defaults(func=cmd_pcap_eda)

    # ---- flows-eda ----
    p_flows_eda = subparsers.add_parser("flows-eda", help="Run EDA on a single flows CSV.")
    p_flows_eda.add_argument("--pcap-name", required=True, help="Original PCAP filename (for naming).")
    p_flows_eda.add_argument("--csv", help="Path to flows CSV (default: outputs/<pcap_stem>/flows_labeled.csv)")
    p_flows_eda.add_argument("--outdir", default="outputs", help="Base output directory")
    p_flows_eda.set_defaults(func=cmd_flows_eda)

    # ---- pipeline (single pcap full pipeline) ----
    p_pipeline = subparsers.add_parser("pipeline", help="Run full pipeline for a single PCAP.")
    p_pipeline.add_argument("--pcap", required=True, help="Path to PCAP file")
    p_pipeline.add_argument("--mac-csv", required=True, help="Path to macAddresses.csv")
    p_pipeline.add_argument("--outdir", default="outputs", help="Base output directory")
    p_pipeline.set_defaults(func=cmd_pipeline)

    # ---- batch-flows ----
    p_bflows = subparsers.add_parser("batch-flows", help="Generate labeled flows for all pcaps in a directory.")
    p_bflows.add_argument("--pcap-dir", required=True, help="Directory with PCAP files")
    p_bflows.add_argument("--mac-csv", required=True, help="Path to macAddresses.csv")
    p_bflows.set_defaults(func=cmd_batch_flows)

    # ---- batch-pcap-eda ----
    p_bpeda = subparsers.add_parser("batch-pcap-eda", help="Run PCAP EDA for all pcaps in a directory.")
    p_bpeda.add_argument("--pcap-dir", required=True, help="Directory with PCAP files")
    p_bpeda.add_argument("--mac-csv", help="Path to macAddresses.csv", default=None)
    p_bpeda.add_argument("--outdir", default="outputs", help="Base output directory")
    p_bpeda.set_defaults(func=cmd_batch_pcap_eda)

    # ---- batch-flows-eda ----
    p_bfeda = subparsers.add_parser("batch-flows-eda", help="Run flows EDA for all subdirs under a root (e.g. outputs/).")
    p_bfeda.add_argument("--root", default="outputs", help="Root directory containing per-pcap subdirs")
    p_bfeda.add_argument("--csv-name", default="flows_labeled.csv", help="Flow CSV filename in each subdir")
    p_bfeda.add_argument("--outdir", default="outputs", help="Base output directory")
    p_bfeda.set_defaults(func=cmd_batch_flows_eda)

    # ---- aggregate ----
    p_agg = subparsers.add_parser("aggregate", help="Aggregate flows CSVs into a single dataset.")
    p_agg.add_argument("--root", default="outputs", help="Root directory with per-pcap subdirs")
    p_agg.add_argument("--csv-name", default="flows_labeled.csv", help="Flow CSV filename to look for")
    p_agg.add_argument("--out-prefix", default="aggregated_flows_all", help="Output prefix (no extension)")
    p_agg.add_argument("--outdir", default="outputs", help="Directory to write aggregated outputs")
    p_agg.add_argument(
        "--skip-unknown",
        action="store_true",
        help="If set, drop rows where device_type == 'unknown'.",
    )
    p_agg.set_defaults(func=cmd_aggregate)

    # ---- train ----
    p_train = subparsers.add_parser("train", help="Train baseline model.")
    p_train.add_argument("--dataset", help="Single aggregated dataset (.csv or .parquet)")
    p_train.add_argument("--csv", action="append", help="One or more flow CSVs (alternative to --dataset)")
    p_train.add_argument("--csv-dir", help="Directory containing per-pcap subdirs with flow CSVs")
    p_train.add_argument("--csv-name", default="flows_labeled.csv", help="Flow CSV filename in each subdir (for --csv-dir)")
    p_train.add_argument("--exp-name", default="baseline_experiment", help="Experiment name")
    p_train.add_argument("--outdir", default="outputs", help="Base output directory")
    p_train.set_defaults(func=cmd_train)

    # ---- batch-all ----
    p_ball = subparsers.add_parser("batch-all", help="Full batch pipeline: batch-flows + aggregate + train.")
    p_ball.add_argument("--pcap-dir", required=True, help="Directory with PCAP files")
    p_ball.add_argument("--mac-csv", required=True, help="Path to macAddresses.csv")
    p_ball.add_argument("--outdir", default="outputs", help="Base output directory")
    p_ball.add_argument("--csv-name", default="flows_labeled.csv", help="Flow CSV filename in each subdir")
    p_ball.add_argument("--out-prefix", default="aggregated_flows_all", help="Aggregated dataset prefix")
    p_ball.add_argument("--skip-unknown", action="store_true", help="Drop device_type == 'unknown'")
    p_ball.add_argument("--exp-name", default="baseline_experiment", help="Experiment name for training")
    p_ball.set_defaults(func=cmd_batch_all)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
