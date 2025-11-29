#!/usr/bin/env python3
"""
flows_eda.py  (CSV summary version)

EDA for flow CSVs.

Single-file mode:
    python -m src.tools.plotting.flows_eda \
        --csv outputs/foo/flows_labeled.csv \
        --pcap-name foo.pcap \
        --outdir outputs

Batch mode (all subdirs under a root dir, e.g. outputs/):
    python -m src.tools.plotting.flows_eda \
        --csv-dir outputs \
        --outdir outputs

In batch mode, it assumes a structure like:
    <csv-dir>/<pcap_name>/flows_labeled.csv
and writes EDA outputs to:
    <outdir>/<pcap_name>/...
"""

import argparse
from collections import Counter
from pathlib import Path
import csv
import time

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd


def flows_basic_eda(csv_path: str, pcap_name: str, outdir: str):
    """
    Run EDA on a single flow CSV and write summary + plots to:
        <outdir>/<pcap_stem>/
    """
    csv_path = Path(csv_path)
    pcap_stem = Path(pcap_name).stem

    out_root = Path(outdir) / pcap_stem
    out_root.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)
    summary_csv_path = out_root / "flows_summary.csv"

    # -------- CSV summary ----------
    with summary_csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])

        w.writerow(["flow_csv", csv_path.name])
        w.writerow(["pcap_name", pcap_name])
        w.writerow(["total_flows", len(df)])

        numeric_cols = [
            c for c in df.columns if np.issubdtype(df[c].dtype, np.number)
        ]
        for col in numeric_cols:
            w.writerow([f"{col}_mean", df[col].mean()])
            w.writerow([f"{col}_median", df[col].median()])
            w.writerow([f"{col}_std", df[col].std()])
            w.writerow([f"{col}_min", df[col].min()])
            w.writerow([f"{col}_max", df[col].max()])

        if "src_ip" in df.columns:
            for ip, count in Counter(df["src_ip"]).most_common(10):
                w.writerow([f"top_src_ip__{ip}", count])
        if "dst_ip" in df.columns:
            for ip, count in Counter(df["dst_ip"]).most_common(10):
                w.writerow([f"top_dst_ip__{ip}", count])

        if "src_port" in df.columns:
            for p, count in Counter(df["src_port"]).most_common(10):
                w.writerow([f"top_src_port__{p}", count])
        if "dst_port" in df.columns:
            for p, count in Counter(df["dst_port"]).most_common(10):
                w.writerow([f"top_dst_port__{p}", count])

        if "device_type" in df.columns:
            for dev, count in Counter(df["device_type"]).most_common():
                w.writerow([f"device_type__{dev}", count])

    print(f"[{pcap_stem}] Saved CSV summary: {summary_csv_path}")

    # -------- Plots ----------

    if "duration" in df.columns:
        plt.figure()
        plt.hist(df["duration"], bins=80)
        plt.xlabel("Duration (s)")
        plt.ylabel("Count")
        plt.title("Flow duration distribution")
        plt.tight_layout()
        out_path = out_root / "flows_duration_hist.png"
        plt.savefig(out_path)
        plt.close()
        print(f"[{pcap_stem}] Saved: {out_path}")

    if "total_bytes" in df.columns:
        plt.figure()
        plt.hist(df["total_bytes"], bins=80)
        plt.xscale("log")
        plt.xlabel("Total bytes (log)")
        plt.ylabel("Count")
        plt.title("Flow size distribution")
        plt.tight_layout()
        out_path = out_root / "flows_total_bytes_hist.png"
        plt.savefig(out_path)
        plt.close()
        print(f"[{pcap_stem}] Saved: {out_path}")

    if {"duration", "total_bytes"} <= set(df.columns):
        x = np.log1p(df["duration"])
        y = np.log1p(df["total_bytes"])
        plt.figure()
        plt.scatter(x, y, s=5, alpha=0.3)
        plt.xlabel("log(1 + duration)")
        plt.ylabel("log(1 + total_bytes)")
        plt.title("Duration vs Total Bytes")
        plt.tight_layout()
        out_path = out_root / "flows_duration_vs_bytes.png"
        plt.savefig(out_path)
        plt.close()
        print(f"[{pcap_stem}] Saved: {out_path}")

    if {"duration", "total_bytes", "device_type"} <= set(df.columns):
        plt.figure()
        for dev, g in df.groupby("device_type"):
            x = np.log1p(g["duration"])
            y = np.log1p(g["total_bytes"])
            plt.scatter(x, y, s=6, alpha=0.4, label=dev)
        plt.xlabel("log(1 + duration)")
        plt.ylabel("log(1 + total_bytes)")
        plt.title("Duration vs Total Bytes by Device Type")
        plt.legend()
        plt.tight_layout()
        out_path = out_root / "flows_duration_vs_bytes_by_device.png"
        plt.savefig(out_path)
        plt.close()
        print(f"[{pcap_stem}] Saved: {out_path}")


def process_single_csv(csv_path: Path, pcap_name: str, outdir: str):
    """
    Wrapper to run EDA on a single flows CSV with timing.
    """
    start = time.time()
    flows_basic_eda(str(csv_path), pcap_name, outdir)
    elapsed = time.time() - start
    print(f"[{Path(pcap_name).stem}] flows EDA completed in {elapsed:.2f}s")


def main():
    parser = argparse.ArgumentParser(description="Flow CSV EDA (single or batch).")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--csv",
        help="Path to a single flow CSV file (e.g. outputs/foo/flows_labeled.csv)"
    )
    group.add_argument(
        "--csv-dir",
        help=(
            "Directory containing per-pcap subdirectories with flow CSVs "
            "(e.g. outputs/ with outputs/foo/flows_labeled.csv, outputs/bar/flows_labeled.csv, ...)"
        )
    )

    parser.add_argument(
        "--pcap-name",
        help=(
            "Original pcap filename (e.g. foo.pcap). "
            "Required in single-file mode."
        )
    )
    parser.add_argument("--outdir", default="outputs", help="Base output directory")
    parser.add_argument(
        "--csv-name",
        default="flows_labeled.csv",
        help="Flow CSV filename to look for inside each subdirectory in batch mode "
             "(default: flows_labeled.csv)"
    )

    args = parser.parse_args()

    # Single-file mode
    if args.csv:
        if not args.pcap_name:
            raise SystemExit("--pcap-name is required when using --csv")
        csv_path = Path(args.csv)
        process_single_csv(csv_path, args.pcap_name, args.outdir)
        return

    # Batch mode
    csv_dir = Path(args.csv_dir)
    if not csv_dir.is_dir():
        raise SystemExit(f"{csv_dir} is not a directory")

    subdirs = [p for p in csv_dir.iterdir() if p.is_dir()]
    if not subdirs:
        raise SystemExit(f"No subdirectories found in {csv_dir}")

    print(f"Found {len(subdirs)} subdirectories under {csv_dir}. Starting batch flows EDA...")

    batch_start = time.time()
    processed = 0

    for subdir in sorted(subdirs):
        csv_path = subdir / args.csv_name
        if not csv_path.is_file():
            print(f"[WARN] No {args.csv_name} in {subdir}, skipping.")
            continue

        # pcap_name inferred from subdirectory name
        pcap_name = f"{subdir.name}.pcap"
        process_single_csv(csv_path, pcap_name, args.outdir)
        processed += 1

    batch_elapsed = time.time() - batch_start
    print(f"Batch flows EDA completed for {processed} item(s) in {batch_elapsed:.2f}s")


if __name__ == "__main__":
    main()
