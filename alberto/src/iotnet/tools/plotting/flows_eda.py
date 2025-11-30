"""
flows_eda.py

EDA for flow CSVs (single PCAP flow file or aggregated flows).

This module is library-style (no argparse). Entry points:

- flows_basic_eda(csv_path: str, pcap_name: str, outdir: str)
- process_single_csv(csv_path: Path, pcap_name: str, outdir: str)
- run_eda(dataset_path: Path, output_dir: Path)
"""

from collections import Counter
from pathlib import Path
import csv
import time
from typing import List

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd


def _save_fig(path: Path) -> None:
    """
    Convenience to tighten layout and save current figure to the given path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")


def flows_basic_eda(csv_path: str, pcap_name: str, outdir: str) -> None:
    """
    Run EDA on a single flow CSV and write summary + plots to:
        <outdir>/<pcap_stem>/

    This is suitable both for:
    - per-PCAP flow files (flows_labeled.csv)
    - aggregated flow files (e.g. aggregated_flows_known.csv),
      in which case pcap_name can just be the dataset filename.
    """
    csv_path = Path(csv_path)
    pcap_stem = Path(pcap_name).stem

    out_root = Path(outdir) / pcap_stem
    out_root.mkdir(parents=True, exist_ok=True)

    # Load CSV
    df = pd.read_csv(csv_path)

    summary_csv_path = out_root / "flows_summary.csv"

    # -------- CSV summary ----------
    with summary_csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])

        w.writerow(["flow_csv", csv_path.name])
        w.writerow(["pcap_name_or_dataset", pcap_name])
        w.writerow(["total_flows", len(df)])

        numeric_cols: List[str] = [
            c for c in df.columns if np.issubdtype(df[c].dtype, np.number)
        ]
        for col in numeric_cols:
            col_series = df[col].dropna()
            if col_series.empty:
                continue
            w.writerow([f"{col}_mean", col_series.mean()])
            w.writerow([f"{col}_median", col_series.median()])
            w.writerow([f"{col}_std", col_series.std()])
            w.writerow([f"{col}_min", col_series.min()])
            w.writerow([f"{col}_max", col_series.max()])

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

    # -------- Global plots ----------

    # 1) Flow duration distribution (global)
    if "duration" in df.columns:
        plt.figure()
        plt.hist(df["duration"].dropna(), bins=80)
        plt.xlabel("Duration (s)")
        plt.ylabel("Count")
        plt.title(f"Flow duration distribution\n{pcap_stem}")
        _save_fig(out_root / "flows_duration_hist.png")

    # 2) Total bytes distribution (global, log-scaled)
    if "total_bytes" in df.columns:
        plt.figure()
        # avoid log of zeros
        data = df["total_bytes"].dropna()
        data = data[data > 0]
        if not data.empty:
            plt.hist(data, bins=80)
            plt.xscale("log")
        plt.xlabel("Total bytes (log scale)")
        plt.ylabel("Count")
        plt.title(f"Flow size distribution\n{pcap_stem}")
        _save_fig(out_root / "flows_total_bytes_hist.png")

    # 3) Duration vs Total Bytes (global)
    if {"duration", "total_bytes"} <= set(df.columns):
        x = np.log1p(df["duration"].fillna(0))
        y = np.log1p(df["total_bytes"].fillna(0))
        plt.figure()
        plt.scatter(x, y, s=5, alpha=0.3)
        plt.xlabel("log(1 + duration)")
        plt.ylabel("log(1 + total_bytes)")
        plt.title(f"Duration vs Total Bytes\n{pcap_stem}")
        _save_fig(out_root / "flows_duration_vs_bytes.png")

    # 4) IAT-related plots (global) if available
    if "mean_iat" in df.columns:
        plt.figure()
        mean_iat = df["mean_iat"].dropna()
        plt.hist(mean_iat, bins=80)
        plt.xlabel("Mean inter-arrival time (s)")
        plt.ylabel("Count")
        plt.title(f"Flow mean IAT distribution\n{pcap_stem}")
        _save_fig(out_root / "flows_mean_iat_hist.png")

    # -------- Per-device-type plots ----------

    if "device_type" in df.columns and not df["device_type"].isna().all():
        # Device type counts
        counts = df["device_type"].value_counts()
        plt.figure()
        positions = np.arange(len(counts))
        plt.bar(positions, counts.values)
        plt.xticks(positions, counts.index, rotation=45, ha="right")
        plt.ylabel("Flow count")
        plt.title(f"Flows per device type\n{pcap_stem}")
        _save_fig(out_root / "flows_device_type_counts.png")

        # Choose top N device types for detailed plots
        top_device_types = list(counts.index[:6])

        # Duration vs Total Bytes by device type (existing behavior)
        if {"duration", "total_bytes"} <= set(df.columns):
            plt.figure()
            for dev in top_device_types:
                g = df[df["device_type"] == dev]
                if g.empty:
                    continue
                x = np.log1p(g["duration"].fillna(0))
                y = np.log1p(g["total_bytes"].fillna(0))
                plt.scatter(x, y, s=6, alpha=0.4, label=dev)
            plt.xlabel("log(1 + duration)")
            plt.ylabel("log(1 + total_bytes)")
            plt.title(f"Duration vs Total Bytes by Device Type\n{pcap_stem}")
            plt.legend()
            _save_fig(out_root / "flows_duration_vs_bytes_by_device.png")

        # Duration distribution by device type
        if "duration" in df.columns:
            plt.figure()
            for dev in top_device_types:
                g = df[df["device_type"] == dev]
                if g.empty:
                    continue
                plt.hist(
                    g["duration"].dropna(),
                    bins=60,
                    alpha=0.5,
                    histtype="stepfilled",
                    label=dev,
                )
            plt.xlabel("Duration (s)")
            plt.ylabel("Count")
            plt.title(f"Flow duration by device type\n{pcap_stem}")
            plt.legend()
            _save_fig(out_root / "flows_duration_by_device_type.png")

        # Total bytes distribution by device type (log)
        if "total_bytes" in df.columns:
            plt.figure()
            for dev in top_device_types:
                g = df[df["device_type"] == dev]
                if g.empty:
                    continue
                data = g["total_bytes"].dropna()
                data = data[data > 0]
                if data.empty:
                    continue
                plt.hist(
                    data,
                    bins=60,
                    alpha=0.5,
                    histtype="stepfilled",
                    label=dev,
                )
            plt.xscale("log")
            plt.xlabel("Total bytes (log scale)")
            plt.ylabel("Count")
            plt.title(f"Flow size by device type\n{pcap_stem}")
            plt.legend()
            _save_fig(out_root / "flows_total_bytes_by_device_type.png")

        # Mean IAT distribution by device type
        if "mean_iat" in df.columns:
            plt.figure()
            for dev in top_device_types:
                g = df[df["device_type"] == dev]
                if g.empty:
                    continue
                data = g["mean_iat"].dropna()
                if data.empty:
                    continue
                plt.hist(
                    data,
                    bins=60,
                    alpha=0.5,
                    histtype="stepfilled",
                    label=dev,
                )
            plt.xlabel("Mean inter-arrival time (s)")
            plt.ylabel("Count")
            plt.title(f"Flow mean IAT by device type\n{pcap_stem}")
            plt.legend()
            _save_fig(out_root / "flows_mean_iat_by_device_type.png")

        # total_pkts vs mean_iat by device type
        if {"total_pkts", "mean_iat"} <= set(df.columns):
            plt.figure()
            for dev in top_device_types:
                g = df[df["device_type"] == dev]
                if g.empty:
                    continue
                x = np.log1p(g["total_pkts"].fillna(0))
                y = np.log1p(g["mean_iat"].fillna(0))
                plt.scatter(x, y, s=6, alpha=0.4, label=dev)
            plt.xlabel("log(1 + total_pkts)")
            plt.ylabel("log(1 + mean_iat)")
            plt.title(f"Total packets vs mean IAT by device type\n{pcap_stem}")
            plt.legend()
            _save_fig(out_root / "flows_total_pkts_vs_mean_iat_by_device.png")


def process_single_csv(csv_path: Path, pcap_name: str, outdir: str) -> None:
    """
    Wrapper to run EDA on a single flows CSV with timing.
    """
    start = time.time()
    flows_basic_eda(str(csv_path), pcap_name, outdir)
    elapsed = time.time() - start
    print(f"[{Path(pcap_name).stem}] flows EDA completed in {elapsed:.2f}s")


def run_eda(dataset_path: Path, output_dir: Path) -> None:
    """
    Convenience wrapper intended for CLI use.

    dataset_path:
        Path to a flows CSV (per-PCAP or aggregated).
    output_dir:
        Base directory where EDA outputs will be written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    # Use the dataset filename as "pcap_name" identifier in outputs.
    process_single_csv(dataset_path, dataset_path.name, str(output_dir))
