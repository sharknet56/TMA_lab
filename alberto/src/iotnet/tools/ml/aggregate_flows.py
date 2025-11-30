"""
aggregate_flows.py

Aggregate multiple flows_labeled.csv files into a single ML-ready dataset.

Assumes directory structure like:
    <root>/
        foo/
            flows_labeled.csv
        bar/
            flows_labeled.csv
        ...

Core API:

    aggregate_flows(
        root: str | Path,
        csv_name: str = "flows_labeled.csv",
        out_prefix: str = "aggregated_flows",
        skip_unknown: bool = False,
        outdir: str | Path = "outputs",
    )

This will produce:
    <outdir>/<out_prefix>.csv
    <outdir>/<out_prefix>.parquet
    <outdir>/<out_prefix>_summary.csv
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Union

import pandas as pd


def aggregate_flows(
    root: Union[str, Path],
    csv_name: str = "flows_labeled.csv",
    out_prefix: str = "aggregated_flows",
    skip_unknown: bool = False,
    outdir: Union[str, Path] = "outputs",
) -> None:
    """
    Aggregate all <csv_name> files under <root>/<pcap_name>/ into a single dataset.

    Args:
        root:
            Root directory containing per-PCAP subdirectories with flow CSVs.
        csv_name:
            Flow CSV filename to look for inside each subdirectory
            (default: "flows_labeled.csv").
        out_prefix:
            Prefix for the output dataset files
            (default: "aggregated_flows").
        skip_unknown:
            If True, drop rows where device_type == "unknown" before aggregating.
        outdir:
            Directory to write aggregated outputs to (default: "outputs").

    Produces:
        <outdir>/<out_prefix>.csv
        <outdir>/<out_prefix>.parquet
        <outdir>/<out_prefix>_summary.csv
    """
    root_path = Path(root)
    if not root_path.is_dir():
        raise SystemExit(f"{root_path} is not a directory")

    subdirs: List[Path] = [p for p in root_path.iterdir() if p.is_dir()]
    if not subdirs:
        raise SystemExit(f"No subdirectories found in {root_path}")

    print(f"Scanning {len(subdirs)} subdirectories under {root_path} for {csv_name}...")

    dfs: List[pd.DataFrame] = []
    for subdir in sorted(subdirs):
        csv_path = subdir / csv_name
        if not csv_path.is_file():
            print(f"[WARN] No {csv_name} in {subdir}, skipping.")
            continue

        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            print(f"[ERROR] Failed to read {csv_path}: {e}")
            continue

        # Assume subdir name == pcap_name without .pcap
        pcap_name = subdir.name
        df["pcap_name"] = pcap_name
        df["source_csv_path"] = str(csv_path)

        if skip_unknown and "device_type" in df.columns:
            before = len(df)
            df = df[df["device_type"] != "unknown"]
            after = len(df)
            print(f"[{pcap_name}] Filtered unknown device_type: {before} -> {after} rows")

        dfs.append(df)
        print(f"[{pcap_name}] Loaded {len(df)} rows from {csv_path}")

    if not dfs:
        raise SystemExit("No CSVs loaded; nothing to aggregate.")

    data = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal aggregated rows: {len(data)}")

    outdir_path = Path(outdir)
    outdir_path.mkdir(parents=True, exist_ok=True)

    csv_out = outdir_path / f"{out_prefix}.csv"
    parquet_out = outdir_path / f"{out_prefix}.parquet"
    summary_out = outdir_path / f"{out_prefix}_summary.csv"

    # Save main dataset (CSV)
    data.to_csv(csv_out, index=False)

    # Save as Parquet if possible
    try:
        data.to_parquet(parquet_out, index=False)
        parquet_status = "OK"
    except Exception as e:
        parquet_status = f"FAILED ({e})"

    print(f"Saved aggregated CSV to: {csv_out}")
    print(f"Saved aggregated Parquet to: {parquet_out} [{parquet_status}]")

    # Build and save summary
    summary_rows = []

    # Per device_type (global)
    if "device_type" in data.columns:
        counts = data["device_type"].value_counts()
        for dev, count in counts.items():
            summary_rows.append({
                "level": "global",
                "metric": f"device_type__{dev}",
                "value": int(count),
            })

    # Per pcap_name and device_type
    if {"pcap_name", "device_type"} <= set(data.columns):
        grouped = data.groupby(["pcap_name", "device_type"]).size()
        for (pcap_name, dev), count in grouped.items():
            summary_rows.append({
                "level": "per_pcap",
                "pcap_name": pcap_name,
                "metric": f"device_type__{dev}",
                "value": int(count),
            })

    # Overall row count
    summary_rows.append({
        "level": "global",
        "metric": "total_rows",
        "value": int(len(data)),
    })

    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(summary_out, index=False)
    print(f"Saved summary to: {summary_out}")
