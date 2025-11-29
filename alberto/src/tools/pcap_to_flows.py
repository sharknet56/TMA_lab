#!/usr/bin/env python3
"""
src/tools/pcap_to_flows.py

CLI wrapper to convert PCAP file(s) into flow records, saving them to:
    outputs/<pcap_name>/flows.csv     (default per file)

Supports:
    --pcap <file>
    --pcap-dir <directory>

Usage:
    # Single PCAP
    python -m src.tools.pcap_to_flows --pcap path/to/file.pcap

    # Batch mode
    python -m src.tools.pcap_to_flows --pcap-dir dataset/pcapIoT
"""

import argparse
import csv
import time
from pathlib import Path

from ..utils.flow_builder import pcap_to_flows


def process_single_pcap(pcap_path: Path, timeout: float, out_csv: Path | None = None):
    """
    Process a single PCAP file and save flows.csv.
    If out_csv is None → outputs/<pcap_name>/flows.csv
    """
    pcap_name = pcap_path.stem

    start = time.time()

    if out_csv is None:
        outdir = Path("outputs") / pcap_name
        outdir.mkdir(parents=True, exist_ok=True)
        out_csv = outdir / "flows.csv"
    else:
        out_csv = Path(out_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)

    writer = None
    count = 0

    with out_csv.open("w", newline="") as f:
        for flow in pcap_to_flows(str(pcap_path), flow_timeout=timeout):
            if writer is None:
                writer = csv.DictWriter(f, fieldnames=list(flow.keys()))
                writer.writeheader()
            writer.writerow(flow)
            count += 1

    elapsed = time.time() - start
    print(f"[{pcap_name}] Saved {count} flows to {out_csv} (elapsed: {elapsed:.2f}s)")


def main():
    parser = argparse.ArgumentParser(description="Extract flows from PCAP file(s).")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", help="Single PCAP file path")
    group.add_argument("--pcap-dir", help="Directory containing multiple PCAP files")

    parser.add_argument("--out", help="Output CSV path (only for --pcap)")
    parser.add_argument("--timeout", type=float, default=60.0, help="Flow timeout (seconds)")

    args = parser.parse_args()

    # ========== Single file mode ==========
    if args.pcap:
        pcap_path = Path(args.pcap)
        process_single_pcap(pcap_path, timeout=args.timeout, out_csv=args.out)
        return

    # ========== Batch mode ==========
    pcap_dir = Path(args.pcap_dir)

    if args.out is not None:
        raise SystemExit(
            "--out cannot be used with --pcap-dir. "
            "Each file outputs to outputs/<pcap_name>/flows.csv"
        )

    if not pcap_dir.is_dir():
        raise SystemExit(f"{pcap_dir} is not a directory.")

    pcaps = sorted(p for p in pcap_dir.iterdir() if p.suffix.lower() == ".pcap")

    if not pcaps:
        raise SystemExit(f"No .pcap files found in directory {pcap_dir}")

    print(f"Found {len(pcaps)} PCAP files in {pcap_dir}. Starting batch processing...")
    batch_start = time.time()

    for pcap_path in pcaps:
        process_single_pcap(pcap_path, timeout=args.timeout, out_csv=None)

    batch_elapsed = time.time() - batch_start
    print(f"Batch processing completed in {batch_elapsed:.2f}s")


if __name__ == "__main__":
    main()
