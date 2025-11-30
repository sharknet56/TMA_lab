"""
src/iotnet/tools/pcap_to_flows.py

Library wrapper to convert PCAP file(s) into flow records (without labels).

Flows are obtained via:
    src.iotnet.utils.flow_builder.pcap_to_flows

Typical usage:

    from pathlib import Path
    from src.iotnet.tools.pcap_to_flows import process_single_pcap, process_pcap_directory

    # Single PCAP
    process_single_pcap(Path("dataset/foo.pcap"), timeout=60.0)

    # Batch over directory
    process_pcap_directory(Path("dataset/pcapIoT"), timeout=60.0)

By default, outputs are written to:
    outputs/<pcap_name>/flows.csv
"""

import csv
import time
from pathlib import Path

from src.iotnet.utils.flow_builder import pcap_to_flows


def process_single_pcap(pcap_path: Path, timeout: float, out_csv: Path | None = None) -> None:
    """
    Process a single PCAP file and save flows.csv.

    Args:
        pcap_path: Path to the input PCAP file.
        timeout: Flow timeout (seconds) for flow_builder.pcap_to_flows.
        out_csv: Optional explicit output CSV path.
                 If None, uses outputs/<pcap_name>/flows.csv.
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


def process_pcap_directory(pcap_dir: Path, timeout: float) -> None:
    """
    Process all *.pcap files in a directory (non-recursive).

    Each file is written to:
        outputs/<pcap_name>/flows.csv

    Args:
        pcap_dir: Directory containing PCAP files.
        timeout: Flow timeout (seconds) for flow_builder.pcap_to_flows.
    """
    if not pcap_dir.is_dir():
        raise SystemExit(f"{pcap_dir} is not a directory.")

    pcaps = sorted(p for p in pcap_dir.iterdir() if p.suffix.lower() == ".pcap")
    if not pcaps:
        raise SystemExit(f"No .pcap files found in directory {pcap_dir}")

    print(f"Found {len(pcaps)} PCAP files in {pcap_dir}. Starting batch processing...")
    batch_start = time.time()

    for pcap_path in pcaps:
        process_single_pcap(pcap_path, timeout=timeout, out_csv=None)

    batch_elapsed = time.time() - batch_start
    print(f"Batch processing completed in {batch_elapsed:.2f}s")
