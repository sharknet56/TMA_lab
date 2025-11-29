#!/usr/bin/env python3
"""
src/tools/pcap_to_labeled_flows.py

Extract labeled flows from PCAP(s) using MAC→device_type mapping.

Single file mode:
    python -m src.tools.pcap_to_labeled_flows \
        --pcap dataset/pcapIoT/foo.pcap \
        --mac-csv dataset/CSVs/macAddresses.csv

Batch mode (all .pcap in a directory, non-recursive):
    python -m src.tools.pcap_to_labeled_flows \
        --pcap-dir dataset/pcapIoT \
        --mac-csv dataset/CSVs/macAddresses.csv

Outputs (default):
    outputs/<pcap_name>/flows_labeled.csv
"""

import argparse
from pathlib import Path
import time

import pandas as pd
from scapy.all import PcapReader, Ether, IP, IPv6, DLT_LINUX_SLL
from scapy.layers.l2 import CookedLinux

from ..utils.flow_builder import canonical_flow_key, pcap_to_flows
from ..utils.mac_to_type import load_mac_to_device_type


def build_flow_to_type_map(pcap_path: str, mac_csv_path: str) -> dict:
    """
    First pass: read packets, use MAC addresses to infer device_type per flow key.
    Returns:
        dict[(src_ip, src_port, dst_ip, dst_port, proto)] = device_type
    """
    mac_to_type = load_mac_to_device_type(mac_csv_path)
    flow2type = {}

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            link = pkt.getlayer(Ether) or pkt.getlayer(CookedLinux)
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)

            if link is None or ip is None:
                continue

            smac = getattr(link, "src", None)
            dmac = getattr(link, "dst", None)
            if smac is None or dmac is None:
                continue

            smac = smac.lower()
            dmac = dmac.lower()

            #smac = link.src.lower()
            #dmac = link.dst.lower()

            # determine if either endpoint is an IoT device
            dev_type = None
            if smac in mac_to_type:
                dev_type = mac_to_type[smac]
            elif dmac in mac_to_type:
                dev_type = mac_to_type[dmac]

            if dev_type is None:
                continue

            # extract transport info
            sport = getattr(pkt, "sport", 0)
            dport = getattr(pkt, "dport", 0)
            proto = ip.proto if isinstance(ip, IP) else ip.nh

            key = canonical_flow_key(ip.src, sport, ip.dst, dport, proto)
            # if multiple MACs map to same flow, last one wins (usually fine)
            flow2type[key] = dev_type

    return flow2type


def extract_labeled_flows(pcap_path: str, mac_csv_path: str) -> pd.DataFrame:
    """
    Full pipeline:
    - Build flow→device_type map via MACs
    - Run pcap_to_flows
    - Attach device_type to each flow (default: 'unknown')
    """
    flow2type = build_flow_to_type_map(pcap_path, mac_csv_path)

    flows = []
    for flow in pcap_to_flows(pcap_path):
        key = canonical_flow_key(
            flow["src_ip"],
            flow["src_port"],
            flow["dst_ip"],
            flow["dst_port"],
            flow["proto"],
        )
        flow["device_type"] = flow2type.get(key, "unknown")
        flows.append(flow)

    return pd.DataFrame(flows)


def process_single_pcap(pcap_path: Path, mac_csv: str, out_csv: Path | None = None):
    """
    Process one PCAP and write flows_labeled.csv to the appropriate place.
    If out_csv is None, use: outputs/<pcap_name>/flows_labeled.csv
    """
    pcap_name = pcap_path.stem

    start = time.time()

    if out_csv is None:
        outdir = Path("outputs") / pcap_name
        outdir.mkdir(parents=True, exist_ok=True)
        out_csv = outdir / "flows_labeled.csv"
    else:
        out_csv = Path(out_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)

    df = extract_labeled_flows(str(pcap_path), mac_csv)
    df.to_csv(out_csv, index=False)

    elapsed = time.time() - start
    print(f"[{pcap_name}] Saved {len(df)} labeled flows to {out_csv} (elapsed: {elapsed:.2f}s)")


def main():
    parser = argparse.ArgumentParser(description="Extract labeled flows from PCAP(s).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", help="Path to a single PCAP file")
    group.add_argument("--pcap-dir", help="Directory containing PCAP files (batch mode)")

    parser.add_argument("--mac-csv", required=True, help="Path to macAddresses.csv")
    parser.add_argument(
        "--out",
        help=(
            "Output CSV path (only valid in single-file mode). "
            "In batch mode, outputs always go to outputs/<pcap_name>/flows_labeled.csv"
        ),
    )

    args = parser.parse_args()

    if args.pcap:
        # Single-file mode
        pcap_path = Path(args.pcap)
        process_single_pcap(pcap_path, args.mac_csv, args.out)

    else:
        # Batch mode: all *.pcap in directory (non-recursive)
        if args.out is not None:
            raise SystemExit(
                "--out cannot be used with --pcap-dir. "
                "Batch mode always writes to outputs/<pcap_name>/flows_labeled.csv."
            )

        pcap_dir = Path(args.pcap_dir)
        if not pcap_dir.is_dir():
            raise SystemExit(f"{pcap_dir} is not a directory")

        pcaps = sorted(p for p in pcap_dir.iterdir() if p.suffix.lower() == ".pcap")
        if not pcaps:
            raise SystemExit(f"No .pcap files found in directory {pcap_dir}")

        print(f"Found {len(pcaps)} pcap files in {pcap_dir}, processing in batch...")
        batch_start = time.time()
        for pcap_path in pcaps:
            process_single_pcap(pcap_path, args.mac_csv, out_csv=None)
        batch_elapsed = time.time() - batch_start
        print(f"Batch processing completed in {batch_elapsed:.2f}s")

if __name__ == "__main__":
    main()

