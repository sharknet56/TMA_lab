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
from scapy.all import PcapReader, Ether, IP, IPv6
from scapy.layers.l2 import CookedLinux

from ..utils.flow_builder import canonical_flow_key, pcap_to_flows
from ..utils.mac_to_type import load_mac_to_device_type, normalize_mac


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

def build_ip_to_type_map(pcap_path: str, mac_csv_path: str) -> dict:
    """
    First pass: read packets, use MAC addresses to infer device_type per *IP*.

    Returns:
        dict[ip_str] = device_type

    Also prints debug info about which MACs and IPs were seen and matched.
    """
    mac_to_type = load_mac_to_device_type(mac_csv_path)
    mac_keys = set(mac_to_type.keys())
    print(f"[DEBUG] mac_to_type has {len(mac_keys)} entries")

    ip2type: dict[str, str] = {}
    seen_macs: set[str] = set()
    matched_macs: set[str] = set()
    seen_ips: set[str] = set()

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            # For Linux cooked captures, Ether is usually None, CookedLinux present
            link = pkt.getlayer(Ether) or pkt.getlayer(CookedLinux)
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)

            if link is None or ip is None:
                continue

            # CookedLinux only has a single 'src' address; Ether has src/dst
            smac = getattr(link, "src", None)
            dmac = getattr(link, "dst", None)
            #print(smac)

            if smac is not None:
                smac = normalize_mac(smac)
                #print(smac)
                seen_macs.add(smac)
            if dmac is not None:
                dmac = normalize_mac(dmac)
                seen_macs.add(dmac)

            dev_type = None
            if smac in mac_to_type:
                dev_type = mac_to_type[smac]
                matched_macs.add(smac)
            elif dmac in mac_to_type:
                dev_type = mac_to_type[dmac]
                matched_macs.add(dmac)
            
            if dev_type is None:
                continue

            src_match = smac in mac_to_type if smac is not None else False
            dst_match = dmac in mac_to_type if dmac is not None else False

            if src_match:
                dev_type = mac_to_type[smac]
                matched_macs.add(smac)
            elif dst_match:
                dev_type = mac_to_type[dmac]
                matched_macs.add(dmac)

            if dev_type is None:
                continue

            # Any IPs we see in this packet are associated with that dev_type
            if getattr(ip, "src", None):
                seen_ips.add(ip.src)
                ip2type.setdefault(ip.src, dev_type)
            if getattr(ip, "dst", None):
                seen_ips.add(ip.dst)
                ip2type.setdefault(ip.dst, dev_type)

    # ---- debug report ----
    print(f"[DEBUG] Unique MACs seen in PCAP: {len(seen_macs)}")
    print(f"[DEBUG] Unique MACs that matched CSV: {len(matched_macs)}")
    if matched_macs:
        print(f"[DEBUG] Example matched MACs: {list(sorted(matched_macs))[:10]}")
    else:
        print("[DEBUG] No MACs in the capture matched the CSV keys.")

    print(f"[DEBUG] Unique IPs seen (any): {len(seen_ips)}")
    print(f"[DEBUG] IPs mapped to device_type: {len(ip2type)}")
    if ip2type:
        example_items = list(ip2type.items())[:10]
        print("[DEBUG] Example IP→type mappings:")
        for ip, t in example_items:
            print(f"    {ip} -> {t}")

    return ip2type


'''
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
'''

def extract_labeled_flows(pcap_path: str, mac_csv_path: str) -> pd.DataFrame:
    ip2type = build_ip_to_type_map(pcap_path, mac_csv_path)

    flows = []
    labeled = 0

    for flow in pcap_to_flows(pcap_path):
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")

        dev_type = "unknown"
        if src_ip in ip2type:
            dev_type = ip2type[src_ip]
        elif dst_ip in ip2type:
            dev_type = ip2type[dst_ip]

        if dev_type != "unknown":
            labeled += 1

        flow["device_type"] = dev_type
        flows.append(flow)

    total = len(flows)
    pct = (labeled / total * 100) if total else 0.0
    print(f"[DEBUG] Labeled {labeled} / {total} flows ({pct:.2f}%)")

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

