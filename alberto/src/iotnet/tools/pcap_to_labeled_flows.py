"""
src/iotnet/tools/pcap_to_labeled_flows.py

Extract labeled flows from PCAP(s) using MAC→device_type mapping.

Core functionality:

    - build_ip_to_type_map(pcap_path, mac_csv_path)
    - extract_labeled_flows(pcap_path, mac_csv_path) -> pd.DataFrame
    - process_single_pcap(pcap_path, mac_csv, out_csv=None)
    - process_pcap_directory(pcap_dir, mac_csv)

By default, outputs are written to:
    outputs/<pcap_name>/flows_labeled.csv
"""

from __future__ import annotations

from pathlib import Path
import time
from typing import Dict

import pandas as pd
from scapy.all import PcapReader, Ether, IP, IPv6
from scapy.layers.l2 import CookedLinux

from src.iotnet.utils.flow_builder import canonical_flow_key, pcap_to_flows
from src.iotnet.utils.mac_to_type import load_mac_to_device_type, normalize_mac


def build_flow_to_type_map(pcap_path: str, mac_csv_path: str) -> Dict[tuple, str]:
    """
    First pass: read packets, use MAC addresses to infer device_type per flow key.

    Returns:
        dict[(src_ip, src_port, dst_ip, dst_port, proto)] = device_type
    """
    mac_to_type = load_mac_to_device_type(mac_csv_path)
    flow2type: Dict[tuple, str] = {}

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

            dev_type = None
            if smac in mac_to_type:
                dev_type = mac_to_type[smac]
            elif dmac in mac_to_type:
                dev_type = mac_to_type[dmac]

            if dev_type is None:
                continue

            sport = getattr(pkt, "sport", 0)
            dport = getattr(pkt, "dport", 0)
            proto = ip.proto if isinstance(ip, IP) else ip.nh

            key = canonical_flow_key(ip.src, sport, ip.dst, dport, proto)
            flow2type[key] = dev_type

    return flow2type


def build_ip_to_type_map(pcap_path: str, mac_csv_path: str) -> Dict[str, str]:
    """
    First pass: read packets, use MAC addresses to infer device_type per *IP*.

    Returns:
        dict[ip_str] = device_type

    Also prints debug info about which MACs and IPs were seen and matched.
    """
    mac_to_type = load_mac_to_device_type(mac_csv_path)
    mac_keys = set(mac_to_type.keys())
    print(f"[DEBUG] mac_to_type has {len(mac_keys)} entries")

    ip2type: Dict[str, str] = {}
    seen_macs: set[str] = set()
    matched_macs: set[str] = set()
    seen_ips: set[str] = set()

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            link = pkt.getlayer(Ether) or pkt.getlayer(CookedLinux)
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)

            if link is None or ip is None:
                continue

            smac = getattr(link, "src", None)
            dmac = getattr(link, "dst", None)

            if smac is not None:
                smac_n = normalize_mac(smac)
                seen_macs.add(smac_n)
            else:
                smac_n = None

            if dmac is not None:
                dmac_n = normalize_mac(dmac)
                seen_macs.add(dmac_n)
            else:
                dmac_n = None

            dev_type = None
            if smac_n is not None and smac_n in mac_to_type:
                dev_type = mac_to_type[smac_n]
                matched_macs.add(smac_n)
            elif dmac_n is not None and dmac_n in mac_to_type:
                dev_type = mac_to_type[dmac_n]
                matched_macs.add(dmac_n)

            if dev_type is None:
                continue

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


def extract_labeled_flows(pcap_path: str, mac_csv_path: str) -> pd.DataFrame:
    """
    Full pipeline:
    - Build IP→device_type map via MACs
    - Run pcap_to_flows
    - Attach device_type to each flow (default: 'unknown')

    Returns:
        DataFrame with one row per flow, including 'device_type'.
    """
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


def process_single_pcap(pcap_path: Path, mac_csv: str, out_csv: Path | None = None) -> None:
    """
    Process one PCAP and write flows_labeled.csv to the appropriate place.

    Args:
        pcap_path: Path to input PCAP.
        mac_csv: Path to macAddresses.csv for MAC→device_type mapping.
        out_csv: Optional explicit output CSV path.
                 If None: outputs/<pcap_name>/flows_labeled.csv
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


def process_pcap_directory(pcap_dir: Path, mac_csv: str) -> None:
    """
    Process all *.pcap files in a directory (non-recursive) and
    write a flows_labeled.csv for each.

    Outputs:
        outputs/<pcap_name>/flows_labeled.csv per PCAP.
    """
    if not pcap_dir.is_dir():
        raise SystemExit(f"{pcap_dir} is not a directory")

    pcaps = sorted(p for p in pcap_dir.iterdir() if p.suffix.lower() == ".pcap")
    if not pcaps:
        raise SystemExit(f"No .pcap files found in directory {pcap_dir}")

    print(f"Found {len(pcaps)} pcap files in {pcap_dir}, processing in batch...")
    batch_start = time.time()

    for pcap_path in pcaps:
        process_single_pcap(pcap_path, mac_csv=mac_csv, out_csv=None)

    batch_elapsed = time.time() - batch_start
    print(f"Batch processing completed in {batch_elapsed:.2f}s")
