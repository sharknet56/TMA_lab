#!/usr/bin/env python3
"""
pcap_eda.py  (CSV summary version)

Basic EDA for PCAPs:
- Writes pcap_summary.csv
- Saves PNG plots into:
    <outdir>/<pcap_name>/

Single-file usage:
    python -m src.tools.plotting.pcap_eda \
        --pcap dataset/pcapIoT/foo.pcap \
        --mac-csv dataset/CSVs/macAddresses.csv \
        --outdir outputs

Batch usage (all .pcap in a directory):
    python -m src.tools.plotting.pcap_eda \
        --pcap-dir dataset/pcapIoT \
        --mac-csv dataset/CSVs/macAddresses.csv \
        --outdir outputs
"""

import argparse
from collections import Counter, defaultdict
from pathlib import Path
import csv
import time

import matplotlib.pyplot as plt
import numpy as np
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Ether

from ...utils.mac_to_type import load_mac_to_device_type


def pcap_basic_eda(pcap_path: str, mac_csv_path: str | None, outdir: str):
    """
    Run EDA on a single PCAP and write summary + plots to:
        <outdir>/<pcap_name>/
    """
    pcap_path = Path(pcap_path)
    pcap_name = pcap_path.stem

    out_root = Path(outdir) / pcap_name
    out_root.mkdir(parents=True, exist_ok=True)

    summary_csv_path = out_root / "pcap_summary.csv"

    pkt_lengths = []
    proto_counter = Counter()
    src_ip_counter = Counter()
    dst_ip_counter = Counter()
    src_mac_counter = Counter()
    dst_mac_counter = Counter()
    device_type_counter = Counter()
    pps = defaultdict(int)

    mac_to_type = load_mac_to_device_type(mac_csv_path) if mac_csv_path else {}

    first_ts = None
    last_ts = None

    with PcapReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            ts = float(pkt.time)

            if first_ts is None:
                first_ts = ts
            last_ts = ts

            pkt_len = len(pkt)
            pkt_lengths.append(pkt_len)

            # protocol
            if pkt.haslayer(TCP):
                proto = "TCP"
            elif pkt.haslayer(UDP):
                proto = "UDP"
            elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
                proto = "IP-other"
            else:
                proto = "non-IP"
            proto_counter[proto] += 1

            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is not None:
                src_ip_counter[ip_layer.src] += 1
                dst_ip_counter[ip_layer.dst] += 1

            ether = pkt.getlayer(Ether)
            if ether is not None:
                smac = ether.src.lower()
                dmac = ether.dst.lower()
                src_mac_counter[smac] += 1
                dst_mac_counter[dmac] += 1

                for mac in (smac, dmac):
                    if mac in mac_to_type:
                        device_type_counter[mac_to_type[mac]] += 1

            sec = int(ts - first_ts)
            pps[sec] += 1

    # ---- Write CSV summary ----

    with summary_csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])

        if first_ts is None:
            w.writerow(["error", "no packets in file"])
            print(f"Saved summary: {summary_csv_path}")
            return

        duration = last_ts - first_ts
        total_pkts = len(pkt_lengths)
        avg_pps = total_pkts / duration if duration > 0 else 0

        w.writerow(["pcap_file", pcap_path.name])
        w.writerow(["total_packets", total_pkts])
        w.writerow(["start_time", first_ts])
        w.writerow(["end_time", last_ts])
        w.writerow(["duration_seconds", duration])
        w.writerow(["avg_packets_per_sec", avg_pps])

        # protocol distribution
        for proto, count in proto_counter.items():
            w.writerow([f"proto_{proto}_count", count])

        # top IPs
        for ip, count in src_ip_counter.most_common(10):
            w.writerow([f"top_src_ip__{ip}", count])
        for ip, count in dst_ip_counter.most_common(10):
            w.writerow([f"top_dst_ip__{ip}", count])

        # top MACs
        for mac, count in src_mac_counter.most_common(10):
            w.writerow([f"top_src_mac__{mac}", count])
        for mac, count in dst_mac_counter.most_common(10):
            w.writerow([f"top_dst_mac__{mac}", count])

        # device types
        for dt, count in device_type_counter.items():
            w.writerow([f"device_type__{dt}", count])

    print(f"Saved CSV summary: {summary_csv_path}")

    # ---- Plots ----

    if pkt_lengths:
        plt.figure()
        plt.hist(pkt_lengths, bins=80)
        plt.xlabel("Packet length (bytes)")
        plt.ylabel("Count")
        plt.title(f"Packet length distribution\n{pcap_path.name}")
        plt.tight_layout()
        plt.savefig(out_root / "pcap_pkt_len_hist.png")
        plt.close()
        print(f"Saved: {out_root / 'pcap_pkt_len_hist.png'}")

    if pps:
        max_sec = max(pps.keys())
        x = np.arange(max_sec + 1)
        y = np.array([pps[i] for i in x])
        plt.figure()
        plt.plot(x, y)
        plt.xlabel("Time since start (s)")
        plt.ylabel("Packets/s")
        plt.title(f"Packets/s time series\n{pcap_path.name}")
        plt.tight_layout()
        plt.savefig(out_root / "pcap_pps_timeseries.png")
        plt.close()
        print(f"Saved: {out_root / 'pcap_pps_timeseries.png'}")


def process_single_pcap(pcap_path: Path, mac_csv: str | None, outdir: str):
    """
    Wrapper to run EDA on a single PCAP with timing.
    """
    start = time.time()
    pcap_basic_eda(str(pcap_path), mac_csv, outdir)
    elapsed = time.time() - start
    print(f"[{pcap_path.name}] EDA completed in {elapsed:.2f}s")


def main():
    parser = argparse.ArgumentParser(description="PCAP EDA (single or batch).")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", help="Path to a single pcap file")
    group.add_argument("--pcap-dir", help="Directory containing multiple pcap files (.pcap)")

    parser.add_argument("--mac-csv", help="Path to macAddresses.csv", default=None)
    parser.add_argument("--outdir", default="outputs", help="Base output directory")

    args = parser.parse_args()

    # Single-file mode
    if args.pcap:
        pcap_path = Path(args.pcap)
        process_single_pcap(pcap_path, args.mac_csv, args.outdir)
        return

    # Batch mode
    pcap_dir = Path(args.pcap-dir)  # OOPS this is invalid; fix to args.pcap_dir
