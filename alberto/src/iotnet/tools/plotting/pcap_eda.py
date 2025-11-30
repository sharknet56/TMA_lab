from collections import Counter, defaultdict
from pathlib import Path
import csv
import time
from typing import Dict, List, Optional

import matplotlib.pyplot as plt
import numpy as np
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Ether
from scapy.layers.l2 import CookedLinux

from src.iotnet.utils.mac_to_type import load_mac_to_device_type, normalize_mac


def _save_fig(fig: plt.Figure, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def pcap_basic_eda(pcap_path: str, mac_csv_path: str | None, outdir: str) -> None:
    """
    Run EDA on a single PCAP and write summary + plots to:
        <outdir>/<pcap_name>/
    """
    pcap_path = Path(pcap_path)
    pcap_name = pcap_path.stem

    out_root = Path(outdir) / pcap_name
    out_root.mkdir(parents=True, exist_ok=True)

    summary_csv_path = out_root / "pcap_summary.csv"

    # Global stats
    pkt_lengths: List[int] = []
    proto_counter: Counter[str] = Counter()
    src_ip_counter: Counter[str] = Counter()
    dst_ip_counter: Counter[str] = Counter()
    src_mac_counter: Counter[str] = Counter()
    dst_mac_counter: Counter[str] = Counter()
    device_type_counter: Counter[str] = Counter()
    pps: Dict[int, int] = defaultdict(int)

    # NEW: inter-arrival times (IAT)
    global_iats: List[float] = []
    device_iats: Dict[str, List[float]] = defaultdict(list)

    # Per-device-type stats
    device_pkt_lengths: Dict[str, List[int]] = defaultdict(list)
    device_proto_counter: Dict[str, Counter[str]] = defaultdict(Counter)
    device_pps: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    mac_to_type = load_mac_to_device_type(mac_csv_path) if mac_csv_path else {}

    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    last_ts_global: Optional[float] = None
    last_ts_device: Dict[str, float] = {}

    with PcapReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            ts = float(pkt.time)

            if first_ts is None:
                first_ts = ts
            last_ts = ts

            # --- Inter-arrival times ---

            # Global IAT
            if last_ts_global is not None:
                global_iats.append(ts - last_ts_global)
            last_ts_global = ts

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

            # IPs
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is not None:
                src_ip_counter[ip_layer.src] += 1
                dst_ip_counter[ip_layer.dst] += 1

            # MACs & device types
            link = pkt.getlayer(Ether) or pkt.getlayer(CookedLinux)
            pkt_device_types: set[str] = set()
            if link is not None:
                smac = getattr(link, "src", None)
                dmac = getattr(link, "dst", None)

                if smac is not None:
                    smac_n = normalize_mac(smac)
                    src_mac_counter[smac_n] += 1
                    if smac_n in mac_to_type:
                        dt = mac_to_type[smac_n]
                        device_type_counter[dt] += 1
                        pkt_device_types.add(dt)

                if dmac is not None:
                    dmac_n = normalize_mac(dmac)
                    dst_mac_counter[dmac_n] += 1
                    if dmac_n in mac_to_type:
                        dt = mac_to_type[dmac_n]
                        device_type_counter[dt] += 1
                        pkt_device_types.add(dt)

            # packets per second
            if first_ts is not None:
                sec = int(ts - first_ts)
                pps[sec] += 1

                # per-device-type: pps, pkt_lengths, proto, IAT
                for dt in pkt_device_types:
                    device_pps[dt][sec] += 1
                    device_pkt_lengths[dt].append(pkt_len)
                    device_proto_counter[dt][proto] += 1

                    # device-specific IAT
                    if dt in last_ts_device:
                        device_iats[dt].append(ts - last_ts_device[dt])
                    last_ts_device[dt] = ts

    # ---- Write CSV summary ----

    with summary_csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])

        if first_ts is None:
            w.writerow(["error", "no packets in file"])
            print(f"Saved CSV summary: {summary_csv_path}")
            return

        duration = last_ts - first_ts if last_ts is not None else 0.0
        total_pkts = len(pkt_lengths)
        avg_pps = total_pkts / duration if duration > 0 else 0

        w.writerow(["pcap_file", pcap_path.name])
        w.writerow(["total_packets", total_pkts])
        w.writerow(["start_time", first_ts])
        w.writerow(["end_time", last_ts])
        w.writerow(["duration_seconds", duration])
        w.writerow(["avg_packets_per_sec", avg_pps])

        # IAT stats (global)
        if global_iats:
            w.writerow(["global_iat_min", float(min(global_iats))])
            w.writerow(["global_iat_max", float(max(global_iats))])
            w.writerow(["global_iat_mean", float(sum(global_iats) / len(global_iats))])

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

        # per-device IAT stats
        for dt, iats in device_iats.items():
            if not iats:
                continue
            w.writerow([f"device_{dt}_iat_min", float(min(iats))])
            w.writerow([f"device_{dt}_iat_max", float(max(iats))])
            w.writerow([f"device_{dt}_iat_mean", float(sum(iats) / len(iats))])

    print(f"Saved CSV summary: {summary_csv_path}")

    # ---- Global plots ----

    if pkt_lengths:
        fig = plt.figure()
        plt.hist(pkt_lengths, bins=80)
        plt.xlabel("Packet length (bytes)")
        plt.ylabel("Count")
        plt.title(f"Packet length distribution\n{pcap_path.name}")
        _save_fig(fig, out_root / "pcap_pkt_len_hist.png")

    if pps:
        max_sec = max(pps.keys())
        x = np.arange(max_sec + 1)
        y = np.array([pps[i] for i in x])
        fig = plt.figure()
        plt.plot(x, y)
        plt.xlabel("Time since start (s)")
        plt.ylabel("Packets/s")
        plt.title(f"Packets/s time series\n{pcap_path.name}")
        _save_fig(fig, out_root / "pcap_pps_timeseries.png")

    # NEW: Global IAT histogram
    if global_iats:
        fig = plt.figure()
        plt.hist(global_iats, bins=80)
        plt.xlabel("Inter-arrival time (s)")
        plt.ylabel("Count")
        plt.title(f"Global packet inter-arrival times\n{pcap_path.name}")
        _save_fig(fig, out_root / "pcap_global_iat_hist.png")

    # ---- Per-device-type plots ----
    if device_type_counter:
        # (reuse existing packet length / pps / proto plots here...)

        # NEW: per-device IAT hist + CDF for top device types
        top_device_types = [dt for dt, _ in device_type_counter.most_common(6)]

        # Histogram
        fig = plt.figure()
        for dt in top_device_types:
            iats = device_iats.get(dt, [])
            if not iats:
                continue
            plt.hist(
                iats,
                bins=60,
                alpha=0.5,
                histtype="stepfilled",
                label=dt,
            )
        plt.xlabel("Inter-arrival time (s)")
        plt.ylabel("Count")
        plt.title(f"IAT distribution by device type\n{pcap_path.name}")
        plt.legend()
        _save_fig(fig, out_root / "pcap_iat_by_device_type.png")

        # CDF
        fig = plt.figure()
        for dt in top_device_types:
            iats = sorted(device_iats.get(dt, []))
            if not iats:
                continue
            n = len(iats)
            x = np.array(iats)
            y = np.arange(1, n + 1) / n
            plt.plot(x, y, label=dt)
        plt.xlabel("Inter-arrival time (s)")
        plt.ylabel("CDF")
        plt.title(f"IAT CDF by device type\n{pcap_path.name}")
        plt.legend()
        _save_fig(fig, out_root / "pcap_iat_cdf_by_device_type.png")
