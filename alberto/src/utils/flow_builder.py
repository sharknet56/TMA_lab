"""
flow_builder.py

Shared utilities for building flows from PCAPs.
Exposes:
    - canonical_flow_key(...)
    - pcap_to_flows(pcap_path, flow_timeout=60.0, max_active_flows=200_000)
"""

import math
from scapy.all import PcapReader, IP, IPv6, TCP, UDP


def canonical_flow_key(src_ip, src_port, dst_ip, dst_port, proto):
    """
    Canonicalize flow direction:
    Ensure (A,port) -> (B,port) is consistent regardless of packet direction.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, src_port, dst_ip, dst_port, proto)
    else:
        return (dst_ip, dst_port, src_ip, src_port, proto)


def pcap_to_flows(pcap_path, flow_timeout=60.0, max_active_flows=200_000):
    """
    Generator: yields flow dictionaries as they are completed.

    - Uses a canonical 5-tuple key.
    - Produces bidirectional flow stats (fwd/bwd).
    - Flushes flows based on idle timeout (flow_timeout).
    - Has a soft limit on number of active flows.

    Yields:
        dict: one per completed flow.
    """

    flows = {}        # key -> flow stats dict
    last_seen = {}    # key -> timestamp of last seen packet

    def finalize_flow(flow):
        """Compute derived stats and clean internal fields before output."""
        dur = flow["end_time"] - flow["start_time"]
        flow["duration"] = max(dur, 0.0)

        # mean packet length
        if flow["total_pkts"] > 0:
            flow["mean_pkt_len"] = flow["sum_pkt_len"] / flow["total_pkts"]
        else:
            flow["mean_pkt_len"] = 0.0

        # mean IAT
        if flow["iat_count"] > 0:
            flow["mean_iat"] = flow["sum_iat"] / flow["iat_count"]
        else:
            flow["mean_iat"] = 0.0

        # replace infinities
        if math.isinf(flow["min_pkt_len"]):
            flow["min_pkt_len"] = 0.0
        if math.isinf(flow["min_iat"]):
            flow["min_iat"] = 0.0

        # remove internal accumulators
        for k in ("sum_pkt_len", "sum_iat", "iat_count", "last_ts"):
            flow.pop(k, None)

        return flow

    def flush_expired(ts_now):
        expired = [
            key for key, last in last_seen.items()
            if ts_now - last > flow_timeout
        ]
        for key in expired:
            flow = flows.pop(key, None)
            last_seen.pop(key, None)
            if flow:
                yield finalize_flow(flow)

    def flush_all():
        for key, flow in list(flows.items()):
            yield finalize_flow(flow)
        flows.clear()
        last_seen.clear()

    # ===========================
    # Main PCAP parsing loop
    # ===========================
    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            try:
                ts = float(pkt.time)
            except Exception:
                continue

            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue

            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto if isinstance(ip, IP) else ip.nh

            sport = 0
            dport = 0
            tcp_flags = None

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                sport = int(tcp.sport)
                dport = int(tcp.dport)
                tcp_flags = int(tcp.flags)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport = int(udp.sport)
                dport = int(udp.dport)

            key = canonical_flow_key(src_ip, sport, dst_ip, dport, proto)

            # direction relative to canonical key
            direction = "fwd" if (src_ip, sport) <= (dst_ip, dport) else "bwd"

            # create flow if not present
            if key not in flows:
                flows[key] = {
                    "src_ip": key[0],
                    "src_port": key[1],
                    "dst_ip": key[2],
                    "dst_port": key[3],
                    "proto": key[4],
                    "start_time": ts,
                    "end_time": ts,
                    "total_pkts": 0,
                    "total_bytes": 0,

                    "fwd_pkts": 0,
                    "bwd_pkts": 0,
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,

                    "min_pkt_len": math.inf,
                    "max_pkt_len": 0.0,
                    "sum_pkt_len": 0.0,

                    "last_ts": None,
                    "min_iat": math.inf,
                    "max_iat": 0.0,
                    "sum_iat": 0.0,
                    "iat_count": 0,

                    "tcp_flags_or": 0,
                    "syn_count": 0,
                    "fin_count": 0,
                    "rst_count": 0,
                }

            flow = flows[key]

            # timestamps
            if ts < flow["start_time"]:
                flow["start_time"] = ts
            if ts > flow["end_time"]:
                flow["end_time"] = ts

            # basic counts
            pkt_len = len(pkt)
            flow["total_pkts"] += 1
            flow["total_bytes"] += pkt_len

            if direction == "fwd":
                flow["fwd_pkts"] += 1
                flow["fwd_bytes"] += pkt_len
            else:
                flow["bwd_pkts"] += 1
                flow["bwd_bytes"] += pkt_len

            # packet size stats
            flow["sum_pkt_len"] += pkt_len
            flow["min_pkt_len"] = min(flow["min_pkt_len"], pkt_len)
            flow["max_pkt_len"] = max(flow["max_pkt_len"], pkt_len)

            # IAT
            if flow["last_ts"] is not None:
                iat = ts - flow["last_ts"]
                flow["min_iat"] = min(flow["min_iat"], iat)
                flow["max_iat"] = max(flow["max_iat"], iat)
                flow["sum_iat"] += iat
                flow["iat_count"] += 1
            flow["last_ts"] = ts

            # TCP flags
            if tcp_flags is not None:
                flow["tcp_flags_or"] |= tcp_flags
                if tcp_flags & 0x02:
                    flow["syn_count"] += 1
                if tcp_flags & 0x01:
                    flow["fin_count"] += 1
                if tcp_flags & 0x04:
                    flow["rst_count"] += 1

            last_seen[key] = ts

            # flush expired flows
            for expired_flow in flush_expired(ts):
                yield expired_flow

            # prevent memory blowup
            if len(flows) > max_active_flows:
                oldest = sorted(last_seen.items(), key=lambda x: x[1])[:5000]
                for fk, _ in oldest:
                    f = flows.pop(fk, None)
                    last_seen.pop(fk, None)
                    if f:
                        yield finalize_flow(f)

    # flush all remaining flows at end of file
    for f in flush_all():
        yield f
