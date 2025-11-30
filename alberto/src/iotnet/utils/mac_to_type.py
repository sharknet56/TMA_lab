"""
mac_to_type.py

Utility to map MAC addresses to high-level device types.
"""

import pandas as pd


def classify_device(name: str) -> str:
    n = name.lower()
    if "echo dot" in n or "echo show" in n:
        return "smart_speaker"
    if "camera" in n or "doorbell" in n:
        return "camera"
    if "monitor" in n or "frame" in n or "hp envy" in n:
        return "display"
    if "plug" in n:
        return "plug"
    if "sensor" in n or "weather" in n or "scales" in n or "connect" in n:
        return "sensor"
    if "alarm" in n or "protect" in n:
        return "alarm"
    if "watch" in n:
        return "wearable"
    if "hub" in n:
        return "hub"
    return "unknown"


def load_mac_to_device_type(csv_path: str) -> dict:
    """
    Reads macAddresses.csv and returns:
        dict[normalized_mac] = device_type
    """
    df = pd.read_csv(csv_path)
    df["MAC Address"] = df["MAC Address"].astype(str).str.lower()

    mapping = {}
    for mac, devname in zip(df["MAC Address"], df["Device Name"]):
        norm = normalize_mac(mac)
        mapping[norm] = classify_device(devname)
    return mapping

def normalize_mac(mac) -> str:
    """
    Normalize MAC-like values to a 6-byte, colon-separated lowercase string.

    Handles:
    - bytes / bytearray (e.g. b'p\\xeePW\\x95)\\x00\\x00')
    - strings with or without colons
    - SLL 8-byte "MACs": we keep the *first* 6 bytes (real MAC), last 2 are padding.
    """
    # bytes / bytearray → hex
    if isinstance(mac, (bytes, bytearray)):
        b = bytes(mac)
        # For SLL, often 8 bytes: keep first 6 (real MAC), remaining are padding
        if len(b) > 6:
            b = b[:6]
        return ":".join(f"{x:02x}" for x in b)

    # ... keep the string-handling part as you already have it ...
    s = str(mac).strip().lower()

    if ":" in s:
        parts = [p for p in s.split(":") if p]
        if len(parts) > 6:
            parts = parts[-6:]
        parts = [p.zfill(2) for p in parts]
        return ":".join(parts)

    if len(s) >= 12 and all(c in "0123456789abcdef" for c in s):
        s = s[-12:]
        parts = [s[i:i+2] for i in range(0, 12, 2)]
        return ":".join(parts)

    return s
