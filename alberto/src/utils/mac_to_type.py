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
        dict[mac_lower] = device_type
    """
    df = pd.read_csv(csv_path)
    df["MAC Address"] = df["MAC Address"].str.lower()

    mapping = {}
    for mac, devname in zip(df["MAC Address"], df["Device Name"]):
        mapping[mac] = classify_device(devname)
    return mapping
