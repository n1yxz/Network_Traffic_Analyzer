
"""Packet capture utilities for the Network Traffic Analyzer.

Uses scapy to sniff live packets from a given network interface.
NOTE: Capturing live packets often requires administrator/root privileges.
"""

from datetime import datetime
from typing import List, Dict, Optional

import pandas as pd

try:
    from scapy.all import sniff, IP, TCP, UDP  # type: ignore
except Exception as exc:  # pragma: no cover - handled at runtime
    sniff = None
    IP = TCP = UDP = None


def _packet_to_record(pkt) -> Dict:
    """Convert a Scapy packet to a plain Python dict with safe defaults."""
    record = {
        "timestamp": datetime.now(),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "length": len(pkt),
    }

    if IP and IP in pkt:
        record["src_ip"] = pkt[IP].src
        record["dst_ip"] = pkt[IP].dst
        proto = pkt[IP].proto
        if proto == 6:
            record["protocol"] = "TCP"
        elif proto == 17:
            record["protocol"] = "UDP"
        else:
            record["protocol"] = str(proto)

    if TCP and TCP in pkt:
        record["src_port"] = pkt[TCP].sport
        record["dst_port"] = pkt[TCP].dport
        record["protocol"] = record["protocol"] or "TCP"

    if UDP and UDP in pkt:
        record["src_port"] = pkt[UDP].sport
        record["dst_port"] = pkt[UDP].dport
        record["protocol"] = record["protocol"] or "UDP"

    return record


def capture_packets(
    count: int = 200,
    timeout: Optional[int] = None,
    interface: Optional[str] = None,
) -> pd.DataFrame:
    """Capture packets and return them as a pandas DataFrame.

    Parameters
    ----------
    count:
        Approximate number of packets to capture. If 0, capture until timeout.
    timeout:
        Maximum number of seconds to sniff. If None, waits until count is reached.
    interface:
        Name of the network interface (e.g. 'eth0', 'Wi-Fi') or None for default.

    Returns
    -------
    pandas.DataFrame
        One row per captured packet.
    """
    if sniff is None:
        raise RuntimeError(
            "scapy is not available. Install it with `pip install scapy` and "
            "run this script with appropriate permissions."
        )

    records: List[Dict] = []

    def _callback(pkt):
        try:
            records.append(_packet_to_record(pkt))
        except Exception:
            # Ignore malformed packets instead of breaking the capture loop.
            pass

    sniff(
        prn=_callback,
        count=count if count > 0 else 0,
        timeout=timeout,
        iface=interface,
        store=False,
    )

    if not records:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "length",
            ]
        )

    return pd.DataFrame(records)
