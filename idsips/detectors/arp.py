"""
Starter: ARP spoof heuristic.
If the same IP is seen with >= 2 different MACs within 'arp_window_sec', raise ARP_MULTIMAC.
"""

from ..agent.logging import emit_event
from collections import deque, defaultdict
import time

# Track recent (ts, ip, mac) within the sliding window
_TS = deque()  # (timestamp, ip, mac)

def detect_arp(cfg, pkt, src, dst) -> None:
    if not hasattr(pkt, "arp"):
        return

    layer = pkt.arp
    ip  = getattr(layer, "spa", None)   # sender protocol address
    mac = getattr(layer, "sha", None)   # sender hardware address
    if not ip or not mac:
        return
    ip, mac = str(ip), str(mac)

    now = time.time()
    window = int(cfg["thresholds"]["arp_window_sec"])

    # Add this observation
    _TS.append((now, ip, mac))

    # Evict entries older than the window
    while _TS and (now - _TS[0][0]) > window:
        _TS.popleft()

    # Build IP -> set(MAC) view from the window
    ip2macs = defaultdict(set)
    for _, i, m in _TS:
        ip2macs[i].add(m)

    # If this IP maps to >=2 MACs in the window, flag it
    macs = ip2macs.get(ip, set())
    if len(macs) >= 2:
        emit_event(
            cfg,
            src=ip,
            dst=str(dst) if dst else "",
            proto="ARP",
            rule_id="ARP_MULTIMAC",
            severity="medium",
            summary=f"Multiple MACs observed for IP {ip} over {window}s window",
            metadata={"macs": sorted(macs), "window": window},
        )
