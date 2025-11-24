"""
Starter: ICMP rate heuristic (simple rolling 1-second window per source).
Emits ICMP_RATE when a single source exceeds configured packets/sec.
"""

from ..agent.logging import emit_event
from collections import deque
import time

# A tiny in-memory rolling window: (timestamp, src)
_WINDOW = deque()

# Add a cooldown to avoid spam alerts
_LAST_ALERT = {}

def detect_icmp(cfg, pkt, src, dst) -> None:
    if not hasattr(pkt, "icmp"):
        return

    now = time.time()
    _WINDOW.append((now, src))

    # Evict entries older than 1 second
    while _WINDOW and (now - _WINDOW[0][0]) > 1.0:
        _WINDOW.popleft()

    # Count how many ICMPs came from this source in the last 1s
    threshold = int(cfg["thresholds"]["icmp_per_sec"])
    count_src = sum(1 for t, s in _WINDOW if s == src)

    if count_src > threshold:
        # Only alert 5 seconds after the last alert for this src
        cooldown = 5.0
        last_alert = _LAST_ALERT.get(src, 0)
        
        if (now - last_alert) < cooldown:
            return  # still in cooldown
        
        _LAST_ALERT[src] = now
        
        emit_event(
            cfg,
            src=str(src) if src else "",
            dst=str(dst) if dst else "",
            proto="ICMP",
            rule_id="ICMP_RATE",
            severity="high",
            summary=f"ICMP echo rate {count_src}/s exceeds threshold {threshold}",
            metadata={"rate": count_src, "threshold": threshold},
        )
