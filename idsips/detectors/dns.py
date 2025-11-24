"""
Starter: DNS suspicious-name heuristic.
Compatible with PyShark packet objects: pkt.dns.qry_name (if present).
"""

from ..agent.logging import emit_event
import math

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    c = Counter(s)
    return -sum((cnt/n) * math.log2(cnt/n) for cnt in c.values())

def detect_dns(cfg, pkt, src, dst) -> None:
    # 1) Only proceed if this packet has a DNS layer
    if not hasattr(pkt, "dns"):
        return

    # 2) Try to extract the queried name; be defensive about field names
    dns = pkt.dns
    name = getattr(dns, "qry_name", None) or getattr(dns, "qry_name_raw", None)
    if not name:
        return
    name = str(name)

    # 3) Thresholds from config.yaml
    label_max = int(cfg["thresholds"]["dns_label_max"])
    name_max  = int(cfg["thresholds"]["dns_name_max"])

    # 4) Simple suspiciousness checks
    labels = [l for l in name.split(".") if l]
    long_label = any(len(l) > label_max for l in labels)
    too_long   = len(name) > name_max

    # 5) Entropy (basic signal for algorithmically-generated subdomains)
    ent = _entropy(name)
    ENTROPY_THRESHOLD = float(cfg["thresholds"]["dns_entropy_threshold"])
    high_entropy = ent >= ENTROPY_THRESHOLD

    if long_label or too_long or high_entropy:
        emit_event(
            cfg,
            src=str(src) if src else "",
            dst=str(dst) if dst else "",
            proto="DNS",
            rule_id="DNS_SUSPICIOUS",
            severity="medium",
            summary="Suspicious DNS query name",
            metadata={
                "name": name,
                "long_label": long_label,
                "too_long": too_long,
                "entropy": round(ent, 2),
            },
        )
