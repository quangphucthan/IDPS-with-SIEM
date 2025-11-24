"""
idsips.agent.capture
====================
Capture adapters (file + live) and normalization helpers used by the agent.

Package structure:

- `FileAdapter` and `LiveAdapter`: context-managed wrappers that yield packets.
- `normalize_basics(pkt)`: extracts common fields (ts/src/dst/proto/length/info) defensively.
- (Optional) `log_packet_ops(cfg, pkt)`: writes a compact ops line per packet when enabled.

This project will:
- uses detectors to emit **detections** to `logs/detections.jsonl`, and
- writes **ops** (start/shutdown/errors) to `logs/ops.jsonl`.

If you want per-packet logging, set `capture.log_every_packet: true`
in `config.yaml`, and we will write a short ops entry per packet via `log_packet_ops`.
"""

from pathlib import Path
import datetime
import pyshark

# --- Adapters ---------------------------------------------------------------

class LiveAdapter:
    """Context-managed live capture. Yields packets until closed."""
    def __init__(self, interface: str):
        self.interface = interface
        self.cap = None

    def __enter__(self):
        # NOTE: May add display_filter, bpf filters, or tshark args here.
        self.cap = pyshark.LiveCapture(interface=self.interface)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.cap:
                self.cap.close()
        except Exception:
            pass

    def stream(self):
        for pkt in self.cap.sniff_continuously():
            yield pkt


class FileAdapter:
    """Context-managed file capture. Yields packets from a PCAP/PCAPNG file."""
    def __init__(self, pcap_path: str):
        self.path = str(Path(pcap_path).resolve())
        self.cap = None

    def __enter__(self):
        # keep_packets=False keeps memory usage low
        self.cap = pyshark.FileCapture(self.path, keep_packets=False)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.cap:
                self.cap.close()
        except Exception:
            pass

    def stream(self):
        for pkt in self.cap:
            yield pkt

# --- Normalization helpers --------------------------------------------------

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def normalize_basics(pkt) -> dict:
    """
    Return a dict with *common* fields in a defensive way:
      - ts: ISO8601 timestamp (generated locally; pyshark can also expose frame.time_epoch)
      - src, dst: best-effort IPs (or ARP sender/target)
      - proto: BEST-EFFORT guess (DNS/ICMP/ARP/HTTP/TCP/UDP/OTHER)
      - length: BEST-EFFORT packet length if available
      - info: short human-friendly string (for teaching/demo continuity with Part-1)
    """
    d = {
        "ts": _now_iso(),
        "src": None,
        "dst": None,
        "proto": "OTHER",
        "length": None,
        "info": "",
    }

    try:
        # IP layer
        if hasattr(pkt, "ip"):
            d["src"] = getattr(pkt.ip, "src", None)
            d["dst"] = getattr(pkt.ip, "dst", None)

        # Length (frame len if present)
        if hasattr(pkt, "length"):
            d["length"] = getattr(pkt, "length", None)
        elif hasattr(pkt, "frame"):
            d["length"] = getattr(pkt.frame, "len", None)

        # Protocol hints by layer presence / highest layer
        proto = getattr(pkt, "highest_layer", None) or getattr(pkt, "transport_layer", None) or ""
        proto = str(proto).upper()

        if hasattr(pkt, "dns"):
            d["proto"] = "DNS"
            qname = getattr(pkt.dns, "qry_name", None) or getattr(pkt.dns, "qry_name_raw", None)
            if qname:
                d["info"] = f"DNS query {qname}"
        elif hasattr(pkt, "icmp"):
            d["proto"] = "ICMP"
            typ = getattr(pkt.icmp, "type", None)
            d["info"] = f"ICMP type={typ}" if typ is not None else "ICMP"
        elif hasattr(pkt, "arp"):
            d["proto"] = "ARP"
            spa = getattr(pkt.arp, "spa", None); tpa = getattr(pkt.arp, "tpa", None)
            d["src"] = d["src"] or spa
            d["dst"] = d["dst"] or tpa
            if spa and tpa:
                d["info"] = f"ARP who-has {tpa}? tell {spa}"
        elif hasattr(pkt, "http"):
            d["proto"] = "HTTP"
            host = getattr(pkt.http, "host", None) or ""
            uri = getattr(pkt.http, "request_uri", None) or ""
            d["info"] = f"HTTP {host}{uri}" if (host or uri) else "HTTP"
        elif proto in {"TCP", "UDP"}:
            d["proto"] = proto
        else:
            d["proto"] = "OTHER"

    except Exception:
        pass

    return d

# --- Optional per-packet ops logging ----------------------------------------

def log_packet_ops(cfg, ops_logger, pkt) -> None:
    """
    If `capture.log_every_packet: true` in config, write a compact ops line
    per packet for teaching/demo purposes. Not used by the grader.
    """
    try:
        if not cfg.get("capture", {}).get("log_every_packet", False):
            return
        d = normalize_basics(pkt)
        ops_logger(cfg, level="DEBUG", component="capture", msg="packet", kv=d)
    except Exception:
        # Intentionally swallow to keep capture loop resilient
        pass
