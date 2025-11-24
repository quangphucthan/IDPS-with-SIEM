"""
idsips.agent.cli
=================
Command-line entrypoint for the IDS/IPS agent.

This module wires up:
- Argument parsing for subcommands: `pcap` and `live`
- Config loading from `config.yaml`
- SIGINT (Ctrl-C) handling shared by both modes
- Packet processing pipeline that calls detectors
"""

import argparse, sys, yaml, time, os
from .signals import install_sigint_handler
from .logging import emit_ops
from . import capture as cap

# --- Detectors (students extend here) ---------------------------------------
# NOTE: These imports are the "current" detectors. If you add new ones later,
# import them below and plug them into `process_packet`.
from ..detectors.dns import detect_dns
from ..detectors.icmp import detect_icmp
from ..detectors.arp import detect_arp
from ..detectors.http import detect_http  # optional bonus

# Shared stop-flag set by SIGINT (Ctrl-C). Both pcap & live loops respect it.
STOP = install_sigint_handler()

def load_cfg(path="config.yaml"):
    """Load YAML config. Keep options small & explicit for grading clarity."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def process_packet(cfg, pkt):
    """
    Normalize a packet object enough so detectors can make decisions.
    This function is intentionally *minimal* because different capture libs
    (pyshark/scapy) expose fields differently.
    """
    try:
        # --- Minimal normalization (students may extend) ---------------------
        proto = "OTHER"
        src = dst = None

        # A few common pyshark layers; add more mappings if you need them.
        if hasattr(pkt, "ip"):
            # highest_layer is a pyshark helper; fall back to transport_layer
            proto = getattr(pkt, "highest_layer", None) or getattr(pkt, "transport_layer", None) or "OTHER"
            src = getattr(pkt.ip, "src", None)
            dst = getattr(pkt.ip, "dst", None)
        elif hasattr(pkt, "arp"):
            proto = "ARP"
            src = getattr(pkt.arp, "spa", None)
            dst = getattr(pkt.arp, "tpa", None)
        elif hasattr(pkt, "icmp"):
            proto = "ICMP"
            src = getattr(pkt.icmp, "src", None)
            dst = getattr(pkt.icmp, "dst", None)
        elif hasattr(pkt, "dns"):
            proto = "DNS"
            src = getattr(pkt.dns, "src", None)
            dst = getattr(pkt.dns, "dst", None)
        elif hasattr(pkt, "http"):
            proto = "HTTP"
            src = getattr(pkt.http, "src", None)
            dst = getattr(pkt.http, "dst", None)

        # --- Detector routing ------------------------------------------------
        # Each detector is toggled by config flags. Add new detectors here.
        if cfg["rules"].get("dns_suspicious"):
            detect_dns(cfg, pkt, src, dst)
        if cfg["rules"].get("icmp_flood"):
            detect_icmp(cfg, pkt, src, dst)
        if cfg["rules"].get("arp_spoof"):
            detect_arp(cfg, pkt, src, dst)
        if cfg["rules"].get("http_keyword"):
            detect_http(cfg, pkt, src, dst)

    except Exception as e:
        # Robust to decoding errors; we log but do not crash the capture loop.
        emit_ops(cfg, "ERROR", "decoder", "packet_error", {"error": str(e)})

# --- Subcommand implementations ---------------------------------------------

def cmd_pcap(args):
    """
    Offline processing from a pcap file.
    - Must gracefully stop on SIGINT (Ctrl-C)
    - Must write start/shutdown messages to ops log
    """
    cfg = load_cfg(args.config)
    emit_ops(cfg, "INFO", "runner", "start_pcap", {"file": args.pcap})
    try:
        with cap.FileAdapter(args.pcap) as reader:
            for pkt in reader.stream():
                if STOP["flag"]:
                    break
                process_packet(cfg, pkt)
    finally:
        # Always write a shutdown message, even if exceptions occur.
        emit_ops(cfg, "INFO", "runner", "shutdown", {"reason": "EOF_or_SIGINT"})
    return 0

def cmd_live(args):
    """
    Live capture.
    - `--dry-run` mode is CI-friendly: it loops & exits on SIGINT without capturing
    - In real mode, reads from an interface and stops on SIGINT
    """
    cfg = load_cfg(args.config)
    emit_ops(cfg, "INFO", "runner", "start_live", {"iface": args.iface, "dry_run": args.dry_run})
    try:
        if args.dry_run or cfg.get("capture", {}).get("dry_run"):
            # No capture; idle until SIGINT. Great for visible tests & CI.
            while not STOP["flag"]:
                time.sleep(0.2)
        else:
            with cap.LiveAdapter(args.iface) as reader:
                for pkt in reader.stream():
                    if STOP["flag"]:
                        break
                    process_packet(cfg, pkt)
    finally:
        emit_ops(cfg, "INFO", "runner", "shutdown", {"reason": "SIGINT" if STOP["flag"] else "normal"})
    return 0

def main(argv=None):
    """
    CLI definition.
    """
    p = argparse.ArgumentParser(prog="idsips-agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="config.yaml", help="Path to YAML config")

    p_pcap = sub.add_parser("pcap", parents=[common], help="Process a pcap file")
    p_pcap.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng")
    p_pcap.set_defaults(func=cmd_pcap)

    p_live = sub.add_parser("live", parents=[common], help="Live capture from an interface")
    p_live.add_argument("--iface", default="lo", help="Network interface (default: loopback)")
    p_live.add_argument("--dry-run", action="store_true", help="Loop until SIGINT without capturing (CI-friendly)")
    p_live.set_defaults(func=cmd_live)

    args = p.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
