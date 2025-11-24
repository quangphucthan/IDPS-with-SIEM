# Network IDS/IPS System with Mini-SIEM

A network intrusion detection and prevention system (IDS/IPS) with packet analysis capabilities and an integrated security information and event management (SIEM) system.

## Overview

This project provides:

- **Packet processing agent**: Analyzes PCAP files or captures packets directly from network interfaces
- **Built-in detectors**: DNS suspicious-name, ICMP flood, ARP spoofing, HTTP keyword detection
- **Mini-SIEM**: Ingests, correlates, and generates alerts from detections

## Installation

### System Requirements

- Python 3.7+
- Tshark/Wireshark (for pyshark)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Main libraries:

- `pyshark` - Packet analysis
- `pyyaml` - Configuration parsing
- `orjson` - High-performance JSON processing
- `rich` - Beautiful output formatting

## Usage

### Process PCAP Files (Offline)

Analyze existing PCAP files:

```bash
python -m idsips.agent.cli pcap --pcap pcaps/dns_examples.pcapng
```

### Live Capture

Capture packets from network interfaces:

```bash
# Capture from loopback interface
python -m idsips.agent.cli live --iface lo

# Dry-run mode (no actual capture, useful for testing)
python -m idsips.agent.cli live --iface lo --dry-run
```

**Note**: Press `Ctrl+C` to stop capture.

### Mini-SIEM Views

View statistics and analysis from detections:

```bash
# Statistics by rule
python -m idsips.siem.mini_siem --rule-stats

# Timeline view
python -m idsips.siem.mini_siem --timeline

# Top talkers (most active IPs)
python -m idsips.siem.mini_siem --top
```

### Run Tests

Run the test script to verify the system:

```bash
python scripts/run_tests.py
```

The script will print pass/fail results and exit with a non-zero code on failure.

## Detectors

### DNS Suspicious Name Detection

Detects suspicious DNS query names based on:

- Label too long (> `dns_label_max`)
- Name too long (> `dns_name_max`)
- High entropy (possibly algorithmically-generated names)

### ICMP Flood Detection

Detects ICMP floods when the number of ICMP packets exceeds the `icmp_per_sec` threshold over a time period.

### ARP Spoofing Detection

Detects ARP spoofing when an IP address is mapped to multiple different MAC addresses within the `arp_window_sec` time window.

### HTTP Keyword Detection

Detects suspicious keywords in HTTP requests.

## Mini-SIEM

Mini-SIEM performs:

1. **Ingestion**: Reads detections from `logs/detections.jsonl`
2. **Correlation**: Correlates events to detect patterns:
   - ICMP Flood meta-alert: 30+ events from the same source within 60 seconds
   - Repeated Rule alert: A rule triggered 50+ times
3. **Alerting**: Generates alerts and writes to `logs/alerts.jsonl`

## Notes

- The project uses `pyshark` to parse packets. Ensure Wireshark/tshark is installed before running live captures.
- The `--dry-run` option is useful for CI/CD and testing when pyshark is unavailable.
- The test script will automatically skip ARP tests if the PCAP file is not available.

## Troubleshooting

If you encounter issues:

1. Check dependencies: `pip install -r requirements.txt`
2. Verify Wireshark/tshark is installed
3. Run the test script: `python scripts/run_tests.py`
4. Check log files in the `logs/` directory for debugging
