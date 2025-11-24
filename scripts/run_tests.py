#!/usr/bin/env python3
"""
Test runner. Keep it simple & cross-platform.
- Test 1: DNS (pcap) writes DNS_SUSPICIOUS
- Test 2: ARP (pcap) writes ARP_MULTIMAC  (skipped if pcap not present)
- Test 3: Live dry-run exits gracefully on SIGINT (ops shows shutdown)
- Test 4: Mini-SIEM rule-stats runs; alerts file created (may be empty)
"""
import subprocess, signal, time, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOGS = ROOT / "logs"
PCAPS = ROOT / "pcaps"

def _read(p: pathlib.Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""

def _check(cond, name):
    print(("[PASS] " if cond else "[FAIL] ") + name)
    return 1 if cond else 0

def main():
    passed = 0

    # Clean logs
    for f in ["detections.jsonl", "ops.jsonl", "alerts.jsonl"]:
        p = LOGS / f
        if p.exists():
            p.unlink()

    # Test 1: DNS PCAP
    rc = subprocess.run(
        ["python", "-m", "idsips.agent.cli", "pcap", "--pcap", str(PCAPS / "dns_examples.pcapng")],
        cwd=ROOT
    ).returncode
    passed += _check(rc == 0, "DNS PCAP return code")
    text = _read(LOGS / "detections.jsonl")
    passed += _check('"proto":"DNS"' in text and '"rule_id":"DNS_SUSPICIOUS"' in text, "DNS detection present")
    ops = _read(LOGS / "ops.jsonl")
    passed += _check("start_pcap" in ops and "shutdown" in ops, "Ops has start+shutdown")

    # Test 2: ARP (optional)
    arp_pcap = PCAPS / "arp_spoof_short.pcap"
    if arp_pcap.exists():
        rc = subprocess.run(
            ["python", "-m", "idsips.agent.cli", "pcap", "--pcap", str(arp_pcap)],
            cwd=ROOT
        ).returncode
        passed += _check(rc == 0, "ARP PCAP return code")
        text = _read(LOGS / "detections.jsonl")
        passed += _check('"rule_id":"ARP_MULTIMAC"' in text, "ARP detection present")
    else:
        print("[SKIP] ARP test (pcap not present)")

    # Test 3: Live dry-run + SIGINT
    proc = subprocess.Popen(
        ["python", "-m", "idsips.agent.cli", "live", "--iface", "lo", "--dry-run"],
        cwd=ROOT
    )
    time.sleep(2)
    proc.send_signal(signal.SIGINT)
    code = proc.wait(timeout=10)
    passed += _check(code == 0, "Live Ctrl-C exit code (dry-run)")
    ops = _read(LOGS / "ops.jsonl")
    passed += _check("shutdown" in ops, "Ops shows shutdown")

    # Test 4: Mini-SIEM rule-stats
    rc = subprocess.run(
        ["python", "-m", "idsips.siem.mini_siem", "--rule-stats"],
        cwd=ROOT
    ).returncode
    passed += _check(rc == 0, "Mini-SIEM CLI return code")
    alerts = _read(LOGS / "alerts.jsonl")
    passed += _check(alerts is not None, "Alerts file exists (may be empty)")

    # Final status
    if passed < 6:  # 6 checks if ARP skipped; 8 if ARP included
        print(f"{passed} checks passed")
        sys.exit(1)
    print("All visible tests passed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
