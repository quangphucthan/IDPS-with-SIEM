import argparse, sys, yaml, collections, time
from .ingest import read_events
from .alerts import emit_alert

def load_cfg(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def timeline_view(events):
    buckets = collections.defaultdict(int)
    for e in events:
        ts = e.get("ts","")[:16]  # minute resolution
        buckets[ts] += 1
    for k in sorted(buckets):
        print(k, buckets[k])

def top_talkers(events):
    c = collections.Counter(e.get("src","") for e in events)
    for ip, n in c.most_common(10):
        print(f"{ip:>16}  {n}")

def rule_stats(events):
    c = collections.Counter(e.get("rule_id","") for e in events)
    for r, n in c.most_common():
        print(f"{r:>16}  {n}")

def correlate(cfg, events):
    # example: repeated rule within 60s
    window = 60.0
    by_src = collections.defaultdict(list)
    by_rule = collections.defaultdict(list)

    from datetime import datetime
    def to_epoch(ts):
        try:
            return datetime.fromisoformat(ts).timestamp()
        except Exception:
            return time.time()

    for e in events:
        t = to_epoch(e.get("ts",""))
        by_src[e.get("src","")].append(t)
        by_rule[e.get("rule_id","")].append(t)

    # ICMP_FLOOD meta-alert: any 30+ events in 60s from same src
    for src, times in by_src.items():
        times.sort()
        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > window:
                i += 1
            if (j - i + 1) >= 30:
                emit_alert(cfg, "ALERT_ICMP_FLOOD", "high",
                           f"High volume events from {src} in 60s",
                           {"src": src}, j - i + 1)
                break

    # Repeated same rule many times
    for r, times in by_rule.items():
        if len(times) >= 50:
            emit_alert(cfg, "ALERT_REPEATED_RULE", "medium",
                       f"Rule {r} fired {len(times)} times",
                       {"rule_id": r}, len(times))

def main(argv=None):
    p = argparse.ArgumentParser(prog="mini-siem")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--timeline", action="store_true")
    p.add_argument("--top", action="store_true")
    p.add_argument("--rule-stats", action="store_true")
    args = p.parse_args(argv)

    cfg = load_cfg(args.config)
    events = read_events("./logs/detections.jsonl")
    if args.timeline:
        timeline_view(events)
    if args.top:
        top_talkers(events)
    if args.rule_stats:
        rule_stats(events)

    # Always run correlation when invoked
    correlate(cfg, events)
    return 0

if __name__ == "__main__":
    sys.exit(main())
