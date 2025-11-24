from ..agent.utils import logs_dir, now_iso, json_dumps

def emit_alert(cfg, alert_id, severity, summary, entities, evidence_count):
    obj = {
        "ts": now_iso(),
        "alert_id": alert_id,
        "severity": severity,
        "summary": summary,
        "entities": entities,
        "evidence_count": int(evidence_count),
    }
    p = logs_dir(cfg) / "alerts.jsonl"
    with open(p, "a", encoding="utf-8") as f:
        f.write(json_dumps(obj) + "\n")
    print(f"[{severity}] {alert_id}: {summary}")
