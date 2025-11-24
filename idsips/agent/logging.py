"""Starter: JSONL logging helpers for detections and ops logs."""

from pathlib import Path
import datetime, json

def _logs_dir(cfg) -> Path:
    p = Path(cfg["paths"]["logs_dir"]).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def _write_jsonl(path: Path, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")

def emit_event(cfg, **kwargs) -> None:
    """
    Detection events (one JSON object per line) → logs/detections.jsonl
    Required schema keys: ts, schema_version, src, dst, proto, rule_id, severity, summary, metadata
    """
    base = {"ts": _now_iso(), "schema_version": "1.0"}
    _write_jsonl(_logs_dir(cfg) / "detections.jsonl", {**base, **kwargs})

def emit_ops(cfg, level: str, component: str, msg: str, kv: dict | None = None) -> None:
    """
    Operational log lines (start/stop/errors) → logs/ops.jsonl
    """
    obj = {
        "ts": _now_iso(),
        "level": level,
        "component": component,
        "msg": msg,
        "kv": kv or {},
    }
    _write_jsonl(_logs_dir(cfg) / "ops.jsonl", obj)
