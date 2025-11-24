from pathlib import Path
import datetime, json

def logs_dir(cfg):
    p = Path(cfg["paths"]["logs_dir"]).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def json_dumps(obj):
    try:
        import orjson
        return orjson.dumps(obj).decode("utf-8")
    except Exception:
        return json.dumps(obj, ensure_ascii=False)
