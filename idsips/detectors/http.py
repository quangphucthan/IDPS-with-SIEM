from ..agent.logging import emit_event

KEYWORDS = ["admin", "password", "login"]

def detect_http(cfg, pkt, src, dst):
    try:
        if not hasattr(pkt, "http"):
            return
        # very simple: check request uri or host
        uri = getattr(pkt.http, "request_full_uri", None) or getattr(pkt.http, "request_uri", None) or ""
        host = getattr(pkt.http, "host", "") or ""
        s = f"{host}{uri}".lower()
        if any(k in s for k in KEYWORDS):
            emit_event(cfg,
                src=str(src) if src else "",
                dst=str(dst) if dst else "",
                proto="HTTP",
                rule_id="HTTP_KEYWORD",
                severity="low",
                summary="HTTP keyword match",
                metadata={"host": host, "uri": uri},
            )
    except Exception:
        pass
