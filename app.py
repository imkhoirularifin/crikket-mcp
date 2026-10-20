"""Read-only MCP server for Crikket bug reports (streamable HTTP at /mcp, bearer auth)."""
from __future__ import annotations

import hmac
import json
import os
import re
from datetime import date, datetime, timedelta
from typing import Any, Literal

import asyncpg
import boto3
from botocore.config import Config
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse

DATABASE_URL = os.environ["DATABASE_URL"]
AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "crikket-mcp.arifin.dev")
APP_URL = os.environ.get("CRIKKET_APP_URL", "https://crikket.arifin.dev").rstrip("/")
S3_ENDPOINT = os.environ.get("STORAGE_ENDPOINT", "https://crikket-files.arifin.dev")
S3_BUCKET = os.environ.get("STORAGE_BUCKET", "crikket")
S3_REGION = os.environ.get("STORAGE_REGION", "us-east-1")
MEDIA_EXPIRY = 900
DEFAULT_BODY_CAP = 2000
MAX_BODY_CAP = 10000
MAX_TEXT = 4000

# ---------------------------------------------------------------- redaction
SENSITIVE_HEADER = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|"
    r"x-csrf-token|x-xsrf-token|x-amz-security-token|x-goog-api-key|.*(token|secret|password|session|signature|credential|auth).*)$",
    re.I,
)
SENSITIVE_KEY = re.compile(
    r"(pass(word|wd|phrase)|^pass$|^pwd$|secret|token|api[_-]?key|apikey|authorization|^auth$|cookie|session[_-]?id|^session$|"
    r"credential|private[_-]?key|access[_-]?key|signature|^(otp|pin|ssn|cvv|cvc)$|card[_-]?number)",
    re.I,
)
R = "[REDACTED]"
TEXT_PATTERNS = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + R),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), R),  # JWT
    (
        re.compile(
            r"""(?ix)(["']?[\w-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|authorization|cookie|session|credential|private[_-]?key|access[_-]?key|signature)[\w-]*["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s&,;"'}]+)"""
        ),
        r"\1" + '"' + R + '"',
    ),
]


def redact_text(s: Any) -> Any:
    if not isinstance(s, str):
        return s
    for pat, rep in TEXT_PATTERNS:
        s = pat.sub(rep, s)
    return s


def redact_obj(o: Any, depth: int = 0) -> Any:
    if depth > 20:
        return "[TRUNCATED]"
    if isinstance(o, dict):
        return {k: (R if SENSITIVE_KEY.search(str(k)) else redact_obj(v, depth + 1)) for k, v in o.items()}
    if isinstance(o, list):
        return [redact_obj(v, depth + 1) for v in o]
    return redact_text(o)


def redact_headers(h: Any) -> Any:
    if isinstance(h, str):
        try:
            h = json.loads(h)
        except Exception:
            return redact_text(h)
    if isinstance(h, dict):
        return {k: (R if SENSITIVE_HEADER.match(str(k)) else redact_text(v)) for k, v in h.items()}
    if isinstance(h, list):  # [{name,value}] or [[k,v]]
        out = []
        for item in h:
            if isinstance(item, dict) and "name" in item:
                out.append({**item, "value": R} if SENSITIVE_HEADER.match(str(item["name"])) else redact_obj(item))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                out.append([item[0], R if SENSITIVE_HEADER.match(str(item[0])) else redact_text(item[1])])
            else:
                out.append(redact_obj(item))
        return out
    return h


def redact_url(u: Any) -> Any:
    if not isinstance(u, str):
        return u
    return re.sub(
        r"(?i)([?&](?:[^=&#]*(?:token|secret|passw|signature|credential|api[_-]?key|apikey|access[_-]?key|private[_-]?key)[^=&#]*"
        r"|key|sig|auth|code|session|sessionid|sid|jwt|otp)=)[^&#]*",
        r"\1" + R,
        u,
    )


def cap(s: Any, n: int) -> Any:
    if not isinstance(s, str) or len(s) <= n:
        return s
    return s[:n] + f"... [truncated {len(s) - n} chars]"


def redact_body(b: Any, n: int) -> Any:
    if b is None or b == "":
        return b
    if isinstance(b, str):
        try:
            parsed = json.loads(b)
            return cap(json.dumps(redact_obj(parsed), ensure_ascii=False), n)
        except Exception:
            return cap(redact_text(b), n)
    return cap(json.dumps(redact_obj(b), ensure_ascii=False), n)


def jsonish(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return v
    return v


def iso(v: Any) -> Any:
    return v.isoformat() + ("Z" if isinstance(v, datetime) and v.tzinfo is None else "") if isinstance(v, (datetime, date)) else v


# ---------------------------------------------------------------- db / s3
_pool: asyncpg.Pool | None = None


async def pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=0,
            max_size=4,
            command_timeout=15,
            server_settings={"default_transaction_read_only": "on", "application_name": "crikket-mcp"},
        )
    return _pool


async def fetch(sql: str, *args: Any) -> list[asyncpg.Record]:
    p = await pool()
    async with p.acquire() as c:
        async with c.transaction(readonly=True):
            return await c.fetch(sql, *args)


_s3 = None


def s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT,
            region_name=S3_REGION,
            aws_access_key_id=os.environ["STORAGE_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["STORAGE_SECRET_ACCESS_KEY"],
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )
    return _s3


def report_url(rid: str) -> str:
    return f"{APP_URL}/s/{rid}"


async def require_report(rid: str) -> asyncpg.Record:
    rows = await fetch(
        "select r.*, o.name as organization_name from bug_report r left join organization o on o.id = r.organization_id where r.id = $1",
        rid,
    )
    if not rows:
        raise ToolError(f"Report {rid!r} not found")
    return rows[0]


def parse_dt(s: str | None, end: bool = False) -> datetime | None:
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    if len(s) == 10:
        d = datetime.fromisoformat(s)
        return d + timedelta(days=1) if end else d
    d = datetime.fromisoformat(s)
    if d.tzinfo is not None:  # normalise to naive UTC (DB columns are naive UTC)
        d = d.replace(tzinfo=None) - (d.utcoffset() or timedelta(0))
    return d


# ---------------------------------------------------------------- MCP
mcp = MCPServer(
    name="crikket",
    title="Crikket bug reports (read-only)",
    instructions=(
        "Read-only access to Crikket bug reports at crikket.arifin.dev. Start with list_reports, then get_report and the "
        "get_console_logs / get_network_requests / get_user_actions tools for a report id. Sensitive headers and "
        "secret-like fields are redacted; large bodies are truncated. Timestamps are UTC."
    ),
    version="0.1.0",
)
RO = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


@mcp.tool(annotations=RO)
async def list_reports(
    status: Literal["open", "in_progress", "resolved", "closed"] | None = None,
    priority: Literal["none", "low", "medium", "high", "critical"] | None = None,
    tag: str | None = None,
    keyword: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    """List bug reports, newest first. keyword matches title/description (case-insensitive).
    Dates are ISO 8601 (YYYY-MM-DD or full timestamp, UTC); created_before with a bare date is inclusive.
    limit 1-100, paginate with offset (see next_offset)."""
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    where, args = [], []

    def add(cond: str, val: Any) -> None:
        args.append(val)
        where.append(cond.replace("$?", f"${len(args)}"))

    if status:
        add("r.status = $?", status)
    if priority:
        add("r.priority = $?", priority)
    if tag:
        add("$? = any(r.tags)", tag)
    if keyword:
        kw = "%" + keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args.append(kw)
        where.append(f"(r.title ilike ${len(args)} or r.description ilike ${len(args)})")
    if created_after:
        add("r.created_at >= $?", parse_dt(created_after))
    if created_before:
        add("r.created_at < $?", parse_dt(created_before, end=True))
    w = ("where " + " and ".join(where)) if where else ""
    total = (await fetch(f"select count(*) as n from bug_report r {w}", *args))[0]["n"]
    args += [limit, offset]
    rows = await fetch(
        f"select r.id, r.title, r.url, r.status, r.priority, r.tags, r.created_at from bug_report r {w} "
        f"order by r.created_at desc, r.id limit ${len(args) - 1} offset ${len(args)}",
        *args,
    )
    items = [
        {
            "id": r["id"],
            "title": r["title"],
            "url": redact_url(r["url"]),
            "report_url": report_url(r["id"]),
            "status": r["status"],
            "priority": r["priority"],
            "tags": list(r["tags"] or []),
            "created_at": iso(r["created_at"]),
        }
        for r in rows
    ]
    nxt = offset + len(items)
    return {"total": total, "offset": offset, "count": len(items), "next_offset": nxt if nxt < total else None, "reports": items}


@mcp.tool(annotations=RO)
async def get_report(report_id: str) -> dict:
    """Full details of one bug report: description, device info, metadata and debugger summary counts."""
    r = await require_report(report_id)
    c = (
        await fetch(
            """select
              (select count(*) from bug_report_log where bug_report_id=$1) as logs,
              (select count(*) from bug_report_log where bug_report_id=$1 and lower(level) in ('error','fatal')) as console_errors,
              (select count(*) from bug_report_log where bug_report_id=$1 and lower(level) in ('warn','warning')) as console_warnings,
              (select count(*) from bug_report_network_request where bug_report_id=$1) as requests,
              (select count(*) from bug_report_network_request where bug_report_id=$1 and (status is null or status = 0 or status >= 400)) as failed_requests,
              (select count(*) from bug_report_action where bug_report_id=$1) as actions""",
            report_id,
        )
    )[0]
    return {
        "id": r["id"],
        "title": r["title"],
        "description": cap(redact_text(r["description"]), MAX_TEXT),
        "url": redact_url(r["url"]),
        "report_url": report_url(r["id"]),
        "organization": r["organization_name"],
        "status": r["status"],
        "priority": r["priority"],
        "tags": list(r["tags"] or []),
        "visibility": r["visibility"],
        "attachment_type": r["attachment_type"],
        "has_capture": bool(r["capture_key"]),
        "capture_content_type": r["capture_content_type"],
        "has_thumbnail": bool(r["thumbnail_key"]),
        "submission_status": r["submission_status"],
        "debugger_ingestion_status": r["debugger_ingestion_status"],
        "device_info": redact_obj(jsonish(r["device_info"])),
        "metadata": redact_obj(jsonish(r["metadata"])),
        "counts": {k: c[k] for k in c.keys()},
        "created_at": iso(r["created_at"]),
        "updated_at": iso(r["updated_at"]),
    }


@mcp.tool(annotations=RO)
async def get_console_logs(
    report_id: str,
    level: Literal["all", "errors", "warnings_and_errors", "error", "warn", "info", "log", "debug"] = "all",
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Console logs of a report in chronological order. level='errors' returns only error-level entries."""
    await require_report(report_id)
    limit = max(1, min(int(limit), 500))
    levels = {
        "errors": ["error", "fatal"],
        "warnings_and_errors": ["error", "fatal", "warn", "warning"],
        "error": ["error", "fatal"],
        "warn": ["warn", "warning"],
    }.get(level, [level] if level != "all" else None)
    args: list[Any] = [report_id]
    cond = ""
    if levels:
        args.append(levels)
        cond = "and lower(level) = any($2::text[])"
    total = (await fetch(f"select count(*) n from bug_report_log where bug_report_id=$1 {cond}", *args))[0]["n"]
    rows = await fetch(
        f'select level, message, "timestamp", "offset", metadata from bug_report_log where bug_report_id=$1 {cond} '
        f'order by "offset" nulls last, "timestamp", id limit {limit} offset {max(0, int(offset))}',
        *args,
    )
    return {
        "report_id": report_id,
        "total": total,
        "logs": [
            {
                "level": x["level"],
                "message": cap(redact_text(x["message"]), MAX_TEXT),
                "timestamp": iso(x["timestamp"]),
                "offset_ms": x["offset"],
                "metadata": redact_obj(jsonish(x["metadata"])),
            }
            for x in rows
        ],
    }


@mcp.tool(annotations=RO)
async def get_network_requests(
    report_id: str,
    failed_only: bool = False,
    include_bodies: bool = False,
    max_body_chars: int = DEFAULT_BODY_CAP,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Network requests of a report in chronological order. failed_only keeps status >= 400 or no status (network error).
    Sensitive headers and secret-like body fields are redacted; bodies only with include_bodies, capped at max_body_chars (<=10000)."""
    await require_report(report_id)
    limit = max(1, min(int(limit), 200))
    n = max(100, min(int(max_body_chars), MAX_BODY_CAP))
    cond = "and (status is null or status = 0 or status >= 400)" if failed_only else ""
    total = (await fetch(f"select count(*) n from bug_report_network_request where bug_report_id=$1 {cond}", report_id))[0]["n"]
    rows = await fetch(
        f'select method, url, status, duration, request_headers, response_headers, request_body, response_body, "timestamp", "offset" '
        f'from bug_report_network_request where bug_report_id=$1 {cond} order by "offset" nulls last, "timestamp", id '
        f"limit {limit} offset {max(0, int(offset))}",
        report_id,
    )
    out = []
    for x in rows:
        item = {
            "method": x["method"],
            "url": cap(redact_url(x["url"]), 2000),
            "status": x["status"],
            "failed": x["status"] is None or x["status"] == 0 or x["status"] >= 400,
            "duration_ms": x["duration"],
            "timestamp": iso(x["timestamp"]),
            "offset_ms": x["offset"],
            "request_headers": redact_headers(jsonish(x["request_headers"])),
            "response_headers": redact_headers(jsonish(x["response_headers"])),
        }
        if include_bodies:
            item["request_body"] = redact_body(x["request_body"], n)
            item["response_body"] = redact_body(x["response_body"], n)
        else:
            item["request_body_chars"] = len(x["request_body"] or "")
            item["response_body_chars"] = len(x["response_body"] or "")
        out.append(item)
    return {"report_id": report_id, "total": total, "requests": out}


@mcp.tool(annotations=RO)
async def get_user_actions(report_id: str, limit: int = 200, offset: int = 0) -> dict:
    """User actions (clicks, inputs, navigation...) of a report, chronological by recording offset."""
    await require_report(report_id)
    limit = max(1, min(int(limit), 500))
    total = (await fetch("select count(*) n from bug_report_action where bug_report_id=$1", report_id))[0]["n"]
    rows = await fetch(
        f'select type, target, "timestamp", "offset", metadata from bug_report_action where bug_report_id=$1 '
        f'order by "offset" nulls last, "timestamp", id limit {limit} offset {max(0, int(offset))}',
        report_id,
    )
    return {
        "report_id": report_id,
        "total": total,
        "actions": [
            {
                "type": x["type"],
                "target": cap(redact_text(x["target"]), 1000),
                "timestamp": iso(x["timestamp"]),
                "offset_ms": x["offset"],
                "metadata": redact_obj(jsonish(x["metadata"])),
            }
            for x in rows
        ],
    }


@mcp.tool(annotations=RO)
async def get_media_link(report_id: str, kind: Literal["capture", "thumbnail"] = "capture") -> dict:
    """Presigned HTTPS GET link (valid 15 minutes) for the report's capture (video/screenshot) or thumbnail."""
    r = await require_report(report_id)
    key = r["capture_key"] if kind == "capture" else r["thumbnail_key"]
    if not key:
        raise ToolError(f"Report {report_id!r} has no {kind}")
    url = s3().generate_presigned_url("get_object", Params={"Bucket": S3_BUCKET, "Key": key}, ExpiresIn=MEDIA_EXPIRY)
    return {
        "report_id": report_id,
        "kind": kind,
        "content_type": r["capture_content_type"] if kind == "capture" else r["thumbnail_content_type"],
        "url": url,
        "expires_in_seconds": MEDIA_EXPIRY,
        "expires_at": (datetime.utcnow() + timedelta(seconds=MEDIA_EXPIRY)).replace(microsecond=0).isoformat() + "Z",
    }


# ---------------------------------------------------------------- HTTP app + auth
inner = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    host="0.0.0.0",
    max_request_body_size=1_000_000,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[PUBLIC_HOST, "localhost:*", "127.0.0.1:*", "localhost", "127.0.0.1"],
        allowed_origins=[],
    ),
)


async def _send_json(send, status: int, body: dict, extra: list | None = None) -> None:
    data = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())] + (extra or [])
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})


async def app(scope, receive, send):
    if scope["type"] != "http":
        return await inner(scope, receive, send)  # lifespan
    path = scope.get("path", "")
    if path == "/healthz" and scope.get("method") in ("GET", "HEAD"):
        return await _send_json(send, 200, {"ok": True})
    if len(AUTH_TOKEN) < 32:
        return await _send_json(send, 503, {"error": "server auth token not configured"})
    auth = b""
    for k, v in scope.get("headers", []):
        if k == b"authorization":
            auth = v
            break
    expected = b"Bearer " + AUTH_TOKEN.encode()
    if not hmac.compare_digest(auth, expected):
        return await _send_json(
            send, 401, {"error": "unauthorized"}, [(b"www-authenticate", b'Bearer realm="crikket-mcp"')]
        )
    return await inner(scope, receive, send)
