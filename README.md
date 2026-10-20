# Crikket MCP (read-only)

Python MCP server (official `mcp` SDK) that exposes Crikket bug reports over Streamable HTTP. All tools are read-only.

## Tools

| Tool | Description |
|------|-------------|
| `list_reports` | List/filter bug reports (status, priority, keyword, date range, pagination) |
| `get_report` | Fetch one report with counts and metadata |
| `get_console_logs` | Console logs for a report (optional level filter) |
| `get_network_requests` | Network requests (optional failed-only, bodies) |
| `get_user_actions` | User action timeline for a report |
| `get_media_link` | Presigned GET URL for capture or thumbnail |

## Required environment variables

- `DATABASE_URL`
- `MCP_AUTH_TOKEN`
- `STORAGE_ACCESS_KEY_ID`
- `STORAGE_SECRET_ACCESS_KEY`

Optional / commonly set (see `compose.yml` / `app.py`):

- `PUBLIC_HOST`
- `CRIKKET_APP_URL`
- `STORAGE_ENDPOINT`
- `STORAGE_BUCKET`
- `STORAGE_REGION`

## Run with Docker

```bash
# Provide secrets via env or a .env file (not committed)
export DATABASE_URL=...
export MCP_AUTH_TOKEN=...
export STORAGE_ACCESS_KEY_ID=...
export STORAGE_SECRET_ACCESS_KEY=...

docker build -t crikket-mcp:0.1.0 .
docker compose up -d
```

Health check: `GET /healthz` → `{"ok":true}` (no auth).

## Connect

- Transport: **Streamable HTTP** at `/mcp`
- Auth: `Authorization: Bearer <MCP_AUTH_TOKEN>` on every MCP request
- Missing/short server token → `503`; wrong/missing client token → `401`

## Redaction & security

From deployment notes:

- Sensitive headers (`authorization`, `cookie`, `set-cookie`, `x-api-key`, and names containing `token` / `secret` / `session`, etc.) are redacted.
- Secret-like JSON keys and `key=value` pairs in bodies/messages/metadata, Bearer/Basic credentials, JWTs, and sensitive URL query params are redacted.
- Request/response bodies are included only when requested; body text is capped (default 2000, max 10000 chars); messages capped at 4000.
- Auth uses constant-time compare (`hmac.compare_digest`). DNS-rebinding protection restricts allowed `Host` values.
- DB role is intended to be read-only (`SELECT` on bug-report tables only). Storage access is via short-lived (15 min) presigned GETs.
