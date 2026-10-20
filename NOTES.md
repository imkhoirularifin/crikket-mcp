# Crikket MCP server (read-only) — deployed 2026-10-20 ~15:45 WIB

- URL: https://crikket-mcp.arifin.dev/mcp (MCP streamable HTTP, stateless, JSON responses). GET /healthz -> {"ok":true} (no auth, no data).
- Auth: every other request needs `Authorization: Bearer <token>` (hmac.compare_digest). Token = Coolify env MCP_AUTH_TOKEN (locked) = box env CRIKKET_MCP_TOKEN.
  Missing/short token on server => 503 for everything. DNS-rebinding protection: allowed Host crikket-mcp.arifin.dev (+localhost).
- Code: app.py (Python, official `mcp` SDK 2.3.0 MCPServer, asyncpg, boto3 presign, uvicorn). Dockerfile, requirements.txt, compose.yml, create.py, e2e.py.
- Deploy: Coolify *service* `crikket-mcp` uuid xwjj6tpqmjmvykopldlbbilg (DocuMind/production). Image `crikket-mcp:0.1.0` built ON the VM
  from /root/crikket-mcp (pull_policy: never). mem_limit 256m (~62 MiB used), read_only rootfs, cap_drop ALL, no-new-privileges, non-root.
  Update: scp app.py to /root/crikket-mcp, `docker build -t crikket-mcp:0.1.0 .`, then POST /api/v1/services/xwjj.../restart.
- Traefik: compose labels, Host(crikket-mcp.arifin.dev) http->https redirect, LE cert.
- DNS: A crikket-mcp.arifin.dev -> 13.140.64.217, DNS-only, record 878582ea45422b135aa99646a04de813.
- DB: role `crikket_mcp` on documind-postgres (pw only in /root/crikket-mcp.env 0600 + Coolify env DATABASE_URL locked).
  LOGIN, conn limit 8, default_transaction_read_only=on, statement_timeout 15s. GRANT CONNECT db crikket, USAGE schema public,
  SELECT on bug_report, bug_report_log, bug_report_network_request, bug_report_action; SELECT(id,name) on organization only.
  user/session/account/verification etc. -> permission denied (verified). Note: PUBLIC still has CONNECT on db documind/postgres
  (Postgres default) but crikket_mcp can read 0 tables there.
- Storage: presigned GET (15 min) via https://crikket-files.arifin.dev using the existing bucket-scoped MinIO user `crikket`
  (keys copied from crikket server container env into Coolify env; secret locked).
- Tools (all readOnlyHint): list_reports, get_report, get_console_logs, get_network_requests, get_user_actions, get_media_link.
- Redaction: sensitive headers (authorization, cookie, set-cookie, x-api-key, *token*, *secret*, *session*, ...), secret-like JSON keys
  and key=value pairs in bodies/messages/metadata, Bearer/Basic creds, JWTs, sensitive URL query params. Bodies only on request,
  capped (default 2000, max 10000 chars); messages capped 4000.
- Verified 2026-10-20: 401 without/with wrong token; initialize + tools/list + all tools on real data (7 reports); pagination & filters;
  presigned GET 206 video/webm; redaction (real body password field redacted; header redaction unit-checked in the deployed container,
  since stored Crikket data contains no auth/cookie headers). Bots scanning the host get 401.
- Remove: delete Coolify service, DNS record, `drop role crikket_mcp` (after revoking grants), docker rmi crikket-mcp:0.1.0.
