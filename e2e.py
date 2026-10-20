import json, sys, subprocess, urllib.request, ssl
TOK = sys.stdin.read().strip()
URL = "https://crikket-mcp.arifin.dev/mcp"
def post(body, auth=True, tok=None):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
    if auth: h["Authorization"] = "Bearer " + (tok if tok is not None else TOK)
    r = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=30) as x: return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e: return e.code, e.read()[:100]
init = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}
print("no auth:", post(init, auth=False)[0]); print("wrong token:", post(init, tok="x"*64)[0]); print("wrong scheme-ish:", post(init, tok=TOK[:-1]+"0")[0] if TOK[-1]!="0" else "skip")
c, r = post(init); print("initialize:", c, r["result"]["serverInfo"])
c, r = post({"jsonrpc":"2.0","id":2,"method":"tools/list"}); print("tools/list:", c, [(t["name"], t.get("annotations",{}).get("readOnlyHint")) for t in r["result"]["tools"]])
n = [3]
def call(name, **args):
    n[0] += 1
    c, r = post({"jsonrpc":"2.0","id":n[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    res = r.get("result", {})
    if res.get("isError"): return {"ERROR": res["content"][0]["text"][:200]}
    return res.get("structuredContent") or json.loads(res["content"][0]["text"])
lr = call("list_reports", limit=3); print("list_reports:", lr["total"], lr["next_offset"], [(x["id"], x["status"], x["priority"], x["created_at"][:16]) for x in lr["reports"]])
p2 = call("list_reports", limit=3, offset=3); print("page2:", [x["id"] for x in p2["reports"]])
print("filter status=open:", call("list_reports", status="open")["total"], "| keyword 'zzzqqq':", call("list_reports", keyword="zzzqqq")["total"], "| after 2030:", call("list_reports", created_after="2030-01-01")["total"], "| before today incl:", call("list_reports", created_before="2026-10-20")["total"])
allr = call("list_reports", limit=100)["reports"]
best = None
for x in allr:
    g = call("get_report", report_id=x["id"])
    if best is None or g["counts"]["requests"] > best["counts"]["requests"]: best = g
print("get_report:", best["id"], best["counts"], "device_info keys:", list((best["device_info"] or {}).keys())[:6])
rid = best["id"]
cl = call("get_console_logs", report_id=rid, level="errors"); print("console errors:", cl["total"], [ (l["level"], l["message"][:50]) for l in cl["logs"][:2]])
nr = call("get_network_requests", report_id=rid, failed_only=True, include_bodies=True, max_body_chars=300); print("failed requests:", nr["total"], [(q["method"], q["status"], q["url"][:50]) for q in nr["requests"][:3]])
ua = call("get_user_actions", report_id=rid, limit=5); print("actions:", ua["total"], [(a["type"], a["offset_ms"]) for a in ua["actions"]], "ordered:", [a["offset_ms"] for a in ua["actions"]] == sorted(a["offset_ms"] for a in ua["actions"]))
print("bad id:", call("get_report", report_id="nope"))
# redaction check across ALL reports: collect every returned request, look at sensitive headers
allreq = []
for x in allr:
    q = call("get_network_requests", report_id=x["id"], include_bodies=True, limit=200, max_body_chars=10000)
    allreq += q["requests"]
import re
sens = re.compile(r"^(authorization|cookie|set-cookie|x-api-key)$", re.I)
seen = {}
def hdr_items(h):
    if isinstance(h, dict): return h.items()
    if isinstance(h, list): return [(i.get("name"), i.get("value")) if isinstance(i, dict) else tuple(i) for i in h]
    return []
for q in allreq:
    for part in ("request_headers", "response_headers"):
        for k, v in hdr_items(q[part]):
            if sens.match(str(k)): seen.setdefault(k.lower(), set()).add(v)
print("sensitive headers returned (values shown only if not redacted):", {k: (sorted(v) if v != {"[REDACTED]"} else "all [REDACTED]") for k, v in seen.items()})
out = json.dumps(allreq)
json.dump({"out": out}, open("/tmp/mcp_out.json", "w"))
print("total requests returned:", len(allreq), "| REDACTED markers:", out.count("[REDACTED]"), "| max body len:", max([len(q.get("response_body") or "") for q in allreq] + [0]))
ml = call("get_media_link", report_id=rid, kind="capture"); print("media:", ml.get("kind"), ml.get("content_type"), ml.get("expires_in_seconds"), "host ok:", ml.get("url","").startswith("https://crikket-files.arifin.dev/crikket/"))
r = urllib.request.Request(ml["url"], headers={"Range": "bytes=0-15"})
with urllib.request.urlopen(r, timeout=20) as x: print("presigned GET:", x.status, x.headers.get("Content-Type"), len(x.read()), "bytes")
th = call("get_media_link", report_id=rid, kind="thumbnail"); print("thumbnail:", "url" in th or th)
reps = [call("get_report", report_id=x["id"]) for x in allr]
e = max(reps, key=lambda g: g["counts"]["console_errors"]); f = max(reps, key=lambda g: g["counts"]["failed_requests"])
print("max console_errors:", e["id"], e["counts"]["console_errors"], "of", e["counts"]["logs"])
cl = call("get_console_logs", report_id=e["id"], level="errors"); print("  errors-only levels:", sorted({l["level"] for l in cl["logs"]}), "n=", cl["total"])
print("  all levels:", sorted({l["level"] for l in call("get_console_logs", report_id=e["id"])["logs"]}))
print("max failed:", f["id"], f["counts"]["failed_requests"])
nr = call("get_network_requests", report_id=f["id"], failed_only=True); print("  failed statuses:", sorted({str(q["status"]) for q in nr["requests"]}), "n=", nr["total"])
