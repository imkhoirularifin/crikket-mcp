#!/usr/bin/env python3
# Runs ON the VM. stdin: line1 Coolify token, line2 MCP auth token. Never prints secrets.
import json, sys, base64, subprocess, urllib.request
lines = sys.stdin.read().split("\n")
TOKEN, MCP_TOKEN = lines[0].strip(), lines[1].strip()
API = "http://localhost:8000/api/v1"
def req(m, p, b=None):
    r = urllib.request.Request(API + p, method=m, data=json.dumps(b).encode() if b is not None else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(r) as x: return x.status, json.loads(x.read() or b"null")
    except urllib.error.HTTPError as e: return e.code, (e.read() or b"")[:300].decode(errors="replace")
st = json.load(open("/root/documind-sg-created.json"))
pg = dict(l.strip().split("=", 1) for l in open("/root/crikket-mcp.env") if "=" in l)
cenv = dict(l.split("=", 1) for l in subprocess.check_output(["docker", "exec", f"server-{st['crikket']}", "env"], text=True).splitlines() if "=" in l)
assert len(MCP_TOKEN) >= 32
if not st.get("crikket_mcp"):
    code, r = req("POST", "/services", dict(server_uuid=st["server"], project_uuid=st["project"], environment_name="production",
        name="crikket-mcp", description="Read-only MCP server for Crikket bug reports. https://crikket-mcp.arifin.dev/mcp (image crikket-mcp built on VM from /root/crikket-mcp)",
        docker_compose_raw=base64.b64encode(open("/root/crikket-mcp/compose.yml").read().encode()).decode(), instant_deploy=False))
    print("create", code, r.get("uuid") if isinstance(r, dict) else r)
    st["crikket_mcp"] = r["uuid"]; json.dump(st, open("/root/documind-sg-created.json", "w"), indent=1)
S = st["crikket_mcp"]
print("net", req("PATCH", f"/services/{S}", {"connect_to_docker_network": True})[0])
env = [
 ("DATABASE_URL", f"postgresql://crikket_mcp:{pg['CRIKKET_MCP_PG_PASSWORD']}@{st['postgres']}:5432/crikket", True),
 ("MCP_AUTH_TOKEN", MCP_TOKEN, True),
 ("STORAGE_ACCESS_KEY_ID", cenv["STORAGE_ACCESS_KEY_ID"].strip(), False),
 ("STORAGE_SECRET_ACCESS_KEY", cenv["STORAGE_SECRET_ACCESS_KEY"].strip(), True),
]
for k, v, locked in env:
    code, r = req("PATCH", f"/services/{S}/envs", {"key": k, "value": v, "is_literal": True, "is_shown_once": locked})
    if code == 404:
        code, r = req("POST", f"/services/{S}/envs", {"key": k, "value": v, "is_literal": True, "is_shown_once": locked})
    print("env", k, code, "locked" if locked else "")
print("uuid", S)
