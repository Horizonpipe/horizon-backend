#!/usr/bin/env bash
# Keep AutoSync presign/heartbeat from turning a brief Node restart into a 10s 502 blackhole.
# Idempotent. Does not start PM2. Reloads nginx only after nginx -t succeeds.
set -euo pipefail

python3 - <<'PY'
import pathlib
import re

nginx_conf = pathlib.Path("/etc/nginx/nginx.conf")
if nginx_conf.is_file():
    text = nginx_conf.read_text(encoding="utf-8", errors="replace")
    orig = text
    if "worker_rlimit_nofile" not in text:
        text = re.sub(r"(worker_processes\s+[^;]+;)", r"\1\nworker_rlimit_nofile 8192;", text, count=1)
    else:
        text = re.sub(r"worker_rlimit_nofile\s+\d+;", "worker_rlimit_nofile 8192;", text, count=1)
    text = re.sub(r"worker_connections\s+\d+;", "worker_connections 4096;", text, count=1)
    if text != orig:
        nginx_conf.write_text(text, encoding="utf-8")
        print("[nginx-tune] raised worker_connections / nofile")
    else:
        print("[nginx-tune] worker_connections already set")

heartbeat = """
    # Desktop AutoSync heartbeat. Short, not sticky, and not retried into a 502.
    location = /auto-import-plugin/desktop-heartbeat {
        proxy_pass http://horizon_node;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_connect_timeout 2s;
        proxy_read_timeout 15s;
        proxy_send_timeout 15s;
        proxy_buffering off;
        proxy_next_upstream off;
    }

"""

roots = [
    pathlib.Path("/etc/nginx/sites-enabled"),
    pathlib.Path("/etc/nginx/sites-available"),
]
seen = set()
for root in roots:
    if not root.is_dir():
        continue
    for path in root.iterdir():
        if not path.is_file():
            continue
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "upstream horizon_node" not in text:
            continue
        seen.add(key)
        orig = text

        def patch_horizon_node(match):
            block = match.group(0)
            block = re.sub(
                r"server\s+127\.0\.0\.1:3000(?!\s+max_fails)\s*;",
                "server 127.0.0.1:3000 max_fails=0;",
                block,
            )
            block = re.sub(r"keepalive\s+64\s*;", "keepalive 128;", block)
            return block

        text = re.sub(r"upstream horizon_node \{[^}]*\}", patch_horizon_node, text)
        text = text.replace(
            "proxy_next_upstream error timeout http_502 http_503;",
            "proxy_next_upstream error timeout http_502;",
        )
        if "location = /auto-import-plugin/desktop-heartbeat" not in text:
            needle = "    location ^~ /api/files/download/ {"
            if needle in text:
                text = text.replace(needle, heartbeat + needle)
        if text != orig:
            path.write_text(text, encoding="utf-8")
            print(f"[nginx-tune] patched {path}")
        else:
            print(f"[nginx-tune] unchanged {path}")
PY

nginx -t
systemctl reload nginx
echo "[nginx-tune] reloaded"
