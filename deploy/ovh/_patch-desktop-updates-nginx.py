#!/usr/bin/env python3
from pathlib import Path

path = Path("/etc/nginx/sites-available/horizon")
text = path.read_text()
marker = "horizon-desktop-updates"
if marker in text:
    print("already patched")
else:
    snippet = """
    # horizon-desktop-updates — public NSIS feed for electron-updater
    location ^~ /desktop-updates/ {
        alias /opt/horizon/desktop-updates/;
        autoindex off;
        default_type application/octet-stream;
        types {
            text/yaml yml yaml;
            application/octet-stream exe blockmap;
        }
        add_header Cache-Control "public, max-age=60";
        add_header Access-Control-Allow-Origin "*";
    }
"""
    needle = "    location / {\n        try_files $uri $uri/ @node_live;"
    count = text.count(needle)
    if count < 1:
        raise SystemExit("needle not found for @node_live")
    text = text.replace(needle, snippet + "\n" + needle)
    path.write_text(text)
    print(f"patched {count} location block(s)")
