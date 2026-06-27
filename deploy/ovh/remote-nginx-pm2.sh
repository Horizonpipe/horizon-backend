#!/usr/bin/env bash
set -euo pipefail
cat >/etc/nginx/sites-available/horizon <<'NGINX'
upstream horizon_node {
    least_conn;
    server 127.0.0.1:3000;
    keepalive 64;
}
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    client_max_body_size 25m;
    location / {
        proxy_pass http://horizon_node;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/horizon /etc/nginx/sites-enabled/horizon
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
echo NGINX_OK
