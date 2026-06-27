#!/usr/bin/env bash
set -euo pipefail
PG_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
echo "$PG_PASS" > /root/.horizon_pg_pass
chmod 600 /root/.horizon_pg_pass
sudo -u postgres psql -c "CREATE USER horizon WITH PASSWORD '$PG_PASS';" 2>/dev/null \
  || sudo -u postgres psql -c "ALTER USER horizon WITH PASSWORD '$PG_PASS';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='horizon'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE DATABASE horizon OWNER horizon;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE horizon TO horizon;"
echo PG_READY
