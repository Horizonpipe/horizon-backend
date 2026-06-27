#!/usr/bin/env bash
# Bootstrap OVH ADVANCE-1 (Ubuntu 24.04) for Horizonpipe.
# Run as root on a fresh server: bash setup-server.sh
set -euo pipefail

HORIZON_USER="${HORIZON_USER:-horizon}"
HORIZON_HOME="/opt/horizon"
PG_DB="${PG_DB:-horizon}"
PG_USER="${PG_USER:-horizon}"
PG_PASS="${PG_PASS:-$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)}"

echo "==> System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
apt-get install -y curl git nginx certbot python3-certbot-nginx ufw fail2ban \
  postgresql postgresql-contrib jq unzip

echo "==> Node.js 20 LTS"
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

echo "==> PM2"
npm install -g pm2
pm2 startup systemd -u "$HORIZON_USER" --hp "$HORIZON_HOME" || true

echo "==> App user + directories"
id "$HORIZON_USER" &>/dev/null || useradd -m -d "$HORIZON_HOME" -s /bin/bash "$HORIZON_USER"
mkdir -p "$HORIZON_HOME" /var/log/horizon /var/backups/horizon/postgres /var/www/certbot
chown -R "$HORIZON_USER:$HORIZON_USER" "$HORIZON_HOME" /var/log/horizon /var/backups/horizon

echo "==> PostgreSQL database"
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$PG_USER'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE USER $PG_USER WITH PASSWORD '$PG_PASS';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE DATABASE $PG_DB OWNER $PG_USER;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $PG_DB TO $PG_USER;"

PG_CONF=$(find /etc/postgresql -name postgresql.conf | head -1)
if [[ -n "$PG_CONF" ]]; then
  sed -i "s/#shared_buffers = 128MB/shared_buffers = 4GB/" "$PG_CONF" || true
  sed -i "s/#effective_cache_size = 4GB/effective_cache_size = 16GB/" "$PG_CONF" || true
  systemctl restart postgresql
fi

echo "==> Firewall"
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

echo ""
echo "=============================================="
echo "Server bootstrap complete."
echo ""
echo "Postgres local connection:"
echo "  DATABASE_URL=postgresql://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}"
echo ""
echo "Save that password — add to /opt/horizon/horizon-backend/.env"
echo ""
echo "Next steps (as user $HORIZON_USER):"
echo "  1. Clone repos into $HORIZON_HOME"
echo "  2. Copy deploy/ovh/env.production.template → .env and fill secrets"
echo "  3. npm install in horizon-backend"
echo "  4. bash deploy/ovh/migrate-from-render.sh  (imports Render Postgres)"
echo "  5. sudo cp deploy/ovh/nginx-horizon.conf /etc/nginx/sites-available/horizon"
echo "  6. sudo certbot --nginx -d YOUR_DOMAIN"
echo "  7. pm2 start deploy/ovh/ecosystem.config.cjs && pm2 save"
echo "  8. sudo bash deploy/ovh/install-backups.sh"
echo "=============================================="
