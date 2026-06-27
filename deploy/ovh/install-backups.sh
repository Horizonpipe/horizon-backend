#!/usr/bin/env bash
# Install cron jobs + AWS CLI + Wasabi backup config.
# Run as root: sudo bash deploy/ovh/install-backups.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_ROOT="/opt/horizon/horizon-backend/deploy/ovh"
LOG_DIR="/var/log/horizon"

mkdir -p /etc/horizon "$LOG_DIR"
chmod 700 /etc/horizon

bash "$SCRIPT_DIR/install-awscli.sh"

bash "$SCRIPT_DIR/configure-backup-wasabi.sh"

CRON_FILE="/etc/cron.d/horizon-backups"
cat >"$CRON_FILE" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily Postgres dump (03:15 UTC) — 14 days local, 90 days on Wasabi
15 3 * * * root bash ${INSTALL_ROOT}/backup-postgres.sh >> ${LOG_DIR}/backup.log 2>&1

# Weekly config tarball (Sunday 04:00 UTC) — .env, nginx, cron, PM2
0 4 * * 0 root bash ${INSTALL_ROOT}/backup-config.sh >> ${LOG_DIR}/backup.log 2>&1
EOF
chmod 644 "$CRON_FILE"

echo "Backup cron installed:"
echo "  - Daily Postgres → Wasabi: ${INSTALL_ROOT}/backup-postgres.sh"
echo "  - Weekly config  → Wasabi: ${INSTALL_ROOT}/backup-config.sh"
echo "  - Wasabi prefix: backups/ovh-horizon/ (inside app bucket)"
echo "  - Logs: ${LOG_DIR}/backup.log"
echo ""
echo "Test now:"
echo "  sudo bash ${INSTALL_ROOT}/backup-postgres.sh"
echo "  sudo bash ${INSTALL_ROOT}/backup-config.sh"
