#!/usr/bin/env bash
# Configure GoDaddy / Microsoft 365 SMTP for pipeshare.net sign-up verification emails.
#
# Mailbox: EmailVerification@pipeshare.net
# M365 (default): smtp.office365.com:587 — requires SMTP Authentication ON in GoDaddy Advanced Settings
# Legacy Workspace: SMTP_HOST=smtpout.secureserver.net SMTP_PORT=465
#
# On OVH after git pull:
#   SMTP_PASS='your-mailbox-password' bash /opt/horizon/horizon-backend/deploy/ovh/setup-pipeshare-signup-smtp.sh
#
# From your PC (SSH alias horizon-ovh):
#   ssh horizon-ovh "SMTP_PASS='your-mailbox-password' bash /opt/horizon/horizon-backend/deploy/ovh/setup-pipeshare-signup-smtp.sh"
set -euo pipefail

ENV="${HP_BACKEND_ENV:-/opt/horizon/horizon-backend/.env}"
SMTP_USER="${SMTP_USER:-EmailVerification@pipeshare.net}"
SMTP_PASS="${SMTP_PASS:-}"
SMTP_HOST="${SMTP_HOST:-smtp.office365.com}"
SMTP_PORT="${SMTP_PORT:-587}"
if [[ -z "${SMTP_SECURE:-}" ]]; then
  if [[ "$SMTP_PORT" == "465" ]]; then SMTP_SECURE=true; else SMTP_SECURE=false; fi
fi

if [[ -z "$SMTP_PASS" ]]; then
  echo "ERROR: Set SMTP_PASS to the GoDaddy mailbox password for ${SMTP_USER}." >&2
  echo "  SMTP_PASS='...' bash $0" >&2
  exit 1
fi

if [[ ! -f "$ENV" ]]; then
  echo "ERROR: $ENV not found" >&2
  exit 1
fi

grep -v -E '^(SMTP_|SIGNUP_MAIL_FROM_NAME)=' "$ENV" > /tmp/horizon.env.smtp || true
{
  cat /tmp/horizon.env.smtp
  echo ''
  echo '# PipeShare.net sign-up verification email'
  echo "SMTP_HOST=${SMTP_HOST}"
  echo "SMTP_PORT=${SMTP_PORT}"
  echo "SMTP_SECURE=${SMTP_SECURE}"
  echo "SMTP_USER=${SMTP_USER}"
  echo "SMTP_PASS=${SMTP_PASS}"
  echo "SMTP_FROM=PipeShare <${SMTP_USER}>"
  echo 'SIGNUP_MAIL_FROM_NAME=PipeShare'
} > "${ENV}.new"
mv "${ENV}.new" "$ENV"
chmod 600 "$ENV"

if id ubuntu &>/dev/null; then
  chown ubuntu:ubuntu "$ENV" 2>/dev/null || true
fi

if command -v pm2 >/dev/null 2>&1; then
  pm2 reload horizon-backend --update-env
  echo "==> PM2 reloaded horizon-backend"
fi

echo "OK: SMTP configured for ${SMTP_USER} via ${SMTP_HOST}:${SMTP_PORT}"
echo "    Test sign-up at https://pipeshare.net/ → Create account"
