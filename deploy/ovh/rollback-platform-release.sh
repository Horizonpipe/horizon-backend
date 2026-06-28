#!/usr/bin/env bash
# Roll back frontend or backend from a published platform release on Wasabi (non-SaaS OVH).
# Usage: rollback-platform-release.sh {frontend|backend} <version>
set -euo pipefail

TARGET="${1:-}"
VERSION="${2:-${HP_RELEASE_VERSION:-}}"
if [[ -z "$TARGET" || -z "$VERSION" ]]; then
  echo "[rollback-release] usage: rollback-platform-release.sh {frontend|backend} <version>" >&2
  exit 1
fi

ROOT="${HP_REPO_ROOT:-/opt/horizon}"
BACKEND_DIR="${ROOT}/horizon-backend"
FRONTEND_DIR="${ROOT}/horizon-frontend"
ENV_FILE="${BACKEND_DIR}/.env"
STAGING="/tmp/hp-platform-rollback-${TARGET}-${VERSION}-$$"
PM2_USER="${HP_PM2_USER:-ubuntu}"

cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[rollback-release] missing $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

if [[ "${HP_DEPLOYMENT_MODE:-non-saas}" == "saas" ]]; then
  echo "[rollback-release] use apply-platform-release.sh on SaaS hosts" >&2
  exit 1
fi

if [[ -z "${WASABI_BUCKET:-}" || -z "${WASABI_ACCESS_KEY_ID:-}" || -z "${WASABI_SECRET_ACCESS_KEY:-}" ]]; then
  echo "[rollback-release] Wasabi credentials required" >&2
  exit 1
fi

WASABI_ENDPOINT="${WASABI_ENDPOINT:-https://s3.us-east-1.wasabisys.com}"
WASABI_REGION="${WASABI_REGION:-us-east-1}"

case "$TARGET" in
  frontend)
    ARTIFACT_KEY="${HP_RELEASE_FRONTEND_KEY:-platform/releases/${VERSION}/artifacts/frontend.tar.gz}"
    LIVE_DIR="$FRONTEND_DIR"
    ;;
  backend)
    ARTIFACT_KEY="${HP_RELEASE_BACKEND_KEY:-platform/releases/${VERSION}/artifacts/backend.tar.gz}"
    LIVE_DIR="$BACKEND_DIR"
    ;;
  *)
    echo "[rollback-release] target must be frontend or backend" >&2
    exit 1
    ;;
esac

aws_get() {
  AWS_ACCESS_KEY_ID="${WASABI_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${WASABI_SECRET_ACCESS_KEY}" \
  AWS_DEFAULT_REGION="${WASABI_REGION}" \
    aws s3 cp "s3://${WASABI_BUCKET}/$1" "$2" --endpoint-url "$WASABI_ENDPOINT"
}

mkdir -p "$STAGING/extract"
ARCHIVE="$STAGING/artifact.tar.gz"

echo "[rollback-release] downloading v${VERSION} ${TARGET} artifact…"
aws_get "$ARTIFACT_KEY" "$ARCHIVE"

echo "[rollback-release] extracting…"
tar -xzf "$ARCHIVE" -C "$STAGING/extract"

TS="$(date +%Y%m%d-%H%M%S)"
if [[ -d "$LIVE_DIR" ]]; then
  mv "$LIVE_DIR" "${LIVE_DIR}.bak-${TS}"
fi
mv "$STAGING/extract" "$LIVE_DIR"

if [[ "$TARGET" == "backend" && -f "${BACKEND_DIR}.bak-${TS}/.env" ]]; then
  cp "${BACKEND_DIR}.bak-${TS}/.env" "${BACKEND_DIR}/.env"
  chmod 600 "${BACKEND_DIR}/.env"
fi

if [[ "$TARGET" == "backend" ]]; then
  echo "[rollback-release] npm install…"
  cd "$BACKEND_DIR"
  npm install --omit=dev
fi

echo "[rollback-release] pm2 reload…"
if id "$PM2_USER" &>/dev/null; then
  sudo -u "$PM2_USER" bash -lc "cd '$BACKEND_DIR' && pm2 reload deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
else
  cd "$BACKEND_DIR"
  pm2 reload deploy/ovh/ecosystem.config.cjs --update-env || pm2 restart horizon-backend --update-env
  pm2 save || true
fi

echo "[rollback-release] ${TARGET} restored to v${VERSION}."
