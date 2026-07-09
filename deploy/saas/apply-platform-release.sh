#!/usr/bin/env bash
# Apply a platform release on a SAAS host (HP_DEPLOYMENT_MODE=saas).
# Called by POST /saas/platform/releases/apply — do not run on non-SaaS servers.
#
# Usage: apply-platform-release.sh <version>
set -euo pipefail

VERSION="${1:-${HP_RELEASE_VERSION:-}}"
if [[ -z "$VERSION" ]]; then
  echo "[apply] version argument required" >&2
  exit 1
fi

ROOT="${HP_REPO_ROOT:-/opt/horizon}"
BACKEND_DIR="${ROOT}/horizon-backend"
FRONTEND_DIR="${ROOT}/horizon-frontend"
ENV_FILE="${BACKEND_DIR}/.env"
STAGING="/tmp/hp-platform-apply-${VERSION}-$$"

cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[apply] missing $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

MODE="${HP_DEPLOYMENT_MODE:-}"
if [[ "$MODE" != "saas" && "$MODE" != "hybrid" ]]; then
  echo "[apply] HP_DEPLOYMENT_MODE must be saas or hybrid on this host" >&2
  exit 1
fi

# Hybrid BASE+SaaS on one box: artifacts live in the SaaS virtualbox bucket when configured.
if [[ -n "${SAAS_WASABI_BUCKET:-}" ]]; then
  WASABI_BUCKET="${SAAS_WASABI_BUCKET}"
  if [[ -n "${SAAS_WASABI_ENDPOINT:-}" ]]; then
    WASABI_ENDPOINT="${SAAS_WASABI_ENDPOINT}"
  fi
  if [[ -n "${SAAS_WASABI_REGION:-}" ]]; then
    WASABI_REGION="${SAAS_WASABI_REGION}"
  fi
fi

FE_KEY="${HP_RELEASE_FRONTEND_KEY:-platform/releases/${VERSION}/artifacts/frontend.tar.gz}"
BE_KEY="${HP_RELEASE_BACKEND_KEY:-platform/releases/${VERSION}/artifacts/backend.tar.gz}"

if [[ -z "${WASABI_BUCKET:-}" || -z "${WASABI_ACCESS_KEY_ID:-}" || -z "${WASABI_SECRET_ACCESS_KEY:-}" ]]; then
  echo "[apply] Wasabi credentials required" >&2
  exit 1
fi

WASABI_ENDPOINT="${WASABI_ENDPOINT:-https://s3.us-east-1.wasabisys.com}"
WASABI_REGION="${WASABI_REGION:-us-east-1}"

mkdir -p "$STAGING/fe" "$STAGING/be"

aws_get() {
  AWS_ACCESS_KEY_ID="${WASABI_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${WASABI_SECRET_ACCESS_KEY}" \
  AWS_DEFAULT_REGION="${WASABI_REGION}" \
    aws s3 cp "s3://${WASABI_BUCKET}/$1" "$2" --endpoint-url "$WASABI_ENDPOINT"
}

echo "[apply] downloading v${VERSION} artifacts…"
aws_get "$FE_KEY" "$STAGING/frontend.tar.gz"
aws_get "$BE_KEY" "$STAGING/backend.tar.gz"

echo "[apply] extracting to staging…"
tar -xzf "$STAGING/frontend.tar.gz" -C "$STAGING/fe"
tar -xzf "$STAGING/backend.tar.gz" -C "$STAGING/be"

echo "[apply] swapping live directories…"
TS="$(date +%Y%m%d-%H%M%S)"
if [[ -d "$FRONTEND_DIR" ]]; then
  mv "$FRONTEND_DIR" "${FRONTEND_DIR}.bak-${TS}"
fi
if [[ -d "$BACKEND_DIR" ]]; then
  mv "$BACKEND_DIR" "${BACKEND_DIR}.bak-${TS}"
fi
mv "$STAGING/fe" "$FRONTEND_DIR"
mv "$STAGING/be" "$BACKEND_DIR"

# Preserve .env from backup
if [[ -f "${BACKEND_DIR}.bak-${TS}/.env" ]]; then
  cp "${BACKEND_DIR}.bak-${TS}/.env" "${BACKEND_DIR}/.env"
  chmod 600 "${BACKEND_DIR}/.env"
fi

echo "[apply] npm install + pm2 reload…"
cd "$BACKEND_DIR"
npm install --omit=dev
sudo -u ubuntu pm2 reload horizon-backend --update-env || sudo -u ubuntu pm2 restart horizon-backend --update-env

if [[ -x "${BACKEND_DIR}/deploy/ovh/install-performance.sh" ]]; then
  sudo bash "${BACKEND_DIR}/deploy/ovh/install-performance.sh" || true
fi

echo "[apply] v${VERSION} live on SaaS platform."
