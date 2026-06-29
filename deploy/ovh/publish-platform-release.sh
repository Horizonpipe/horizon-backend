#!/usr/bin/env bash
# Publish a numbered platform release from your NON-SaaS server to Wasabi.
# SaaS customers only receive updates when you apply a version in horizonpipe-cpanel/releases.html
#
# Usage:
#   bash deploy/ovh/publish-platform-release.sh ["Short title"] ["Longer plain-English description"]
#
# Requires: aws CLI, tar, git, HP_DEPLOYMENT_MODE=non-saas, Wasabi credentials in .env
set -euo pipefail

ROOT="${HP_REPO_ROOT:-/opt/horizon}"
BACKEND_DIR="${ROOT}/horizon-backend"
FRONTEND_DIR="${ROOT}/horizon-frontend"
ENV_FILE="${BACKEND_DIR}/.env"
STAGING="/tmp/hp-platform-release-$$"
TITLE="${1:-}"
DESCRIPTION="${2:-}"
DRAFT_FILE="${BACKEND_DIR}/platform-release-draft.json"

cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[publish] missing $ENV_FILE" >&2
  exit 1
fi

# Only load vars this script needs — do not `source` the full .env (values may contain spaces).
load_publish_env() {
  local line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^(WASABI_|HP_|PUBLIC_ORIGIN|SAAS_CPANEL_BASE_URL) ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    val="${val%\"}"
    val="${val#\"}"
    val="${val%\'}"
    val="${val#\'}"
    export "${key}=${val}"
  done < "$ENV_FILE"
}
load_publish_env

if [[ "${HP_DEPLOYMENT_MODE:-hybrid}" == "saas" ]]; then
  echo "[publish] HP_DEPLOYMENT_MODE must be non-saas or hybrid on this host" >&2
  exit 1
fi

if [[ -z "${WASABI_BUCKET:-}" || -z "${WASABI_ACCESS_KEY_ID:-}" || -z "${WASABI_SECRET_ACCESS_KEY:-}" ]]; then
  echo "[publish] WASABI_BUCKET and credentials required in .env" >&2
  exit 1
fi

command -v aws >/dev/null 2>&1 || { echo "[publish] install aws CLI first (deploy/ovh/install-awscli.sh)" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "[publish] tar required" >&2; exit 1; }

WASABI_ENDPOINT="${WASABI_ENDPOINT:-https://s3.us-east-1.wasabisys.com}"
WASABI_REGION="${WASABI_REGION:-us-east-1}"
API_BASE="${PUBLIC_ORIGIN:-${SAAS_CPANEL_BASE_URL:-http://127.0.0.1:3000}}"

aws_cp() {
  AWS_ACCESS_KEY_ID="${WASABI_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${WASABI_SECRET_ACCESS_KEY}" \
  AWS_DEFAULT_REGION="${WASABI_REGION}" \
    aws s3 cp "$1" "s3://${WASABI_BUCKET}/$2" --endpoint-url "$WASABI_ENDPOINT"
}

mkdir -p "$STAGING"

echo "[publish] reading current manifest from Wasabi…"
MANIFEST_JSON="$STAGING/manifest.json"
if AWS_ACCESS_KEY_ID="${WASABI_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${WASABI_SECRET_ACCESS_KEY}" \
  AWS_DEFAULT_REGION="${WASABI_REGION}" \
    aws s3 cp "s3://${WASABI_BUCKET}/platform/releases/manifest.json" "$MANIFEST_JSON" \
      --endpoint-url "$WASABI_ENDPOINT" 2>/dev/null; then
  LATEST="$(node -e "const m=require(process.argv[1]); console.log(m.latestPublished||'');" "$MANIFEST_JSON")"
else
  LATEST=""
fi

if [[ -n "$LATEST" ]]; then
  IFS=. read -r MA MI PA <<< "$LATEST"
  NEXT_VERSION="${MA}.${MI}.$((PA + 1))"
else
  NEXT_VERSION="0.0.1"
fi

echo "[publish] packaging v${NEXT_VERSION}…"
FRONTEND_TAR="$STAGING/frontend.tar.gz"
BACKEND_TAR="$STAGING/backend.tar.gz"

tar -czf "$FRONTEND_TAR" -C "$FRONTEND_DIR" \
  --exclude=node_modules \
  --exclude=.git \
  .

tar -czf "$BACKEND_TAR" -C "$BACKEND_DIR" \
  --exclude=node_modules \
  --exclude=.git \
  .

FE_KEY="platform/releases/${NEXT_VERSION}/artifacts/frontend.tar.gz"
BE_KEY="platform/releases/${NEXT_VERSION}/artifacts/backend.tar.gz"

echo "[publish] uploading artifacts…"
aws_cp "$FRONTEND_TAR" "$FE_KEY"
aws_cp "$BACKEND_TAR" "$BE_KEY"

GIT_SHA="$(git -C "$BACKEND_DIR" rev-parse --short HEAD 2>/dev/null || true)"
GIT_BRANCH="$(git -C "$BACKEND_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"

PAYLOAD="$STAGING/payload.json"
TITLE="$TITLE" DESCRIPTION="$DESCRIPTION" NEXT_VERSION="$NEXT_VERSION" \
GIT_SHA="$GIT_SHA" GIT_BRANCH="$GIT_BRANCH" FE_KEY="$FE_KEY" BE_KEY="$BE_KEY" \
DRAFT_FILE="$DRAFT_FILE" PAYLOAD="$PAYLOAD" node <<'NODE'
const fs = require('fs');
let title = process.env.TITLE || '';
let description = process.env.DESCRIPTION || '';
let changeLog = [];
try {
  if (process.env.DRAFT_FILE && fs.existsSync(process.env.DRAFT_FILE)) {
    const draft = JSON.parse(fs.readFileSync(process.env.DRAFT_FILE, 'utf8'));
    if (!title) title = draft.title || '';
    if (!description) description = draft.description || '';
    if (Array.isArray(draft.changeLog)) changeLog = draft.changeLog.filter(Boolean);
  }
} catch { /* ignore */ }
const payload = {
  version: process.env.NEXT_VERSION,
  title,
  description,
  changeLog,
  gitSha: process.env.GIT_SHA || '',
  gitBranch: process.env.GIT_BRANCH || '',
  artifactKeys: {
    frontend: process.env.FE_KEY,
    backend: process.env.BE_KEY
  }
};
fs.writeFileSync(process.env.PAYLOAD, JSON.stringify(payload));
NODE

if [[ -n "${HP_RELEASE_ADMIN_TOKEN:-}" ]]; then
  echo "[publish] registering release via API…"
  curl -sfS -X POST "${API_BASE}/saas/platform/releases/publish" \
    -H "Authorization: Bearer ${HP_RELEASE_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    --data-binary @"$PAYLOAD"
  echo
  echo "[publish] done — v${NEXT_VERSION} published and registered (recommended for SaaS)."
else
  echo "[publish] artifacts uploaded for v${NEXT_VERSION}."
  echo "[publish] Set HP_RELEASE_ADMIN_TOKEN in .env to auto-register, or open:"
  echo "          ${API_BASE}/horizonpipe-cpanel/releases.html → Register release"
fi

if command -v git >/dev/null 2>&1; then
  git -C "$BACKEND_DIR" tag -f "platform-v${NEXT_VERSION}" 2>/dev/null || true
  git -C "$FRONTEND_DIR" tag -f "platform-v${NEXT_VERSION}" 2>/dev/null || true
fi
