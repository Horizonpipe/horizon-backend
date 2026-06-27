#!/usr/bin/env bash
# Ensure OVH GitHub deploy keys exist, permissions are correct, and SSH pull works.
# Run on the server: sudo bash deploy/ovh/setup-github-deploy-keys.sh
set -euo pipefail

REPO_ROOT="${HP_REPO_ROOT:-/opt/horizon}"
SSH_DIR="${HP_SSH_DIR:-$REPO_ROOT/.ssh}"
BACKEND_KEY="${HP_BACKEND_DEPLOY_KEY:-$SSH_DIR/github_ovh_deploy}"
FRONTEND_KEY="${HP_FRONTEND_DEPLOY_KEY:-$SSH_DIR/github_ovh_frontend}"
DEPLOY_USER="${HP_PM2_USER:-ubuntu}"
BACKEND_REPO="${HP_GITHUB_BACKEND:-git@github.com:Horizonpipe/horizon-backend.git}"
FRONTEND_REPO="${HP_GITHUB_FRONTEND:-git@github.com:Horizonpipe/horizon-frontend.git}"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

ensure_key() {
  local key="$1"
  local comment="$2"
  if [[ ! -f "$key" ]]; then
    echo "[deploy-keys] generating $key"
    ssh-keygen -t ed25519 -f "$key" -N "" -C "$comment"
  fi
  chmod 600 "$key"
  chmod 644 "${key}.pub"
}

ensure_key "$BACKEND_KEY" "ovh-horizon-backend-deploy"
ensure_key "$FRONTEND_KEY" "ovh-horizon-frontend-deploy"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$SSH_DIR"

test_repo() {
  local label="$1"
  local key="$2"
  local repo="$3"
  echo "[deploy-keys] testing $label"
  sudo -u "$DEPLOY_USER" env GIT_SSH_COMMAND="ssh -i ${key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" \
    git ls-remote "$repo" HEAD >/dev/null
  echo "[deploy-keys] ok $label"
}

test_repo backend "$BACKEND_KEY" "$BACKEND_REPO"
test_repo frontend "$FRONTEND_KEY" "$FRONTEND_REPO"

echo ""
echo "Deploy keys are configured on disk and GitHub SSH pull works."
echo "If test failed with 'Permission denied', add each public key to its repo:"
echo "  $BACKEND_KEY.pub  -> Horizonpipe/horizon-backend  (Deploy keys, read-only is enough for pull)"
echo "  $FRONTEND_KEY.pub -> Horizonpipe/horizon-frontend (Deploy keys, read-only is enough for pull)"
echo ""
echo "Register from your PC (with GITHUB_TOKEN):"
echo "  pwsh deploy/ovh/setup-github-deploy-keys.ps1"
