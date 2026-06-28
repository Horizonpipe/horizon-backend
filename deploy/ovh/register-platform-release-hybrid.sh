#!/usr/bin/env bash
set -euo pipefail
ENV=/opt/horizon/horizon-backend/.env
BACKEND=/opt/horizon/horizon-backend
STASH="/tmp/hp-env-register-stash.$$"
VERSION="${1:-0.0.1}"
GIT_SHA="${2:-}"
cp "$ENV" "$STASH"
sed -i 's/^HP_DEPLOYMENT_MODE=.*/HP_DEPLOYMENT_MODE=non-saas/' "$ENV"
cd "$BACKEND"
node scripts/register-platform-release.cjs "$VERSION" "$GIT_SHA"
REG=$?
cp "$STASH" "$ENV"
rm -f "$STASH"
exit "$REG"
