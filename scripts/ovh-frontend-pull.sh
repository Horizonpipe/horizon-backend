#!/usr/bin/env bash
set -euo pipefail
cd /opt/horizon/horizon-frontend
export GIT_SSH_COMMAND="ssh -i /opt/horizon/.ssh/github_ovh_frontend -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
git fetch origin main
git reset --hard origin/main
echo "frontend at $(git log -1 --oneline)"
