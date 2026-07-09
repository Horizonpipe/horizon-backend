#!/usr/bin/env bash
# OVH hybrid hosts must run horizon-backend under ONE PM2 daemon (ubuntu).
# A second PM2 started as root (e.g. deploy/ovh/remote-start-app.sh) binds :3000
# with stale code and makes ubuntu PM2 crash-loop with EADDRINUSE.
set -euo pipefail

PM2_USER="${HP_PM2_USER:-ubuntu}"
PM2_HOME="/home/${PM2_USER}/.pm2"
BACKEND="${HP_BACKEND_DIR:-/opt/horizon/horizon-backend}"

stop_root_pm2() {
  if ! pgrep -u root -f 'PM2 v.*God Daemon \(\/root\/\.pm2\)' >/dev/null 2>&1; then
    echo "[dedupe-pm2] no root PM2 god daemon"
    return 0
  fi
  echo "[dedupe-pm2] stopping root PM2 god daemon (/root/.pm2)"
  # pm2 kill as root — do NOT use bare `sudo pm2` elsewhere (it respawns /root/.pm2).
  PM2_HOME=/root/.pm2 pm2 delete all 2>/dev/null || true
  PM2_HOME=/root/.pm2 pm2 kill 2>/dev/null || true
  for pid in $(ps -eo user=,pid=,args= | awk '$1=="root" && /node.*horizon-backend\/server.js/ {print $2}'); do
    echo "[dedupe-pm2] killing orphan root node pid=$pid"
    kill "$pid" 2>/dev/null || true
  done
  if pgrep -u root -f 'PM2 v.*God Daemon \(\/root\/\.pm2\)' >/dev/null 2>&1; then
    root_god=$(pgrep -u root -f 'PM2 v.*God Daemon \(\/root\/\.pm2\)' | head -1)
    echo "[dedupe-pm2] SIGTERM root PM2 god pid=$root_god"
    kill -TERM "$root_god" 2>/dev/null || true
    sleep 1
  fi
  if [[ -d /root/.pm2 ]]; then
    mv /root/.pm2 "/root/.pm2.disabled.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    echo "[dedupe-pm2] archived /root/.pm2 (prevents accidental sudo pm2 respawn)"
  fi
  if pgrep -u root -f 'PM2 v.*God Daemon \(\/root\/\.pm2\)' >/dev/null 2>&1; then
    echo "[dedupe-pm2] WARN: root PM2 god still running" >&2
    return 1
  fi
  echo "[dedupe-pm2] root PM2 removed"
}

ensure_ubuntu_pm2() {
  if [[ ! -d "$PM2_HOME" ]]; then
    echo "[dedupe-pm2] WARN: missing $PM2_HOME" >&2
    return 0
  fi
  if ! sudo -u "$PM2_USER" pm2 jlist >/dev/null 2>&1; then
    echo "[dedupe-pm2] starting ubuntu PM2 from ecosystem"
    sudo -u "$PM2_USER" bash -lc "cd '$BACKEND' && pm2 start deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
    return 0
  fi
  if ! sudo -u "$PM2_USER" pm2 describe horizon-backend >/dev/null 2>&1; then
    echo "[dedupe-pm2] horizon-backend missing from ubuntu PM2 — starting"
    sudo -u "$PM2_USER" bash -lc "cd '$BACKEND' && pm2 start deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
    return 0
  fi
  echo "[dedupe-pm2] ubuntu PM2 horizon-backend ok"
}

if [[ "$(id -un)" != "root" ]]; then
  exec sudo bash "$0" "$@"
fi

stop_root_pm2
ensure_ubuntu_pm2
