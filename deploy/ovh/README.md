# OVH migration (Render → ADVANCE-1, Vint Hill)

Move **horizon-backend**, **horizon-frontend**, and **Postgres** from Render onto one OVH dedicated server.

**Target hardware:** ADVANCE-1 · 6 cores · 32 GB RAM · 2×960 GB NVMe RAID · 3 Gbps unmetered · **US East (Vint Hill, VA)**

**Monthly cost:** ~$134/mo (+ $134 setup once). Wasabi/Stripe unchanged.

---

## Will this host work for everything?

| Workload | This box |
|----------|----------|
| Horizonpipe SaaS (Node + Postgres + static frontend) | **Yes** |
| Municipal / business tenants + portal clients | **Yes** for early → mid growth |
| Wasabi presigned files (no proxy through server) | **Yes** — keep `PORTAL_PROXY_FILE_DOWNLOAD=0` |
| Stripe billing + webhooks | **Yes** |
| Hundreds of concurrent users | **Yes** with PM2 cluster (4 workers) |
| Thousands concurrent / HA / zero-downtime | Plan **2nd app node + LB** later — not day one |

**32 GB RAM** is enough for Node + local Postgres. **NVMe RAID** is ideal for DB. **Vint Hill** is excellent US East latency.

---

## What Render gives you vs OVH

| Render | OVH (you set up) |
|--------|------------------|
| Auto deploy from Git | GitHub Actions or manual `git pull` + `pm2 reload` |
| Managed Postgres backups | Daily `pg_dump` cron + optional Wasabi upload |
| HTTPS | Let's Encrypt (certbot) + nginx |
| Health restarts | PM2 cluster + `pm2 startup` |
| Separate frontend + backend URLs | **One domain** — backend serves frontend (already in `server.js`) |

---

## Before you start

1. OVH server provisioned with **Ubuntu 24.04 LTS**
2. SSH access as `root` (or sudo user)
3. Domain name (e.g. `app.horizonpipe.com`) — DNS **A record** → OVH public IP (after server is up)
4. From Render Dashboard, export:
   - **Postgres → External Database URL** (for migration dump)
   - **Web service → Environment** (all env vars)
5. Stripe Dashboard → Webhooks → update endpoint URL after cutover
6. **Do not commit** `.env` or paste secrets into tickets/chat

---

## Step 1 — Bootstrap the server

SSH in as root:

```bash
# Copy setup script to server, or clone repo first (step 2) and run:
bash /opt/horizon/horizon-backend/deploy/ovh/setup-server.sh
```

Save the **Postgres password** printed at the end.

---

## Step 2 — Clone repos

As user `horizon` (or root, then `chown`):

```bash
sudo -u horizon bash
cd /opt/horizon
git clone https://github.com/Horizonpipe/horizon-backend.git
git clone https://github.com/Horizonpipe/horizon-frontend.git
cd horizon-backend
npm install --omit=dev
```

---

## Step 3 — Production `.env`

```bash
cp deploy/ovh/env.production.template .env
chmod 600 .env
nano .env
```

Fill from Render env + local Postgres URL from setup script:

- `DATABASE_URL=postgresql://horizon:YOUR_PASS@127.0.0.1:5432/horizon`
- Wasabi keys, Stripe keys, `CORS_ORIGINS`, `SAAS_CPANEL_BASE_URL` → your domain
- Remove `SAAS_SKIP_*` when billing/Wasabi provision are verified in prod

Paste Render DB URL into a one-time file for migration:

```bash
echo 'RENDER_DATABASE_URL=postgresql://...render.com/...' > .env.migrate
chmod 600 .env.migrate
```

---

## Step 4 — Import Render Postgres

```bash
bash deploy/ovh/migrate-from-render.sh
```

Verify:

```bash
source .env  # or use psql with DATABASE_URL
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM users;"
```

---

## Step 5 — nginx + SSL

```bash
sudo sed "s/YOUR_DOMAIN/app.yourdomain.com/g" deploy/ovh/nginx-horizon.conf \
  | sudo tee /etc/nginx/sites-available/horizon
sudo ln -sf /etc/nginx/sites-available/horizon /etc/nginx/sites-enabled/horizon
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d app.yourdomain.com
```

---

## Step 6 — Start the app

```bash
pm2 start deploy/ovh/ecosystem.config.cjs
pm2 save
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u horizon --hp /opt/horizon
```

Smoke test:

```bash
curl -sS https://app.yourdomain.com/session
# expect 401 JSON (auth required) — means API is up

curl -sS -o /dev/null -w "%{http_code}" https://app.yourdomain.com/horizonpipe-cpanel/
# expect 200
```

---

## Step 7 — Backups (Render-like)

```bash
sudo bash deploy/ovh/install-backups.sh
sudo bash deploy/ovh/backup-postgres.sh   # test run
sudo bash deploy/ovh/backup-config.sh    # test config → Wasabi
```

| Backup | Schedule | Retention |
|--------|----------|-----------|
| Postgres `pg_dump` | Daily 03:15 UTC | 14 days local / 90 days Wasabi |
| Server config tarball | Weekly Sun 04:00 UTC | 56 days local / 90 days Wasabi |
| Wasabi folder | — | `s3://<bucket>/backups/ovh-horizon/` |

---

## Step 7b — Auto Git backup (rollback)

Every change on the OVH server is committed and pushed to GitHub branch **`ovh-live`** (separate from `main` — safe for dev).

```bash
sudo bash deploy/ovh/install-git-backup.sh
# Add printed deploy key to both GitHub repos (Deploy keys → Allow write)
sudo -u ubuntu bash deploy/ovh/auto-git-backup.sh   # test push
```

| | |
|--|--|
| Schedule | Every 10 minutes (cron) |
| Branch | `ovh-live` on `horizon-backend` + `horizon-frontend` |
| Excluded | `.env`, `node_modules`, dumps (see `server-gitignore.snippet`) |
| Log | `/var/log/horizon/git-backup.log` |

**Rollback on server:**

```bash
bash deploy/ovh/rollback-server.sh backend list
bash deploy/ovh/rollback-server.sh backend HEAD~1    # undo last auto-backup
bash deploy/ovh/rollback-server.sh both abc1234      # specific commit
```

**Rollback from your PC** (clone/pull `ovh-live`):

```bash
git fetch origin ovh-live
git checkout ovh-live
git log --oneline -10
git checkout <commit-hash> -- path/to/file
```

---

## Step 8 — Cutover checklist

- [ ] DNS A record → OVH IP (lower TTL to 300 a day before)
- [ ] HTTPS works on new domain
- [ ] Login, PipeShare, PipeSync, cPanel setup/billing
- [ ] Stripe webhook → `https://app.yourdomain.com/saas/billing/webhook`
- [ ] Wasabi bucket CORS includes new origin
- [ ] Remove hardcoded `onrender.com` fallbacks in frontend when convenient (same-origin works when frontend is served from OVH)
- [ ] Stop Render web services (keep Postgres until migration verified, then delete)
- [ ] Rotate any secrets that were ever pasted in chat/logs

---

## Deploy updates (after initial setup)

Manual:

```bash
cd /opt/horizon/horizon-backend && git pull && npm install --omit=dev
cd /opt/horizon/horizon-frontend && git pull
# rebuild if using React login bundle: npm install && npm run build
pm2 reload horizon-backend
```

Or use `.github/workflows/deploy-ovh.yml` with GitHub secrets `OVH_HOST`, `OVH_SSH_KEY`.

---

## Monitoring (recommended)

```bash
pm2 monit
pm2 logs horizon-backend
tail -f /var/log/nginx/horizon-error.log
tail -f /var/log/horizon/backup.log
```

Optional: UptimeRobot (free) HTTP check on `https://app.yourdomain.com/horizonpipe-cpanel/`

---

## When to scale beyond one box

- Sustained high CPU (>70%) on all PM2 workers
- Postgres connections maxed (`PG_POOL_MAX` already 20+)
- Municipal SLA requiring HA

Next step: second OVH app server + Hetzner/OVH load balancer, **keep Postgres on this box** or move to managed Postgres.

---

## Files in this folder

| File | Purpose |
|------|---------|
| `setup-server.sh` | Node, Postgres, PM2, nginx, firewall |
| `migrate-from-render.sh` | pg_dump Render → restore local |
| `env.production.template` | Production env starter |
| `ecosystem.config.cjs` | PM2 cluster (4 workers) |
| `nginx-horizon.conf` | Reverse proxy + SSL |
| `backup-postgres.sh` | Daily dump + optional Wasabi |
| `install-backups.sh` | Cron installation |
