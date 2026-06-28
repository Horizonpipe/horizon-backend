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

## Step 5 — nginx + SSL (GoDaddy DNS → OVH)

**OVH server IP:** `40.160.72.39` (non-SaaS private instance; currently HTTP on IP only).

### PipeShare domains (pipeshare.live + pipeshare.net)

| Domain | Role |
|--------|------|
| **pipeshare.live** | Primary — `https://pipeshare.live/client-portal/` |
| **pipeshare.net** | 301 redirect → pipeshare.live |

**Recommendation:** Use **pipeshare.live** as the only canonical URL. pipeshare.net redirects so bookmarks and typos still work.

#### GoDaddy DNS — pipeshare.live

1. Log in at [godaddy.com](https://www.godaddy.com) → **My Products** → **pipeshare.live** → **DNS** (or **Manage DNS**).
2. Remove or edit conflicting records (old A/CNAME/forwarding for `@` and `www`).
3. Add:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| **A** | `@` | `40.160.72.39` | 600 |
| **A** | `www` | `40.160.72.39` | 600 |

4. Save. Propagation usually 5–30 minutes (up to 48h).

#### GoDaddy DNS — pipeshare.net

Same steps for **pipeshare.net** → **DNS**:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| **A** | `@` | `40.160.72.39` | 600 |
| **A** | `www` | `40.160.72.39` | 600 |

*(GoDaddy may label the host column "Name" or "@". Use `@` for the apex/root domain.)*

**Verify propagation** (from your PC or OVH):

```bash
dig pipeshare.live +short
dig pipeshare.net +short
# both should return 40.160.72.39
```

#### OVH — nginx + certbot (after DNS resolves)

```bash
# On OVH (or from PC: scp configs then ssh)
sudo bash /opt/horizon/horizon-backend/deploy/ovh/setup-pipeshare-tls.sh
```

If certbot fails with "DNS problem", wait for GoDaddy propagation and re-run:

```bash
sudo certbot certonly --webroot -w /var/www/certbot \
  -d pipeshare.live -d www.pipeshare.live -d pipeshare.net -d www.pipeshare.net \
  --cert-name pipeshare.live
sudo bash /opt/horizon/horizon-backend/deploy/ovh/setup-pipeshare-tls.sh --ssl-only
```

**Test URLs:**

- `https://pipeshare.live/client-portal/` — portal (200)
- `https://pipeshare.net/` — 301 → pipeshare.live
- `https://pipeshare.live/session` — 401 JSON (API up)

Config files: `nginx-horizon-pipeshare.conf` (HTTP/ACME), `nginx-horizon-pipeshare-ssl.conf` (HTTPS).

---

### A — GoDaddy DNS (generic / other hostnames)

Pick one hostname for the Horizon app (examples: `app.horizonpipe.com`, `portal.horizonpipe.com`). Do **not** point the marketing Squarespace site (`www.horizonpipe.com`) at OVH unless you intend to move it off Squarespace.

| Type | Name / Host | Value | TTL |
|------|-------------|-------|-----|
| **A** | `@` | `40.160.72.39` | 600 (or 300 before cutover) |
| **A** | `www` | `40.160.72.39` | 600 |
| **A** | `app` (or your chosen subdomain) | `40.160.72.39` | 600 |

- Use **A records** to the OVH IP — not CNAME to the IP (invalid).
- CNAME is only if you later point a subdomain at another hostname nginx already serves.
- Lower TTL to **300** a day before cutover; raise after stable.
- Wait for propagation (`dig app.yourdomain.com +short` should return `40.160.72.39`).

### B — nginx on OVH

**Option 1 — TLS vhost** (recommended once DNS resolves):

```bash
sudo sed "s/YOUR_DOMAIN/app.yourdomain.com/g" deploy/ovh/nginx-horizon.conf \
  | sudo tee /etc/nginx/sites-available/horizon
sudo ln -sf /etc/nginx/sites-available/horizon /etc/nginx/sites-enabled/horizon
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d app.yourdomain.com
# If www also points here: sudo certbot --nginx -d app.yourdomain.com -d www.yourdomain.com
```

**Option 2 — performance static config** (currently live on OVH: `nginx-horizon-performance.conf`, `server_name _`, port 80 only). After DNS works, either add a second `server { listen 443 ssl; server_name app.yourdomain.com; … }` block from `nginx-horizon.conf`, or switch to the TLS template above and merge static `location` blocks from the performance file.

Live check (read-only):

```bash
ssh horizon-ovh "ls /etc/nginx/sites-enabled/; head -30 /etc/nginx/sites-enabled/horizon"
```

### C — certbot (Let's Encrypt)

First time on Ubuntu (if certbot not installed — `setup-server.sh` usually installs it):

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo mkdir -p /var/www/certbot
sudo certbot --nginx -d app.yourdomain.com
sudo certbot renew --dry-run
```

Certbot edits nginx for `ssl_certificate` paths under `/etc/letsencrypt/live/…/`.

### D — After HTTPS works

1. Set `PUBLIC_ORIGIN`, `SAAS_CPANEL_BASE_URL`, and `CORS_ORIGINS` in `/opt/horizon/horizon-backend/.env` to `https://app.yourdomain.com`.
2. In `horizon-frontend/client-portal/index.html` and `mobile.html`, set:
   ```html
   <meta name="hp-portal-secure-origin" content="https://app.yourdomain.com" />
   ```
3. Stripe webhook URL → `https://app.yourdomain.com/saas/billing/webhook`
4. Wasabi bucket CORS → include the new HTTPS origin.
5. `pm2 reload horizon-backend`

---

## Step 5 (legacy one-liner)

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
- [ ] Stop Render web services and Postgres after OVH cutover is verified
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

**Web console (Render-style):** Admins open `https://YOUR_DOMAIN/horizonpipe-cpanel/ops.html` — CPU, RAM, bandwidth, logs, events, manual deploy, rollback.

**GitHub auto-deploy:** On each repo, add a webhook to `https://YOUR_DOMAIN/ops/webhook/github` (JSON, Push events, secret = `GITHUB_WEBHOOK_SECRET` in `.env`). Deploy keys (one per repo):

```bash
sudo bash deploy/ovh/setup-github-deploy-keys.sh   # on OVH — tests SSH pull
# From your PC (GITHUB_TOKEN set):
pwsh deploy/ovh/setup-github-deploy-keys.ps1 -OvhHost YOUR_OVH_IP
bash deploy/ovh/github-deploy.sh                   # manual pull + pm2 reload (on server)
pwsh deploy/ovh/deploy-from-local.ps1              # from your PC (uses ~/.ssh/config → horizon-ovh)
```

**Local SSH:** `~/.ssh/config` Host `horizon-ovh` (or `40.160.72.39`) → `IdentityFile ~/.ssh/id_ed25519_horizon_ovh`, `IdentitiesOnly yes`.

**Desktop monitor:** Java app in `ovh-ops-monitor/` — see `ovh-ops-monitor/README.md`.

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
| `github-deploy.sh` | Pull main + npm install + pm2 reload (webhook / manual) |
| `deploy-from-local.ps1` | One-command deploy from PC via `ssh horizon-ovh` |
| `rollback-main.sh` | Roll back backend/frontend/both on main |
| `../ovh-ops-monitor/` | Portable Java desktop monitor |


## Cross-host remote support presence (non-SaaS OVH ↔ SaaS OVH)

Both deployment models run on **OVH** (not Render). Each backend has its own Postgres; heartbeats write to local `cp_support_presence` only.

| Host | `HP_DEPLOYMENT_MODE` | Typical role |
|------|----------------------|--------------|
| Non-SaaS OVH | `non-saas` | Municipal / private PipeShare + PipeSync |
| SaaS OVH | `saas` | Horizonpipe SaaS tenants + cPanel apply target |

They may be **two OVH servers** (different public origins) or **two PM2/nginx vhosts on one box** (different domains or ports → different `.env` per instance). Peer URLs must be the **public HTTPS API origin** of the other instance (`PUBLIC_ORIGIN` or `SAAS_CPANEL_BASE_URL` — no trailing slash).

**Approach:** peer read federation. Each backend exposes `GET /internal/support/presence-snapshot` (header `X-CP-Support-Peer-Secret`). Mike’s global `GET /saas/support/presence` merges local rows with peer snapshots.

### Environment (set on both backends)

- `CP_SUPPORT_PRESENCE_PEER_SECRET` — same long random string on both (generate once; do not commit)
- `CP_SUPPORT_PRESENCE_PEER_URLS` — comma-separated HTTPS base URL(s) of the **other** backend(s), no trailing slash

**Example — non-SaaS OVH** (`/opt/horizon/horizon-backend/.env` on the private instance):

```env
HP_DEPLOYMENT_MODE=non-saas
PUBLIC_ORIGIN=https://app.example.com
SAAS_CPANEL_BASE_URL=https://app.example.com
CP_SUPPORT_PRESENCE_PEER_SECRET=<same-secret-on-both>
CP_SUPPORT_PRESENCE_PEER_URLS=https://saas.example.com
```

**Example — SaaS OVH** (dedicated SaaS instance):

```env
HP_DEPLOYMENT_MODE=saas
PUBLIC_ORIGIN=https://saas.example.com
SAAS_CPANEL_BASE_URL=https://saas.example.com
CP_SUPPORT_PRESENCE_PEER_SECRET=<same-secret-on-both>
CP_SUPPORT_PRESENCE_PEER_URLS=https://app.example.com
```

Replace `app.example.com` / `saas.example.com` with your real domains. This repo’s OVH scripts often use **`40.160.72.39`** as the non-SaaS origin until DNS/TLS is in place — use `https://YOUR_DOMAIN` in production peer URLs so federation works from browsers and between nginx fronts.

**Same physical server:** run two backend processes (e.g. ports 3000 and 3001), each with its own `.env` and `HP_DEPLOYMENT_MODE`, nginx `server_name` per hostname, then point each side’s `CP_SUPPORT_PRESENCE_PEER_URLS` at the other hostname’s public origin.

After editing `.env` on each host: `pm2 reload horizon-backend` (or reload both app names if you run two instances).

Remote sessions, chat, and SSE are **not** federated — presence list only.
