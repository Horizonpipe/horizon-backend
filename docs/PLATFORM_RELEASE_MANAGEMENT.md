# Platform release management (Non-SaaS vs SaaS)

Horizonpipe runs on **two tracks**:

| Track | Who uses it | How code updates |
|-------|-------------|------------------|
| **Non-SaaS** | Your private PipeShare / PipeSync (OVH today) | Direct deploy — git pull, pm2 reload. Never pushes to SaaS automatically. |
| **SaaS** | Paying tenant platform | **Only** when you pick a version in **Platform updates** (`/horizonpipe-cpanel/releases.html`) |

## Wasabi layout

All release metadata and bundles live in your shared Wasabi bucket:

```
platform/
  releases/
    manifest.json                 # catalog + recommended version
    0.0.1/
      release.json                # title, plain-English description, changelog
      artifacts/
        frontend.tar.gz
        backend.tar.gz
    0.0.2/
      ...
  runtime/
    non-saas-current.json         # heartbeat from your private server
    saas-deployed.json            # last version applied to SaaS
```

## Version numbers

- Start at **0.0.1**
- Each publish bumps the patch: **0.0.2**, **0.0.3**, …
- **Recommended** version always mirrors what non-SaaS is running

## Environment variables

### Non-SaaS (your OVH server)

```env
HP_DEPLOYMENT_MODE=non-saas
# optional — auto-register after publish script uploads artifacts
HP_RELEASE_ADMIN_TOKEN=<your admin session token>
HP_REPO_ROOT=/opt/horizon
```

### SaaS platform host (dedicated OVH instance)

```env
HP_DEPLOYMENT_MODE=saas
HP_PLATFORM_APPLY_SCRIPT=/opt/horizon/horizon-backend/deploy/saas/apply-platform-release.sh
HP_REPO_ROOT=/opt/horizon
```

## Workflow

### 1. Work on non-SaaS (normal day-to-day)

Edit code, deploy to OVH as you do today. SaaS is **not** touched.

**Cursor agent:** updates `platform-release-draft.json` with plain-English title + description for every deploy batch. The cPanel form reads this automatically.

### 2. Publish a release when SaaS should get an update

On your **non-SaaS** server:

```bash
bash /opt/horizon/horizon-backend/deploy/ovh/publish-platform-release.sh \
  "Auto-save before refresh" \
  "PipeSync now saves plan highlights and segment edits before the 15-minute refresh so work is not lost."
```

This:

1. Packages frontend + backend tarballs
2. Uploads to `platform/releases/{version}/artifacts/` on Wasabi
3. Registers the version (if `HP_RELEASE_ADMIN_TOKEN` is set) or prompts you to register in cPanel

The **Description of changes** field is auto-filled from recent git commits in plain English. Edit it in cPanel before registering if you want clearer notes for future-you.

### 3. Apply to SaaS (when ready)

1. Open **Horizonpipe cPanel → Platform updates** (admin only)
2. Select a version — **recommended** defaults to non-SaaS current
3. Click **Apply to SaaS**

Apply runs only on hosts with `HP_DEPLOYMENT_MODE=saas`.

## API (admin only)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/saas/platform/releases/status` | Catalog + non-SaaS vs SaaS versions |
| GET | `/saas/platform/releases/preview` | Preview next version + auto changelog |
| POST | `/saas/platform/releases/publish` | Register release (non-SaaS host only) |
| POST | `/saas/platform/releases/apply` | Deploy version to SaaS host |
| POST | `/saas/platform/releases/heartbeat` | Record non-SaaS version without full publish |

## Current OVH setup note

Your OVH server today runs **both** non-SaaS apps and the cPanel UI with `HP_DEPLOYMENT_MODE=non-saas`. That is correct for development. When you split SaaS onto a second OVH host (or a second PM2/nginx vhost on the same box), set `HP_DEPLOYMENT_MODE=saas` there and configure `HP_PLATFORM_APPLY_SCRIPT`.

Until then, use cPanel to **publish** release records and upload artifacts; **apply** will activate once a dedicated SaaS host exists.
