# horizon-backend

Node API for Horizon (planner, portal files, Wasabi state, etc.).

## Configuration

- Copy [`.env.example`](.env.example) to `.env` for local development (do not commit secrets).
- **Bandwidth / Wasabi:** see [`BANDWIDTH_RENDER_ENV.txt`](BANDWIDTH_RENDER_ENV.txt) for a lean Render preset (presigned portal downloads, lighter snapshots, optional SQL mirror off).

### Presigned portal file flows

- Set **`PORTAL_PROXY_FILE_DOWNLOAD=0`** on the host so large downloads use **`GET /api/files/presign/:id`** (bytes go **Wasabi → client**, not through Render). The web client in `horizon-frontend` already prefers presign and falls back only when needed.
- Configure the **Wasabi bucket CORS** policy so your portal origin can `GET`/`HEAD` (and `PUT` for uploads) against presigned URLs.

### Wasabi `latest.json` snapshot

- **`WASABI_STATE_ARCHIVE_SNAPSHOTS`:** duplicate history objects under `history/snapshot-*.json`. Default in code is off unless set to `1`.
- **`WASABI_STATE_SNAPSHOT_GZIP`:** gzip snapshot bodies on write (default on); reads support gzip **or** legacy uncompressed JSON.
- Tune **`WASABI_STATE_WRITE_DEBOUNCE_MS`** and **`WASABI_LATEST_STATE_CACHE_MS`** to reduce snapshot frequency and repeated reads (see `BANDWIDTH_RENDER_ENV.txt`).

## Smoke test (presign)

After deploy, with a real session token and a portal file id from `GET /api/files/tree`:

```bash
set HP_API_BASE=https://your-api.example.com
set HP_TOKEN=your_jwt
set HP_FILE_ID=portal-file-uuid
npm run smoke:portal-presign
```

Optional: also probe proxied download (expect `410` when proxy is disabled):

```bash
set HP_CHECK_PROXY_DOWNLOAD=1
npm run smoke:portal-presign
```

## Run

```bash
npm install
npm start
```
