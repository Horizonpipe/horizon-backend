#!/usr/bin/env node
/**
 * Smoke test: portal presign + optional meta + optional proxy-download check.
 *
 * Usage:
 *   HP_API_BASE=https://your-api.onrender.com HP_TOKEN=eyJ... HP_FILE_ID=<portal_file_uuid> node scripts/smoke-portal-presign.mjs
 *
 * Optional:
 *   HP_CHECK_META=1            — GET /api/files/meta/:id (small JSON; mirrors Explorer parallel meta+presign).
 *   HP_CHECK_PROXY_DOWNLOAD=1  — GET /api/files/download/:id with Bearer; expect 410 when PORTAL_PROXY_FILE_DOWNLOAD=0
 *
 * Manual (browser Network tab, multi-TB / zero-proxy): uploads and downloads should show the **Wasabi**
 * host (e.g. `*.wasabisys.com` or your custom endpoint) for byte traffic; the Render API host should
 * only show small JSON (presign, meta, multipart sign-part, errors), not multi-GB responses.
 *
 * Requires Node 18+ (global fetch).
 */

const base = String(process.env.HP_API_BASE || process.env.API_BASE || '').replace(/\/+$/, '');
const token = String(process.env.HP_TOKEN || process.env.TOKEN || '').trim();
const fileId = String(process.env.HP_FILE_ID || '').trim();

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

if (!base) fail('Set HP_API_BASE (horizon-backend origin, no trailing slash).');
if (!token) fail('Set HP_TOKEN (Bearer session JWT).');
if (!fileId) fail('Set HP_FILE_ID (portal file id from tree or DB).');

const enc = encodeURIComponent(fileId);
const presignUrl = `${base}/api/files/presign/${enc}`;

if (String(process.env.HP_CHECK_META || '').trim() === '1') {
  const metaUrl = `${base}/api/files/meta/${enc}`;
  const metaRes = await fetch(metaUrl, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const metaText = await metaRes.text();
  let metaJson = {};
  try {
    metaJson = metaText ? JSON.parse(metaText) : {};
  } catch {
    metaJson = {};
  }
  if (!metaRes.ok) {
    fail(`meta HTTP ${metaRes.status}: ${metaText.slice(0, 500)}`);
  }
  const id = metaJson?.id != null ? String(metaJson.id) : '';
  if (id && id !== String(fileId)) {
    console.warn('Note: meta id differs from HP_FILE_ID (unexpected).');
  }
  console.log('OK: GET /api/files/meta/:id returned JSON.');
}

const preRes = await fetch(presignUrl, {
  headers: { Authorization: `Bearer ${token}` }
});
const preText = await preRes.text();
let preJson = {};
try {
  preJson = preText ? JSON.parse(preText) : {};
} catch {
  preJson = {};
}
if (!preRes.ok) {
  fail(`presign HTTP ${preRes.status}: ${preText.slice(0, 500)}`);
}
const url = typeof preJson.url === 'string' ? preJson.url.trim() : '';
if (!url) fail('presign JSON missing url');

const headRes = await fetch(url, { method: 'HEAD' });
if (!headRes.ok && headRes.status !== 403) {
  // Some S3 configs reject HEAD on presigned URL; try small GET
  const r = await fetch(url, { method: 'GET', headers: { Range: 'bytes=0-0' } });
  if (!r.ok && r.status !== 206) {
    fail(`Wasabi URL not reachable: HEAD ${headRes.status}, GET Range ${r.status} (check bucket CORS for your machine/browser origin if testing from browser).`);
  }
}

console.log('OK: presign returned url; object storage responded.');

if (String(process.env.HP_CHECK_PROXY_DOWNLOAD || '').trim() === '1') {
  const dlUrl = `${base}/api/files/download/${enc}`;
  const dlRes = await fetch(dlUrl, { headers: { Authorization: `Bearer ${token}` } });
  const t = await dlRes.text();
  if (dlRes.status === 410) {
    console.log('OK: proxy download disabled (410) as expected with PORTAL_PROXY_FILE_DOWNLOAD=0.');
  } else {
    console.log(
      `Note: GET /api/files/download returned HTTP ${dlRes.status} (expected 410 when proxy disabled). Body: ${t.slice(0, 200)}`
    );
  }
}
