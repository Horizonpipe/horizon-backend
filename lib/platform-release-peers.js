'use strict';

function cleanString(v) {
  return String(v ?? '').trim();
}

function cleanDomain(value, fallback) {
  const d = String(value || fallback || '')
    .trim()
    .toLowerCase()
    .replace(/^\.+|\.+$/g, '');
  return d || fallback;
}

function envFlag(name) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return false;
  const v = String(raw).trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/** Comma-separated SaaS platform origins (no trailing slash), e.g. https://pipeshare.net */
function parsePlatformApplyPeerUrls(env = process.env) {
  const raw = cleanString(env.HP_PLATFORM_APPLY_PEER_URLS);
  if (!raw) return [];
  return raw
    .split(/[,;\s]+/)
    .map((u) => u.replace(/\/+$/, ''))
    .filter(Boolean);
}

/** Shared secret for BASE → SaaS internal apply. Falls back to support presence peer secret. */
function platformApplyPeerSecret(env = process.env) {
  return (
    cleanString(env.HP_PLATFORM_APPLY_PEER_SECRET) ||
    cleanString(env.CP_SUPPORT_PRESENCE_PEER_SECRET)
  );
}

function platformApplyLocalEnabled(env = process.env) {
  return envFlag('HP_PLATFORM_APPLY_LOCAL');
}

/** Hybrid OVH: BASE and SaaS share one git checkout — mark SaaS version without Wasabi tarball swap. */
function platformApplyManifestOnly(env = process.env) {
  return envFlag('HP_PLATFORM_APPLY_MANIFEST_ONLY');
}

function isPlatformApplyPeerConfigured(env = process.env) {
  return Boolean(platformApplyPeerSecret(env) && parsePlatformApplyPeerUrls(env).length);
}

function requirePlatformApplyPeerSecret(req, res, next) {
  const expected = platformApplyPeerSecret();
  if (!expected) {
    return res.status(503).json({ success: false, error: 'Platform apply peer federation not configured' });
  }
  const got = cleanString(req.headers['x-hp-platform-apply-peer-secret']);
  if (!got || got !== expected) {
    return res.status(403).json({ success: false, error: 'Invalid platform apply peer secret' });
  }
  return next();
}

/**
 * Ask each SaaS platform host to apply a published release (server-to-server).
 * @param {string} version
 * @param {{ actor?: string, timeoutMs?: number }} [opts]
 */
async function pushPlatformReleaseToPeers(version, opts = {}) {
  const v = cleanString(version);
  if (!v) throw new Error('version is required');

  const secret = platformApplyPeerSecret();
  const peers = parsePlatformApplyPeerUrls();
  if (!secret) {
    throw new Error(
      'HP_PLATFORM_APPLY_PEER_SECRET (or CP_SUPPORT_PRESENCE_PEER_SECRET) is not configured on BASE'
    );
  }
  if (!peers.length) {
    throw new Error('HP_PLATFORM_APPLY_PEER_URLS is not configured on BASE');
  }

  const timeoutMs = Math.max(30_000, Math.min(600_000, Number(opts.timeoutMs || 300_000)));
  const actor = cleanString(opts.actor);
  const results = [];

  await Promise.all(
    peers.map(async (base) => {
      const url = `${base}/internal/platform/releases/apply`;
      const started = Date.now();
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), timeoutMs);
        const resp = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-HP-Platform-Apply-Peer-Secret': secret
          },
          body: JSON.stringify({ version: v, actor }),
          signal: ctrl.signal
        });
        clearTimeout(timer);
        const text = await resp.text();
        let data = null;
        try {
          data = text ? JSON.parse(text) : null;
        } catch {
          data = { raw: text.slice(0, 400) };
        }
        if (!resp.ok) {
          const msg = cleanString(data?.error) || text.slice(0, 200) || `HTTP ${resp.status}`;
          results.push({ peer: base, ok: false, status: resp.status, error: msg, ms: Date.now() - started });
          return;
        }
        results.push({
          peer: base,
          ok: true,
          status: resp.status,
          version: cleanString(data?.version) || v,
          appliedAt: cleanString(data?.appliedAt),
          ms: Date.now() - started
        });
      } catch (err) {
        results.push({
          peer: base,
          ok: false,
          error: err instanceof Error ? err.message : String(err),
          ms: Date.now() - started
        });
      }
    })
  );

  const failed = results.filter((r) => !r.ok);
  if (failed.length) {
    const summary = failed.map((f) => `${f.peer}: ${f.error || f.status}`).join('; ');
    throw new Error(`SaaS push failed for ${failed.length}/${results.length} peer(s): ${summary}`);
  }

  return results;
}

/** Host header value for in-process apply on a hybrid box (pipeshare.net). */
function defaultSaasPlatformRequestHost() {
  return cleanDomain(process.env.SAAS_PIPESHARE_BASE_DOMAIN, 'pipeshare.net');
}

module.exports = {
  parsePlatformApplyPeerUrls,
  platformApplyPeerSecret,
  platformApplyLocalEnabled,
  platformApplyManifestOnly,
  isPlatformApplyPeerConfigured,
  requirePlatformApplyPeerSecret,
  pushPlatformReleaseToPeers,
  defaultSaasPlatformRequestHost
};
