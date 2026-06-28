'use strict';

const {
  parseSaasTenantSlugFromHost,
  saasPipeshareBaseDomain
} = require('./saas-tenant-access-urls');

function saasTenantCorsEnabled() {
  return String(process.env.SAAS_TENANT_CORS_ENABLED || '1').trim().toLowerCase() !== '0';
}

/** Allow https://{tenant}.pipeshare.net (PipeShare + PipeSync on same host). */
function isSaasTenantCorsOrigin(origin) {
  if (!saasTenantCorsEnabled() || !origin) return false;
  try {
    const u = new URL(origin);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    const host = u.hostname;
    const slug = parseSaasTenantSlugFromHost(host);
    if (!slug) return false;
    const h = host.toLowerCase();
    const ps = saasPipeshareBaseDomain();
    return h.endsWith('.' + ps);
  } catch (_) {
    return false;
  }
}

module.exports = {
  saasTenantCorsEnabled,
  isSaasTenantCorsOrigin
};
