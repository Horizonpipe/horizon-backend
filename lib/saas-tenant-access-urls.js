'use strict';

const { slugifyTenantName } = require('./saas-tenant-paths');

function cleanDomain(value, fallback) {
  const d = String(value || fallback || '')
    .trim()
    .toLowerCase()
    .replace(/^\.+|\.+$/g, '');
  return d || fallback;
}

function saasPipeshareBaseDomain() {
  return cleanDomain(process.env.SAAS_PIPESHARE_BASE_DOMAIN, 'pipeshare.net');
}

/** PipeSync runs on the same tenant host as PipeShare (path under pipeshare.net). */
function saasPipesyncPath() {
  const p = String(process.env.SAAS_PIPESYNC_PATH || '/pipesync.html').trim();
  return p.startsWith('/') ? p : `/${p}`;
}

function saasPipesharePortalPath() {
  const p = String(process.env.SAAS_PIPESHARE_PORTAL_PATH || '/client-portal/').trim();
  return p.startsWith('/') ? p : `/${p}`;
}

/** @deprecated PipeSync is on pipeshare.net; kept for env overrides only. */
function saasPipesyncBaseDomain() {
  return saasPipeshareBaseDomain();
}

/** Display + URL label from what the customer typed (preserves case). Techpipe → Techpipe */
function businessNameToSubdomainLabel(businessName) {
  let s = String(businessName || '').trim();
  if (!s) return '';
  s = s.replace(/\s+/g, '');
  s = s.replace(/[^a-zA-Z0-9-]/g, '');
  if (!s || !/^[a-zA-Z0-9]/.test(s)) return '';
  return s.slice(0, 63);
}

/** Lowercase slug for Wasabi paths and portal client id (tenant-techpipe). */
function businessNameToStorageSlug(businessName) {
  return slugifyTenantName(businessName);
}

function tenantSlugFromWasabiRoot(wasabiRootPrefix) {
  const m = /^(?:Tenants|tenants)\/([^/]+)\/?$/i.exec(String(wasabiRootPrefix || '').trim());
  return m ? slugifyTenantName(m[1]) : '';
}

/**
 * Build customer-facing workspace URLs from the business name field.
 * @param {string} businessName
 */
function buildTenantAccessUrls(businessName) {
  const label = businessNameToSubdomainLabel(businessName);
  const slug = businessNameToStorageSlug(businessName);
  if (!label || !slug) {
    return {
      subdomainLabel: '',
      slug: '',
      pipeshareHost: '',
      pipesyncHost: '',
      pipeshareUrl: '',
      pipesyncUrl: ''
    };
  }
  const pipeshareHost = `${label}.${saasPipeshareBaseDomain()}`;
  const portalPath = saasPipesharePortalPath();
  const pipesyncPath = saasPipesyncPath();
  const pipesyncDisplayPath = pipesyncPath.replace(/\.html$/i, '') || '/pipesync';
  return {
    subdomainLabel: label,
    slug,
    pipeshareHost,
    pipesyncHost: `${pipeshareHost}${pipesyncDisplayPath}`,
    pipeshareUrl: `https://${pipeshareHost}${portalPath}`,
    pipesyncUrl: `https://${pipeshareHost}${pipesyncPath}`
  };
}

function parseTenantSlugFromHost(host, productBaseDomain) {
  const h = String(host || '')
    .trim()
    .toLowerCase()
    .split(':')[0];
  const base = cleanDomain(productBaseDomain, '');
  if (!h || !base) return '';
  if (h === base || h === `www.${base}`) return '';
  const suffix = `.${base}`;
  if (!h.endsWith(suffix)) return '';
  const sub = h.slice(0, -suffix.length);
  if (!sub || sub === 'www' || sub.includes('.')) return '';
  return slugifyTenantName(sub);
}

function parseSaasTenantSlugFromHost(host) {
  return parseTenantSlugFromHost(host, saasPipeshareBaseDomain());
}

module.exports = {
  saasPipeshareBaseDomain,
  saasPipesyncBaseDomain,
  saasPipesyncPath,
  saasPipesharePortalPath,
  businessNameToSubdomainLabel,
  businessNameToStorageSlug,
  tenantSlugFromWasabiRoot,
  buildTenantAccessUrls,
  parseTenantSlugFromHost,
  parseSaasTenantSlugFromHost
};
