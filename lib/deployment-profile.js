'use strict';

const {
  parseSaasTenantSlugFromHost,
  saasPipeshareBaseDomain,
  saasPipesharePortalPath,
  saasPipesyncPath
} = require('./saas-tenant-access-urls');

/** @typedef {'saas' | 'non-saas'} DeploymentMode */

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

function privateBaseDomain() {
  return cleanDomain(process.env.HP_PRIVATE_BASE_DOMAIN, 'pipeshare.live');
}

function envFlag(name, defaultFalse = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return defaultFalse;
  const v = String(raw).trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

function normalizeHost(host) {
  return cleanString(host).toLowerCase().split(':')[0];
}

/**
 * Hostname → deployment mode when serving Base + SaaS from one Node process.
 * @param {string} requestHost
 * @returns {DeploymentMode | null} null = unknown host (use env fallback)
 */
function resolveModeFromHost(requestHost) {
  const h = normalizeHost(requestHost);
  if (!h) return null;

  const baseDomain = privateBaseDomain();
  if (h === baseDomain || h === `www.${baseDomain}`) {
    return 'non-saas';
  }

  const saasDomain = saasPipeshareBaseDomain();
  if (h === saasDomain || h === `www.${saasDomain}`) {
    return 'saas';
  }

  if (parseSaasTenantSlugFromHost(h)) {
    return 'saas';
  }

  return null;
}

/**
 * Env default when hostname is localhost / unknown.
 * @returns {DeploymentMode | 'hybrid'}
 */
function deploymentModeEnv() {
  const mode = cleanString(process.env.HP_DEPLOYMENT_MODE || 'hybrid').toLowerCase();
  if (mode === 'saas') return 'saas';
  if (mode === 'non-saas') return 'non-saas';
  return 'hybrid';
}

/**
 * @returns {DeploymentMode}
 */
function deploymentMode() {
  const env = deploymentModeEnv();
  if (env === 'hybrid') {
    const fb = cleanString(process.env.HP_DEPLOYMENT_MODE_FALLBACK || 'non-saas').toLowerCase();
    return fb === 'saas' ? 'saas' : 'non-saas';
  }
  return env;
}

/**
 * @param {{ requestHost?: string }} [options]
 * @returns {DeploymentMode}
 */
function resolveEffectiveMode(options = {}) {
  const fromHost = resolveModeFromHost(options.requestHost);
  if (fromHost) return fromHost;
  return deploymentMode();
}

function isSaasDeployment(options = {}) {
  return resolveEffectiveMode(options) === 'saas';
}

function isPrivateBaseDeployment(options = {}) {
  return resolveEffectiveMode(options) === 'non-saas';
}

/**
 * @param {DeploymentMode} mode
 */
function buildFeatureFlags(mode) {
  const saas = mode === 'saas';
  return Object.freeze({
    subscriptionBilling: saas,
    tenantSubdomains: saas,
    tenantVirtualboxStorage: saas,
    saasCustomerLoginGate: saas,
    platformReleasePublish: !saas,
    platformReleaseApply: saas,
    devSignupPin: !saas,
    legacySharedPortalBucket: !saas,
    tenantHostBindingStrict: saas && !envFlag('SAAS_SKIP_HOST_BINDING')
  });
}

/**
 * @param {DeploymentMode} mode
 */
function buildStorageProfile(mode) {
  const saas = mode === 'saas';
  return Object.freeze({
    portalBucketEnv: saas ? 'SAAS_WASABI_BUCKET' : 'WASABI_BUCKET',
    tenantPrefix: saas ? cleanString(process.env.SAAS_TENANT_FOLDER_PREFIX || 'Tenants/') : '',
    defaultPortalClientId: saas ? '' : cleanString(process.env.PORTAL_SHARED_DEFAULT_CLIENT_ID || 'portal-users'),
    defaultPortalJobId: saas ? '1' : cleanString(process.env.PORTAL_SHARED_DEFAULT_JOB_ID || '8')
  });
}

/**
 * @param {{ requestHost?: string }} [options]
 */
function resolveDeploymentProfile(options = {}) {
  const requestHost = cleanString(options.requestHost);
  const modeFromHost = resolveModeFromHost(requestHost);
  const mode = resolveEffectiveMode(options);
  const tenantSlugFromHost = parseSaasTenantSlugFromHost(requestHost);
  const isTenantWorkspaceHost = !!tenantSlugFromHost;
  return Object.freeze({
    version: 1,
    mode,
    modeDerivedFromHost: modeFromHost !== null,
    isPrivateBase: mode === 'non-saas',
    isSaasPlatform: mode === 'saas',
    isTenantWorkspaceHost,
    tenantSlugFromHost,
    privateBaseDomain: privateBaseDomain(),
    pipeshareBaseDomain: saasPipeshareBaseDomain(),
    pipesharePortalPath: saasPipesharePortalPath(),
    pipesyncPath: saasPipesyncPath(),
    features: buildFeatureFlags(mode),
    storage: buildStorageProfile(mode)
  });
}

/** JSON-safe subset for browsers (no secrets). */
function getPublicDeploymentConfig(options = {}) {
  const p = resolveDeploymentProfile(options);
  return {
    version: p.version,
    mode: p.mode,
    modeDerivedFromHost: p.modeDerivedFromHost,
    isPrivateBase: p.isPrivateBase,
    isSaasPlatform: p.isSaasPlatform,
    isTenantWorkspaceHost: p.isTenantWorkspaceHost,
    tenantSlugFromHost: p.tenantSlugFromHost,
    privateBaseDomain: p.privateBaseDomain,
    pipeshareBaseDomain: p.pipeshareBaseDomain,
    pipesharePortalPath: p.pipesharePortalPath,
    pipesyncPath: p.pipesyncPath,
    features: { ...p.features },
    storage: {
      defaultPortalClientId: p.storage.defaultPortalClientId,
      defaultPortalJobId: p.storage.defaultPortalJobId
    }
  };
}

function renderDeploymentBootstrapJs(options = {}) {
  const cfg = getPublicDeploymentConfig(options);
  const slug = cfg.tenantSlugFromHost || '';
  const portalClientId = slug ? `tenant-${slug}` : '';
  const portalJobId = slug ? '1' : '';
  return `(function(){'use strict';
var c=${JSON.stringify(cfg)};
window.__HP_DEPLOYMENT_CONFIG__=c;
window.__HP_DEPLOYMENT_MODE__=c.mode;
${slug ? `window.__HP_SAAS_TENANT_SLUG__=${JSON.stringify(slug)};window.__HP_SAAS_PORTAL_CLIENT_ID__=${JSON.stringify(portalClientId)};window.__HP_SAAS_PORTAL_JOB_ID__=${JSON.stringify(portalJobId)};` : ''}
})();`;
}

function logDeploymentProfileAtStartup() {
  const hybrid = deploymentModeEnv() === 'hybrid';
  console.log(
    `[deployment] env=${deploymentModeEnv()} hybrid=${hybrid} fallback=${deploymentMode()} ` +
      `baseDomain=${privateBaseDomain()} saasDomain=${saasPipeshareBaseDomain()}`
  );
}

module.exports = {
  deploymentMode,
  deploymentModeEnv,
  resolveModeFromHost,
  resolveEffectiveMode,
  isSaasDeployment,
  isPrivateBaseDeployment,
  resolveDeploymentProfile,
  getPublicDeploymentConfig,
  renderDeploymentBootstrapJs,
  logDeploymentProfileAtStartup,
  privateBaseDomain
};
