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

function envFlag(name, defaultFalse = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return defaultFalse;
  const v = String(raw).trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

/**
 * Canonical deployment mode for this process (one PM2 app = one mode).
 * @returns {DeploymentMode}
 */
function deploymentMode() {
  const mode = cleanString(process.env.HP_DEPLOYMENT_MODE || 'non-saas').toLowerCase();
  return mode === 'saas' ? 'saas' : 'non-saas';
}

function isSaasDeployment() {
  return deploymentMode() === 'saas';
}

function isPrivateBaseDeployment() {
  return !isSaasDeployment();
}

/**
 * Feature flags — SaaS-first defaults; private base is the explicit exception profile.
 * @param {DeploymentMode} mode
 */
function buildFeatureFlags(mode) {
  const saas = mode === 'saas';
  return Object.freeze({
    /** Stripe checkout, tenant billing portal, subscription gate */
    subscriptionBilling: saas,
    /** `{tenant}.pipeshare.net` workspace hosts */
    tenantSubdomains: saas,
    /** `Tenants/{slug}/` Wasabi virtualbox + SAAS_WASABI_BUCKET */
    tenantVirtualboxStorage: saas,
    /** Customer must have active subscription to sign in on tenant hosts */
    saasCustomerLoginGate: saas,
    /** cPanel → publish release artifact to Wasabi (Mike base) */
    platformReleasePublish: !saas,
    /** cPanel → apply release artifact from Wasabi (SaaS fleet) */
    platformReleaseApply: saas,
    /** Show dev PIN on signup when SMTP missing (base only) */
    devSignupPin: !saas,
    /** Legacy `portal-users/{job}` shared bucket layout (base default) */
    legacySharedPortalBucket: !saas,
    /** Allow relaxing tenant host↔slug binding for integration tests on base */
    tenantHostBindingStrict: saas && !envFlag('SAAS_SKIP_HOST_BINDING')
  });
}

/**
 * Storage layout for portal files on this host.
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
 * Full deployment profile for this Node process.
 * @param {{ requestHost?: string }} [options]
 */
function resolveDeploymentProfile(options = {}) {
  const mode = deploymentMode();
  const requestHost = cleanString(options.requestHost);
  const tenantSlugFromHost = parseSaasTenantSlugFromHost(requestHost);
  const isTenantWorkspaceHost = !!tenantSlugFromHost;
  return Object.freeze({
    version: 1,
    mode,
    isPrivateBase: mode === 'non-saas',
    isSaasPlatform: mode === 'saas',
    isTenantWorkspaceHost,
    tenantSlugFromHost,
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
    isPrivateBase: p.isPrivateBase,
    isSaasPlatform: p.isSaasPlatform,
    isTenantWorkspaceHost: p.isTenantWorkspaceHost,
    tenantSlugFromHost: p.tenantSlugFromHost,
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

/** Inline bootstrap script — sets `window.__HP_DEPLOYMENT_CONFIG__` and tenant portal globals. */
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
  const p = resolveDeploymentProfile();
  console.log(
    `[deployment] mode=${p.mode} saasPlatform=${p.isSaasPlatform} tenantSubdomains=${p.features.tenantSubdomains} ` +
      `virtualbox=${p.features.tenantVirtualboxStorage} domain=${p.pipeshareBaseDomain}`
  );
}

module.exports = {
  deploymentMode,
  isSaasDeployment,
  isPrivateBaseDeployment,
  resolveDeploymentProfile,
  getPublicDeploymentConfig,
  renderDeploymentBootstrapJs,
  logDeploymentProfileAtStartup
};
