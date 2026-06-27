'use strict';

const {
  loadTenantByOwner,
  upsertTenantDraft,
  provisionTenantInstance,
  normalizeBranding
} = require('./tenant-provisioning.service');

function cleanString(v) {
  return String(v ?? '').trim();
}

function subscriptionAllowsProvisioning(status) {
  const s = cleanString(status).toLowerCase();
  if (process.env.SAAS_SKIP_SUBSCRIPTION_CHECK === '1') return true;
  return s === 'active' || s === 'trialing';
}

/**
 * @param {import('express').Express} app
 * @param {{
 *   pool: import('pg').Pool,
 *   requireAuth: import('express').RequestHandler,
 *   wasabiClient: import('@aws-sdk/client-s3').S3Client | null,
 *   wasabiBucket: string
 * }} deps
 */
function registerSaasTenantRoutes(app, { pool, requireAuth, wasabiClient, wasabiBucket }) {
  function jsonError(res, status, message) {
    return res.status(status).json({ success: false, error: message });
  }

  app.get('/saas/tenant/me', requireAuth, async (req, res) => {
    try {
      const tenant = await loadTenantByOwner(pool, req.user?.id);
      return res.json({ success: true, tenant });
    } catch (error) {
      console.error('[saas/tenant/me]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.put('/saas/tenant/setup', requireAuth, async (req, res) => {
    try {
      const tenant = await upsertTenantDraft(pool, req.user?.id, {
        businessName: cleanString(req.body?.businessName),
        websiteUrl: cleanString(req.body?.websiteUrl),
        branding: normalizeBranding({
          businessName: req.body?.businessName,
          websiteUrl: req.body?.websiteUrl,
          logoStorageKey: req.body?.logoStorageKey,
          primaryColor: req.body?.primaryColor,
          accentColor: req.body?.accentColor,
          sampleAssetKeys: req.body?.sampleAssetKeys
        })
      });
      return res.json({ success: true, tenant });
    } catch (error) {
      console.error('[saas/tenant/setup]', error);
      return jsonError(res, 400, error.message || 'Invalid setup payload');
    }
  });

  app.post('/saas/tenant/provision', requireAuth, async (req, res) => {
    try {
      const tenant = await loadTenantByOwner(pool, req.user?.id);
      if (!tenant) return jsonError(res, 404, 'Complete setup before provisioning');
      if (!subscriptionAllowsProvisioning(tenant.subscriptionStatus)) {
        return jsonError(res, 402, 'An active subscription is required before provisioning');
      }
      const provisioned = await provisionTenantInstance(pool, wasabiClient, wasabiBucket, req.user?.id);
      return res.json({ success: true, tenant: provisioned });
    } catch (error) {
      console.error('[saas/tenant/provision]', error);
      return jsonError(res, 500, error.message || 'Provisioning failed');
    }
  });

  app.get('/saas/tenant/status', requireAuth, async (req, res) => {
    try {
      const tenant = await loadTenantByOwner(pool, req.user?.id);
      if (!tenant) {
        return res.json({
          success: true,
          status: 'none',
          subscriptionStatus: 'pending',
          setupStatus: 'draft'
        });
      }
      return res.json({
        success: true,
        status: tenant.setupStatus,
        subscriptionStatus: tenant.subscriptionStatus,
        setupStatus: tenant.setupStatus,
        tenant
      });
    } catch (error) {
      console.error('[saas/tenant/status]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  console.log('[saas-tenant] /saas/tenant/* routes mounted');
}

module.exports = { registerSaasTenantRoutes, subscriptionAllowsProvisioning };
