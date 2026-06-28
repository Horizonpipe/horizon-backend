'use strict';

const {
  loadTenantByOwner,
  loadTenantByPortalSlug,
  upsertTenantDraft,
  provisionTenantInstance,
  normalizeBranding
} = require('./tenant-provisioning.service');
const { normalizeAppFeatures } = require('./company-permissions.service');
const {
  buildTenantBrandingStorageKey,
  isValidTenantBrandingStorageKey,
  isAllowedBrandingContentType,
  maxBytesForKind,
  presignTenantBrandingPut,
} = require('./lib/saas-branding-upload');
const {
  parseSaasTenantSlugFromHost,
  buildTenantAccessUrls
} = require('./lib/saas-tenant-access-urls');
const {
  getSaasWasabiClient,
  saasWasabiBucket,
  saasVirtualboxConfigured
} = require('./lib/saas-virtualbox-config');
const { slugifyTenantName } = require('./lib/saas-tenant-paths');

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

  function storageClient() {
    return saasVirtualboxConfigured() ? getSaasWasabiClient() : wasabiClient;
  }

  function storageBucket() {
    return saasVirtualboxConfigured() ? saasWasabiBucket() : wasabiBucket;
  }

  /** Public tenant branding for {Company}.pipeshare.net login shell (no auth). */
  app.get('/saas/tenant/public-by-host', async (req, res) => {
    try {
      const host = cleanString(req.query.host || req.headers.host);
      const slug = parseSaasTenantSlugFromHost(host);
      if (!slug) {
        return jsonError(res, 404, 'Unknown tenant host');
      }
      const tenant = await loadTenantByPortalSlug(pool, slug);
      if (!tenant) {
        return jsonError(res, 404, 'Tenant not found');
      }
      const branding = tenant.branding || {};
      return res.json({
        success: true,
        tenant: {
          slug,
          businessName: branding.businessName || '',
          primaryColor: branding.primaryColor || '',
          accentColor: branding.accentColor || '',
          setupStatus: tenant.setupStatus,
          accessUrls: tenant.accessUrls || buildTenantAccessUrls(branding.businessName)
        }
      });
    } catch (error) {
      console.error('[saas/tenant/public-by-host]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

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
      let tenant = await loadTenantByOwner(pool, req.user?.id);
      const logoKey = cleanString(req.body?.logoStorageKey);
      const sampleKeys = Array.isArray(req.body?.sampleAssetKeys)
        ? req.body.sampleAssetKeys.map((k) => cleanString(k)).filter(Boolean)
        : null;
      if (tenant && logoKey && !isValidTenantBrandingStorageKey(logoKey, tenant.wasabiRootPrefix)) {
        return jsonError(res, 400, 'Invalid logo storage key for this tenant');
      }
      if (tenant && sampleKeys) {
        for (const key of sampleKeys) {
          if (!isValidTenantBrandingStorageKey(key, tenant.wasabiRootPrefix)) {
            return jsonError(res, 400, 'Invalid brand sample storage key for this tenant');
          }
        }
      }
      tenant = await upsertTenantDraft(pool, req.user?.id, {
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

  app.post('/saas/tenant/branding/upload-url', requireAuth, async (req, res) => {
    try {
      const client = storageClient();
      const bucket = storageBucket();
      if (!client || !bucket) {
        return jsonError(res, 503, 'Object storage is not configured on this server');
      }
      const kind = cleanString(req.body?.kind).toLowerCase() === 'logo' ? 'logo' : 'sample';
      const fileName = cleanString(req.body?.fileName) || (kind === 'logo' ? 'logo.png' : 'sample.png');
      const contentType = cleanString(req.body?.contentType) || 'application/octet-stream';
      const fileSize = Number(req.body?.fileSize);

      if (!isAllowedBrandingContentType(contentType)) {
        return jsonError(res, 400, 'Only image uploads are allowed for branding');
      }
      if (!Number.isFinite(fileSize) || fileSize <= 0) {
        return jsonError(res, 400, 'fileSize is required');
      }
      if (fileSize > maxBytesForKind(kind)) {
        return jsonError(res, 400, `File exceeds ${kind} upload limit`);
      }

      let tenant = await loadTenantByOwner(pool, req.user?.id);
      if (!tenant) {
        tenant = await upsertTenantDraft(pool, req.user?.id, {
          businessName: cleanString(req.user?.company || req.user?.displayName || req.user?.username || 'My Business'),
          websiteUrl: '',
          branding: {
            businessName: cleanString(req.user?.company || req.user?.displayName || req.user?.username || 'My Business')
          }
        });
      }
      if (!tenant?.wasabiRootPrefix) {
        return jsonError(res, 400, 'Tenant storage root is not ready — save business name first');
      }

      const storageKey = buildTenantBrandingStorageKey(tenant.wasabiRootPrefix, kind, fileName);
      const presigned = await presignTenantBrandingPut(client, bucket, storageKey, contentType);

      return res.json({
        success: true,
        kind,
        uploadUrl: presigned.url,
        uploadMethod: presigned.method,
        uploadHeaders: presigned.headers,
        storageKey: presigned.storageKey,
        expiresIn: presigned.expiresIn
      });
    } catch (error) {
      console.error('[saas/tenant/branding/upload-url]', error);
      return jsonError(res, 500, error.message || 'Could not create upload URL');
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
      let appFeatures = null;
      if (tenant.companyId) {
        const feat = await pool.query(`SELECT app_features FROM companies WHERE id = $1 LIMIT 1`, [
          tenant.companyId
        ]);
        appFeatures = normalizeAppFeatures(feat.rows[0]?.app_features);
      }
      const tenantOut = { ...tenant, appFeatures };
      return res.json({
        success: true,
        status: tenant.setupStatus,
        subscriptionStatus: tenant.subscriptionStatus,
        setupStatus: tenant.setupStatus,
        tenant: tenantOut
      });
    } catch (error) {
      console.error('[saas/tenant/status]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  console.log('[saas-tenant] /saas/tenant/* routes mounted');
}

module.exports = { registerSaasTenantRoutes, subscriptionAllowsProvisioning };
