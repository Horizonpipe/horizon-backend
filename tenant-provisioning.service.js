'use strict';

const { PutObjectCommand } = require('@aws-sdk/client-s3');
const {
  slugifyTenantName,
  buildTenantWasabiRoot,
  buildTenantPortalScope,
  buildTenantSkeletonKeys,
  FOLDER_MARKER
} = require('./lib/saas-tenant-paths');
const { buildTenantAccessUrls } = require('./lib/saas-tenant-access-urls');
const { getSaasWasabiClient, saasWasabiBucket, saasVirtualboxConfigured } = require('./lib/saas-virtualbox-config');
const { seedTenantAuthSnapshot, upsertTenantOwnerAuthSnapshot } = require('./lib/saas-tenant-auth-store');
const { applySaasTenantOwnerPrivileges, isHorizonPlatformAdmin } = require('./lib/saas-tenant-owner');
const { seedTenantAppDataSnapshot } = require('./lib/tenant-wasabi-state');
const { SAAS_INITIAL_SUBSCRIPTION_STATUS } = require('./lib/saas-subscription-constants');

function cleanString(v) {
  return String(v ?? '').trim();
}

function normalizeBranding(raw) {
  const base = {
    businessName: '',
    websiteUrl: '',
    logoStorageKey: '',
    primaryColor: '',
    accentColor: '',
    sampleAssetKeys: []
  };
  if (!raw || typeof raw !== 'object') return base;
  return {
    businessName: cleanString(raw.businessName ?? raw.business_name),
    websiteUrl: cleanString(raw.websiteUrl ?? raw.website_url),
    logoStorageKey: cleanString(raw.logoStorageKey ?? raw.logo_storage_key),
    primaryColor: cleanString(raw.primaryColor ?? raw.primary_color),
    accentColor: cleanString(raw.accentColor ?? raw.accent_color),
    sampleAssetKeys: Array.isArray(raw.sampleAssetKeys ?? raw.sample_asset_keys)
      ? (raw.sampleAssetKeys ?? raw.sample_asset_keys).map((k) => cleanString(k)).filter(Boolean)
      : []
  };
}

function serializeTenantRow(row) {
  if (!row) return null;
  const tenant = {
    id: row.id,
    companyId: row.company_id,
    ownerUserId: row.owner_user_id,
    websiteUrl: row.website_url || '',
    wasabiRootPrefix: row.wasabi_root_prefix || '',
    portalClientId: row.portal_client_id || '',
    portalJobId: row.portal_job_id || '1',
    branding: normalizeBranding(row.branding),
    subscriptionStatus: row.subscription_status || SAAS_INITIAL_SUBSCRIPTION_STATUS,
    stripeCustomerId: row.stripe_customer_id || '',
    stripeSubscriptionId: row.stripe_subscription_id || '',
    setupStatus: row.setup_status || 'draft',
    setupCompletedAt: row.setup_completed_at || null,
    provisioningError: row.provisioning_error || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
  tenant.accessUrls = buildTenantAccessUrls(tenant.branding.businessName);
  return tenant;
}

async function loadTenantByOwner(pool, ownerUserId) {
  const r = await pool.query(
    `SELECT *
     FROM saas_tenant_instances
     WHERE owner_user_id = $1
     LIMIT 1`,
    [String(ownerUserId)]
  );
  return serializeTenantRow(r.rows[0] || null);
}

async function loadTenantById(pool, tenantId) {
  const r = await pool.query(
    `SELECT *
     FROM saas_tenant_instances
     WHERE id = $1
     LIMIT 1`,
    [String(tenantId)]
  );
  return serializeTenantRow(r.rows[0] || null);
}

async function loadTenantByPortalSlug(pool, slug) {
  const s = slugifyTenantName(slug);
  if (!s) return null;
  const r = await pool.query(
    `SELECT *
     FROM saas_tenant_instances
     WHERE portal_client_id = $1
     LIMIT 1`,
    [`tenant-${s}`]
  );
  return serializeTenantRow(r.rows[0] || null);
}

async function upsertTenantDraft(pool, ownerUserId, payload) {
  const branding = normalizeBranding(payload?.branding);
  const businessName = branding.businessName || cleanString(payload?.businessName);
  const websiteUrl = branding.websiteUrl || cleanString(payload?.websiteUrl);
  if (!businessName) throw new Error('Business name is required');

  const slug = slugifyTenantName(businessName);
  const existing = await loadTenantByOwner(pool, ownerUserId);
  if (existing && existing.setupStatus === 'ready') {
    throw new Error('Tenant is already provisioned');
  }

  const wasabiRoot = buildTenantWasabiRoot(slug);
  const scope = buildTenantPortalScope(slug);

  if (existing) {
    const r = await pool.query(
      `UPDATE saas_tenant_instances
       SET website_url = $2,
           wasabi_root_prefix = $3,
           portal_client_id = $4,
           portal_job_id = $5,
           branding = $6::jsonb,
           updated_at = NOW()
       WHERE owner_user_id = $1
       RETURNING *`,
      [
        String(ownerUserId),
        websiteUrl,
        wasabiRoot,
        scope.clientId,
        scope.jobId,
        JSON.stringify({ ...branding, businessName, websiteUrl })
      ]
    );
    return serializeTenantRow(r.rows[0]);
  }

  const companyInsert = await pool.query(
    `INSERT INTO companies (name, slug, app_features, customer_enabled)
     VALUES ($1, $2, $3::jsonb, true)
     ON CONFLICT (name) DO UPDATE SET updated_at = NOW()
     RETURNING id`,
    [
      businessName,
      slug,
      JSON.stringify({ pipeshare: true, pipesync: true, autosync: false, planview: true })
    ]
  );
  const companyId = companyInsert.rows[0].id;

  for (const roleKey of ['admin', 'employee', 'customer']) {
    await pool.query(
      `INSERT INTO company_roles (company_id, role_key, enabled)
       VALUES ($1, $2, $3)
       ON CONFLICT (company_id, role_key) DO NOTHING`,
      [companyId, roleKey, roleKey !== 'customer']
    );
  }

  const r = await pool.query(
    `INSERT INTO saas_tenant_instances (
       company_id, owner_user_id, website_url, wasabi_root_prefix,
       portal_client_id, portal_job_id, branding, setup_status, subscription_status
     ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'draft', $8)
     RETURNING *`,
    [
      companyId,
      String(ownerUserId),
      websiteUrl,
      wasabiRoot,
      scope.clientId,
      scope.jobId,
      JSON.stringify({ ...branding, businessName, websiteUrl }),
      SAAS_INITIAL_SUBSCRIPTION_STATUS
    ]
  );
  return serializeTenantRow(r.rows[0]);
}

async function putFolderMarkers(s3Client, bucket, keys) {
  if (!s3Client || !bucket) {
    return { ok: false, reason: 'wasabi_not_configured', created: 0 };
  }
  let created = 0;
  for (const key of keys) {
    await s3Client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: '',
        ContentType: 'application/octet-stream',
        Metadata: { 'hp-folder-marker': FOLDER_MARKER }
      })
    );
    created += 1;
  }
  return { ok: true, created };
}

/**
 * Provision Wasabi skeleton + bind owner as tenant admin (company membership + portal scope).
 * Stripe/subscription gating is enforced by routes before calling this.
 */
async function provisionTenantInstance(pool, s3Client, bucket, ownerUserId) {
  const tenant = await loadTenantByOwner(pool, ownerUserId);
  if (!tenant) throw new Error('No tenant setup found for this account');
  if (tenant.setupStatus === 'ready') return tenant;

  const slug = slugifyTenantName(tenant.branding.businessName);
  const skeletonKeys = buildTenantSkeletonKeys(slug);
  const storageClient = saasVirtualboxConfigured() ? getSaasWasabiClient() : s3Client;
  const storageBucket = saasVirtualboxConfigured() ? saasWasabiBucket() : bucket;

  await pool.query(
    `UPDATE saas_tenant_instances
     SET setup_status = 'provisioning', provisioning_error = '', updated_at = NOW()
     WHERE owner_user_id = $1`,
    [String(ownerUserId)]
  );

  try {
    const markerResult = await putFolderMarkers(storageClient, storageBucket, skeletonKeys);
    if (!markerResult.ok) {
      const requireWasabi = String(process.env.SAAS_REQUIRE_WASABI_PROVISION || '').trim() === '1';
      if (markerResult.reason === 'wasabi_not_configured' && !requireWasabi) {
        console.warn('[saas-provision] Skipping Wasabi folder markers — not configured on this server');
      } else {
        throw new Error(
          markerResult.reason === 'wasabi_not_configured'
            ? 'Wasabi is not configured on the server'
            : markerResult.reason || 'Wasabi folder creation failed'
        );
      }
    }

    const ownerRow = await pool.query(
      `SELECT id, username, email, display_name FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
      [String(ownerUserId)]
    );
    const ownerUser = ownerRow.rows[0] || null;
    await seedTenantAuthSnapshot(slug, ownerUser);
    await upsertTenantOwnerAuthSnapshot(slug, ownerUser);
    await seedTenantAppDataSnapshot(slug);
    await applySaasTenantOwnerPrivileges(pool, ownerUserId);

    await pool.query(
      `INSERT INTO user_company_membership (user_id, company_id, role_key, override_folder_grants)
       VALUES ($1, $2, 'admin', '[]'::jsonb)
       ON CONFLICT (user_id) DO UPDATE
       SET company_id = EXCLUDED.company_id,
           role_key = 'admin',
           updated_at = NOW()`,
      [String(ownerUserId), tenant.companyId]
    );

    const skipPortalScopeBind = isHorizonPlatformAdmin(ownerUser);
    if (!skipPortalScopeBind) {
      await pool.query(
        `UPDATE users
         SET portal_files_client_id = $2,
             portal_files_job_id = $3,
             portal_files_access_granted = true,
             portal_permissions_access = true,
             company = COALESCE(NULLIF(BTRIM(company), ''), $4),
             updated_at = NOW()
         WHERE CAST(id AS text) = $1`,
        [
          String(ownerUserId),
          tenant.portalClientId,
          tenant.portalJobId,
          tenant.branding.businessName
        ]
      );
    } else {
      await pool.query(
        `UPDATE users
         SET portal_files_access_granted = true,
             portal_permissions_access = true,
             updated_at = NOW()
         WHERE CAST(id AS text) = $1`,
        [String(ownerUserId)]
      );
    }

    const updated = await pool.query(
      `UPDATE saas_tenant_instances
       SET setup_status = 'ready',
           setup_completed_at = NOW(),
           provisioning_error = '',
           updated_at = NOW()
       WHERE owner_user_id = $1
       RETURNING *`,
      [String(ownerUserId)]
    );
    return serializeTenantRow(updated.rows[0]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await pool.query(
      `UPDATE saas_tenant_instances
       SET setup_status = 'failed', provisioning_error = $2, updated_at = NOW()
       WHERE owner_user_id = $1`,
      [String(ownerUserId), message.slice(0, 2000)]
    );
    throw error;
  }
}

module.exports = {
  normalizeBranding,
  serializeTenantRow,
  loadTenantByOwner,
  loadTenantById,
  loadTenantByPortalSlug,
  upsertTenantDraft,
  provisionTenantInstance,
  putFolderMarkers,
  buildTenantSkeletonKeys
};
