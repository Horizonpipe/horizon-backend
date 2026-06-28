'use strict';

require('dotenv').config();
const pg = require('pg');
const {
  loadTenantByOwner,
  putFolderMarkers,
  buildTenantSkeletonKeys,
  serializeTenantRow
} = require('../tenant-provisioning.service');
const { buildTenantWasabiRoot, slugifyTenantName } = require('../lib/saas-tenant-paths');
const { getSaasWasabiClient, saasWasabiBucket, saasVirtualboxConfigured } = require('../lib/saas-virtualbox-config');
const { seedTenantAuthSnapshot } = require('../lib/saas-tenant-auth-store');

const email = (process.argv[2] || 'hstboot+1@gmail.com').trim().toLowerCase();

async function main() {
  if (!saasVirtualboxConfigured()) {
    console.error('Set SAAS_WASABI_BUCKET (and WASABI credentials) before running.');
    process.exit(1);
  }

  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const user = await pool.query(
    `SELECT id, username, email, display_name FROM users WHERE LOWER(COALESCE(email, username, '')) = $1 LIMIT 1`,
    [email]
  );
  if (!user.rows[0]) {
    console.error('User not found:', email);
    process.exit(1);
  }
  const ownerId = String(user.rows[0].id);
  let tenant = await loadTenantByOwner(pool, ownerId);
  if (!tenant) {
    console.error('No tenant for', email);
    process.exit(1);
  }

  const slug = slugifyTenantName(tenant.branding.businessName || 'techpipe');
  const newRoot = buildTenantWasabiRoot(slug);
  const client = getSaasWasabiClient();
  const bucket = saasWasabiBucket();

  console.log('Migrating tenant to SaaS virtualbox bucket:', bucket, 'root:', newRoot);

  const updated = await pool.query(
    `UPDATE saas_tenant_instances
     SET wasabi_root_prefix = $2,
         setup_status = 'provisioning',
         provisioning_error = '',
         updated_at = NOW()
     WHERE owner_user_id = $1
     RETURNING *`,
    [ownerId, newRoot]
  );
  tenant = serializeTenantRow(updated.rows[0]);

  const keys = buildTenantSkeletonKeys(slug);
  const markers = await putFolderMarkers(client, bucket, keys);
  console.log('Folder markers:', markers);

  await seedTenantAuthSnapshot(slug, user.rows[0]);

  await pool.query(
    `UPDATE saas_tenant_instances
     SET setup_status = 'ready',
         setup_completed_at = COALESCE(setup_completed_at, NOW()),
         provisioning_error = '',
         updated_at = NOW()
     WHERE owner_user_id = $1`,
    [ownerId]
  );

  tenant = await loadTenantByOwner(pool, ownerId);
  console.log(
    JSON.stringify(
      {
        email,
        bucket,
        wasabiRootPrefix: tenant.wasabiRootPrefix,
        portalClientId: tenant.portalClientId,
        accessUrls: tenant.accessUrls,
        setupStatus: tenant.setupStatus
      },
      null,
      2
    )
  );
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
