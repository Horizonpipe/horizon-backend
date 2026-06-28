'use strict';

require('dotenv').config();
const pg = require('pg');
const { applySaasTenantOwnerPrivileges } = require('../lib/saas-tenant-owner');
const { upsertTenantOwnerAuthSnapshot } = require('../lib/saas-tenant-auth-store');
const { slugifyTenantName } = require('../lib/saas-tenant-paths');

async function main() {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const owners = await pool.query(
    `SELECT t.owner_user_id, t.branding,
            u.id, u.username, u.email, u.display_name
     FROM saas_tenant_instances t
     JOIN users u ON CAST(u.id AS text) = CAST(t.owner_user_id AS text)`
  );
  let updated = 0;
  for (const row of owners.rows) {
    const userId = row.owner_user_id;
    const result = await applySaasTenantOwnerPrivileges(pool, userId);
    if (result.updated) updated += 1;
    const branding = row.branding && typeof row.branding === 'object' ? row.branding : {};
    const slug = slugifyTenantName(branding.businessName || row.company || '');
    if (slug) {
      await upsertTenantOwnerAuthSnapshot(slug, row);
    }
    console.log('owner', userId, row.email || row.username, result.updated ? 'elevated' : result.reason || 'skip');
  }
  console.log(`Done. ${updated}/${owners.rowCount} tenant owners elevated to superadmin.`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
