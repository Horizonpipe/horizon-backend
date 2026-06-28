'use strict';

require('dotenv').config();
const pg = require('pg');
const { serializeTenantRow } = require('../tenant-provisioning.service');

const email = (process.argv[2] || 'hstboot+1@gmail.com').trim().toLowerCase();
const businessName = (process.argv[3] || 'Techpipe').trim();

async function main() {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const user = await pool.query(
    `SELECT id, email FROM users WHERE LOWER(COALESCE(email, username, '')) = $1 LIMIT 1`,
    [email]
  );
  if (!user.rows[0]) {
    console.error('User not found:', email);
    process.exit(1);
  }
  const ownerId = String(user.rows[0].id);

  const existing = await pool.query(
    `SELECT * FROM saas_tenant_instances WHERE owner_user_id = $1 LIMIT 1`,
    [ownerId]
  );
  if (!existing.rows[0]) {
    console.error('No tenant for user', email);
    process.exit(1);
  }

  const branding = {
    ...(existing.rows[0].branding || {}),
    businessName,
    websiteUrl: ''
  };

  const updated = await pool.query(
    `UPDATE saas_tenant_instances
     SET website_url = '',
         branding = $2::jsonb,
         updated_at = NOW()
     WHERE owner_user_id = $1
     RETURNING *`,
    [ownerId, JSON.stringify(branding)]
  );

  const companyId = updated.rows[0].company_id;
  if (companyId) {
    await pool.query(`UPDATE companies SET name = $2 WHERE id = $1`, [companyId, businessName]);
  }

  const tenant = serializeTenantRow(updated.rows[0]);
  console.log(
    JSON.stringify(
      {
        email,
        ownerUserId: ownerId,
        businessName: tenant.branding.businessName,
        setupStatus: tenant.setupStatus,
        subscriptionStatus: tenant.subscriptionStatus,
        accessUrls: tenant.accessUrls
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
