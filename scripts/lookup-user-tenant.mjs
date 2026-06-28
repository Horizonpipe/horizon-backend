import 'dotenv/config';
import pg from 'pg';

const email = (process.argv[2] || 'hstboot+1@gmail.com').trim().toLowerCase();
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const userRes = await pool.query(
  `SELECT id, username, email, email_verified, portal_files_access_granted, self_signup
   FROM users
   WHERE LOWER(TRIM(email)) = $1 OR LOWER(TRIM(username)) = $1
   LIMIT 1`,
  [email]
);
console.log('USER', JSON.stringify(userRes.rows[0] || null, null, 2));

if (userRes.rows[0]) {
  const tenantRes = await pool.query(
    `SELECT id, company_id, owner_user_id, subscription_status, setup_status
     FROM saas_tenant_instances
     WHERE owner_user_id = $1
     LIMIT 1`,
    [String(userRes.rows[0].id)]
  );
  console.log('TENANT', JSON.stringify(tenantRes.rows[0] || null, null, 2));
}

await pool.end();
