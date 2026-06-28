import 'dotenv/config';
import pg from 'pg';

const email = (process.argv[2] || 'hstboot+1@gmail.com').trim().toLowerCase();
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const userRes = await pool.query(
  `SELECT id, username, email FROM users
   WHERE LOWER(TRIM(email)) = $1 OR LOWER(TRIM(username)) = $1
   LIMIT 1`,
  [email]
);
const user = userRes.rows[0];
if (!user) {
  console.error('User not found:', email);
  process.exit(1);
}

const upd = await pool.query(
  `UPDATE saas_tenant_instances
   SET subscription_status = 'active', updated_at = NOW()
   WHERE owner_user_id = $1
   RETURNING id, company_id, owner_user_id, subscription_status, setup_status`,
  [String(user.id)]
);

if (!upd.rowCount) {
  console.error('No tenant row for user', user.id, user.username);
  process.exit(1);
}

console.log('UPDATED', JSON.stringify(upd.rows[0], null, 2));
await pool.end();
