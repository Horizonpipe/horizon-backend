import 'dotenv/config';
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const companies = await pool.query(`SELECT id, name, slug, created_at FROM companies ORDER BY created_at DESC LIMIT 10`);
console.log('COMPANIES', JSON.stringify(companies.rows, null, 2));
const allTenants = await pool.query(
  `SELECT st.id, st.subscription_status, st.setup_status, st.owner_user_id, u.email, u.username, st.created_at
   FROM saas_tenant_instances st LEFT JOIN users u ON CAST(u.id AS text) = st.owner_user_id
   ORDER BY st.created_at DESC`
);
console.log('ALL TENANTS', JSON.stringify(allTenants.rows, null, 2));
await pool.end();
