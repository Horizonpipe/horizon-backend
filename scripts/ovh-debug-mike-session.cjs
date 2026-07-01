require('dotenv').config({ path: '/opt/horizon/horizon-backend/.env' });
const pg = require('pg');
const crypto = require('crypto');

async function issueSession(pool, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query(
    `INSERT INTO auth_sessions (token, user_id, keep_session, expires_at)
     VALUES ($1, $2, true, NOW() + INTERVAL '7 days')
     ON CONFLICT (token) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
    [token, String(userId)]
  );
  return token;
}

(async () => {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const u = await pool.query(`SELECT * FROM users WHERE username = 'Mike Strickland' LIMIT 1`);
  const row = u.rows[0];
  if (!row) throw new Error('Mike not found');
  console.log('DB', {
    portal_files_client_id: row.portal_files_client_id,
    portal_files_job_id: row.portal_files_job_id,
    portal_files_access_granted: row.portal_files_access_granted,
    is_admin: row.is_admin
  });
  const token = await issueSession(pool, row.id);
  const fetch = globalThis.fetch;
  const headers = {
    Authorization: `Bearer ${token}`,
    Host: 'pipeshare.live',
    'X-Forwarded-Host': 'pipeshare.live'
  };
  const sessionRes = await fetch('http://127.0.0.1:3000/session', { headers });
  const session = await sessionRes.json();
  const user = session.user || {};
  console.log('SESSION', JSON.stringify({
    status: sessionRes.status,
    capabilities: session.capabilities,
    portalFilesClientId: user.portalFilesClientId,
    portalFilesJobId: user.portalFilesJobId,
    portalFilesAccessGranted: user.portalFilesAccessGranted,
    isAdmin: user.isAdmin,
    capabilities: user.capabilities,
    portalScopes: user.portalScopes
  }, null, 2));
  for (const q of [
    'clientId=portal-users&jobId=8',
    'clientId=tenant-mike-strickland&jobId=1',
    'clientId=tenant-mike-strickland&jobId=8',
    'clientId=&jobId=8'
  ]) {
    const r = await fetch(`http://127.0.0.1:3000/api/files/tree?${q}`, { headers });
    const t = await r.text();
    let d;
    try {
      d = JSON.parse(t);
    } catch {
      d = { raw: t.slice(0, 200) };
    }
    console.log('TREE', q, {
      status: r.status,
      folders: Array.isArray(d.folders) ? d.folders.length : null,
      files: Array.isArray(d.files) ? d.files.length : null,
      error: d.error,
      code: d.code
    });
  }
  await pool.query('DELETE FROM auth_sessions WHERE token = $1', [token]);
  await pool.end();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
