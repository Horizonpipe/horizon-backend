require('dotenv').config({ path: '/opt/horizon/horizon-backend/.env' });
const pg = require('pg');
const crypto = require('crypto');

(async () => {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const u = await pool.query(`SELECT id FROM users WHERE username = 'Mike Strickland' LIMIT 1`);
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query(
    `INSERT INTO auth_sessions (token, user_id, keep_session, expires_at) VALUES ($1, $2, true, NOW() + INTERVAL '7 days')`,
    [token, String(u.rows[0].id)]
  );
  for (const jobId of ['8', '2']) {
    const r = await fetch(`http://127.0.0.1:3000/api/files/tree?clientId=portal-users&jobId=${jobId}`, {
      headers: { Authorization: `Bearer ${token}`, Host: 'pipeshare.live' }
    });
    const t = await r.text();
    let parsed;
    try {
      parsed = JSON.parse(t);
    } catch {
      parsed = null;
    }
    console.log(
      JSON.stringify({
        jobId,
        status: r.status,
        bytes: t.length,
        code: parsed?.code,
        error: parsed?.error,
        folders: parsed?.folders?.length,
        files: parsed?.files?.length
      })
    );
  }
  await pool.query('DELETE FROM auth_sessions WHERE token = $1', [token]);
  await pool.end();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
