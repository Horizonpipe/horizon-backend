const express = require('express');
const cors = require('cors');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const initSqlJs = require('sql.js');
const { createWorker } = require('tesseract.js');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';
const FRONTEND_ORIGINS = (process.env.CORS_ORIGINS || 'https://horizon-frontend.onrender.com,http://localhost:3000,http://127.0.0.1:3000')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const SESSION_TTL_MS = 15 * 60 * 1000;

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required.');
  process.exit(1);
}

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
});

app.use(cors({
  origin(origin, callback) {
    if (!origin || FRONTEND_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS blocked origin: ${origin}`));
  },
  credentials: true
}));

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.set('trust proxy', 1);
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    maxAge: SESSION_TTL_MS
  }
}));

const storage = multer.diskStorage({
  destination: async (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: async (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}_${crypto.randomUUID()}_${safe}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 40 * 1024 * 1024 } });

function uid() { return crypto.randomUUID(); }
function nowIso() { return new Date().toISOString(); }
function safeJsonParse(value, fallback) {
  try { return typeof value === 'string' ? JSON.parse(value) : (value ?? fallback); }
  catch { return fallback; }
}
function normalizeStatus(value) {
  const v = String(value || '').trim().toLowerCase();
  if (['complete','video complete'].includes(v)) return 'complete';
  if (['failed','video failed'].includes(v)) return 'failed';
  if (['rerun','rerun queue','rerun queued','needs rerun'].includes(v)) return 'rerun';
  if (['revideoed','rerun-videoed','rerun videoed'].includes(v)) return 'rerun-videoed';
  if (['rerun-failed','rerun failed'].includes(v)) return 'rerun-failed';
  if (['ni','not installed','could not locate','could-not-locate'].includes(v)) return 'could-not-locate';
  if (['jetted'].includes(v)) return 'jetted';
  return 'neutral';
}
function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    is_admin: !!row.is_admin,
    can_camera: !!row.can_camera,
    can_vac: !!row.can_vac,
    must_change_password: !!row.must_change_password
  };
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Authentication required.' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Authentication required.' });
  if (!req.session.user.is_admin) return res.status(403).json({ error: 'Admin access required.' });
  next();
}
function requireMike(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Authentication required.' });
  const username = String(req.session.user.username || '').trim().toLowerCase();
  if (!['mike strickland', 'mik'].includes(username)) return res.status(403).json({ error: 'Mike Strickland access only.' });
  next();
}
function allowSegmentWrite(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Authentication required.' });
  const user = req.session.user;
  if (user.is_admin || user.can_camera || user.can_vac) return next();
  return res.status(403).json({ error: 'Segment edit access required.' });
}
function formatUploadFile(req, file) {
  const base = `${req.protocol}://${req.get('host')}`;
  return {
    name: file.originalname,
    original_name: file.originalname,
    filename: file.filename,
    mime: file.mimetype,
    size: file.size,
    url: `${base}/uploads/${file.filename}`,
    uploaded_at: nowIso()
  };
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      can_camera BOOLEAN NOT NULL DEFAULT TRUE,
      can_vac BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS jobsites (
      id TEXT PRIMARY KEY,
      client TEXT NOT NULL,
      city TEXT NOT NULL,
      street TEXT DEFAULT '',
      jobsite TEXT NOT NULL,
      record_date DATE NOT NULL DEFAULT CURRENT_DATE,
      contact_name TEXT DEFAULT '',
      contact_phone TEXT DEFAULT '',
      contact_email TEXT DEFAULT '',
      contact_notes TEXT DEFAULT '',
      drive_url TEXT DEFAULT '',
      create_storm BOOLEAN NOT NULL DEFAULT TRUE,
      create_sanitary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_jobsites_lookup ON jobsites (LOWER(client), LOWER(city), LOWER(jobsite));

    CREATE TABLE IF NOT EXISTS segments (
      id TEXT PRIMARY KEY,
      jobsite_id TEXT NOT NULL REFERENCES jobsites(id) ON DELETE CASCADE,
      system_type TEXT NOT NULL,
      reference TEXT NOT NULL,
      upstream TEXT DEFAULT '',
      downstream TEXT DEFAULT '',
      dia TEXT DEFAULT '',
      material TEXT DEFAULT '',
      length NUMERIC(12,3) DEFAULT 0,
      footage NUMERIC(12,3) DEFAULT 0,
      latest_status TEXT NOT NULL DEFAULT 'neutral',
      versions JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(jobsite_id, system_type, reference)
    );

    CREATE TABLE IF NOT EXISTS pricing_rates (
      dia TEXT PRIMARY KEY,
      rate NUMERIC(12,2) NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS daily_reports (
      id TEXT PRIMARY KEY,
      report_date DATE NOT NULL,
      title TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_by TEXT NOT NULL,
      files JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS jobsite_assets (
      id TEXT PRIMARY KEY,
      client TEXT NOT NULL,
      city TEXT NOT NULL,
      street TEXT DEFAULT '',
      jobsite TEXT NOT NULL,
      contact_name TEXT DEFAULT '',
      contact_phone TEXT DEFAULT '',
      contact_email TEXT DEFAULT '',
      drive_url TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      files JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const existingCount = await pool.query('SELECT COUNT(*)::int AS count FROM app_users');
  if (existingCount.rows[0].count === 0) {
    const defaults = [
      { username: 'Tyler Clark', password: '1234', is_admin: true, can_camera: true, can_vac: true },
      { username: 'Nick Krull', password: '1234', is_admin: true, can_camera: true, can_vac: true },
      { username: 'Mike Strickland', password: '1234', is_admin: true, can_camera: true, can_vac: true }
    ];
    for (const item of defaults) {
      const hash = await bcrypt.hash(item.password, 10);
      await pool.query(`
        INSERT INTO app_users (id, username, password_hash, must_change_password, is_admin, can_camera, can_vac)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
      `, [uid(), item.username, hash, true, item.is_admin, item.can_camera, item.can_vac]);
    }
  }
}

async function findUserByUsername(username) {
  const result = await pool.query('SELECT * FROM app_users WHERE LOWER(username)=LOWER($1) LIMIT 1', [username]);
  return result.rows[0] || null;
}

async function hydrateRecords() {
  const jobsResult = await pool.query('SELECT * FROM jobsites ORDER BY LOWER(client), LOWER(city), LOWER(jobsite), record_date DESC');
  const segmentsResult = await pool.query('SELECT * FROM segments ORDER BY LOWER(reference)');
  const segmentMap = new Map();
  for (const row of segmentsResult.rows) {
    const segment = {
      id: row.id,
      reference: row.reference,
      upstream: row.upstream || '',
      downstream: row.downstream || '',
      dia: row.dia || '',
      material: row.material || '',
      length: row.length == null ? '' : String(row.length),
      footage: row.footage == null ? '' : String(row.footage),
      status: normalizeStatus(row.latest_status),
      selectedVersionId: null,
      versions: safeJsonParse(row.versions, []).map((v) => ({
        id: v.id || uid(),
        createdAt: v.createdAt || v.created_at || row.updated_at,
        savedBy: v.savedBy || v.saved_by || 'System',
        status: normalizeStatus(v.status),
        notes: v.notes || '',
        failureReason: v.failureReason || v.failure_reason || '',
        recordedDate: String(v.recordedDate || v.recorded_date || '').slice(0, 10),
        displayStatus: v.displayStatus || v.display_status || ''
      }))
    };
    segment.selectedVersionId = segment.versions[segment.versions.length - 1]?.id || null;
    if (!segmentMap.has(row.jobsite_id)) segmentMap.set(row.jobsite_id, { storm: [], sanitary: [] });
    const systems = segmentMap.get(row.jobsite_id);
    if (!systems[row.system_type]) systems[row.system_type] = [];
    systems[row.system_type].push(segment);
  }
  return jobsResult.rows.map((job) => ({
    id: job.id,
    client: job.client,
    city: job.city,
    street: job.street || '',
    jobsite: job.jobsite,
    record_date: String(job.record_date || '').slice(0, 10),
    contact_name: job.contact_name || '',
    contact_phone: job.contact_phone || '',
    contact_email: job.contact_email || '',
    contact_notes: job.contact_notes || '',
    drive_url: job.drive_url || '',
    createStorm: !!job.create_storm,
    createSanitary: !!job.create_sanitary,
    systems: segmentMap.get(job.id) || { storm: [], sanitary: [] }
  }));
}

async function ensureTargetJobsite({ client, city, jobsite, street = '' }) {
  const existing = await pool.query(
    'SELECT * FROM jobsites WHERE LOWER(client)=LOWER($1) AND LOWER(city)=LOWER($2) AND LOWER(jobsite)=LOWER($3) LIMIT 1',
    [client, city, jobsite]
  );
  if (existing.rows[0]) return existing.rows[0];
  const id = uid();
  const result = await pool.query(`
    INSERT INTO jobsites (id, client, city, street, jobsite, record_date, create_storm, create_sanitary)
    VALUES ($1,$2,$3,$4,$5,CURRENT_DATE,TRUE,TRUE)
    RETURNING *
  `, [id, client, city, street || '', jobsite]);
  return result.rows[0];
}

async function segmentExists(jobsiteId, systemType, reference) {
  const result = await pool.query(
    'SELECT id FROM segments WHERE jobsite_id=$1 AND system_type=$2 AND LOWER(reference)=LOWER($3) LIMIT 1',
    [jobsiteId, systemType, reference]
  );
  return !!result.rows[0];
}

function buildVersion({ status, notes = '', failureReason = '', recordedDate = '', savedBy = 'System' }) {
  return {
    id: uid(),
    createdAt: nowIso(),
    savedBy,
    status: normalizeStatus(status),
    displayStatus: normalizeStatus(status),
    notes,
    failureReason,
    recordedDate: String(recordedDate || nowIso().slice(0, 10)).slice(0, 10)
  };
}

async function writeSegment(jobsiteId, payload, saveBy) {
  const versions = Array.isArray(payload.versions) && payload.versions.length
    ? payload.versions
    : [buildVersion({ status: payload.status || 'neutral', notes: payload.notes || '', failureReason: payload.failureReason || '', recordedDate: payload.recordedDate || '', savedBy: saveBy || 'System' })];
  const latest = versions[versions.length - 1];
  return pool.query(`
    INSERT INTO segments (id, jobsite_id, system_type, reference, upstream, downstream, dia, material, length, footage, latest_status, versions)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
    ON CONFLICT (jobsite_id, system_type, reference)
    DO UPDATE SET upstream=EXCLUDED.upstream, downstream=EXCLUDED.downstream, dia=EXCLUDED.dia, material=EXCLUDED.material,
      length=EXCLUDED.length, footage=EXCLUDED.footage, latest_status=EXCLUDED.latest_status, versions=EXCLUDED.versions,
      updated_at=NOW()
  `, [
    payload.id || uid(),
    jobsiteId,
    payload.system || payload.system_type || 'storm',
    payload.reference,
    payload.upstream || '',
    payload.downstream || '',
    payload.dia || '',
    payload.material || '',
    Number(payload.length || payload.footage || 0),
    Number(payload.footage || payload.length || 0),
    normalizeStatus(latest.status || payload.status || 'neutral'),
    JSON.stringify(versions)
  ]);
}

async function parseDb3(filePath) {
  const SQL = await initSqlJs({ locateFile: (file) => require.resolve(`sql.js/dist/${file}`) });
  const buffer = await fsp.readFile(filePath);
  const db = new SQL.Database(buffer);
  const tables = new Set(db.exec("SELECT name FROM sqlite_master WHERE type='table'")[0]?.values?.map((row) => row[0]) || []);
  if (!tables.has('SECTION')) throw new Error('SECTION table not found in DB3 file.');
  const query = `
    SELECT
      s.OBJ_Key AS reference,
      COALESCE(si.INS_InspectedLength, s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(s.OBJ_FromNode_REF, '') AS upstream,
      COALESCE(s.OBJ_ToNode_REF, '') AS downstream,
      COALESCE(s.OBJ_Material, '') AS material,
      COALESCE(s.OBJ_Shape, '') AS shape,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2
    FROM SECTION s
    LEFT JOIN SECINSP si ON si.OBJ_ID = s.OBJ_ID
  `;
  const result = db.exec(query);
  const rows = [];
  if (!result[0]) return rows;
  const columns = result[0].columns;
  for (const values of result[0].values) {
    const row = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
    const shape = normalizeShape(row.shape, row.size1, row.size2);
    rows.push({
      reference: String(row.reference || '').trim(),
      length: Number(row.length || 0).toFixed(3),
      city: String(row.city || '').trim(),
      street: String(row.street || '').trim(),
      upstream: String(row.upstream || '').trim(),
      downstream: String(row.downstream || '').trim(),
      material: normalizeMaterial(row.material),
      shape: shape.shape,
      dia: shape.dia,
      duplicate: false
    });
  }
  return rows.filter((row) => row.reference);
}

function normalizeMaterial(raw) {
  const v = String(raw || '').trim();
  const map = {
    PE: 'Polyethylene',
    PVC: 'Polyvinyl Chloride',
    PP: 'Polypropylene',
    RCP: 'Reinforced Concrete Pipe',
    VCP: 'Vitrified Clay Pipe'
  };
  return map[v] || v;
}

function normalizeShape(shape, size1, size2) {
  const s = String(shape || '').trim().toUpperCase();
  const a = String(size1 || '').trim();
  const b = String(size2 || '').trim();
  if (!s && !a && !b) return { shape: '', dia: '' };
  if (b && Number(b) > 0) return { shape: s === 'O' ? 'Oval' : 'Shape', dia: `${a}/${b}` };
  const label = s === 'C' ? 'Circular' : s === 'O' ? 'Oval' : s;
  return { shape: label, dia: a };
}

async function parseImageFile(filePath) {
  const worker = await createWorker('eng');
  try {
    const out = await worker.recognize(filePath);
    const text = out.data.text || '';
    const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const rows = [];
    const rowPattern = /^([A-Z0-9-]+)\s+([0-9]+(?:\.[0-9]+)?)\s+(.+)$/i;
    for (const line of lines) {
      const match = line.match(rowPattern);
      if (!match) continue;
      rows.push({
        reference: match[1].trim(),
        length: Number(match[2]).toFixed(3),
        city: '',
        street: '',
        upstream: '',
        downstream: '',
        material: '',
        shape: '',
        dia: '',
        duplicate: false,
        raw_line: line
      });
    }
    return rows;
  } finally {
    await worker.terminate();
  }
}

app.get('/health', async (req, res) => {
  res.json({ ok: true, now: nowIso() });
});

app.get('/session', async (req, res) => {
  if (!req.session.user) return res.status(200).json({ authenticated: false });
  res.json({ authenticated: true, user: req.session.user });
});

app.post('/session/logout', requireAuth, async (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.post('/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  const user = await findUserByUsername(username);
  if (!user) return res.status(401).json({ error: 'Invalid username or password.' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid username or password.' });
  req.session.cookie.maxAge = SESSION_TTL_MS;
  req.session.user = publicUser(user);
  res.json({ ok: true, user: req.session.user });
});

app.post('/change-password', requireAuth, async (req, res) => {
  const targetUsername = String(req.body.username || req.session.user.username || '').trim();
  const newPassword = String(req.body.newPassword || '').trim();
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'New password must be at least 4 characters.' });
  if (!req.session.user.is_admin && targetUsername.toLowerCase() !== String(req.session.user.username || '').toLowerCase()) {
    return res.status(403).json({ error: 'You can only change your own password.' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE app_users SET password_hash=$1, must_change_password=FALSE, updated_at=NOW() WHERE LOWER(username)=LOWER($2)', [hash, targetUsername]);
  if (targetUsername.toLowerCase() === String(req.session.user.username || '').toLowerCase()) {
    const updated = await findUserByUsername(targetUsername);
    req.session.user = publicUser(updated);
  }
  res.json({ ok: true });
});

app.get('/users', async (req, res) => {
  const result = await pool.query('SELECT id, username, is_admin, can_camera, can_vac, must_change_password FROM app_users ORDER BY LOWER(username)');
  res.json({ users: result.rows });
});

app.post('/create-user', requireAdmin, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '1234');
  if (!username) return res.status(400).json({ error: 'Username is required.' });
  const existing = await findUserByUsername(username);
  if (existing) return res.status(409).json({ error: 'That username already exists.' });
  const hash = await bcrypt.hash(password, 10);
  const row = await pool.query(`
    INSERT INTO app_users (id, username, password_hash, must_change_password, is_admin, can_camera, can_vac)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    RETURNING id, username, is_admin, can_camera, can_vac, must_change_password
  `, [uid(), username, hash, password === '1234', !!req.body.is_admin, !!req.body.can_camera, !!req.body.can_vac]);
  res.status(201).json({ user: row.rows[0] });
});

app.put('/users/:id', requireAdmin, async (req, res) => {
  const row = await pool.query(`
    UPDATE app_users SET is_admin=$1, can_camera=$2, can_vac=$3, updated_at=NOW()
    WHERE id=$4 RETURNING id, username, is_admin, can_camera, can_vac, must_change_password
  `, [!!req.body.is_admin, !!req.body.can_camera, !!req.body.can_vac, req.params.id]);
  if (!row.rows[0]) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: row.rows[0] });
});

app.get('/records', requireAuth, async (req, res) => {
  const records = await hydrateRecords();
  res.json({ records });
});

app.post('/records', requireAdmin, async (req, res) => {
  const id = uid();
  const client = String(req.body.client || '').trim();
  const city = String(req.body.city || '').trim();
  const jobsite = String(req.body.jobsite || '').trim();
  if (!client || !city || !jobsite) return res.status(400).json({ error: 'Client, city, and jobsite are required.' });
  const recordDate = String(req.body.record_date || req.body.date || '').slice(0, 10) || nowIso().slice(0, 10);
  await pool.query(`
    INSERT INTO jobsites (id, client, city, street, jobsite, record_date, create_storm, create_sanitary)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
  `, [id, client, city, String(req.body.street || ''), jobsite, recordDate, !!req.body.createStorm, !!req.body.createSanitary]);
  res.status(201).json({ ok: true, id });
});

app.delete('/records/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM jobsites WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.delete('/clients/:client', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM jobsites WHERE LOWER(client)=LOWER($1)', [req.params.client]);
  res.json({ ok: true });
});

app.post('/records/:id/segments', allowSegmentWrite, async (req, res) => {
  const recordId = req.params.id;
  const record = await pool.query('SELECT * FROM jobsites WHERE id=$1', [recordId]);
  if (!record.rows[0]) return res.status(404).json({ error: 'Jobsite not found.' });
  if (!req.body.reference) return res.status(400).json({ error: 'Segment reference is required.' });
  await writeSegment(recordId, { ...req.body, id: uid() }, req.session.user.username);
  res.status(201).json({ ok: true });
});

app.post('/records/:id/segments/bulk', requireAdmin, async (req, res) => {
  const recordId = req.params.id;
  const list = Array.isArray(req.body.segments) ? req.body.segments : [];
  for (const segment of list) {
    if (!segment.reference) continue;
    await writeSegment(recordId, { ...segment, id: uid() }, req.session.user.username);
  }
  res.json({ ok: true, count: list.length });
});

app.put('/records/:recordId/segments/:segmentId', allowSegmentWrite, async (req, res) => {
  const row = await pool.query('SELECT * FROM segments WHERE id=$1 AND jobsite_id=$2', [req.params.segmentId, req.params.recordId]);
  if (!row.rows[0]) return res.status(404).json({ error: 'Segment not found.' });
  const segment = row.rows[0];
  const recordPatch = req.body.recordPatch || {};
  const segmentPatch = req.body.segmentPatch || {};
  const versionPatch = req.body.versionPatch || {};
  if (Object.keys(recordPatch).length) {
    const record = await pool.query(`
      UPDATE jobsites SET jobsite=COALESCE(NULLIF($1,''), jobsite), updated_at=NOW() WHERE id=$2
    `, [recordPatch.jobsite || '', req.params.recordId]);
  }
  const versions = safeJsonParse(segment.versions, []);
  if (Object.keys(versionPatch).length) {
    const latest = versions[versions.length - 1] || buildVersion({ status: segment.latest_status, savedBy: req.session.user.username });
    const nextVersion = {
      ...latest,
      id: uid(),
      createdAt: nowIso(),
      savedBy: req.body.saveBy || req.session.user.username,
      status: normalizeStatus(versionPatch.status || latest.status),
      notes: versionPatch.notes ?? latest.notes ?? '',
      failureReason: versionPatch.failureReason ?? latest.failureReason ?? '',
      recordedDate: String(versionPatch.recordedDate || latest.recordedDate || nowIso().slice(0, 10)).slice(0, 10)
    };
    versions.push(nextVersion);
  }
  await pool.query(`
    UPDATE segments SET
      reference=COALESCE(NULLIF($1,''), reference),
      upstream=COALESCE($2, upstream),
      downstream=COALESCE($3, downstream),
      dia=COALESCE($4, dia),
      material=COALESCE($5, material),
      length=COALESCE($6, length),
      footage=COALESCE($7, footage),
      latest_status=$8,
      versions=$9::jsonb,
      updated_at=NOW()
    WHERE id=$10 AND jobsite_id=$11
  `, [
    segmentPatch.reference ?? '',
    segmentPatch.upstream ?? segment.upstream,
    segmentPatch.downstream ?? segment.downstream,
    segmentPatch.dia ?? segment.dia,
    segmentPatch.material ?? segment.material,
    segmentPatch.length === '' ? 0 : (segmentPatch.length ?? segment.length),
    segmentPatch.footage === '' ? (segmentPatch.length === '' ? 0 : segmentPatch.length ?? segment.footage) : (segmentPatch.footage ?? segment.footage),
    normalizeStatus((versions[versions.length - 1] || {}).status || segment.latest_status),
    JSON.stringify(versions),
    req.params.segmentId,
    req.params.recordId
  ]);
  res.json({ ok: true });
});

app.delete('/records/:recordId/segments/:segmentId', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM segments WHERE id=$1 AND jobsite_id=$2', [req.params.segmentId, req.params.recordId]);
  res.json({ ok: true });
});

app.post('/records/:recordId/segments/:segmentId/move', requireAdmin, async (req, res) => {
  const source = await pool.query('SELECT * FROM segments WHERE id=$1 AND jobsite_id=$2', [req.params.segmentId, req.params.recordId]);
  if (!source.rows[0]) return res.status(404).json({ error: 'Segment not found.' });
  const targetClient = String(req.body.targetClient || '').trim();
  const targetCity = String(req.body.targetCity || '').trim();
  const targetJobsite = String(req.body.targetJobsite || '').trim();
  const targetSystem = String(req.body.targetSystem || 'storm').trim();
  if (!targetClient || !targetCity || !targetJobsite) return res.status(400).json({ error: 'Target client, city, and jobsite are required.' });
  const target = await ensureTargetJobsite({ client: targetClient, city: targetCity, jobsite: targetJobsite, street: '' });
  const dup = await segmentExists(target.id, targetSystem, source.rows[0].reference);
  if (dup) return res.status(409).json({ error: 'That target already has this segment reference.' });
  await pool.query('UPDATE segments SET jobsite_id=$1, system_type=$2, updated_at=NOW() WHERE id=$3', [target.id, targetSystem, req.params.segmentId]);
  res.json({ ok: true });
});

app.get('/pricing-rates', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT dia, rate FROM pricing_rates ORDER BY dia');
  res.json({ rates: result.rows });
});

app.put('/pricing-rates/:dia', requireAdmin, async (req, res) => {
  const dia = String(req.params.dia || '').trim();
  const rate = Number(req.body.rate || 0);
  if (!dia) return res.status(400).json({ error: 'DIA is required.' });
  await pool.query(`
    INSERT INTO pricing_rates (dia, rate, updated_at) VALUES ($1,$2,NOW())
    ON CONFLICT (dia) DO UPDATE SET rate=EXCLUDED.rate, updated_at=NOW()
  `, [dia, rate]);
  res.json({ ok: true });
});

app.delete('/pricing-rates/:dia', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM pricing_rates WHERE dia=$1', [req.params.dia]);
  res.json({ ok: true });
});

app.get('/daily-reports', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM daily_reports ORDER BY report_date DESC, created_at DESC');
  res.json({ reports: result.rows.map((row) => ({ ...row, files: safeJsonParse(row.files, []) })) });
});

app.post('/daily-reports', requireAdmin, upload.array('files', 12), async (req, res) => {
  const files = (req.files || []).map((file) => formatUploadFile(req, file));
  const row = await pool.query(`
    INSERT INTO daily_reports (id, report_date, title, notes, created_by, files)
    VALUES ($1,$2,$3,$4,$5,$6::jsonb)
    RETURNING *
  `, [uid(), String(req.body.report_date || '').slice(0, 10) || nowIso().slice(0, 10), req.body.title || '', req.body.notes || '', req.session.user.username, JSON.stringify(files)]);
  res.status(201).json({ report: { ...row.rows[0], files } });
});

app.delete('/daily-reports/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM daily_reports WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.get('/jobsite-assets', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM jobsite_assets ORDER BY LOWER(client), LOWER(city), LOWER(jobsite), created_at DESC');
  res.json({ assets: result.rows.map((row) => ({ ...row, files: safeJsonParse(row.files, []) })) });
});

app.post('/jobsite-assets', requireAdmin, upload.array('files', 20), async (req, res) => {
  const files = (req.files || []).map((file) => formatUploadFile(req, file));
  const row = await pool.query(`
    INSERT INTO jobsite_assets (id, client, city, street, jobsite, contact_name, contact_phone, contact_email, drive_url, notes, files)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
    RETURNING *
  `, [uid(), req.body.assetClient || '', req.body.assetCity || '', '', req.body.assetJobsite || '', req.body.assetContactName || '', req.body.assetContactPhone || '', req.body.assetContactEmail || '', req.body.assetDriveUrl || '', req.body.assetNotes || '', JSON.stringify(files)]);
  res.status(201).json({ asset: { ...row.rows[0], files } });
});

app.delete('/jobsite-assets/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM jobsite_assets WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.post('/imports/wincan/preview', requireMike, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Import file is required.' });
  const ext = path.extname(req.file.originalname).toLowerCase();
  const sourceKind = ['.db3', '.sqlite', '.db'].includes(ext) ? 'DB3' : 'SCREENSHOT';
  let rows = [];
  if (sourceKind === 'DB3') rows = await parseDb3(req.file.path);
  else rows = await parseImageFile(req.file.path);

  const target = await ensureTargetJobsite({
    client: String(req.body.targetClient || 'Imported Client').trim(),
    city: String(req.body.targetCity || 'Imported City').trim(),
    jobsite: String(req.body.targetJobsite || 'Imported Jobsite').trim(),
    street: rows[0]?.street || ''
  });
  const system = String(req.body.targetSystem || 'storm').trim();
  for (const row of rows) {
    row.duplicate = await segmentExists(target.id, system, row.reference);
  }
  res.json({ rows, sourceKind });
});

app.post('/imports/wincan/commit', requireMike, async (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
  if (!rows.length) return res.status(400).json({ error: 'Nothing to import.' });
  const target = await ensureTargetJobsite({
    client: String(req.body.targetClient || '').trim(),
    city: String(req.body.targetCity || '').trim(),
    jobsite: String(req.body.targetJobsite || '').trim(),
    street: rows[0]?.street || ''
  });
  const system = String(req.body.targetSystem || 'storm').trim();
  let count = 0;
  for (const row of rows) {
    if (!row.reference) continue;
    if (await segmentExists(target.id, system, row.reference)) continue;
    await writeSegment(target.id, {
      id: uid(),
      system,
      reference: row.reference,
      upstream: row.upstream || '',
      downstream: row.downstream || '',
      dia: row.dia || '',
      material: row.material || '',
      length: Number(row.length || 0),
      footage: Number(row.length || 0),
      versions: [buildVersion({ status: 'neutral', notes: `Imported from ${req.body.targetClient || 'WinCan'} preview.`, recordedDate: nowIso().slice(0, 10), savedBy: req.session.user.username })]
    }, req.session.user.username);
    count += 1;
  }
  res.json({ ok: true, imported: count });
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: error.message || 'Server error.' });
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`Horizon backend listening on ${PORT}`));
}).catch((error) => {
  console.error('Failed to initialize backend:', error);
  process.exit(1);
});
