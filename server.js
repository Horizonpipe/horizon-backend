
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const PgSessionFactory = require('connect-pg-simple');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const initSqlJs = require('sql.js');
const { randomUUID } = require('crypto');
const { Pool } = require('pg');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-now';
const RAW_CORS_ORIGINS = process.env.CORS_ORIGINS || '';
const CORS_ORIGINS = RAW_CORS_ORIGINS.split(',').map((value) => value.trim()).filter(Boolean);

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const PgSession = PgSessionFactory(session);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 30 * 1024 * 1024 }
});

app.set('trust proxy', 1);

function cleanString(value) {
  return String(value || '').trim();
}

function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

function normalizeRoles(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return {
      camera: value.camera !== false,
      vac: value.vac !== false
    };
  }
  if (typeof value === 'string') {
    try {
      return normalizeRoles(JSON.parse(value));
    } catch (error) {
      return { camera: true, vac: false };
    }
  }
  return { camera: true, vac: false };
}

function sessionUserPayload(row) {
  const roles = normalizeRoles(row.roles);
  const displayName = row.display_name || row.displayName || row.name || row.username;
  return {
    id: row.id,
    username: row.username || displayName,
    name: displayName,
    displayName,
    isAdmin: !!row.is_admin || !!row.isAdmin,
    is_admin: !!row.is_admin || !!row.isAdmin,
    roles,
    can_camera: !!roles.camera,
    can_vac: !!roles.vac,
    mustChangePassword: !!row.must_change_password || !!row.mustChangePassword,
    must_change_password: !!row.must_change_password || !!row.mustChangePassword
  };
}

function parseJsonObject(value, fallback = {}) {
  if (value == null) return fallback;
  if (typeof value === 'object') return value;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch (error) {
    return fallback;
  }
}

function normalizeStatus(value) {
  const normalized = cleanString(value).toLowerCase();
  if (!normalized) return 'neutral';
  if (['complete', 'video complete'].includes(normalized)) return 'complete';
  if (['failed', 'video failed'].includes(normalized)) return 'failed';
  if (['rerun', 'rerun queue', 'rerun queued', 'needs rerun'].includes(normalized)) return 'rerun';
  if (['revideoed', 'rerun-videoed', 'rerun videoed'].includes(normalized)) return 'rerun-videoed';
  if (['rerun failed', 'rerun-failed'].includes(normalized)) return 'rerun-failed';
  if (['ni', 'not installed', 'could not locate', 'could-not-locate'].includes(normalized)) return 'could-not-locate';
  if (['jetted', 'jetted/vac'].includes(normalized)) return 'jetted';
  return 'neutral';
}

function createVersion(payload = {}, saveBy = 'System') {
  return {
    id: payload.id || randomUUID(),
    createdAt: payload.createdAt || payload.created_at || new Date().toISOString(),
    savedBy: payload.savedBy || payload.saved_by || saveBy,
    status: normalizeStatus(payload.status || 'neutral'),
    notes: payload.notes || '',
    failureReason: payload.failureReason || payload.failure_reason || '',
    recordedDate: cleanString(payload.recordedDate || payload.recorded_date || todayISO()).slice(0, 10)
  };
}

function normalizeSegment(input = {}) {
  const versions = Array.isArray(input.versions) && input.versions.length
    ? input.versions.map((version) => createVersion(version, version.savedBy || version.saved_by || 'System'))
    : [createVersion({
        status: input.status || 'neutral',
        notes: input.notes || '',
        failureReason: input.failureReason || input.failure_reason || '',
        recordedDate: input.recordedDate || input.recorded_date || todayISO()
      }, input.savedBy || input.saved_by || 'System')];

  return {
    id: input.id || randomUUID(),
    reference: cleanString(input.reference),
    upstream: cleanString(input.upstream),
    downstream: cleanString(input.downstream),
    dia: cleanString(input.dia),
    material: cleanString(input.material),
    length: cleanString(input.length ?? input.footage),
    footage: cleanString(input.footage ?? input.length),
    status: normalizeStatus(input.status || versions[versions.length - 1].status),
    selectedVersionId: input.selectedVersionId || input.selected_version_id || versions[versions.length - 1].id,
    versions
  };
}

function normalizeSystems(source = {}) {
  const storm = source.storm === null ? null : (Array.isArray(source.storm) ? source.storm.map(normalizeSegment) : []);
  const sanitary = source.sanitary === null ? null : (Array.isArray(source.sanitary) ? source.sanitary.map(normalizeSegment) : []);
  return { storm, sanitary };
}

function recordToClientShape(row) {
  const data = parseJsonObject(row.data, {});
  const systems = normalizeSystems(data.systems || {});
  return {
    id: row.id,
    record_date: row.record_date ? String(row.record_date).slice(0, 10) : todayISO(),
    date: row.record_date ? String(row.record_date).slice(0, 10) : todayISO(),
    client: cleanString(row.client || data.client),
    city: cleanString(row.city || data.city),
    street: cleanString(row.street || data.street),
    jobsite: cleanString(row.jobsite || data.jobsite),
    status: cleanString(row.status),
    saved_by: cleanString(row.saved_by),
    created_at: row.created_at,
    updated_at: row.updated_at,
    systems
  };
}

function recordToDbData(record) {
  return {
    systems: {
      storm: record.systems?.storm === null ? null : (Array.isArray(record.systems?.storm) ? record.systems.storm : []),
      sanitary: record.systems?.sanitary === null ? null : (Array.isArray(record.systems?.sanitary) ? record.systems.sanitary : [])
    }
  };
}

function dataUrlFromFile(file) {
  return {
    id: randomUUID(),
    original_name: file.originalname,
    name: file.originalname,
    mime: file.mimetype || 'application/octet-stream',
    size: file.size || 0,
    url: `data:${file.mimetype || 'application/octet-stream'};base64,${file.buffer.toString('base64')}`
  };
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  req.user = req.session.user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  if (!req.session.user.isAdmin && !req.session.user.is_admin) {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  req.user = req.session.user;
  next();
}

function requireMike(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  const username = cleanString(req.session.user.username || req.session.user.displayName || '').toLowerCase();
  if (!['mik', 'mike strickland'].includes(username)) {
    return res.status(403).json({ success: false, error: 'Mike Strickland only' });
  }
  req.user = req.session.user;
  next();
}

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, CORS_ORIGINS[0] || true);
    if (!CORS_ORIGINS.length) return callback(null, origin);
    if (CORS_ORIGINS.includes(origin)) return callback(null, origin);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new PgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  name: 'horizon.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: true,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 15 * 60 * 1000
  }
}));

async function ensureSchema() {
  await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT NOT NULL UNIQUE,
      display_name TEXT,
      password TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT false,
      roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": false}'::jsonb,
      must_change_password BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": false}'::jsonb`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`UPDATE users SET display_name = username WHERE display_name IS NULL OR btrim(display_name) = ''`);
  await pool.query(`UPDATE users SET roles = '{"camera": true, "vac": false}'::jsonb WHERE roles IS NULL`);
  await pool.query(`UPDATE users SET must_change_password = false WHERE must_change_password IS NULL`);
  await pool.query(`UPDATE users SET updated_at = NOW() WHERE updated_at IS NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS planner_records (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      record_date DATE NOT NULL DEFAULT CURRENT_DATE,
      client TEXT NOT NULL DEFAULT '',
      city TEXT NOT NULL DEFAULT '',
      street TEXT NOT NULL DEFAULT '',
      jobsite TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT '',
      saved_by TEXT NOT NULL DEFAULT '',
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS record_date DATE NOT NULL DEFAULT CURRENT_DATE`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS client TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS street TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS jobsite TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS saved_by TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`UPDATE planner_records SET client = '' WHERE client IS NULL`);
  await pool.query(`UPDATE planner_records SET city = '' WHERE city IS NULL`);
  await pool.query(`UPDATE planner_records SET street = '' WHERE street IS NULL`);
  await pool.query(`UPDATE planner_records SET jobsite = '' WHERE jobsite IS NULL`);
  await pool.query(`UPDATE planner_records SET status = '' WHERE status IS NULL`);
  await pool.query(`UPDATE planner_records SET saved_by = '' WHERE saved_by IS NULL`);
  await pool.query(`UPDATE planner_records SET data = '{}'::jsonb WHERE data IS NULL`);
  await pool.query(`UPDATE planner_records SET updated_at = NOW() WHERE updated_at IS NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pricing_rates (
      dia TEXT PRIMARY KEY,
      rate NUMERIC(12,2) NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_reports (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      report_date DATE NOT NULL DEFAULT CURRENT_DATE,
      title TEXT NOT NULL DEFAULT '',
      notes TEXT NOT NULL DEFAULT '',
      files JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_by TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE daily_reports ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE daily_reports ADD COLUMN IF NOT EXISTS files JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await pool.query(`ALTER TABLE daily_reports ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT ''`);
  await pool.query(`UPDATE daily_reports SET files = '[]'::jsonb WHERE files IS NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS jobsite_assets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      client TEXT NOT NULL DEFAULT '',
      city TEXT NOT NULL DEFAULT '',
      street TEXT NOT NULL DEFAULT '',
      jobsite TEXT NOT NULL DEFAULT '',
      contact_name TEXT NOT NULL DEFAULT '',
      contact_phone TEXT NOT NULL DEFAULT '',
      contact_email TEXT NOT NULL DEFAULT '',
      notes TEXT NOT NULL DEFAULT '',
      drive_url TEXT NOT NULL DEFAULT '',
      files JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_by TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS client TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS street TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS jobsite TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS contact_name TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS contact_phone TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS drive_url TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS files JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`UPDATE jobsite_assets SET client = '' WHERE client IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET city = '' WHERE city IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET street = '' WHERE street IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET jobsite = '' WHERE jobsite IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET contact_name = '' WHERE contact_name IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET contact_phone = '' WHERE contact_phone IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET contact_email = '' WHERE contact_email IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET notes = '' WHERE notes IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET drive_url = '' WHERE drive_url IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET files = '[]'::jsonb WHERE files IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET created_by = '' WHERE created_by IS NULL`);
  await pool.query(`UPDATE jobsite_assets SET updated_at = NOW() WHERE updated_at IS NULL`);

  const countResult = await pool.query('SELECT COUNT(*)::int AS count FROM users');
  if (countResult.rows[0].count === 0) {
    const defaults = [
      { username: 'mik', displayName: 'Mike Strickland', isAdmin: true, roles: { camera: true, vac: true } },
      { username: 'nick', displayName: 'Nick Krull', isAdmin: true, roles: { camera: true, vac: true } },
      { username: 'tyler', displayName: 'Tyler Clark', isAdmin: true, roles: { camera: true, vac: true } }
    ];
    for (const user of defaults) {
      const hash = await bcrypt.hash('1234', 10);
      await pool.query(
        `INSERT INTO users (username, display_name, password, is_admin, roles, must_change_password)
         VALUES ($1, $2, $3, $4, $5::jsonb, true)`,
        [user.username, user.displayName, hash, user.isAdmin, JSON.stringify(user.roles)]
      );
    }
  } else {
    await pool.query(`
      UPDATE users
      SET is_admin = true,
          roles = '{"camera": true, "vac": true}'::jsonb,
          display_name = COALESCE(NULLIF(display_name, ''), username)
      WHERE LOWER(username) IN ('mik','mike strickland','nick','tyler')
         OR LOWER(display_name) IN ('mike strickland','nick krull','tyler clark')
    `);
  }
}

async function queryOne(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows[0] || null;
}

async function loadRecord(recordId) {
  const row = await queryOne(
    `SELECT id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at
     FROM planner_records
     WHERE id = $1
     LIMIT 1`,
    [recordId]
  );
  return row ? recordToClientShape(row) : null;
}

async function saveRecord(record) {
  const payload = recordToDbData(record);
  const row = await queryOne(
    `UPDATE planner_records
     SET record_date = $1,
         client = $2,
         city = $3,
         street = $4,
         jobsite = $5,
         status = $6,
         saved_by = $7,
         data = $8::jsonb,
         updated_at = NOW()
     WHERE id = $9
     RETURNING id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at`,
    [
      cleanString(record.record_date || record.date || todayISO()),
      cleanString(record.client),
      cleanString(record.city),
      cleanString(record.street),
      cleanString(record.jobsite),
      cleanString(record.status),
      cleanString(record.saved_by || record.savedBy || ''),
      JSON.stringify(payload),
      record.id
    ]
  );
  return row ? recordToClientShape(row) : null;
}

function findSegment(record, segmentId) {
  for (const system of ['storm', 'sanitary']) {
    const segments = Array.isArray(record.systems?.[system]) ? record.systems[system] : [];
    const index = segments.findIndex((segment) => String(segment.id) === String(segmentId));
    if (index >= 0) {
      return { system, index, segment: segments[index] };
    }
  }
  return null;
}

function ensureSystem(record, system) {
  if (record.systems[system] === null || !Array.isArray(record.systems[system])) {
    record.systems[system] = [];
  }
  return record.systems[system];
}

function compareNames(a, b) {
  return cleanString(a).toLowerCase() === cleanString(b).toLowerCase();
}

async function findOrCreateRecordByPath({ client, city, street = '', jobsite, system = 'storm', savedBy = 'System' }) {
  const found = await queryOne(
    `SELECT id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at
     FROM planner_records
     WHERE LOWER(client) = LOWER($1)
       AND LOWER(city) = LOWER($2)
       AND LOWER(jobsite) = LOWER($3)
     LIMIT 1`,
    [client, city, jobsite]
  );
  if (found) return recordToClientShape(found);

  const baseData = {
    systems: {
      storm: system === 'storm' ? [] : null,
      sanitary: system === 'sanitary' ? [] : null
    }
  };

  const created = await queryOne(
    `INSERT INTO planner_records (record_date, client, city, street, jobsite, status, saved_by, data)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
     RETURNING id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at`,
    [todayISO(), client, city, street, jobsite, '', savedBy, JSON.stringify(baseData)]
  );
  return recordToClientShape(created);
}

function transformUserForList(row) {
  const payload = sessionUserPayload(row);
  return {
    id: payload.id,
    username: payload.username,
    display_name: payload.displayName,
    displayName: payload.displayName,
    name: payload.displayName,
    is_admin: payload.is_admin,
    isAdmin: payload.isAdmin,
    can_camera: payload.can_camera,
    can_vac: payload.can_vac,
    must_change_password: payload.must_change_password,
    mustChangePassword: payload.mustChangePassword,
    roles: payload.roles
  };
}

let sqlJsPromise = null;
async function getSqlJs() {
  if (!sqlJsPromise) {
    sqlJsPromise = initSqlJs();
  }
  return sqlJsPromise;
}

function mapMaterialCode(code) {
  const raw = cleanString(code).toUpperCase();
  const map = {
    PE: 'Polyethylene',
    PP: 'Polypropylene',
    PVC: 'Polyvinyl Chloride',
    VCP: 'Vitrified Clay Pipe',
    RCP: 'Reinforced Concrete Pipe',
    DI: 'Ductile Iron',
    ST: 'Steel Pipe'
  };
  return map[raw] || code || '';
}

function mapShapeCode(code, size1, size2) {
  const raw = cleanString(code).toUpperCase();
  const s1 = cleanString(size1);
  const s2 = cleanString(size2);
  let shapeLabel = code || '';
  if (raw === 'C') shapeLabel = 'Circular';
  else if (raw === 'O') shapeLabel = 'Oval';
  else if (raw === 'R') shapeLabel = 'Rectangular';

  let dia = '';
  if (s1 && s2) dia = `${s1}/${s2}`;
  else dia = s1 || '';
  const shape = dia ? `${shapeLabel} ${dia}inch` : shapeLabel;
  return { shape, dia };
}

async function parseWinCanDb3(buffer) {
  const SQL = await getSqlJs();
  const db = new SQL.Database(new Uint8Array(buffer));
  const query = `
    SELECT
      s.OBJ_PK AS section_pk,
      s.OBJ_Key AS reference,
      COALESCE(MAX(si.INS_InspectedLength), s.OBJ_Length) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(n1.OBJ_Key, '') AS upstream,
      COALESCE(n2.OBJ_Key, '') AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(CAST(s.OBJ_Size1 AS TEXT), '') AS size1,
      COALESCE(CAST(s.OBJ_Size2 AS TEXT), '') AS size2
    FROM SECTION s
    LEFT JOIN SECINSP si ON si.INS_Section_FK = s.OBJ_PK
    LEFT JOIN NODE n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN NODE n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    GROUP BY s.OBJ_PK, s.OBJ_Key, s.OBJ_City, s.OBJ_Street, n1.OBJ_Key, n2.OBJ_Key, s.OBJ_Material, s.OBJ_Shape, s.OBJ_Size1, s.OBJ_Size2, s.OBJ_Length
    ORDER BY s.OBJ_Key
  `;
  const result = db.exec(query);
  db.close();
  if (!result.length) return [];
  const columns = result[0].columns;
  return result[0].values.map((values) => {
    const row = {};
    columns.forEach((column, index) => { row[column] = values[index]; });
    const mapped = mapShapeCode(row.shape_code, row.size1, row.size2);
    return {
      reference: cleanString(row.reference) || [cleanString(row.upstream), cleanString(row.downstream)].filter(Boolean).join('-'),
      length: row.length == null ? '' : String(Number(row.length).toFixed(3)),
      city: cleanString(row.city),
      street: cleanString(row.street),
      upstream: cleanString(row.upstream),
      downstream: cleanString(row.downstream),
      material: mapMaterialCode(row.material_code),
      shape: mapped.shape,
      dia: mapped.dia,
      duplicate: false
    };
  });
}

function previewDuplicates(rows, record, system) {
  const existing = new Set(
    (Array.isArray(record?.systems?.[system]) ? record.systems[system] : [])
      .map((segment) => cleanString(segment.reference).toLowerCase())
      .filter(Boolean)
  );
  const seen = new Set();
  return rows.map((row) => {
    const key = cleanString(row.reference).toLowerCase();
    const duplicate = !key || existing.has(key) || seen.has(key);
    seen.add(key);
    return { ...row, duplicate };
  });
}

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'horizon-backend', timestamp: new Date().toISOString() });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, is_admin, roles, must_change_password
       FROM users
       ORDER BY LOWER(COALESCE(display_name, username)), LOWER(username)`
    );
    const users = result.rows.map(transformUserForList);
    if (req.session?.user?.isAdmin || req.session?.user?.is_admin) {
      return res.json({ success: true, users });
    }
    return res.json({
      success: true,
      users: users.map((user) => ({
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        displayName: user.displayName,
        name: user.name,
        is_admin: user.is_admin,
        can_camera: user.can_camera,
        can_vac: user.can_vac
      }))
    });
  } catch (error) {
    console.error('USERS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/login', async (req, res) => {
  const submittedUsername = cleanString(req.body?.username);
  const submittedPassword = cleanString(req.body?.password);

  if (!submittedUsername || !submittedPassword) {
    return res.status(400).json({ success: false, error: 'Username and password are required' });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, display_name, password, is_admin, roles, must_change_password
       FROM users
       WHERE LOWER(username) = LOWER($1) OR LOWER(display_name) = LOWER($1)
       LIMIT 1`,
      [submittedUsername]
    );

    if (!result.rows.length) {
      return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }

    const row = result.rows[0];
    let passwordOk = false;
    let needsRehash = false;

    if (row.password && row.password.startsWith('$2')) {
      passwordOk = await bcrypt.compare(submittedPassword, row.password);
    } else if (row.password === submittedPassword) {
      passwordOk = true;
      needsRehash = true;
    }

    if (!passwordOk) {
      return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }

    if (needsRehash) {
      const hash = await bcrypt.hash(submittedPassword, 10);
      await pool.query('UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2', [hash, row.id]);
      row.password = hash;
    }

    const user = sessionUserPayload(row);
    req.session.user = user;

    return req.session.save((saveError) => {
      if (saveError) {
        console.error('SESSION SAVE ERROR:', saveError);
        return res.status(500).json({ success: false, error: 'Could not create session' });
      }
      return res.json({ success: true, authenticated: true, user });
    });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/session', requireAuth, (req, res) => {
  res.json({ success: true, authenticated: true, user: req.session.user });
});

function destroySession(req, res) {
  if (!req.session) return res.json({ success: true });
  req.session.destroy(() => {
    res.clearCookie('horizon.sid', {
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    });
    res.json({ success: true });
  });
}
app.post('/logout', destroySession);
app.post('/session/logout', destroySession);

app.post('/change-password', requireAuth, async (req, res) => {
  const currentPassword = cleanString(req.body?.currentPassword);
  const newPassword = cleanString(req.body?.newPassword);

  if (newPassword.length < 4) {
    return res.status(400).json({ success: false, error: 'New password must be at least 4 characters' });
  }

  try {
    const row = await queryOne('SELECT id, password, must_change_password FROM users WHERE id = $1 LIMIT 1', [req.user.id]);
    if (!row) return res.status(404).json({ success: false, error: 'User not found' });

    let currentOk = false;
    if (!currentPassword && row.must_change_password) {
      currentOk = true;
    } else if (row.password && row.password.startsWith('$2')) {
      currentOk = await bcrypt.compare(currentPassword, row.password);
    } else {
      currentOk = row.password === currentPassword;
    }

    if (!currentOk) {
      return res.status(401).json({ success: false, error: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password = $1, must_change_password = false, updated_at = NOW() WHERE id = $2',
      [hash, req.user.id]
    );

    req.session.user = { ...req.session.user, mustChangePassword: false, must_change_password: false };
    res.json({ success: true, user: req.session.user });
  } catch (error) {
    console.error('CHANGE PASSWORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/create-user', requireAdmin, async (req, res) => {
  const username = cleanString(req.body?.username);
  const displayName = cleanString(req.body?.displayName || req.body?.name || username);
  const password = cleanString(req.body?.password || '1234');
  const isAdmin = !!req.body?.isAdmin;
  const roles = normalizeRoles(req.body?.roles);

  if (!username) {
    return res.status(400).json({ success: false, error: 'Username is required' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, display_name, password, is_admin, roles, must_change_password)
       VALUES ($1, $2, $3, $4, $5::jsonb, true)
       RETURNING id, username, display_name, is_admin, roles, must_change_password`,
      [username, displayName, hash, isAdmin, JSON.stringify(roles)]
    );
    res.status(201).json({ success: true, user: transformUserForList(result.rows[0]) });
  } catch (error) {
    console.error('CREATE USER ERROR:', error);
    if (error.code === '23505') {
      return res.status(409).json({ success: false, error: 'Username already exists' });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/users/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const displayName = cleanString(req.body?.displayName || req.body?.name);
    const isAdmin = req.body?.isAdmin === undefined ? null : !!req.body.isAdmin;
    const roles = req.body?.roles === undefined ? null : normalizeRoles(req.body.roles);
    const password = cleanString(req.body?.password || '');

    const current = await queryOne(
      'SELECT id, username, display_name, is_admin, roles, must_change_password FROM users WHERE id = $1 LIMIT 1',
      [id]
    );
    if (!current) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const nextDisplayName = displayName || current.display_name || current.username;
    const nextIsAdmin = isAdmin === null ? current.is_admin : isAdmin;
    const nextRoles = roles === null ? normalizeRoles(current.roles) : roles;

    await pool.query(
      `UPDATE users
       SET display_name = $1,
           is_admin = $2,
           roles = $3::jsonb,
           updated_at = NOW()
       WHERE id = $4`,
      [nextDisplayName, nextIsAdmin, JSON.stringify(nextRoles), id]
    );

    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE users SET password = $1, must_change_password = false, updated_at = NOW() WHERE id = $2',
        [hash, id]
      );
    }

    const updated = await queryOne(
      'SELECT id, username, display_name, is_admin, roles, must_change_password FROM users WHERE id = $1 LIMIT 1',
      [id]
    );

    res.json({ success: true, user: transformUserForList(updated) });
  } catch (error) {
    console.error('UPDATE USER ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/records', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at
       FROM planner_records
       ORDER BY updated_at DESC, created_at DESC`
    );
    res.json({ success: true, records: result.rows.map(recordToClientShape) });
  } catch (error) {
    console.error('GET RECORDS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records', requireAuth, async (req, res) => {
  try {
    const recordDate = cleanString(req.body?.record_date || req.body?.date || todayISO());
    const client = cleanString(req.body?.client);
    const city = cleanString(req.body?.city);
    const street = cleanString(req.body?.street);
    const jobsite = cleanString(req.body?.jobsite);
    const status = cleanString(req.body?.status);
    const savedBy = cleanString(req.body?.saved_by || req.body?.savedBy || req.user.displayName || req.user.username);
    const createStorm = req.body?.createStorm !== false;
    const createSanitary = !!req.body?.createSanitary;
    const systems = parseJsonObject(req.body?.data, {}).systems || {
      storm: createStorm ? [] : null,
      sanitary: createSanitary ? [] : null
    };

    const result = await pool.query(
      `INSERT INTO planner_records (record_date, client, city, street, jobsite, status, saved_by, data)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
       RETURNING id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at`,
      [recordDate, client, city, street, jobsite, status, savedBy, JSON.stringify({ systems })]
    );

    res.status(201).json({ success: true, record: recordToClientShape(result.rows[0]) });
  } catch (error) {
    console.error('CREATE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/records/:id', requireAuth, async (req, res) => {
  try {
    const record = await loadRecord(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });

    record.record_date = cleanString(req.body?.record_date || req.body?.date || record.record_date);
    record.client = cleanString(req.body?.client ?? record.client);
    record.city = cleanString(req.body?.city ?? record.city);
    record.street = cleanString(req.body?.street ?? record.street);
    record.jobsite = cleanString(req.body?.jobsite ?? record.jobsite);
    record.status = cleanString(req.body?.status ?? record.status);
    record.saved_by = cleanString(req.body?.saved_by || req.body?.savedBy || req.user.displayName || req.user.username);

    const dataPatch = parseJsonObject(req.body?.data, null);
    if (dataPatch && dataPatch.systems) {
      record.systems = normalizeSystems(dataPatch.systems);
    }

    const saved = await saveRecord(record);
    res.json({ success: true, record: saved });
  } catch (error) {
    console.error('UPDATE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/records/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM planner_records WHERE id = $1 RETURNING id', [req.params.id]);
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'Record not found' });
    }
    res.json({ success: true, deletedId: result.rows[0].id });
  } catch (error) {
    console.error('DELETE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records/:id/segments', requireAuth, async (req, res) => {
  try {
    const record = await loadRecord(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });

    const system = cleanString(req.body?.system || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
    const list = ensureSystem(record, system);
    const reference = cleanString(req.body?.reference);
    if (!reference) return res.status(400).json({ success: false, error: 'Segment reference is required' });
    if (list.some((segment) => cleanString(segment.reference).toLowerCase() === reference.toLowerCase())) {
      return res.status(409).json({ success: false, error: 'That segment already exists in this system' });
    }

    const version = createVersion({
      status: cleanString(req.body?.status || 'neutral'),
      recordedDate: record.record_date || todayISO(),
      notes: 'Initial segment created.'
    }, req.user.displayName || req.user.username);

    const segment = normalizeSegment({
      reference,
      upstream: req.body?.upstream,
      downstream: req.body?.downstream,
      dia: req.body?.dia,
      material: req.body?.material,
      length: req.body?.length,
      footage: req.body?.footage,
      versions: [version],
      selectedVersionId: version.id
    });

    list.push(segment);
    const saved = await saveRecord(record);
    res.status(201).json({ success: true, record: saved, segment });
  } catch (error) {
    console.error('CREATE SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records/:id/segments/bulk', requireAuth, async (req, res) => {
  try {
    const record = await loadRecord(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });

    const inputSegments = Array.isArray(req.body?.segments) ? req.body.segments : [];
    if (!inputSegments.length) return res.status(400).json({ success: false, error: 'No segments provided' });

    let created = 0;
    for (const incoming of inputSegments) {
      const system = cleanString(incoming.system || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
      const list = ensureSystem(record, system);
      const reference = cleanString(incoming.reference);
      if (!reference) continue;
      if (list.some((segment) => cleanString(segment.reference).toLowerCase() === reference.toLowerCase())) continue;

      const version = createVersion({
        status: 'neutral',
        recordedDate: record.record_date || todayISO(),
        notes: 'Initial segment created by generator.'
      }, req.user.displayName || req.user.username);

      list.push(normalizeSegment({
        reference,
        upstream: incoming.upstream,
        downstream: incoming.downstream,
        dia: incoming.dia,
        material: incoming.material,
        length: incoming.length,
        footage: incoming.footage,
        versions: [version],
        selectedVersionId: version.id
      }));
      created += 1;
    }

    const saved = await saveRecord(record);
    res.json({ success: true, created, record: saved });
  } catch (error) {
    console.error('BULK SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/records/:id/segments/:segmentId', requireAuth, async (req, res) => {
  try {
    const record = await loadRecord(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    const found = findSegment(record, req.params.segmentId);
    if (!found) return res.status(404).json({ success: false, error: 'Segment not found' });

    const { segment } = found;
    const recordPatch = parseJsonObject(req.body?.recordPatch, {});
    const segmentPatch = parseJsonObject(req.body?.segmentPatch, {});
    const versionPatch = parseJsonObject(req.body?.versionPatch, {});
    const saveBy = cleanString(req.body?.saveBy || req.user.displayName || req.user.username);

    ['client', 'city', 'street', 'jobsite', 'record_date', 'status'].forEach((field) => {
      if (recordPatch[field] !== undefined) record[field] = cleanString(recordPatch[field]);
    });

    ['reference', 'upstream', 'downstream', 'dia', 'material', 'length', 'footage'].forEach((field) => {
      if (segmentPatch[field] !== undefined) segment[field] = cleanString(segmentPatch[field]);
    });
    if (segmentPatch.length !== undefined && segmentPatch.footage === undefined) segment.footage = cleanString(segmentPatch.length);
    if (segmentPatch.footage !== undefined && segmentPatch.length === undefined) segment.length = cleanString(segmentPatch.footage);

    if (Object.keys(versionPatch).length) {
      const latest = segment.versions[segment.versions.length - 1] || createVersion({}, saveBy);
      const version = createVersion({
        status: versionPatch.status || latest.status,
        notes: versionPatch.notes !== undefined ? versionPatch.notes : latest.notes,
        failureReason: versionPatch.failureReason !== undefined ? versionPatch.failureReason : latest.failureReason,
        recordedDate: versionPatch.recordedDate || latest.recordedDate || record.record_date || todayISO()
      }, saveBy);
      segment.versions.push(version);
      segment.selectedVersionId = version.id;
      segment.status = version.status;
    }

    record.saved_by = saveBy;
    const saved = await saveRecord(record);
    res.json({ success: true, record: saved });
  } catch (error) {
    console.error('UPDATE SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/records/:id/segments/:segmentId', requireAdmin, async (req, res) => {
  try {
    const record = await loadRecord(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    const found = findSegment(record, req.params.segmentId);
    if (!found) return res.status(404).json({ success: false, error: 'Segment not found' });

    record.systems[found.system].splice(found.index, 1);
    const saved = await saveRecord(record);
    res.json({ success: true, record: saved, deletedSegmentId: req.params.segmentId });
  } catch (error) {
    console.error('DELETE SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records/:id/segments/:segmentId/move', requireAdmin, async (req, res) => {
  try {
    const record = await loadRecord(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    const found = findSegment(record, req.params.segmentId);
    if (!found) return res.status(404).json({ success: false, error: 'Segment not found' });

    const targetClient = cleanString(req.body?.targetClient);
    const targetCity = cleanString(req.body?.targetCity);
    const targetJobsite = cleanString(req.body?.targetJobsite);
    const targetSystem = cleanString(req.body?.targetSystem || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';

    if (!targetClient || !targetCity || !targetJobsite) {
      return res.status(400).json({ success: false, error: 'Target client, city, and jobsite are required' });
    }

    const targetRecord = await findOrCreateRecordByPath({
      client: targetClient,
      city: targetCity,
      jobsite: targetJobsite,
      system: targetSystem,
      savedBy: req.user.displayName || req.user.username
    });

    const targetList = ensureSystem(targetRecord, targetSystem);
    if (targetList.some((segment) => cleanString(segment.reference).toLowerCase() === cleanString(found.segment.reference).toLowerCase())) {
      return res.status(409).json({ success: false, error: 'Target jobsite already contains that segment reference' });
    }

    record.systems[found.system].splice(found.index, 1);
    targetList.push(found.segment);

    await saveRecord(record);
    const savedTarget = await saveRecord(targetRecord);
    res.json({ success: true, movedSegmentId: req.params.segmentId, targetRecord: savedTarget });
  } catch (error) {
    console.error('MOVE SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/clients/:client', requireAdmin, async (req, res) => {
  try {
    const client = req.params.client;
    await pool.query('DELETE FROM jobsite_assets WHERE LOWER(client) = LOWER($1)', [client]);
    const result = await pool.query('DELETE FROM planner_records WHERE LOWER(client) = LOWER($1) RETURNING id', [client]);
    res.json({ success: true, deletedCount: result.rows.length });
  } catch (error) {
    console.error('DELETE CLIENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/pricing-rates', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT dia, rate, updated_at FROM pricing_rates ORDER BY dia');
    res.json({ success: true, rates: result.rows });
  } catch (error) {
    console.error('GET PRICING RATES ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/pricing-rates/:dia', requireAdmin, async (req, res) => {
  try {
    const dia = cleanString(req.params.dia || req.body?.dia);
    const rate = Number(req.body?.rate);
    if (!dia) return res.status(400).json({ success: false, error: 'DIA is required' });
    if (!Number.isFinite(rate)) return res.status(400).json({ success: false, error: 'Rate must be numeric' });

    const result = await pool.query(
      `INSERT INTO pricing_rates (dia, rate, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (dia)
       DO UPDATE SET rate = EXCLUDED.rate, updated_at = NOW()
       RETURNING dia, rate, updated_at`,
      [dia, Number(rate.toFixed(2))]
    );

    res.json({ success: true, rate: result.rows[0] });
  } catch (error) {
    console.error('UPSERT PRICING RATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/pricing-rates/:dia', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM pricing_rates WHERE dia = $1 RETURNING dia', [req.params.dia]);
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'DIA rate not found' });
    }
    res.json({ success: true, deletedDia: result.rows[0].dia });
  } catch (error) {
    console.error('DELETE PRICING RATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/daily-reports', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM daily_reports ORDER BY report_date DESC, updated_at DESC');
    res.json({ success: true, reports: result.rows });
  } catch (error) {
    console.error('GET DAILY REPORTS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/daily-reports', requireAdmin, upload.array('files'), async (req, res) => {
  try {
    const reportDate = cleanString(req.body?.report_date || req.body?.reportDate || todayISO());
    const title = cleanString(req.body?.title);
    const notes = cleanString(req.body?.notes);
    const files = Array.isArray(req.files) ? req.files.map(dataUrlFromFile) : [];
    const result = await pool.query(
      `INSERT INTO daily_reports (report_date, title, notes, files, created_by)
       VALUES ($1, $2, $3, $4::jsonb, $5)
       RETURNING *`,
      [reportDate, title, notes, JSON.stringify(files), req.user.displayName || req.user.username]
    );
    res.status(201).json({ success: true, report: result.rows[0] });
  } catch (error) {
    console.error('CREATE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/daily-reports/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM daily_reports WHERE id = $1 RETURNING id', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ success: false, error: 'Daily report not found' });
    res.json({ success: true, deletedId: result.rows[0].id });
  } catch (error) {
    console.error('DELETE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/jobsite-assets', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jobsite_assets ORDER BY client, city, jobsite, updated_at DESC');
    res.json({ success: true, assets: result.rows });
  } catch (error) {
    console.error('GET JOBSITE ASSETS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/jobsite-assets', requireAdmin, upload.array('files'), async (req, res) => {
  try {
    const files = Array.isArray(req.files) ? req.files.map(dataUrlFromFile) : [];
    const payload = {
      client: cleanString(req.body?.assetClient || req.body?.client),
      city: cleanString(req.body?.assetCity || req.body?.city),
      street: cleanString(req.body?.assetStreet || req.body?.street),
      jobsite: cleanString(req.body?.assetJobsite || req.body?.jobsite),
      contactName: cleanString(req.body?.assetContactName || req.body?.contactName),
      contactPhone: cleanString(req.body?.assetContactPhone || req.body?.contactPhone),
      contactEmail: cleanString(req.body?.assetContactEmail || req.body?.contactEmail),
      notes: cleanString(req.body?.assetNotes || req.body?.notes),
      driveUrl: cleanString(req.body?.assetDriveUrl || req.body?.driveUrl)
    };

    const result = await pool.query(
      `INSERT INTO jobsite_assets
       (client, city, street, jobsite, contact_name, contact_phone, contact_email, notes, drive_url, files, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)
       RETURNING *`,
      [
        payload.client,
        payload.city,
        payload.street,
        payload.jobsite,
        payload.contactName,
        payload.contactPhone,
        payload.contactEmail,
        payload.notes,
        payload.driveUrl,
        JSON.stringify(files),
        req.user.displayName || req.user.username
      ]
    );
    res.status(201).json({ success: true, asset: result.rows[0] });
  } catch (error) {
    console.error('CREATE JOBSITE ASSET ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/jobsite-assets/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM jobsite_assets WHERE id = $1 RETURNING id', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ success: false, error: 'Jobsite asset not found' });
    res.json({ success: true, deletedId: result.rows[0].id });
  } catch (error) {
    console.error('DELETE JOBSITE ASSET ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/imports/wincan/preview', requireMike, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Upload a DB3 file first' });
    const filename = cleanString(req.file.originalname).toLowerCase();
    if (!filename.endsWith('.db3') && !filename.endsWith('.sqlite') && !filename.endsWith('.db')) {
      return res.status(400).json({ success: false, error: 'This build supports DB3/SQLite WinCan project files. Image OCR fallback is not enabled in this bundle.' });
    }

    const targetClient = cleanString(req.body?.targetClient);
    const targetCity = cleanString(req.body?.targetCity);
    const targetJobsite = cleanString(req.body?.targetJobsite);
    const targetSystem = cleanString(req.body?.targetSystem || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';

    let targetRecord = null;
    if (targetClient && targetCity && targetJobsite) {
      const found = await queryOne(
        `SELECT id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at
         FROM planner_records
         WHERE LOWER(client) = LOWER($1)
           AND LOWER(city) = LOWER($2)
           AND LOWER(jobsite) = LOWER($3)
         LIMIT 1`,
        [targetClient, targetCity, targetJobsite]
      );
      if (found) targetRecord = recordToClientShape(found);
    }

    const rows = previewDuplicates(await parseWinCanDb3(req.file.buffer), targetRecord, targetSystem);
    res.json({
      success: true,
      sourceKind: 'DB3',
      rows
    });
  } catch (error) {
    console.error('WINCAN PREVIEW ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/imports/wincan/commit', requireMike, async (req, res) => {
  try {
    const targetClient = cleanString(req.body?.targetClient);
    const targetCity = cleanString(req.body?.targetCity);
    const targetJobsite = cleanString(req.body?.targetJobsite);
    const targetSystem = cleanString(req.body?.targetSystem || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
    const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];

    if (!targetClient || !targetCity || !targetJobsite) {
      return res.status(400).json({ success: false, error: 'Target client, city, and jobsite are required' });
    }
    if (!rows.length) {
      return res.status(400).json({ success: false, error: 'No import rows were supplied' });
    }

    const targetRecord = await findOrCreateRecordByPath({
      client: targetClient,
      city: targetCity,
      jobsite: targetJobsite,
      system: targetSystem,
      savedBy: req.user.displayName || req.user.username
    });
    const list = ensureSystem(targetRecord, targetSystem);
    const existing = new Set(list.map((segment) => cleanString(segment.reference).toLowerCase()));
    let inserted = 0;

    rows.forEach((row) => {
      const reference = cleanString(row.reference);
      if (!reference) return;
      if (existing.has(reference.toLowerCase())) return;
      const version = createVersion({
        status: 'neutral',
        notes: 'Imported from WinCan DB3.',
        recordedDate: targetRecord.record_date || todayISO()
      }, req.user.displayName || req.user.username);
      list.push(normalizeSegment({
        reference,
        upstream: row.upstream,
        downstream: row.downstream,
        dia: row.dia,
        material: row.material,
        length: row.length,
        footage: row.length,
        versions: [version],
        selectedVersionId: version.id
      }));
      existing.add(reference.toLowerCase());
      inserted += 1;
    });

    const saved = await saveRecord(targetRecord);
    res.json({ success: true, inserted, record: saved });
  } catch (error) {
    console.error('WINCAN COMMIT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.use((error, req, res, next) => {
  if (error && /CORS blocked/.test(error.message || '')) {
    return res.status(403).json({ success: false, error: error.message });
  }
  console.error('UNHANDLED ERROR:', error);
  return res.status(500).json({ success: false, error: error.message || 'Server error' });
});

ensureSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Horizon backend listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('BOOT ERROR:', error);
    process.exit(1);
  });
