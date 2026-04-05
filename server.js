
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const initSqlJs = require('sql.js');
const { Pool } = require('pg');
const { ensureOutlookSchema, registerOutlookRoutes } = require('./outlook');
const { registerPortalFilesRoutes } = require('./portal-files.routes');
const { createAutoImportPlugin } = require('./auto-import-plugin.routes');

const app = express();
app.use(express.json());
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL');
  process.exit(1);
}

/** Managed Postgres (Render, Neon, Supabase, etc.) often closes idle connections; recycle clients before that. */
const PG_POOL_MAX = Math.max(2, Math.min(50, Number(process.env.PG_POOL_MAX || 10)));
const PG_IDLE_TIMEOUT_MS = Math.max(
  5000,
  Math.min(120000, Number(process.env.PG_IDLE_TIMEOUT_MS || 25000))
);
const PG_CONNECT_TIMEOUT_MS = Math.max(
  3000,
  Math.min(60000, Number(process.env.PG_CONNECT_TIMEOUT_MS || 20000))
);

const databaseUrlLooksLocal =
  /(^|@)(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(DATABASE_URL) ||
  /sslmode=disable/i.test(DATABASE_URL);
const sslDisabledByEnv =
  process.env.DATABASE_SSL === '0' || /^false$/i.test(String(process.env.DATABASE_SSL || ''));

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: PG_POOL_MAX,
  idleTimeoutMillis: PG_IDLE_TIMEOUT_MS,
  connectionTimeoutMillis: PG_CONNECT_TIMEOUT_MS,
  allowExitOnIdle: process.env.PG_ALLOW_EXIT_ON_IDLE === '1',
  ssl: sslDisabledByEnv || databaseUrlLooksLocal ? false : { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error(
    '[pg] Pool client error (idle connection may have been closed by the host — next query opens a fresh one):',
    err && err.message ? err.message : err
  );
});

console.log(
  `[pg] Pool ready: max=${PG_POOL_MAX}, idleTimeout=${PG_IDLE_TIMEOUT_MS}ms, connectTimeout=${PG_CONNECT_TIMEOUT_MS}ms, ssl=${sslDisabledByEnv || databaseUrlLooksLocal ? 'off' : 'on'}`
);

const SESSION_TTL_MINUTES = 15;
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024, files: 20 }
});
const sqlJsPromise = initSqlJs();

app.set('trust proxy', 1);
function currentToken(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  if (req.headers['x-session-token']) return String(req.headers['x-session-token']).trim();
  const method = String(req.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') {
    const q = req.query?.access_token;
    if (q != null && String(q).trim()) return String(q).trim();
  }
  return '';
}

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      return callback(null, CORS_ORIGINS[0] || true);
    }
    if (!CORS_ORIGINS.length || CORS_ORIGINS.includes(origin)) {
      return callback(null, origin);
    }
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Token', 'Range'],
  exposedHeaders: [
    'Content-Disposition',
    'Content-Length',
    'Content-Type',
    'Content-Range',
    'Accept-Ranges'
  ]
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

function cleanString(value) {
  return String(value || '').trim();
}

function upperCleanString(value) {
  return cleanString(value).toUpperCase();
}

function normalizeRoles(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return {
      camera: value.camera !== false,
      vac: value.vac !== false,
      simpleVac: !!(value.simpleVac ?? value.simple_vac ?? false),
      email: !!value.email,
      psrPlanner: value.psrPlanner !== false && value.viewPsr !== false,
      pricingView: !!value.pricingView,
      footageView: !!value.footageView
    };
  }
  if (typeof value === 'string') {
    try {
      return normalizeRoles(JSON.parse(value));
    } catch (error) {
      return {
        camera: true,
        vac: true,
        simpleVac: false,
        email: false,
        psrPlanner: true,
        pricingView: false,
        footageView: false
      };
    }
  }
  return {
    camera: true,
    vac: true,
    simpleVac: false,
    email: false,
    psrPlanner: true,
    pricingView: false,
    footageView: false
  };
}

/** Shared prefix for per-user portal uploads in Wasabi (`clients/portal-users/jobs/{userId}/…`). */
const PORTAL_FILES_CLIENT_ID = 'portal-users';

function portalPermissionsWhitelistHas(username) {
  const u = String(username || '')
    .trim()
    .toLowerCase();
  if (!u) return false;
  const w = (process.env.PORTAL_PERMISSIONS_WHITELIST_USERS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return w.includes(u);
}

function normalizeUser(row) {
  const id = row.id;
  return {
    id,
    username: row.username,
    displayName: row.display_name || row.username,
    isAdmin: !!row.is_admin,
    roles: normalizeRoles(row.roles),
    mustChangePassword: !!row.must_change_password,
    portalFilesClientId: PORTAL_FILES_CLIENT_ID,
    portalFilesJobId: String(id),
    portalPermissionsAccess:
      !!row.portal_permissions_access || portalPermissionsWhitelistHas(row.username)
  };
}

function parseJsonObject(value, fallback = {}) {
  if (!value) return fallback;
  if (typeof value === 'object') return value;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch (error) {
    return fallback;
  }
}

function normalizeStatus(status) {
  const value = String(status || '').trim().toLowerCase();
  if (['complete', 'video complete'].includes(value)) return 'complete';
  if (['failed', 'video failed'].includes(value)) return 'failed';
  if (['rerun', 'rerun queue', 'needs rerun'].includes(value)) return 'rerun';
  if (['rerun-videoed', 'revideoed', 'rerun videoed'].includes(value)) return 'rerun-videoed';
  if (['rerun-failed', 'rerun failed'].includes(value)) return 'rerun-failed';
  if (['could-not-locate', 'could not locate', 'ni', 'not installed'].includes(value)) return 'could-not-locate';
  if (['jetted', 'vac/jetted'].includes(value)) return 'jetted';
  return 'neutral';
}

function statusLabel(status) {
  const normalized = normalizeStatus(status);
  switch (normalized) {
    case 'complete': return 'Complete';
    case 'failed': return 'Failed';
    case 'rerun': return 'Rerun Queue';
    case 'rerun-videoed': return 'Revideoed';
    case 'rerun-failed': return 'Rerun Failed';
    case 'could-not-locate': return 'Not Installed';
    case 'jetted': return 'Jetted';
    default: return 'Unmarked';
  }
}

function defaultVersion(userName = 'System', payload = {}) {
  return {
    id: payload.id || crypto.randomUUID(),
    createdAt: payload.createdAt || new Date().toISOString(),
    savedBy: payload.savedBy || userName,
    recordedDate: String(payload.recordedDate || new Date().toISOString().slice(0, 10)).slice(0, 10),
    notes: payload.notes || '',
    failureReason: payload.failureReason || '',
    status: normalizeStatus(payload.status || 'neutral')
  };
}

function normalizeSegment(raw = {}, userName = 'System') {
  const versions = Array.isArray(raw.versions) && raw.versions.length
    ? raw.versions.map((version) => defaultVersion(version.savedBy || userName, version))
    : [defaultVersion(userName, { status: raw.status || 'neutral' })];
  return {
    id: raw.id || crypto.randomUUID(),
    reference: upperCleanString(raw.reference),
    upstream: upperCleanString(raw.upstream),
    downstream: upperCleanString(raw.downstream),
    dia: upperCleanString(raw.dia),
    material: upperCleanString(raw.material),
    length: cleanString(raw.length ?? raw.footage),
    footage: cleanString(raw.footage ?? raw.length),
    street: upperCleanString(raw.street),
    system: cleanString(raw.system),
    versions,
    selectedVersionId: raw.selectedVersionId || versions[versions.length - 1].id
  };
}

function normalizeSystems(value, userName = 'System') {
  const systems = value && typeof value === 'object' ? value : {};
  return {
    storm: Array.isArray(systems.storm) ? systems.storm.map((segment) => normalizeSegment(segment, userName)) : [],
    sanitary: Array.isArray(systems.sanitary) ? systems.sanitary.map((segment) => normalizeSegment(segment, userName)) : []
  };
}

function normalizeJobsiteName(jobsite, street = '') {
  const j = upperCleanString(jobsite);
  const s = upperCleanString(street);
  if (!j) return 'NOT SET';
  if (s && j.toLowerCase() === s.toLowerCase()) return 'NOT SET';
  return j;
}

function normalizeRecordRow(row) {
  const data = parseJsonObject(row.data, {});
  const systems = normalizeSystems(data.systems, row.saved_by || 'System');

  const rawJobsite = cleanString(row.jobsite || data.jobsite);
  const rawStreet = cleanString(row.street || data.street);

  const segmentStreets = [
    ...(systems.storm || []),
    ...(systems.sanitary || [])
  ].map((segment) => cleanString(segment.street)).filter(Boolean);

  const looksLikeStreetOnly =
    rawJobsite &&
    segmentStreets.some((street) => street.toLowerCase() === rawJobsite.toLowerCase());

  const fallbackStreet = looksLikeStreetOnly ? rawJobsite : rawStreet;

  ['storm', 'sanitary'].forEach((system) => {
    systems[system] = (systems[system] || []).map((segment) => ({
      ...segment,
      street: cleanString(segment.street || fallbackStreet)
    }));
  });

  return {
    id: String(row.id),
    record_date: String(row.record_date || '').slice(0, 10),
    client: upperCleanString(row.client || data.client),
    city: upperCleanString(row.city || data.city),
    street: upperCleanString(fallbackStreet),
    jobsite: looksLikeStreetOnly ? 'NOT SET' : normalizeJobsiteName(rawJobsite, rawStreet),
    status: cleanString(row.status || data.status),
    saved_by: cleanString(row.saved_by || data.saved_by),
    systems,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function serializeRecordData(record) {
  return {
    systems: {
      storm: (record.systems?.storm || []).map((segment) => normalizeSegment(segment, record.saved_by || 'System')),
      sanitary: (record.systems?.sanitary || []).map((segment) => normalizeSegment(segment, record.saved_by || 'System'))
    }
  };
}

async function issueSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query(
    `INSERT INTO auth_sessions (token, user_id, expires_at)
     VALUES ($1, $2, NOW() + ($3 || ' minutes')::interval)`,
    [token, String(userId), SESSION_TTL_MINUTES]
  );
  return token;
}

async function readSession(token) {
  if (!token) return null;
  await pool.query(`DELETE FROM auth_sessions WHERE expires_at < NOW()`);
  const result = await pool.query(
    `SELECT s.token, s.user_id, s.expires_at, u.id, u.username, u.display_name, u.password,
            u.is_admin, u.roles, u.must_change_password
     FROM auth_sessions s
     JOIN users u ON CAST(u.id AS text) = s.user_id
     WHERE s.token = $1
     LIMIT 1`,
    [token]
  );
  if (!result.rows.length) return null;
  const row = result.rows[0];
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await pool.query('DELETE FROM auth_sessions WHERE token = $1', [token]);
    return null;
  }
  await pool.query(
    `UPDATE auth_sessions
     SET expires_at = NOW() + ($2 || ' minutes')::interval,
         updated_at = NOW()
     WHERE token = $1`,
    [token, SESSION_TTL_MINUTES]
  );
  return normalizeUser(row);
}

async function requireAuth(req, res, next) {
  try {
    const token = currentToken(req);
    const user = await readSession(token);
    if (!user) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    req.user = user;
    req.sessionToken = token;
    return next();
  } catch (error) {
    console.error('AUTH ERROR:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  return next();
}

function requireMike(req, res, next) {
  const name = String(req.user?.displayName || req.user?.username || '').trim().toLowerCase();
  if (name !== 'mike strickland' && name !== 'mik') {
    return res.status(403).json({ success: false, error: 'Mike-only importer access' });
  }
  return next();
}

function fileToStoredJson(file) {
  return {
    id: crypto.randomUUID(),
    name: file.originalname,
    mime: file.mimetype,
    size: file.size,
    dataUrl: `data:${file.mimetype};base64,${file.buffer.toString('base64')}`
  };
}

function shapeLabel(code, size1, size2) {
  const primary = size1 ? String(size1).replace(/\.0+$/, '') : '';
  const secondary = size2 ? String(size2).replace(/\.0+$/, '') : '';
  const base = (() => {
    const upper = String(code || '').trim().toUpperCase();
    if (upper === 'C') return 'Circular';
    if (upper === 'O') return 'Oval';
    if (upper === 'R') return 'Rectangular';
    if (upper === 'E') return 'Egg';
    return upper || 'Unknown';
  })();
  if (!primary) return base;
  if (secondary) return `${base} ${primary}/${secondary}in`;
  return `${base} ${primary}in`;
}

function materialLabel(code) {
  const upper = String(code || '').trim().toUpperCase();
  const map = {
    PE: 'Polyethylene',
    PVC: 'Polyvinyl Chloride',
    PP: 'Polypropylene',
    RCP: 'Reinforced Concrete Pipe',
    VC: 'Vitrified Clay Pipe',
    SP: 'Steel Pipe'
  };
  return map[upper] || upper || '';
}

async function parseDb3(buffer) {
  const SQL = await sqlJsPromise;
  const db = new SQL.Database(new Uint8Array(buffer));

  let projectName = '';
  try {
    const projectStmt = db.prepare(`
      SELECT COALESCE(MAX(PRJ_Key), '') AS project_name
      FROM PROJECT
    `);
    if (projectStmt.step()) {
      const row = projectStmt.getAsObject();
      projectName = cleanString(row.project_name);
    }
    projectStmt.free();
  } catch (error) {
    projectName = '';
  }

  const query = `
    SELECT
      s.OBJ_Key AS reference,
      COALESCE(si.inspected_length, s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(n1.OBJ_Key, '') AS upstream,
      COALESCE(n2.OBJ_Key, '') AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2
    FROM SECTION s
    LEFT JOIN (
      SELECT INS_Section_FK, MAX(COALESCE(INS_InspectedLength, INS_EstimatedLength, 0)) AS inspected_length
      FROM SECINSP
      GROUP BY INS_Section_FK
    ) si ON si.INS_Section_FK = s.OBJ_PK
    LEFT JOIN NODE n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN NODE n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key
  `;

  const stmt = db.prepare(query);
  const rows = [];
  while (stmt.step()) {
    const row = stmt.getAsObject();
    const dia = row.size2
      ? `${String(row.size1).replace(/\.0+$/, '')}/${String(row.size2).replace(/\.0+$/, '')}`
      : String(row.size1 || '').replace(/\.0+$/, '');
    rows.push({
      project: projectName || 'NOT SET',
      reference: cleanString(row.reference),
      length: Number(row.length || 0).toFixed(3),
      city: cleanString(row.city),
      street: cleanString(row.street),
      upstream: cleanString(row.upstream),
      downstream: cleanString(row.downstream),
      material: materialLabel(row.material_code),
      shape: shapeLabel(row.shape_code, row.size1, row.size2),
      dia
    });
  }
  stmt.free();
  db.close();
  return rows;
}

async function ensureSchema() {
  await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT NOT NULL UNIQUE,
      display_name TEXT,
      password TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT false,
      roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": false, "simpleVac": false, "email": false}'::jsonb,
      must_change_password BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const userAlters = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": false, "simpleVac": false, "email": false}'::jsonb`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_permissions_access BOOLEAN NOT NULL DEFAULT false`
  ];
  for (const query of userAlters) await pool.query(query);
  await pool.query(`UPDATE users SET display_name = username WHERE display_name IS NULL OR btrim(display_name) = ''`);
  await pool.query(`UPDATE users SET roles = '{"camera": true, "vac": false, "simpleVac": false, "email": false}'::jsonb WHERE roles IS NULL`);
  await pool.query(`UPDATE users SET roles = '{"camera": true, "vac": false, "simpleVac": false, "email": false}'::jsonb || COALESCE(roles, '{}'::jsonb)`);
  await pool.query(`UPDATE users SET must_change_password = false WHERE must_change_password IS NULL`);

  await pool.query(`DROP TABLE IF EXISTS auth_sessions`);
  await pool.query(`
    CREATE TABLE auth_sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

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

  const plannerAlters = [
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS record_date DATE NOT NULL DEFAULT CURRENT_DATE`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS client TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS street TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS jobsite TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS saved_by TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
    `ALTER TABLE planner_records ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  ];
  for (const query of plannerAlters) await pool.query(query);

  await pool.query(`UPDATE planner_records SET client = '' WHERE client IS NULL`);
  await pool.query(`UPDATE planner_records SET city = '' WHERE city IS NULL`);
  await pool.query(`UPDATE planner_records SET street = '' WHERE street IS NULL`);
  await pool.query(`UPDATE planner_records SET jobsite = 'NOT SET' WHERE jobsite IS NULL OR btrim(jobsite) = ''`);
  await pool.query(`UPDATE planner_records SET status = '' WHERE status IS NULL`);
  await pool.query(`UPDATE planner_records SET saved_by = '' WHERE saved_by IS NULL`);
  await pool.query(`UPDATE planner_records SET data = '{}'::jsonb WHERE data IS NULL`);

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
      title TEXT NOT NULL DEFAULT '',
      report_date DATE NOT NULL DEFAULT CURRENT_DATE,
      notes TEXT NOT NULL DEFAULT '',
      files JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_by TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const reportAlters = [
    `ALTER TABLE daily_reports ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE daily_reports ADD COLUMN IF NOT EXISTS files JSONB NOT NULL DEFAULT '[]'::jsonb`
  ];
  for (const query of reportAlters) await pool.query(query);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS jobsite_assets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      client TEXT NOT NULL DEFAULT '',
      city TEXT NOT NULL DEFAULT '',
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

  const assetAlters = [
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS client TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS jobsite TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS contact_name TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS contact_phone TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS drive_url TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS files JSONB NOT NULL DEFAULT '[]'::jsonb`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
    `ALTER TABLE jobsite_assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  ];
  for (const query of assetAlters) await pool.query(query);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS portal_path_grants (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      client_id TEXT NOT NULL,
      job_id TEXT NOT NULL,
      username TEXT NOT NULL,
      path_prefix TEXT NOT NULL DEFAULT '',
      recursive BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_portal_path_grants_cj ON portal_path_grants (client_id, job_id)`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_portal_path_grants_user ON portal_path_grants (client_id, job_id, lower(username))`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS portal_share_links (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      token TEXT NOT NULL UNIQUE,
      client_id TEXT NOT NULL,
      job_id TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('public', 'interactive', 'signin')),
      created_by_username TEXT,
      payload JSONB NOT NULL DEFAULT '{"folderPaths":[],"fileIds":[]}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_portal_share_links_cj ON portal_share_links (client_id, job_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS portal_share_guest_sessions (
      guest_token TEXT PRIMARY KEY,
      share_link_id UUID NOT NULL REFERENCES portal_share_links(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS portal_share_access_log (
      id BIGSERIAL PRIMARY KEY,
      share_link_id UUID NOT NULL REFERENCES portal_share_links(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ip_inet TEXT,
      user_agent TEXT
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_portal_share_access_log_share ON portal_share_access_log (share_link_id, accessed_at DESC)`
  );

  try {
    await pool.query(`ALTER TABLE portal_share_links DROP CONSTRAINT IF EXISTS portal_share_links_kind_check`);
    await pool.query(
      `ALTER TABLE portal_share_links ADD CONSTRAINT portal_share_links_kind_check CHECK (kind IN ('public', 'interactive', 'signin'))`
    );
  } catch (e) {
    console.warn('[schema] portal_share_links kind constraint migrate:', e instanceof Error ? e.message : e);
  }

  await ensureOutlookSchema(pool);

  const countResult = await pool.query('SELECT COUNT(*)::int AS count FROM users');
  if (countResult.rows[0].count === 0) {
    const defaults = [
      {
        username: 'mik',
        displayName: 'Mike Strickland',
        isAdmin: true,
        roles: {
          camera: true,
          vac: true,
          simpleVac: false,
          email: true,
          psrPlanner: true,
          pricingView: true,
          footageView: true
        }
      },
      {
        username: 'nick',
        displayName: 'Nick Krull',
        isAdmin: true,
        roles: {
          camera: true,
          vac: true,
          simpleVac: false,
          email: true,
          psrPlanner: true,
          pricingView: true,
          footageView: true
        }
      },
      {
        username: 'tyler',
        displayName: 'Tyler Clark',
        isAdmin: true,
        roles: {
          camera: true,
          vac: true,
          simpleVac: false,
          email: true,
          psrPlanner: true,
          pricingView: true,
          footageView: true
        }
      }
    ];
    for (const user of defaults) {
      const hash = await bcrypt.hash('1234', 10);
      await pool.query(
        `INSERT INTO users (username, display_name, password, is_admin, roles, must_change_password)
         VALUES ($1, $2, $3, $4, $5::jsonb, true)`,
        [user.username, user.displayName, hash, user.isAdmin, JSON.stringify(user.roles)]
      );
    }
  }
}

app.get('/', (req, res) => {
  res.json({ success: true, service: 'horizon-backend' });
});

app.get('/health', async (req, res) => {
  const started = Date.now();
  try {
    await pool.query('SELECT 1 AS ok');
    res.json({
      success: true,
      service: 'horizon-backend',
      database: true,
      latencyMs: Date.now() - started
    });
  } catch (error) {
    console.error('[health] Database check failed:', error && error.message ? error.message : error);
    res.status(503).json({
      success: false,
      service: 'horizon-backend',
      database: false,
      error: error && error.message ? error.message : 'Database unreachable',
      latencyMs: Date.now() - started
    });
  }
});

app.get('/sync-state', requireAuth, async (req, res) => {
  try {
    const [records, pricing, reports, assets, users, emails] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM planner_records`),
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM pricing_rates`),
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM daily_reports`),
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM jobsite_assets`),
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM users`),
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM user_outlook_tokens`)
    ]);
    const payload = { records: records.rows[0], pricing: pricing.rows[0], reports: reports.rows[0], assets: assets.rows[0], users: users.rows[0], emails: emails.rows[0] };
    const signature = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    res.json({ success: true, signature, state: payload });
  } catch (error) {
    console.error('SYNC STATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, is_admin, roles, must_change_password
       FROM users
       ORDER BY LOWER(COALESCE(display_name, username)), LOWER(username)`
    );
    const token = currentToken(req);
    const currentUser = await readSession(token);
    const users = result.rows.map((row) => {
      const normalized = normalizeUser(row);
      if (!currentUser?.isAdmin) {
        return {
          id: normalized.id,
          username: normalized.username,
          displayName: normalized.displayName
        };
      }
      return normalized;
    });
    res.json({ success: true, users });
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
       WHERE LOWER(username) = LOWER($1) OR LOWER(COALESCE(display_name, username)) = LOWER($1)
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
    }

    const user = normalizeUser(row);
    const token = await issueSession(row.id);
    res.json({ success: true, user, token });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/session', requireAuth, async (req, res) => {
  res.json({ success: true, user: req.user });
});

/** WinCan / desktop EXE pushes rows using the same session token as the web planner (not a static API key). */
app.post('/auto-import-plugin/push', requireAuth, requireMike, async (req, res) => {
  try {
    const body = req.body || {};
    const source = String(body.source || '').trim();
    const rows = Array.isArray(body.rows) ? body.rows : [];

    return res.json({
      success: true,
      message: rows.length
        ? 'Auto import payload received.'
        : 'Auto import test received.',
      received: {
        source,
        rowCount: rows.length
      }
    });
  } catch (error) {
    console.error('auto-import-plugin/push failed:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/logout', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM auth_sessions WHERE token = $1', [req.sessionToken]);
    res.json({ success: true });
  } catch (error) {
    console.error('LOGOUT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/change-password', requireAuth, async (req, res) => {
  const currentPassword = cleanString(req.body?.currentPassword);
  const newPassword = cleanString(req.body?.newPassword);

  if (newPassword.length < 4) {
    return res.status(400).json({ success: false, error: 'New password must be at least 4 characters' });
  }

  try {
    const result = await pool.query(
      'SELECT id, password, must_change_password FROM users WHERE id = $1 LIMIT 1',
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const row = result.rows[0];
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

    res.json({
      success: true,
      user: {
        ...req.user,
        mustChangePassword: false
      }
    });
  } catch (error) {
    console.error('CHANGE PASSWORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/create-user', requireAuth, requireAdmin, async (req, res) => {
  const username = cleanString(req.body?.username);
  const displayName = cleanString(req.body?.displayName || username);
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
    res.status(201).json({ success: true, user: normalizeUser(result.rows[0]) });
  } catch (error) {
    console.error('CREATE USER ERROR:', error);
    if (error.code === '23505') {
      return res.status(409).json({ success: false, error: 'Username already exists' });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = req.params.id;
  const displayName = cleanString(req.body?.displayName || req.body?.name);
  const isAdmin = req.body?.isAdmin === undefined ? null : !!req.body.isAdmin;
  const roles = req.body?.roles === undefined ? null : normalizeRoles(req.body.roles);
  const password = cleanString(req.body?.password || '');

  try {
    const currentResult = await pool.query(
      'SELECT id, username, display_name, is_admin, roles, must_change_password FROM users WHERE id = $1 LIMIT 1',
      [id]
    );
    if (!currentResult.rows.length) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    const current = currentResult.rows[0];

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

    const updatedResult = await pool.query(
      'SELECT id, username, display_name, is_admin, roles, must_change_password FROM users WHERE id = $1 LIMIT 1',
      [id]
    );

    res.json({ success: true, user: normalizeUser(updatedResult.rows[0]) });
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
       ORDER BY LOWER(client), LOWER(city), LOWER(jobsite), record_date DESC, updated_at DESC`
    );
    const records = result.rows.map(normalizeRecordRow);
    res.json({ success: true, records });
  } catch (error) {
    console.error('GET RECORDS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records', requireAuth, async (req, res) => {
  try {
    const record = {
      record_date: cleanString(req.body?.record_date || req.body?.date || new Date().toISOString().slice(0, 10)),
      client: upperCleanString(req.body?.client),
      city: upperCleanString(req.body?.city),
      street: upperCleanString(req.body?.street),
      jobsite: normalizeJobsiteName(req.body?.jobsite, req.body?.street),
      status: '',
      saved_by: req.user.displayName || req.user.username,
      systems: {
        storm: req.body?.createStorm === false ? [] : [],
        sanitary: req.body?.createSanitary ? [] : []
      }
    };

    const result = await pool.query(
      `INSERT INTO planner_records (record_date, client, city, street, jobsite, status, saved_by, data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
       RETURNING *`,
      [
        record.record_date,
        record.client,
        record.city,
        record.street,
        record.jobsite,
        '',
        record.saved_by,
        JSON.stringify(serializeRecordData(record))
      ]
    );

    res.status(201).json({ success: true, record: normalizeRecordRow(result.rows[0]) });
  } catch (error) {
    console.error('CREATE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

async function fetchRecordById(id) {
  const result = await pool.query('SELECT * FROM planner_records WHERE CAST(id AS text) = $1 LIMIT 1', [String(id)]);
  if (!result.rows.length) return null;
  return normalizeRecordRow(result.rows[0]);
}

async function persistRecord(record) {
  const result = await pool.query(
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
     WHERE CAST(id AS text) = $9
     RETURNING *`,
    [
      record.record_date,
      record.client,
      record.city,
      record.street,
      normalizeJobsiteName(record.jobsite, record.street),
      record.status || '',
      record.saved_by || '',
      JSON.stringify(serializeRecordData(record)),
      String(record.id)
    ]
  );
  return normalizeRecordRow(result.rows[0]);
}

app.put('/records/:id', requireAuth, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });

    record.record_date = cleanString(req.body?.record_date || req.body?.date || record.record_date);
    record.client = upperCleanString(req.body?.client || record.client);
    record.city = upperCleanString(req.body?.city || record.city);
    record.street = upperCleanString(req.body?.street || record.street);
    record.jobsite = normalizeJobsiteName(req.body?.jobsite || record.jobsite, req.body?.street || record.street);
    record.status = cleanString(req.body?.status || record.status);
    record.saved_by = cleanString(req.body?.saved_by || req.body?.savedBy || req.user.displayName || req.user.username);

    const saved = await persistRecord(record);
    res.json({ success: true, record: saved });
  } catch (error) {
    console.error('UPDATE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/records/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM planner_records WHERE CAST(id AS text) = $1 RETURNING id', [String(req.params.id)]);
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'Record not found' });
    }
    res.json({ success: true, deletedId: result.rows[0].id });
  } catch (error) {
    console.error('DELETE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/clients', requireAuth, requireAdmin, async (req, res) => {
  try {
    const client = upperCleanString(req.body?.client);
    const city = upperCleanString(req.body?.city || 'NOT SET');
    const jobsite = normalizeJobsiteName(req.body?.jobsite || 'NOT SET');
    const street = upperCleanString(req.body?.street || '');
    if (!client) return res.status(400).json({ success: false, error: 'Client name is required' });

    const result = await pool.query(
      `INSERT INTO planner_records (record_date, client, city, street, jobsite, status, saved_by, data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
       RETURNING *`,
      [
        new Date().toISOString().slice(0, 10),
        client,
        city,
        street,
        jobsite,
        '',
        req.user.displayName || req.user.username,
        JSON.stringify(serializeRecordData({ systems: { storm: [], sanitary: [] }, saved_by: req.user.displayName || req.user.username }))
      ]
    );

    res.status(201).json({ success: true, record: normalizeRecordRow(result.rows[0]) });
  } catch (error) {
    console.error('CREATE CLIENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/clients/:client', requireAuth, requireAdmin, async (req, res) => {
  try {
    const client = upperCleanString(req.params.client);
    await pool.query('DELETE FROM jobsite_assets WHERE client = $1', [client]);
    const result = await pool.query('DELETE FROM planner_records WHERE client = $1 RETURNING id', [client]);
    res.json({ success: true, deletedCount: result.rowCount });
  } catch (error) {
    console.error('DELETE CLIENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records/:id/segments', requireAuth, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    const system = cleanString(req.body?.system || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
    const segment = normalizeSegment({
      ...req.body,
      reference: upperCleanString(req.body?.reference),
      upstream: upperCleanString(req.body?.upstream),
      downstream: upperCleanString(req.body?.downstream),
      dia: upperCleanString(req.body?.dia),
      material: upperCleanString(req.body?.material),
      street: upperCleanString(req.body?.street || record.street),
      system,
      id: crypto.randomUUID(),
      versions: [
        defaultVersion(req.user.displayName || req.user.username, {
          status: 'neutral',
          recordedDate: record.record_date,
          notes: 'Initial segment created.'
        })
      ]
    }, req.user.displayName || req.user.username);

    record.systems[system] = Array.isArray(record.systems[system]) ? record.systems[system] : [];
    const exists = record.systems[system].some((item) => String(item.reference || '').toLowerCase() === String(segment.reference || '').toLowerCase());
    if (exists) return res.status(409).json({ success: false, error: 'Segment reference already exists in this system' });

    record.systems[system].push(segment);
    record.saved_by = req.user.displayName || req.user.username;

    const saved = await persistRecord(record);
    res.status(201).json({ success: true, record: saved, segment });
  } catch (error) {
    console.error('ADD SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records/:id/segments/bulk', requireAuth, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    const segments = Array.isArray(req.body?.segments) ? req.body.segments : [];
    for (const raw of segments) {
      const system = cleanString(raw.system || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
      record.systems[system] = Array.isArray(record.systems[system]) ? record.systems[system] : [];
      const segment = normalizeSegment({
        ...raw,
        system,
        id: crypto.randomUUID(),
        versions: [
          defaultVersion(req.user.displayName || req.user.username, {
            status: 'neutral',
            recordedDate: record.record_date,
            notes: 'Generated segment.'
          })
        ]
      }, req.user.displayName || req.user.username);
      const exists = record.systems[system].some((item) => String(item.reference || '').toLowerCase() === String(segment.reference || '').toLowerCase());
      if (!exists) record.systems[system].push(segment);
    }
    record.saved_by = req.user.displayName || req.user.username;
    const saved = await persistRecord(record);
    res.json({ success: true, record: saved });
  } catch (error) {
    console.error('BULK SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/records/:id/segments/:segmentId', requireAuth, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });

    let found = null;
    let systemKey = null;
    ['storm', 'sanitary'].forEach((system) => {
      const index = (record.systems[system] || []).findIndex((segment) => segment.id === req.params.segmentId);
      if (index >= 0) {
        found = record.systems[system][index];
        systemKey = system;
      }
    });

    if (!found || !systemKey) {
      return res.status(404).json({ success: false, error: 'Segment not found' });
    }

    const recordPatch = parseJsonObject(req.body?.recordPatch, {});
    const segmentPatch = parseJsonObject(req.body?.segmentPatch, {});
    const versionPatch = parseJsonObject(req.body?.versionPatch, {});
    if (recordPatch.client !== undefined) recordPatch.client = upperCleanString(recordPatch.client);
    if (recordPatch.city !== undefined) recordPatch.city = upperCleanString(recordPatch.city);
    if (recordPatch.street !== undefined) recordPatch.street = upperCleanString(recordPatch.street);
    if (recordPatch.jobsite !== undefined) recordPatch.jobsite = upperCleanString(recordPatch.jobsite);
    if (segmentPatch.reference !== undefined) segmentPatch.reference = upperCleanString(segmentPatch.reference);
    if (segmentPatch.upstream !== undefined) segmentPatch.upstream = upperCleanString(segmentPatch.upstream);
    if (segmentPatch.downstream !== undefined) segmentPatch.downstream = upperCleanString(segmentPatch.downstream);
    if (segmentPatch.dia !== undefined) segmentPatch.dia = upperCleanString(segmentPatch.dia);
    if (segmentPatch.material !== undefined) segmentPatch.material = upperCleanString(segmentPatch.material);
    if (segmentPatch.street !== undefined) segmentPatch.street = upperCleanString(segmentPatch.street);
    record.jobsite = normalizeJobsiteName(recordPatch.jobsite || record.jobsite, record.street);
    record.client = upperCleanString(recordPatch.client || record.client);
    record.city = upperCleanString(recordPatch.city || record.city);
    record.street = upperCleanString(recordPatch.street || record.street);

    Object.assign(found, {
      reference: upperCleanString(segmentPatch.reference || found.reference),
      upstream: upperCleanString(segmentPatch.upstream || found.upstream),
      downstream: upperCleanString(segmentPatch.downstream || found.downstream),
      dia: upperCleanString(segmentPatch.dia !== undefined ? segmentPatch.dia : found.dia),
      material: upperCleanString(segmentPatch.material !== undefined ? segmentPatch.material : found.material),
      length: cleanString(segmentPatch.length !== undefined ? segmentPatch.length : found.length),
      footage: cleanString(segmentPatch.footage !== undefined ? segmentPatch.footage : (segmentPatch.length !== undefined ? segmentPatch.length : found.footage)),
      street: upperCleanString(segmentPatch.street !== undefined ? segmentPatch.street : found.street)
    });

    if (Object.keys(versionPatch).length) {
      const nextVersion = defaultVersion(req.body?.saveBy || req.user.displayName || req.user.username, {
        status: versionPatch.status || found.versions[found.versions.length - 1]?.status || 'neutral',
        notes: versionPatch.notes !== undefined ? versionPatch.notes : found.versions[found.versions.length - 1]?.notes,
        failureReason: versionPatch.failureReason !== undefined ? versionPatch.failureReason : found.versions[found.versions.length - 1]?.failureReason,
        recordedDate: versionPatch.recordedDate || found.versions[found.versions.length - 1]?.recordedDate || record.record_date
      });
      found.versions.push(nextVersion);
      found.selectedVersionId = nextVersion.id;
      found.status = nextVersion.status;
    }

    record.saved_by = req.user.displayName || req.user.username;
    const saved = await persistRecord(record);
    res.json({ success: true, record: saved });
  } catch (error) {
    console.error('UPDATE SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/records/:id/segments/:segmentId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    ['storm', 'sanitary'].forEach((system) => {
      record.systems[system] = (record.systems[system] || []).filter((segment) => segment.id !== req.params.segmentId);
    });
    record.saved_by = req.user.displayName || req.user.username;
    const saved = await persistRecord(record);
    res.json({ success: true, record: saved });
  } catch (error) {
    console.error('DELETE SEGMENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records/:id/segments/:segmentId/move', requireAuth, requireAdmin, async (req, res) => {
  try {
    const source = await fetchRecordById(req.params.id);
    if (!source) return res.status(404).json({ success: false, error: 'Source record not found' });

    let movingSegment = null;
    ['storm', 'sanitary'].forEach((system) => {
      const index = (source.systems[system] || []).findIndex((segment) => segment.id === req.params.segmentId);
      if (index >= 0) {
        movingSegment = { ...source.systems[system][index] };
        source.systems[system].splice(index, 1);
      }
    });

    if (!movingSegment) return res.status(404).json({ success: false, error: 'Segment not found' });

    const targetClient = cleanString(req.body?.targetClient);
    const targetCity = cleanString(req.body?.targetCity);
    const inferredProject = cleanString(rows[0]?.project || 'NOT SET');
    const targetJobsite = normalizeJobsiteName(req.body?.targetJobsite || inferredProject || 'NOT SET');
    const targetSystem = cleanString(req.body?.targetSystem || movingSegment.system || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';

    if (!targetClient || !targetCity || !targetJobsite) {
      return res.status(400).json({ success: false, error: 'Target client, city, and jobsite are required' });
    }

    let target = null;
    const targetResult = await pool.query(
      `SELECT * FROM planner_records
       WHERE LOWER(client) = LOWER($1)
         AND LOWER(city) = LOWER($2)
         AND LOWER(jobsite) = LOWER($3)
       ORDER BY updated_at DESC
       LIMIT 1`,
      [targetClient, targetCity, targetJobsite]
    );
    if (targetResult.rows.length) {
      target = normalizeRecordRow(targetResult.rows[0]);
    } else {
      target = {
        record_date: source.record_date,
        client: targetClient,
        city: targetCity,
        street: '',
        jobsite: targetJobsite,
        status: '',
        saved_by: req.user.displayName || req.user.username,
        systems: { storm: [], sanitary: [] }
      };
      const inserted = await pool.query(
        `INSERT INTO planner_records (record_date, client, city, street, jobsite, status, saved_by, data)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
         RETURNING *`,
        [
          target.record_date,
          target.client,
          target.city,
          target.street,
          target.jobsite,
          '',
          target.saved_by,
          JSON.stringify(serializeRecordData(target))
        ]
      );
      target = normalizeRecordRow(inserted.rows[0]);
    }

    movingSegment.system = targetSystem;
    target.systems[targetSystem] = Array.isArray(target.systems[targetSystem]) ? target.systems[targetSystem] : [];
    target.systems[targetSystem].push(movingSegment);

    await persistRecord(source);
    const savedTarget = await persistRecord(target);
    res.json({ success: true, target: savedTarget });
  } catch (error) {
    console.error('MOVE SEGMENT ERROR:', error);
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

app.put('/pricing-rates/:dia', requireAuth, requireAdmin, async (req, res) => {
  try {
    const dia = upperCleanString(req.params.dia || req.body?.dia);
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

app.delete('/pricing-rates/:dia', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM pricing_rates WHERE dia = $1 RETURNING dia', [req.params.dia]);
    if (!result.rows.length) return res.status(404).json({ success: false, error: 'DIA rate not found' });
    res.json({ success: true, deletedDia: result.rows[0].dia });
  } catch (error) {
    console.error('DELETE PRICING RATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/daily-reports', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM daily_reports ORDER BY report_date DESC, updated_at DESC');
    const reports = result.rows.map((row) => ({ ...row, files: Array.isArray(row.files) ? row.files : parseJsonObject(row.files, []) }));
    res.json({ success: true, reports });
  } catch (error) {
    console.error('GET DAILY REPORTS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/daily-reports', requireAuth, requireAdmin, upload.array('files'), async (req, res) => {
  try {
    const files = (req.files || []).map(fileToStoredJson);
    const result = await pool.query(
      `INSERT INTO daily_reports (title, report_date, notes, files, created_by)
       VALUES ($1, $2, $3, $4::jsonb, $5)
       RETURNING *`,
      [
        cleanString(req.body?.title),
        cleanString(req.body?.report_date || new Date().toISOString().slice(0, 10)),
        cleanString(req.body?.notes),
        JSON.stringify(files),
        req.user.displayName || req.user.username
      ]
    );
    res.status(201).json({ success: true, report: result.rows[0] });
  } catch (error) {
    console.error('CREATE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/daily-reports/:id', requireAuth, requireAdmin, upload.array('files'), async (req, res) => {
  try {
    const existingResult = await pool.query('SELECT * FROM daily_reports WHERE id = $1 LIMIT 1', [req.params.id]);
    if (!existingResult.rows.length) return res.status(404).json({ success: false, error: 'Daily report not found' });
    const current = existingResult.rows[0];
    const currentFiles = Array.isArray(current.files) ? current.files : parseJsonObject(current.files, []);
    const keepIds = new Set([].concat(req.body?.keepFileIds || []).filter(Boolean));
    const keptFiles = keepIds.size ? currentFiles.filter((file) => keepIds.has(file.id)) : currentFiles;
    const addedFiles = (req.files || []).map(fileToStoredJson);
    const nextFiles = [...keptFiles, ...addedFiles];
    const result = await pool.query(
      `UPDATE daily_reports
       SET title = $1,
           report_date = $2,
           notes = $3,
           files = $4::jsonb,
           updated_at = NOW()
       WHERE id = $5
       RETURNING *`,
      [cleanString(req.body?.title), cleanString(req.body?.report_date || current.report_date), cleanString(req.body?.notes), JSON.stringify(nextFiles), req.params.id]
    );
    res.json({ success: true, report: result.rows[0] });
  } catch (error) {
    console.error('UPDATE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/daily-reports/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM daily_reports WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('DELETE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/jobsite-assets', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jobsite_assets ORDER BY LOWER(client), LOWER(city), LOWER(jobsite), updated_at DESC');
    const assets = result.rows.map((row) => ({ ...row, files: Array.isArray(row.files) ? row.files : parseJsonObject(row.files, []) }));
    res.json({ success: true, assets });
  } catch (error) {
    console.error('GET JOBSITE ASSETS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/jobsite-assets', requireAuth, requireAdmin, upload.array('files'), async (req, res) => {
  try {
    const files = (req.files || []).map(fileToStoredJson);
    const result = await pool.query(
      `INSERT INTO jobsite_assets
       (client, city, jobsite, contact_name, contact_phone, contact_email, notes, drive_url, files, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
       RETURNING *`,
      [
        upperCleanString(req.body?.assetClient || req.body?.client),
        upperCleanString(req.body?.assetCity || req.body?.city),
        normalizeJobsiteName(req.body?.assetJobsite || req.body?.jobsite),
        cleanString(req.body?.assetContactName || req.body?.contactName),
        cleanString(req.body?.assetContactPhone || req.body?.contactPhone),
        cleanString(req.body?.assetContactEmail || req.body?.contactEmail),
        cleanString(req.body?.assetNotes || req.body?.notes),
        cleanString(req.body?.assetDriveUrl || req.body?.driveUrl),
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

app.delete('/jobsite-assets/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM jobsite_assets WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('DELETE JOBSITE ASSET ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/imports/wincan/preview', requireAuth, requireMike, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Upload a DB3 file.' });
    const name = req.file.originalname.toLowerCase();
    if (!name.endsWith('.db3') && !name.endsWith('.sqlite') && !name.endsWith('.db')) {
      return res.status(400).json({ success: false, error: 'This build supports DB3/SQLite project imports. Screenshot/PDF OCR fallback is not enabled in this bundle yet.' });
    }

    const rows = await parseDb3(req.file.buffer);
    const targetClient = cleanString(req.body?.targetClient);
    const targetCity = cleanString(req.body?.targetCity);
    const targetJobsite = normalizeJobsiteName(req.body?.targetJobsite || 'NOT SET');
    const targetSystem = cleanString(req.body?.targetSystem || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';

    const existingResult = await pool.query(
      `SELECT * FROM planner_records
       WHERE LOWER(client) = LOWER($1)
         AND LOWER(city) = LOWER($2)
         AND LOWER(jobsite) = LOWER($3)`,
      [targetClient || '', targetCity || '', targetJobsite || 'NOT SET']
    );
    const existingRecords = existingResult.rows.map(normalizeRecordRow);
    const existingRefs = new Set();
    existingRecords.forEach((record) => {
      (record.systems[targetSystem] || []).forEach((segment) => existingRefs.add(String(segment.reference || '').toLowerCase()));
    });

    const previewRows = rows.map((row) => ({
      ...row,
      duplicate: existingRefs.has(String(row.reference || '').toLowerCase())
    }));

    res.json({ success: true, sourceKind: 'DB3', defaultJobsite: cleanString(previewRows[0]?.project || 'NOT SET'), rows: previewRows });
  } catch (error) {
    console.error('IMPORT PREVIEW ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/imports/wincan/commit', requireAuth, requireMike, async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
    const targetClient = cleanString(req.body?.targetClient);
    const targetCity = cleanString(req.body?.targetCity);
    const targetJobsite = normalizeJobsiteName(req.body?.targetJobsite || 'NOT SET');
    const targetSystem = cleanString(req.body?.targetSystem || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
    if (!targetClient || !targetCity || !targetJobsite) {
      return res.status(400).json({ success: false, error: 'Target client, city, and jobsite are required' });
    }

    const existingResult = await pool.query(
      `SELECT * FROM planner_records
       WHERE LOWER(client) = LOWER($1)
         AND LOWER(city) = LOWER($2)
         AND LOWER(jobsite) = LOWER($3)
       ORDER BY updated_at DESC
       LIMIT 1`,
      [targetClient, targetCity, targetJobsite]
    );
    let record;
    if (existingResult.rows.length) {
      record = normalizeRecordRow(existingResult.rows[0]);
    } else {
      record = {
        record_date: new Date().toISOString().slice(0, 10),
        client: targetClient,
        city: targetCity,
        street: '',
        jobsite: targetJobsite,
        status: '',
        saved_by: req.user.displayName || req.user.username,
        systems: { storm: [], sanitary: [] }
      };
      const inserted = await pool.query(
        `INSERT INTO planner_records (record_date, client, city, street, jobsite, status, saved_by, data)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
         RETURNING *`,
        [
          record.record_date,
          record.client,
          record.city,
          record.street,
          record.jobsite,
          '',
          record.saved_by,
          JSON.stringify(serializeRecordData(record))
        ]
      );
      record = normalizeRecordRow(inserted.rows[0]);
    }

    const refSet = new Set((record.systems[targetSystem] || []).map((segment) => String(segment.reference || '').toLowerCase()));
    rows.forEach((row) => {
      if (!row || row.duplicate) return;
      if (refSet.has(String(row.reference || '').toLowerCase())) return;
      const segment = normalizeSegment({
        id: crypto.randomUUID(),
        reference: row.reference,
        upstream: row.upstream,
        downstream: row.downstream,
        dia: row.dia,
        material: row.material,
        length: row.length,
        footage: row.length,
        street: row.street,
        system: targetSystem,
        versions: [
          defaultVersion(req.user.displayName || req.user.username, {
            status: 'neutral',
            recordedDate: record.record_date,
            notes: 'Imported from WinCan DB3.'
          })
        ]
      }, req.user.displayName || req.user.username);
      record.systems[targetSystem].push(segment);
      refSet.add(String(segment.reference || '').toLowerCase());
    });

    record.saved_by = req.user.displayName || req.user.username;
    const saved = await persistRecord(record);
    res.json({ success: true, record: saved });
  } catch (error) {
    console.error('IMPORT COMMIT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

registerOutlookRoutes(app, { pool, requireAuth, currentToken, corsOrigins: CORS_ORIGINS });
registerPortalFilesRoutes(app, { pool, requireAuth, requireAdmin });

const autoImportPlugin = createAutoImportPlugin({
  pool,
  requireMike,
  requireAuth,
  writeSegment: async (jobsiteId, payload, savedBy) => {
    const record = await fetchRecordById(String(jobsiteId));
    if (!record) throw new Error(`Planner record not found for jobsite id ${jobsiteId}`);
    const system = cleanString(payload.system || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
    const segment = normalizeSegment(
      {
        id: payload.id,
        reference: payload.reference,
        upstream: payload.upstream,
        downstream: payload.downstream,
        dia: payload.dia,
        material: payload.material,
        length: payload.length,
        footage: payload.footage,
        street: record.street,
        system,
        versions: payload.versions
      },
      savedBy || 'System'
    );
    record.systems[system] = Array.isArray(record.systems[system]) ? record.systems[system] : [];
    const refLower = String(segment.reference || '').toLowerCase();
    record.systems[system] = record.systems[system].filter(
      (item) => String(item.reference || '').toLowerCase() !== refLower
    );
    record.systems[system].push(segment);
    record.saved_by = savedBy || record.saved_by;
    await persistRecord(record);
  },
  buildVersion: (payload) => defaultVersion(payload.savedBy || 'System', payload)
});
app.use('/auto-import-plugin', requireAuth, autoImportPlugin.router);

app.use((error, req, res, next) => {
  if (error && /CORS blocked/.test(error.message || '')) {
    return res.status(403).json({ success: false, error: error.message });
  }
  console.error('UNHANDLED ERROR:', error);
  res.status(500).json({ success: false, error: error.message || 'Server error' });
});

ensureSchema()
  .then(async () => {
    await autoImportPlugin.initSchema();
    app.listen(PORT, () => {
      console.log(`Horizon backend listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('BOOT ERROR:', error);
    process.exit(1);
  });
