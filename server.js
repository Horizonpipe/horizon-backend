
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
const { registerSignupRoutes } = require('./signup.routes');

const app = express();
app.set('trust proxy', 1);

/** Comma-separated list, or a single `*` to reflect any Origin (Bearer auth still required for data). */
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

function isOnRenderOrigin(origin) {
  try {
    const h = new URL(origin).hostname;
    return h === 'onrender.com' || h.endsWith('.onrender.com');
  } catch {
    return false;
  }
}

const corsOptions = {
  origin(origin, callback) {
    const allowAny = CORS_ORIGINS.length === 0 || (CORS_ORIGINS.length === 1 && CORS_ORIGINS[0] === '*');
    if (allowAny) {
      return callback(null, origin || true);
    }
    if (!origin) {
      return callback(null, true);
    }
    if (CORS_ORIGINS.includes(origin)) {
      return callback(null, origin);
    }
    if (isOnRenderOrigin(origin)) {
      return callback(null, origin);
    }
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Session-Token',
    'Range',
    'Accept',
    'If-None-Match',
    'If-Modified-Since'
  ],
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

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;

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

function cleanString(value) {
  return String(value || '').trim();
}

function upperCleanString(value) {
  return cleanString(value).toUpperCase();
}

function emptyRoles() {
  return {
    camera: false,
    vac: false,
    simpleVac: false,
    email: false,
    psrPlanner: false,
    pricingView: false,
    footageView: false
  };
}

function normalizeRoles(value) {
  const defaults = emptyRoles();
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return {
      camera: value.camera === true || value.can_camera === true,
      vac: value.vac === true || value.can_vac === true,
      simpleVac: value.simpleVac === true || value.simple_vac === true,
      email: value.email === true,
      psrPlanner: value.psrPlanner === true || value.viewPsr === true,
      pricingView: value.pricingView === true || value.pricing === true,
      footageView: value.footageView === true || value.footage === true
    };
  }
  if (typeof value === 'string') {
    try {
      return normalizeRoles(JSON.parse(value));
    } catch (error) {
      return defaults;
    }
  }
  return defaults;
}

/**
 * Self-signup accounts must be explicitly enabled by admin before they can sign in.
 * We treat "any one permission enabled" as active access.
 */
function userHasAnyAssignedAccess(row) {
  if (row?.is_admin) return true;
  const roles = normalizeRoles(row?.roles);
  const hasRoleAccess = Object.values(roles).some((v) => v === true);
  const hasPortalFiles = row?.portal_files_access_granted === true;
  const hasPortalPermissionUi =
    !!row?.portal_permissions_access || portalPermissionsWhitelistHas(row?.username);
  return hasRoleAccess || hasPortalFiles || hasPortalPermissionUi;
}

/** Legacy per-user prefix (kept only when explicitly re-enabled). */
const PORTAL_FILES_CLIENT_ID = 'portal-users';

/**
 * When both are set, every signed-in user gets this client/job in `/session` and the portal UI loads one shared Wasabi prefix (team bucket). Example: PORTAL_FORCE_CLIENT_ID=portal-users PORTAL_FORCE_JOB_ID=15
 */
const PORTAL_FORCE_CLIENT_ID = (process.env.PORTAL_FORCE_CLIENT_ID || '').trim();
const PORTAL_FORCE_JOB_ID = (process.env.PORTAL_FORCE_JOB_ID || '').trim();
const PORTAL_FORCE_JOB_SCOPE = PORTAL_FORCE_CLIENT_ID && PORTAL_FORCE_JOB_ID;
/**
 * Shared default portal scope for all users when no explicit user mapping exists.
 * Defaults to `portal-users/8` per current production bucket layout.
 */
const PORTAL_SHARED_DEFAULT_CLIENT_ID = (process.env.PORTAL_SHARED_DEFAULT_CLIENT_ID || 'portal-users').trim();
const PORTAL_SHARED_DEFAULT_JOB_ID = (process.env.PORTAL_SHARED_DEFAULT_JOB_ID || '8').trim();
const PORTAL_SHARED_DEFAULT_SCOPE = PORTAL_SHARED_DEFAULT_CLIENT_ID && PORTAL_SHARED_DEFAULT_JOB_ID;
/** Backward-compat toggle: set `PORTAL_USER_SCOPED_DEFAULTS=1` to restore `portal-users/{userId}` defaults. */
const PORTAL_USER_SCOPED_DEFAULTS =
  String(process.env.PORTAL_USER_SCOPED_DEFAULTS || '1').trim().toLowerCase() === '1' ||
  String(process.env.PORTAL_USER_SCOPED_DEFAULTS || '1').trim().toLowerCase() === 'true';

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
  const selfSignup = row?.self_signup === true;
  const legacyUserScoped = id != null && String(id).trim() && PORTAL_USER_SCOPED_DEFAULTS;
  const explicitClient =
    row?.portal_files_client_id != null && String(row.portal_files_client_id).trim()
      ? String(row.portal_files_client_id).trim()
      : '';
  const explicitJob =
    row?.portal_files_job_id != null && String(row.portal_files_job_id).trim()
      ? String(row.portal_files_job_id).trim()
      : '';
  const hasExplicitScope = !!(explicitClient && explicitJob);
  /** Self-signup users start false until an admin enables portal file access. */
  const portalFilesAccessGranted = row.portal_files_access_granted === true;

  let portalFilesClientId;
  let portalFilesJobId;
  if (!portalFilesAccessGranted) {
    portalFilesClientId = undefined;
    portalFilesJobId = undefined;
  } else if (hasExplicitScope) {
    portalFilesClientId = explicitClient;
    portalFilesJobId = explicitJob;
  } else if (selfSignup) {
    // Self-signup users must be explicitly scoped by admin before any portal file visibility.
    portalFilesClientId = undefined;
    portalFilesJobId = undefined;
  } else if (PORTAL_FORCE_JOB_SCOPE) {
    portalFilesClientId = PORTAL_FORCE_CLIENT_ID;
    portalFilesJobId = PORTAL_FORCE_JOB_ID;
  } else if (PORTAL_SHARED_DEFAULT_SCOPE) {
    portalFilesClientId = PORTAL_SHARED_DEFAULT_CLIENT_ID;
    portalFilesJobId = PORTAL_SHARED_DEFAULT_JOB_ID;
  } else if (legacyUserScoped) {
    portalFilesClientId = PORTAL_FILES_CLIENT_ID;
    portalFilesJobId = String(id);
  } else {
    portalFilesClientId = undefined;
    portalFilesJobId = undefined;
  }

  return {
    id,
    username: row.username,
    displayName: row.display_name || row.username,
    email: row.email || undefined,
    firstName: row.first_name || undefined,
    lastName: row.last_name || undefined,
    company: row.company || undefined,
    title: row.title || undefined,
    phone: row.phone || undefined,
    emailVerified: row.email_verified !== false,
    isAdmin: !!row.is_admin,
    roles: normalizeRoles(row.roles),
    mustChangePassword: !!row.must_change_password,
    selfSignup,
    portalFilesAccessGranted,
    portalFilesClientId,
    portalFilesJobId,
    portalScopes: [],
    psrScopes: [],
    portalPermissionsAccess:
      !!row.portal_permissions_access || portalPermissionsWhitelistHas(row.username)
  };
}

function normalizePortalScopeEntry(value) {
  if (!value || typeof value !== 'object') return null;
  const clientId = cleanString(value.clientId || value.client_id || value.client);
  const jobId = cleanString(value.jobId || value.job_id || value.job);
  if (!clientId || !jobId) return null;
  return { clientId, jobId };
}

function normalizePsrScopeEntry(value) {
  if (!value || typeof value !== 'object') return null;
  const client = upperCleanString(value.client);
  const city = upperCleanString(value.city);
  const jobsite = normalizeJobsiteName(value.jobsite, value.street);
  if (!client || !city || !jobsite) return null;
  return { client, city, jobsite };
}

function dedupePortalScopes(scopes) {
  const seen = new Set();
  const out = [];
  for (const item of Array.isArray(scopes) ? scopes : []) {
    const n = normalizePortalScopeEntry(item);
    if (!n) continue;
    const key = `${n.clientId}::${n.jobId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(n);
  }
  return out;
}

function dedupePsrScopes(scopes) {
  const seen = new Set();
  const out = [];
  for (const item of Array.isArray(scopes) ? scopes : []) {
    const n = normalizePsrScopeEntry(item);
    if (!n) continue;
    const key = `${n.client}::${n.city}::${n.jobsite}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(n);
  }
  return out;
}

function normalizePortalScopesPayload(value) {
  if (Array.isArray(value)) return dedupePortalScopes(value);
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return normalizePortalScopesPayload(parsed);
    } catch (error) {
      return [];
    }
  }
  return [];
}

function normalizePsrScopesPayload(value) {
  if (Array.isArray(value)) return dedupePsrScopes(value);
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return normalizePsrScopesPayload(parsed);
    } catch (error) {
      return [];
    }
  }
  return [];
}

async function readScopesForUserIds(userIds) {
  const ids = [...new Set((Array.isArray(userIds) ? userIds : []).map((id) => String(id || '').trim()).filter(Boolean))];
  const byUser = new Map();
  for (const id of ids) byUser.set(id, { portalScopes: [], psrScopes: [] });
  if (!ids.length) return byUser;

  const portalRes = await pool.query(
    `SELECT user_id::text AS user_id, client_id, job_id
     FROM user_portal_scopes
     WHERE user_id::text = ANY($1::text[])
     ORDER BY client_id, job_id`,
    [ids]
  );
  for (const row of portalRes.rows) {
    const key = String(row.user_id);
    if (!byUser.has(key)) byUser.set(key, { portalScopes: [], psrScopes: [] });
    byUser.get(key).portalScopes.push({ clientId: String(row.client_id), jobId: String(row.job_id) });
  }

  const psrRes = await pool.query(
    `SELECT user_id::text AS user_id, client, city, jobsite
     FROM user_psr_scopes
     WHERE user_id::text = ANY($1::text[])
     ORDER BY client, city, jobsite`,
    [ids]
  );
  for (const row of psrRes.rows) {
    const key = String(row.user_id);
    if (!byUser.has(key)) byUser.set(key, { portalScopes: [], psrScopes: [] });
    byUser
      .get(key)
      .psrScopes.push({ client: String(row.client || ''), city: String(row.city || ''), jobsite: String(row.jobsite || '') });
  }

  return byUser;
}

async function attachScopesToUsers(users) {
  const list = Array.isArray(users) ? users : [];
  const map = await readScopesForUserIds(list.map((u) => u.id));
  return list.map((u) => {
    const entry = map.get(String(u.id || '')) || { portalScopes: [], psrScopes: [] };
    return {
      ...u,
      portalScopes: dedupePortalScopes(entry.portalScopes),
      psrScopes: dedupePsrScopes(entry.psrScopes)
    };
  });
}

async function attachScopesToUser(user) {
  if (!user?.id) return { ...user, portalScopes: [], psrScopes: [] };
  const [withScopes] = await attachScopesToUsers([user]);
  return withScopes;
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
            u.is_admin, u.roles, u.must_change_password, u.portal_files_client_id, u.portal_files_job_id,
            u.portal_permissions_access, u.portal_files_access_granted, u.self_signup, u.email, u.first_name, u.last_name, u.company, u.title, u.phone, u.email_verified
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
  return attachScopesToUser(normalizeUser(row));
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

function userRoleEnabled(user, roleKey) {
  if (!user || !roleKey) return false;
  if (user.isAdmin) return true;
  const roles = normalizeRoles(user.roles);
  return roles[roleKey] === true;
}

function requireAnyRole(roleKeys, message = 'Access denied for this feature') {
  const keys = Array.isArray(roleKeys) ? roleKeys.filter(Boolean) : [];
  return function requireAnyRoleMiddleware(req, res, next) {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    if (req.user.isAdmin) return next();
    const allowed = keys.some((k) => userRoleEnabled(req.user, k));
    if (!allowed) {
      return res.status(403).json({ success: false, error: message });
    }
    return next();
  };
}

const requirePlannerAccess = requireAnyRole(
  ['psrPlanner', 'camera', 'vac', 'simpleVac', 'pricingView', 'footageView'],
  'Planner access is not enabled for this account'
);
const requirePricingAccess = requireAnyRole(
  ['pricingView'],
  'Pricing access is not enabled for this account'
);
const requireFootageAccess = requireAnyRole(
  ['footageView'],
  'Footage access is not enabled for this account'
);

function userCanAccessPsrScope(user, scope) {
  if (user?.isAdmin) return true;
  const scopes = dedupePsrScopes(user?.psrScopes || []);
  if (!scopes.length) return false;
  const client = upperCleanString(scope?.client);
  const city = upperCleanString(scope?.city);
  const jobsite = normalizeJobsiteName(scope?.jobsite, scope?.street);
  if (!client || !city || !jobsite) return false;
  return scopes.some(
    (entry) =>
      String(entry.client || '').toLowerCase() === client.toLowerCase() &&
      String(entry.city || '').toLowerCase() === city.toLowerCase() &&
      String(entry.jobsite || '').toLowerCase() === jobsite.toLowerCase()
  );
}

function buildPsrScopeWhere(user, alias = '') {
  if (user?.isAdmin) return { clause: 'TRUE', params: [] };
  const scopes = dedupePsrScopes(user?.psrScopes || []);
  if (!scopes.length) return { clause: 'FALSE', params: [] };
  const prefix = alias ? `${alias}.` : '';
  const clauses = [];
  const params = [];
  let index = 1;
  for (const scope of scopes) {
    clauses.push(
      `(LOWER(${prefix}client) = LOWER($${index++}) AND LOWER(${prefix}city) = LOWER($${index++}) AND LOWER(${prefix}jobsite) = LOWER($${index++}))`
    );
    params.push(scope.client, scope.city, scope.jobsite);
  }
  return { clause: clauses.join(' OR '), params };
}

function denyOutOfScope(res) {
  return res.status(403).json({ success: false, error: 'This account is not permitted for that PSR scope' });
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
      portal_files_client_id TEXT,
      portal_files_job_id TEXT,
      roles JSONB NOT NULL DEFAULT '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "pricingView": false, "footageView": false}'::jsonb,
      must_change_password BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const userAlters = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "pricingView": false, "footageView": false}'::jsonb`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_files_client_id TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_files_job_id TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_permissions_access BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS company TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS title TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_files_access_granted BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS self_signup BOOLEAN NOT NULL DEFAULT false`
  ];
  for (const query of userAlters) await pool.query(query);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uq
    ON users (LOWER(TRIM(email)))
    WHERE email IS NOT NULL AND BTRIM(email) <> ''
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS signup_verifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email_normalized TEXT NOT NULL UNIQUE,
      pin_hash TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      company TEXT NOT NULL,
      title TEXT,
      phone TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);
  await pool.query(`UPDATE users SET display_name = username WHERE display_name IS NULL OR btrim(display_name) = ''`);
  await pool.query(
    `ALTER TABLE users ALTER COLUMN roles SET DEFAULT '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "pricingView": false, "footageView": false}'::jsonb`
  );
  await pool.query(`ALTER TABLE users ALTER COLUMN portal_files_access_granted SET DEFAULT false`);
  await pool.query(
    `UPDATE users
     SET roles = '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "pricingView": false, "footageView": false}'::jsonb
     WHERE roles IS NULL`
  );
  await pool.query(
    `UPDATE users
     SET roles = '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "pricingView": false, "footageView": false}'::jsonb
                 || COALESCE(roles, '{}'::jsonb)`
  );
  await pool.query(
    `UPDATE users
     SET portal_files_access_granted = false
     WHERE portal_files_access_granted IS NULL`
  );
  await pool.query(`UPDATE users SET must_change_password = false WHERE must_change_password IS NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_portal_scopes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      job_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, client_id, job_id)
    )
  `);
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'user_portal_scopes'
          AND column_name = 'user_id'
          AND data_type <> 'text'
      ) THEN
        EXECUTE 'ALTER TABLE user_portal_scopes ALTER COLUMN user_id TYPE TEXT USING user_id::text';
      END IF;
    END $$;
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_portal_scopes_user_id ON user_portal_scopes (user_id)`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_portal_scopes_scope ON user_portal_scopes (client_id, job_id)`
  );
  await pool.query(
    `INSERT INTO user_portal_scopes (user_id, client_id, job_id)
     SELECT CAST(id AS text), portal_files_client_id, portal_files_job_id
     FROM users
     WHERE portal_files_access_granted = true
       AND portal_files_client_id IS NOT NULL
       AND BTRIM(portal_files_client_id) <> ''
       AND portal_files_job_id IS NOT NULL
       AND BTRIM(portal_files_job_id) <> ''
     ON CONFLICT (user_id, client_id, job_id) DO NOTHING`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_psr_scopes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT NOT NULL,
      client TEXT NOT NULL,
      city TEXT NOT NULL,
      jobsite TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, client, city, jobsite)
    )
  `);
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'user_psr_scopes'
          AND column_name = 'user_id'
          AND data_type <> 'text'
      ) THEN
        EXECUTE 'ALTER TABLE user_psr_scopes ALTER COLUMN user_id TYPE TEXT USING user_id::text';
      END IF;
    END $$;
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_psr_scopes_user_id ON user_psr_scopes (user_id)`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_psr_scopes_scope ON user_psr_scopes (client, city, jobsite)`
  );

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
  await pool.query(
    `INSERT INTO user_psr_scopes (user_id, client, city, jobsite)
     SELECT DISTINCT CAST(u.id AS text), pr.client, pr.city, pr.jobsite
     FROM users u
     JOIN planner_records pr ON true
     LEFT JOIN user_psr_scopes ups ON ups.user_id = CAST(u.id AS text)
     WHERE ups.user_id IS NULL
       AND u.is_admin = false
       AND (
         LOWER(COALESCE(u.roles ->> 'psrPlanner', 'false')) = 'true'
         OR LOWER(COALESCE(u.roles ->> 'camera', 'false')) = 'true'
         OR LOWER(COALESCE(u.roles ->> 'vac', 'false')) = 'true'
         OR LOWER(COALESCE(u.roles ->> 'simpleVac', 'false')) = 'true'
         OR LOWER(COALESCE(u.roles ->> 'pricingView', 'false')) = 'true'
         OR LOWER(COALESCE(u.roles ->> 'footageView', 'false')) = 'true'
       )
     ON CONFLICT (user_id, client, city, jobsite) DO NOTHING`
  );

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
      access_mode TEXT NOT NULL DEFAULT 'full',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `ALTER TABLE portal_path_grants
     ADD COLUMN IF NOT EXISTS access_mode TEXT NOT NULL DEFAULT 'full'`
  );
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

  await pool.query(`ALTER TABLE portal_share_access_log ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE portal_share_access_log ADD COLUMN IF NOT EXISTS company TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE portal_share_guest_sessions ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE portal_share_guest_sessions ADD COLUMN IF NOT EXISTS company TEXT NOT NULL DEFAULT ''`);

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

  await pool.query(`
    UPDATE users
    SET is_admin = true, updated_at = NOW()
    WHERE LOWER(TRIM(username)) = 'mik'
       OR LOWER(TRIM(COALESCE(display_name, ''))) LIKE 'mike strickland%'
  `);
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

app.get('/users', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, portal_permissions_access, self_signup
       FROM users
       ORDER BY LOWER(COALESCE(display_name, username)), LOWER(username)`
    );
    const currentUser = req.user;
    const normalizedRows = await attachScopesToUsers(result.rows.map((row) => normalizeUser(row)));
    const users = normalizedRows.map((normalized) => {
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

app.get('/permissions/tree', requireAuth, requireAdmin, async (req, res) => {
  try {
    const [portalRows, portalPathRows, psrRows] = await Promise.all([
      pool.query(
        `WITH scope_pairs AS (
           SELECT client_id, job_id FROM user_portal_scopes
           UNION
           SELECT portal_files_client_id AS client_id, portal_files_job_id AS job_id
           FROM users
           WHERE portal_files_client_id IS NOT NULL
             AND BTRIM(portal_files_client_id) <> ''
             AND portal_files_job_id IS NOT NULL
             AND BTRIM(portal_files_job_id) <> ''
           UNION
           SELECT client_id, job_id FROM portal_path_grants
         ),
         scope_pairs_clean AS (
           SELECT DISTINCT BTRIM(client_id) AS client_id, BTRIM(job_id) AS job_id
           FROM scope_pairs
           WHERE client_id IS NOT NULL AND BTRIM(client_id) <> ''
             AND job_id IS NOT NULL AND BTRIM(job_id) <> ''
         ),
         job_labels AS (
           SELECT DISTINCT ON (sp.client_id, sp.job_id)
             sp.client_id,
             sp.job_id,
             pr.client AS label_client,
             pr.city AS label_city,
             pr.jobsite AS label_jobsite
           FROM scope_pairs_clean sp
           LEFT JOIN planner_records pr
             ON LOWER(BTRIM(pr.client)) = LOWER(sp.client_id)
            AND (
              LOWER(BTRIM(pr.jobsite)) = LOWER(sp.job_id)
              OR CAST(pr.id AS text) = sp.job_id
            )
           ORDER BY sp.client_id, sp.job_id, pr.updated_at DESC NULLS LAST
         )
         SELECT client_id, job_id, label_client, label_city, label_jobsite
         FROM job_labels
         ORDER BY COALESCE(label_client, client_id), COALESCE(label_city, 'ZZZ'), COALESCE(label_jobsite, job_id)`
      ),
      pool.query(
        `SELECT client_id, job_id, path_prefix
         FROM portal_path_grants
         WHERE client_id IS NOT NULL AND BTRIM(client_id) <> ''
           AND job_id IS NOT NULL AND BTRIM(job_id) <> ''
         ORDER BY client_id, job_id, path_prefix`
      ),
      pool.query(
        `SELECT DISTINCT client, city, jobsite
         FROM planner_records
         WHERE BTRIM(client) <> '' AND BTRIM(city) <> '' AND BTRIM(jobsite) <> ''
         ORDER BY client, city, jobsite`
      )
    ]);

    const pathMap = new Map();
    for (const row of portalPathRows.rows) {
      const clientId = String(row.client_id || '').trim();
      const jobId = String(row.job_id || '').trim();
      if (!clientId || !jobId) continue;
      const key = `${clientId}|||${jobId}`;
      if (!pathMap.has(key)) pathMap.set(key, new Set());
      const p = String(row.path_prefix || '')
        .replace(/\\/g, '/')
        .replace(/^\/+|\/+$/g, '')
        .replace(/\/+/g, '/');
      pathMap.get(key).add(p || '/');
    }

    const portalMap = new Map();
    for (const row of portalRows.rows) {
      const clientId = String(row.client_id || '').trim();
      const jobId = String(row.job_id || '').trim();
      if (!clientId || !jobId) continue;
      const displayClient = upperCleanString(row.label_client || clientId);
      const displayCity = upperCleanString(row.label_city || 'NOT SET');
      const displayJobsite = normalizeJobsiteName(row.label_jobsite || jobId);
      if (!portalMap.has(displayClient)) portalMap.set(displayClient, new Map());
      const cityMap = portalMap.get(displayClient);
      if (!cityMap.has(displayCity)) cityMap.set(displayCity, []);
      cityMap.get(displayCity).push({
        clientId,
        jobId,
        jobsite: displayJobsite,
        paths: [...(pathMap.get(`${clientId}|||${jobId}`) || new Set(['/']))]
      });
    }
    const portalTree = [...portalMap.entries()].map(([client, cityMap]) => ({
      client,
      cities: [...cityMap.entries()].map(([city, jobs]) => ({
        city,
        jobs: jobs
          .filter((j, idx, arr) => arr.findIndex((x) => x.clientId === j.clientId && x.jobId === j.jobId) === idx)
          .sort((a, b) => a.jobsite.localeCompare(b.jobsite, undefined, { sensitivity: 'base' }))
      }))
    }));

    const psrMap = new Map();
    for (const row of psrRows.rows) {
      const client = upperCleanString(row.client);
      const city = upperCleanString(row.city);
      const jobsite = normalizeJobsiteName(row.jobsite, row.street);
      if (!client || !city || !jobsite) continue;
      if (!psrMap.has(client)) psrMap.set(client, new Map());
      const cityMap = psrMap.get(client);
      if (!cityMap.has(city)) cityMap.set(city, []);
      cityMap.get(city).push(jobsite);
    }
    const psrTree = [...psrMap.entries()].map(([client, cityMap]) => ({
      client,
      cities: [...cityMap.entries()].map(([city, jobsites]) => ({
        city,
        jobsites: [...new Set(jobsites)].sort()
      }))
    }));

    res.json({ success: true, portalTree, psrTree });
  } catch (error) {
    console.error('PERMISSIONS TREE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/login', async (req, res) => {
  const submittedUsername = cleanString(req.body?.username);
  const submittedPassword = cleanString(req.body?.password);

  if (!submittedUsername || !submittedPassword) {
    return res.status(400).json({ success: false, error: 'Email (or username) and password are required' });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, display_name, password, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id,
              email, email_verified, portal_files_access_granted, portal_permissions_access, self_signup
       FROM users u
       WHERE LOWER(TRIM(u.username)) = LOWER(TRIM($1))
          OR LOWER(TRIM(COALESCE(u.display_name, u.username))) = LOWER(TRIM($1))
          OR (u.email IS NOT NULL AND BTRIM(u.email) <> '' AND LOWER(TRIM(u.email)) = LOWER(TRIM($1)))
       LIMIT 1`,
      [submittedUsername]
    );

    if (!result.rows.length) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const row = result.rows[0];
    if (row.email_verified === false) {
      return res.status(403).json({
        success: false,
        error: 'This email is not verified yet. Complete sign-up or contact an administrator.'
      });
    }

    let passwordOk = false;
    let needsRehash = false;

    if (row.password && row.password.startsWith('$2')) {
      passwordOk = await bcrypt.compare(submittedPassword, row.password);
    } else if (row.password === submittedPassword) {
      passwordOk = true;
      needsRehash = true;
    }

    if (!passwordOk) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    if (!userHasAnyAssignedAccess(row)) {
      return res.status(403).json({
        success: false,
        error: 'Account created. Your access is pending admin approval.'
      });
    }

    if (needsRehash) {
      const hash = await bcrypt.hash(submittedPassword, 10);
      await pool.query('UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2', [hash, row.id]);
    }

    const user = await attachScopesToUser(normalizeUser(row));
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
  /** Planner-created accounts now default to no permissions until explicitly assigned by admin edit. */
  const roles = normalizeRoles({
    camera: false,
    vac: false,
    simpleVac: false,
    email: false,
    psrPlanner: false,
    pricingView: false,
    footageView: false
  });

  if (!username) {
    return res.status(400).json({ success: false, error: 'Username is required' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (
         username, display_name, password, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup
       )
       VALUES ($1, $2, $3, $4, $5::jsonb, true, NULL, NULL, false, false)
       RETURNING id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup`,
      [username, displayName, hash, isAdmin, JSON.stringify(roles)]
    );
    const user = await attachScopesToUser(normalizeUser(result.rows[0]));
    res.status(201).json({
      success: true,
      user,
      message: 'User created with no access. Assign roles/portal scope to enable.'
    });
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
  const hasPortalScopeInPayload =
    Object.prototype.hasOwnProperty.call(req.body || {}, 'portalFilesClientId') ||
    Object.prototype.hasOwnProperty.call(req.body || {}, 'portalFilesJobId');
  const portalFilesClientId = hasPortalScopeInPayload ? cleanString(req.body?.portalFilesClientId) : null;
  const portalFilesJobId = hasPortalScopeInPayload ? cleanString(req.body?.portalFilesJobId) : null;
  const hasAccessPayload = Object.prototype.hasOwnProperty.call(
    req.body || {},
    'portalFilesAccessGranted'
  );
  const hasSelfSignupPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'selfSignup');
  const hasPortalPermissionsPayload = Object.prototype.hasOwnProperty.call(
    req.body || {},
    'portalPermissionsAccess'
  );
  const hasPortalScopesPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'portalScopes');
  const hasPsrScopesPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'psrScopes');

  try {
    const currentResult = await pool.query(
      'SELECT id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, portal_permissions_access, self_signup FROM users WHERE id = $1 LIMIT 1',
      [id]
    );
    if (!currentResult.rows.length) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    const current = currentResult.rows[0];
    const scopeMap = await readScopesForUserIds([id]);
    const currentScopes = scopeMap.get(String(id)) || { portalScopes: [], psrScopes: [] };

    const nextDisplayName = displayName || current.display_name || current.username;
    const nextIsAdmin = isAdmin === null ? current.is_admin : isAdmin;
    const nextRoles = roles === null ? normalizeRoles(current.roles) : roles;
    let nextPortalFilesClientId = current.portal_files_client_id || null;
    let nextPortalFilesJobId = current.portal_files_job_id || null;
    if (hasPortalScopeInPayload) {
      if ((portalFilesClientId && !portalFilesJobId) || (!portalFilesClientId && portalFilesJobId)) {
        return res.status(400).json({
          success: false,
          error: 'portalFilesClientId and portalFilesJobId must be set together (or both empty).'
        });
      }
      nextPortalFilesClientId = portalFilesClientId || null;
      nextPortalFilesJobId = portalFilesJobId || null;
    }
    let nextPortalScopes = dedupePortalScopes(currentScopes.portalScopes);
    if (hasPortalScopesPayload) {
      nextPortalScopes = normalizePortalScopesPayload(req.body.portalScopes);
      nextPortalFilesClientId = nextPortalScopes[0]?.clientId || null;
      nextPortalFilesJobId = nextPortalScopes[0]?.jobId || null;
    } else if (hasPortalScopeInPayload) {
      nextPortalScopes =
        portalFilesClientId && portalFilesJobId
          ? [{ clientId: portalFilesClientId, jobId: portalFilesJobId }]
          : [];
    }
    let nextPsrScopes = dedupePsrScopes(currentScopes.psrScopes);
    if (hasPsrScopesPayload) {
      nextPsrScopes = normalizePsrScopesPayload(req.body.psrScopes);
    }

    let nextPortalFilesAccessGranted = current.portal_files_access_granted === true;
    if (hasAccessPayload) {
      nextPortalFilesAccessGranted = !!req.body.portalFilesAccessGranted;
    } else if (hasPortalScopesPayload) {
      nextPortalFilesAccessGranted = nextPortalScopes.length > 0;
    } else if (hasPortalScopeInPayload && portalFilesClientId && portalFilesJobId) {
      nextPortalFilesAccessGranted = true;
    }
    let nextSelfSignup = current.self_signup === true;
    if (hasSelfSignupPayload) {
      nextSelfSignup = !!req.body.selfSignup;
    }
    // When an admin approves/assigns access, this account should no longer be treated as locked self-signup.
    if (nextPortalFilesAccessGranted === true || nextIsAdmin === true) {
      nextSelfSignup = false;
    }

    const nextPortalPermissionsAccess = hasPortalPermissionsPayload
      ? !!req.body.portalPermissionsAccess
      : current.portal_permissions_access === true;

    await pool.query(
      `UPDATE users
       SET display_name = $1,
           is_admin = $2,
           roles = $3::jsonb,
           portal_files_client_id = $4,
           portal_files_job_id = $5,
           portal_files_access_granted = $6,
           self_signup = $7,
           portal_permissions_access = $8,
           updated_at = NOW()
       WHERE id = $9`,
      [
        nextDisplayName,
        nextIsAdmin,
        JSON.stringify(nextRoles),
        nextPortalFilesClientId,
        nextPortalFilesJobId,
        nextPortalFilesAccessGranted,
        nextSelfSignup,
        nextPortalPermissionsAccess,
        id
      ]
    );

    if (hasPortalScopesPayload || hasPortalScopeInPayload) {
      await pool.query('DELETE FROM user_portal_scopes WHERE user_id = $1', [String(id)]);
      for (const scope of nextPortalScopes) {
        await pool.query(
          `INSERT INTO user_portal_scopes (user_id, client_id, job_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (user_id, client_id, job_id) DO NOTHING`,
          [String(id), scope.clientId, scope.jobId]
        );
      }
    }

    if (hasPsrScopesPayload) {
      await pool.query('DELETE FROM user_psr_scopes WHERE user_id = $1', [String(id)]);
      for (const scope of nextPsrScopes) {
        await pool.query(
          `INSERT INTO user_psr_scopes (user_id, client, city, jobsite)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (user_id, client, city, jobsite) DO NOTHING`,
          [String(id), scope.client, scope.city, scope.jobsite]
        );
      }
    }

    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE users SET password = $1, must_change_password = false, updated_at = NOW() WHERE id = $2',
        [hash, id]
      );
    }

    const updatedResult = await pool.query(
      'SELECT id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, portal_permissions_access, self_signup FROM users WHERE id = $1 LIMIT 1',
      [id]
    );

    const user = await attachScopesToUser(normalizeUser(updatedResult.rows[0]));
    res.json({ success: true, user });
  } catch (error) {
    console.error('UPDATE USER ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'User id is required' });
  }
  if (String(req.user?.id || '') === id) {
    return res.status(400).json({ success: false, error: 'You cannot delete your own account.' });
  }
  try {
    const targetResult = await pool.query(
      'SELECT id, username, is_admin FROM users WHERE id = $1 LIMIT 1',
      [id]
    );
    if (!targetResult.rows.length) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    const target = targetResult.rows[0];
    if (target.is_admin) {
      const admins = await pool.query('SELECT COUNT(*)::int AS count FROM users WHERE is_admin = true');
      const adminCount = Number(admins.rows?.[0]?.count || 0);
      if (adminCount <= 1) {
        return res
          .status(400)
          .json({ success: false, error: 'Cannot delete the last admin account.' });
      }
    }
    await pool.query('DELETE FROM auth_sessions WHERE user_id = $1', [id]);
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    return res.json({ success: true, deletedUserId: id, username: target.username });
  } catch (error) {
    console.error('DELETE USER ERROR:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/records', requireAuth, requirePlannerAccess, async (req, res) => {
  try {
    const scopeFilter = buildPsrScopeWhere(req.user);
    const result = await pool.query(
      `SELECT id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at
       FROM planner_records
       WHERE ${scopeFilter.clause}
       ORDER BY LOWER(client), LOWER(city), LOWER(jobsite), record_date DESC, updated_at DESC`,
      scopeFilter.params
    );
    const records = result.rows.map(normalizeRecordRow);
    res.json({ success: true, records });
  } catch (error) {
    console.error('GET RECORDS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records', requireAuth, requirePlannerAccess, async (req, res) => {
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
    if (!userCanAccessPsrScope(req.user, record)) return denyOutOfScope(res);

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

app.put('/records/:id', requireAuth, requirePlannerAccess, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    if (!userCanAccessPsrScope(req.user, record)) return denyOutOfScope(res);

    record.record_date = cleanString(req.body?.record_date || req.body?.date || record.record_date);
    record.client = upperCleanString(req.body?.client || record.client);
    record.city = upperCleanString(req.body?.city || record.city);
    record.street = upperCleanString(req.body?.street || record.street);
    record.jobsite = normalizeJobsiteName(req.body?.jobsite || record.jobsite, req.body?.street || record.street);
    record.status = cleanString(req.body?.status || record.status);
    record.saved_by = cleanString(req.body?.saved_by || req.body?.savedBy || req.user.displayName || req.user.username);
    if (!userCanAccessPsrScope(req.user, record)) return denyOutOfScope(res);

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

app.post('/records/:id/segments', requireAuth, requirePlannerAccess, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    if (!userCanAccessPsrScope(req.user, record)) return denyOutOfScope(res);
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

app.post('/records/:id/segments/bulk', requireAuth, requirePlannerAccess, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    if (!userCanAccessPsrScope(req.user, record)) return denyOutOfScope(res);
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

app.put('/records/:id/segments/:segmentId', requireAuth, requirePlannerAccess, async (req, res) => {
  try {
    const record = await fetchRecordById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    if (!userCanAccessPsrScope(req.user, record)) return denyOutOfScope(res);

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
    if (!userCanAccessPsrScope(req.user, record)) return denyOutOfScope(res);
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

app.get('/pricing-rates', requireAuth, requirePricingAccess, async (req, res) => {
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

app.get('/jobsite-assets', requireAuth, requireFootageAccess, async (req, res) => {
  try {
    const scopeFilter = buildPsrScopeWhere(req.user);
    const result = await pool.query(
      `SELECT * FROM jobsite_assets
       WHERE ${scopeFilter.clause}
       ORDER BY LOWER(client), LOWER(city), LOWER(jobsite), updated_at DESC`,
      scopeFilter.params
    );
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
registerSignupRoutes(app, { pool, cleanString, normalizeRoles, issueSession, normalizeUser });

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
