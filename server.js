
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const initSqlJs = require('sql.js');
const { Pool } = require('pg');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { ensureOutlookSchema, registerOutlookRoutes } = require('./outlook');
const { registerPortalFilesRoutes } = require('./portal-files.routes');
const { createAutoImportPlugin } = require('./auto-import-plugin.routes');
const { registerSignupRoutes } = require('./signup.routes');
const { resolveCapabilities, canAccessAdminPanel } = require('./capabilities');

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
    'X-HP-Portal-Mode',
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
app.use((req, res, next) => {
  res.on('finish', () => {
    const method = String(req.method || '').toUpperCase();
    const writable = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
    if (!writable) return;
    if (res.statusCode >= 500) return;
    queueWasabiStateSnapshot(`${method} ${req.originalUrl || req.url || ''}`);
  });
  next();
});

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

function createWasabiStateClient() {
  const accessKeyId = String(process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY || '').trim();
  const secretAccessKey = String(process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY || '').trim();
  const region = String(process.env.WASABI_REGION || 'us-east-1').trim();
  const endpoint = String(process.env.WASABI_ENDPOINT || '').trim();
  if (!accessKeyId || !secretAccessKey) return null;
  return new S3Client({
    region,
    endpoint: endpoint || undefined,
    forcePathStyle: !!endpoint,
    credentials: { accessKeyId, secretAccessKey }
  });
}

const WASABI_STATE_BUCKET = String(process.env.WASABI_BUCKET || '').trim();
const WASABI_STATE_PREFIX = String(process.env.WASABI_PIPESYNC_STATE_PREFIX || 'clients/portal-users/jobs/3/system-state')
  .trim()
  .replace(/\/+$/, '');
const WASABI_STATE_SNAPSHOT_MS = Math.max(
  10000,
  Math.min(300000, Number(process.env.WASABI_STATE_SNAPSHOT_MS || 60000))
);
const WASABI_STATE_SNAPSHOT_ON_WRITE =
  String(process.env.WASABI_STATE_SNAPSHOT_ON_WRITE || '1').trim().toLowerCase() !== '0';
const WASABI_STATE_WRITE_DEBOUNCE_MS = Math.max(
  1000,
  Math.min(60000, Number(process.env.WASABI_STATE_WRITE_DEBOUNCE_MS || 5000))
);
const WASABI_WRITES_PRIMARY_ENABLED =
  String(process.env.WASABI_WRITES_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_WRITES_PRIMARY_STRICT =
  String(process.env.WASABI_WRITES_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_ALL_READS_PRIMARY_ENABLED =
  String(process.env.WASABI_ALL_READS_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_ALL_READS_PRIMARY_STRICT =
  String(process.env.WASABI_ALL_READS_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_SQL_MIRROR_ENABLED =
  String(process.env.WASABI_SQL_MIRROR_ENABLED || '1').trim().toLowerCase() !== '0';
const WASABI_SQL_MIRROR_INCLUDE_PARAMS =
  String(process.env.WASABI_SQL_MIRROR_INCLUDE_PARAMS || '0').trim().toLowerCase() === '1';
const WASABI_SQL_MIRROR_PREFIX = String(
  process.env.WASABI_SQL_MIRROR_PREFIX || 'clients/portal-users/jobs/3/sql-mirror'
)
  .trim()
  .replace(/\/+$/, '');
const WASABI_SQL_MIRROR_FLUSH_MS = Math.max(
  500,
  Math.min(15000, Number(process.env.WASABI_SQL_MIRROR_FLUSH_MS || 2000))
);
const WASABI_SQL_MIRROR_MAX_BUFFER = Math.max(
  10,
  Math.min(500, Number(process.env.WASABI_SQL_MIRROR_MAX_BUFFER || 100))
);
const WASABI_AUTH_FALLBACK_ENABLED =
  String(process.env.WASABI_AUTH_FALLBACK_ENABLED || '1').trim().toLowerCase() !== '0';
const WASABI_AUTH_FALLBACK_CACHE_MS = Math.max(
  1000,
  Math.min(60000, Number(process.env.WASABI_AUTH_FALLBACK_CACHE_MS || 5000))
);
const WASABI_AUTH_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED || String(process.env.WASABI_AUTH_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_AUTH_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT || String(process.env.WASABI_AUTH_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_AUTH_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_AUTH_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_SCOPES_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED || String(process.env.WASABI_SCOPES_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_SCOPES_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT || String(process.env.WASABI_SCOPES_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_SCOPES_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_SCOPES_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_PERMISSIONS_TREE_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  String(process.env.WASABI_PERMISSIONS_TREE_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_PERMISSIONS_TREE_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  String(process.env.WASABI_PERMISSIONS_TREE_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_PERMISSIONS_TREE_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_PERMISSIONS_TREE_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_LOGIN_FALLBACK_ENABLED =
  String(process.env.WASABI_LOGIN_FALLBACK_ENABLED || '1').trim().toLowerCase() !== '0';
const WASABI_LOGIN_FALLBACK_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_LOGIN_FALLBACK_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_RECORDS_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED || String(process.env.WASABI_RECORDS_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_RECORDS_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT || String(process.env.WASABI_RECORDS_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_RECORDS_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_RECORDS_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_RECORD_DETAIL_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  String(process.env.WASABI_RECORD_DETAIL_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_RECORD_DETAIL_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  String(process.env.WASABI_RECORD_DETAIL_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_RECORD_DETAIL_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_RECORD_DETAIL_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_PRICING_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED || String(process.env.WASABI_PRICING_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_PRICING_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT || String(process.env.WASABI_PRICING_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_PRICING_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_PRICING_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_REPORTS_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED || String(process.env.WASABI_REPORTS_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_REPORTS_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT || String(process.env.WASABI_REPORTS_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_REPORTS_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_REPORTS_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_ASSETS_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED || String(process.env.WASABI_ASSETS_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_ASSETS_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT || String(process.env.WASABI_ASSETS_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_ASSETS_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_ASSETS_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_SYNC_STATE_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  String(process.env.WASABI_SYNC_STATE_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_SYNC_STATE_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  String(process.env.WASABI_SYNC_STATE_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_SYNC_STATE_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_SYNC_STATE_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_USERS_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED || String(process.env.WASABI_USERS_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_USERS_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT || String(process.env.WASABI_USERS_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_USERS_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_USERS_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  String(process.env.WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  String(process.env.WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
/** Planner-only: PSR planner rows + per-user PSR scopes (`user_psr_scopes`) live only in Wasabi — not Postgres CRUD. */
const _envPlannerStoreWasabiOnly =
  String(process.env.WASABI_PLANNER_STORE_WASABI_ONLY || '0').trim().toLowerCase() === '1';
/** Full app business data on Wasabi: planner + pricing + daily reports + jobsite assets (Postgres kept for auth/sessions/API checks). */
const WASABI_APP_DATA_STORE_WASABI_ONLY =
  String(process.env.WASABI_APP_DATA_STORE_WASABI_ONLY || '0').trim().toLowerCase() === '1';
const PLANNER_STORE_WASABI_ONLY = _envPlannerStoreWasabiOnly || WASABI_APP_DATA_STORE_WASABI_ONLY;
const WASABI_PLANNER_MIGRATE_FROM_POSTGRES_ON_BOOT =
  String(process.env.WASABI_PLANNER_MIGRATE_FROM_POSTGRES_ON_BOOT || '0').trim().toLowerCase() === '1';
const WASABI_APP_DATA_MIGRATE_FROM_POSTGRES_ON_BOOT =
  String(process.env.WASABI_APP_DATA_MIGRATE_FROM_POSTGRES_ON_BOOT || '0').trim().toLowerCase() === '1';
/** Boot one-shot: import Postgres app tables into snapshot (legacy planner flag OR explicit app-data flag). */
const MIGRATE_APP_DATA_FROM_POSTGRES_ON_BOOT =
  WASABI_APP_DATA_MIGRATE_FROM_POSTGRES_ON_BOOT || WASABI_PLANNER_MIGRATE_FROM_POSTGRES_ON_BOOT;
const WASABI_AUTO_IMPORT_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  WASABI_WRITES_PRIMARY_ENABLED ||
  String(process.env.WASABI_AUTO_IMPORT_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_AUTO_IMPORT_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  WASABI_WRITES_PRIMARY_STRICT ||
  String(process.env.WASABI_AUTO_IMPORT_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_AUTO_IMPORT_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_AUTO_IMPORT_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_PORTAL_DATA_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  WASABI_WRITES_PRIMARY_ENABLED ||
  String(process.env.WASABI_PORTAL_DATA_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_PORTAL_DATA_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  WASABI_WRITES_PRIMARY_STRICT ||
  String(process.env.WASABI_PORTAL_DATA_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_PORTAL_DATA_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_PORTAL_DATA_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_OUTLOOK_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  WASABI_WRITES_PRIMARY_ENABLED ||
  String(process.env.WASABI_OUTLOOK_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_OUTLOOK_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  WASABI_WRITES_PRIMARY_STRICT ||
  String(process.env.WASABI_OUTLOOK_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_OUTLOOK_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_OUTLOOK_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_SIGNUP_PRIMARY_ENABLED =
  WASABI_ALL_READS_PRIMARY_ENABLED ||
  WASABI_WRITES_PRIMARY_ENABLED ||
  String(process.env.WASABI_SIGNUP_PRIMARY_ENABLED || '0').trim().toLowerCase() === '1';
const WASABI_SIGNUP_PRIMARY_STRICT =
  WASABI_ALL_READS_PRIMARY_STRICT ||
  WASABI_WRITES_PRIMARY_STRICT ||
  String(process.env.WASABI_SIGNUP_PRIMARY_STRICT || '0').trim().toLowerCase() === '1';
const WASABI_SIGNUP_PRIMARY_MAX_SNAPSHOT_AGE_MS = Math.max(
  5000,
  Math.min(15 * 60 * 1000, Number(process.env.WASABI_SIGNUP_PRIMARY_MAX_SNAPSHOT_AGE_MS || 120000))
);
const WASABI_STATE_INCLUDE_ALL_TABLES =
  String(process.env.WASABI_STATE_INCLUDE_ALL_TABLES || '1').trim().toLowerCase() !== '0';
const WASABI_STATE_EXCLUDE_TABLES = new Set(
  String(process.env.WASABI_STATE_EXCLUDE_TABLES || '')
    .split(',')
    .map((v) => String(v || '').trim())
    .filter(Boolean)
);
const wasabiStateClient = createWasabiStateClient();
let wasabiStateSnapshotBusy = false;
let wasabiStateSnapshotTimer = null;
let wasabiStateLastQueuedAt = 0;
let wasabiStateLastRunAt = 0;
let wasabiStateLastReason = 'startup';
let wasabiSqlMirrorTimer = null;
let wasabiSqlMirrorBusy = false;
let wasabiSqlMirrorEvents = [];
let wasabiSqlMirrorLastFlushAt = 0;
let wasabiSqlMirrorTotalFlushed = 0;
let wasabiSqlMirrorLastError = '';
let wasabiLatestStateCache = null;
let wasabiLatestStateCacheAt = 0;
let wasabiStateWriteQueue = Promise.resolve();
let wasabiAutoImportHandledByWasabi = 0;
let wasabiAutoImportFallbackToPostgres = 0;
let wasabiAutoImportLastErrorAt = 0;
let wasabiAutoImportLastError = '';
let wasabiAutoImportFallbackSamples = [];
let wasabiPortalDataHandledByWasabi = 0;
let wasabiPortalDataFallbackToPostgres = 0;
let wasabiPortalDataLastErrorAt = 0;
let wasabiPortalDataLastError = '';
let wasabiPortalDataFallbackSamples = [];
let wasabiOutlookHandledByWasabi = 0;
let wasabiOutlookFallbackToPostgres = 0;
let wasabiOutlookLastErrorAt = 0;
let wasabiOutlookLastError = '';
let wasabiOutlookFallbackSamples = [];
let wasabiSignupHandledByWasabi = 0;
let wasabiSignupFallbackToPostgres = 0;
let wasabiSignupLastErrorAt = 0;
let wasabiSignupLastError = '';
let wasabiSignupFallbackSamples = [];

async function bodyToBuffer(body) {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body.transformToByteArray === 'function') {
    return Buffer.from(await body.transformToByteArray());
  }
  const chunks = [];
  for await (const chunk of body) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function loadWasabiLatestStateSnapshot(force = false) {
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) return null;
  const now = Date.now();
  if (!force && wasabiLatestStateCache && now - wasabiLatestStateCacheAt <= WASABI_AUTH_FALLBACK_CACHE_MS) {
    return wasabiLatestStateCache;
  }
  const out = await wasabiStateClient.send(
    new GetObjectCommand({
      Bucket: WASABI_STATE_BUCKET,
      Key: `${WASABI_STATE_PREFIX}/latest.json`
    })
  );
  const raw = await bodyToBuffer(out.Body);
  const parsed = JSON.parse(raw.toString('utf8'));
  wasabiLatestStateCache = parsed;
  wasabiLatestStateCacheAt = now;
  return parsed;
}

function nowIso() {
  return new Date().toISOString();
}

async function putWasabiStateObject(stateObject) {
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) {
    throw new Error('Wasabi state client is not configured');
  }
  const stamp = nowIso().replace(/[:.]/g, '-');
  const payload = Buffer.from(JSON.stringify(stateObject, null, 2), 'utf8');
  const latestKey = `${WASABI_STATE_PREFIX}/latest.json`;
  const archiveKey = `${WASABI_STATE_PREFIX}/history/snapshot-${stamp}.json`;
  await wasabiStateClient.send(
    new PutObjectCommand({
      Bucket: WASABI_STATE_BUCKET,
      Key: latestKey,
      Body: payload,
      ContentType: 'application/json'
    })
  );
  await wasabiStateClient.send(
    new PutObjectCommand({
      Bucket: WASABI_STATE_BUCKET,
      Key: archiveKey,
      Body: payload,
      ContentType: 'application/json'
    })
  );
  wasabiLatestStateCache = stateObject;
  wasabiLatestStateCacheAt = Date.now();
}

function snapshotStateShape(snapshot) {
  const data = snapshot && snapshot.data && typeof snapshot.data === 'object' ? snapshot.data : {};
  return {
    generatedAt: nowIso(),
    source: 'horizon-backend',
    scope: { clientId: 'portal-users', jobId: '3' },
    data
  };
}

function ensureSnapshotTable(data, tableName) {
  if (!data[tableName] || !Array.isArray(data[tableName])) data[tableName] = [];
  return data[tableName];
}

async function runWasabiStateWrite(reason, mutator) {
  if (!WASABI_WRITES_PRIMARY_ENABLED) {
    throw new Error('WASABI_WRITES_PRIMARY_ENABLED is off');
  }
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) {
    throw new Error('Wasabi state client is not configured');
  }
  const task = async () => {
    const snapshot = await loadWasabiLatestStateSnapshot(true);
    const next = snapshotStateShape(snapshot || {});
    await mutator(next.data);
    next.generatedAt = nowIso();
    next.reason = String(reason || 'mutation');
    await putWasabiStateObject(next);
    return next;
  };
  const run = wasabiStateWriteQueue.then(task, task);
  wasabiStateWriteQueue = run.catch(() => {});
  return run;
}

async function tryWasabiStateWrite(reason, mutator) {
  if (!WASABI_WRITES_PRIMARY_ENABLED) return false;
  try {
    await runWasabiStateWrite(reason, mutator);
    return true;
  } catch (error) {
    if (WASABI_WRITES_PRIMARY_STRICT) throw error;
    console.warn(`[wasabi-write] ${reason} failed, falling back to postgres:`, error?.message || error);
    return false;
  }
}

function snapshotMeta(snapshot) {
  const generatedAtIso = String(snapshot?.generatedAt || '');
  const generatedAtMs = Date.parse(generatedAtIso);
  const ageMs = Number.isFinite(generatedAtMs) ? Math.max(0, Date.now() - generatedAtMs) : null;
  return {
    generatedAt: Number.isFinite(generatedAtMs) ? new Date(generatedAtMs).toISOString() : null,
    ageMs,
    hasData: !!(snapshot && snapshot.data && typeof snapshot.data === 'object')
  };
}

function wasabiReadDomains() {
  return [
    { name: 'auth', enabled: WASABI_AUTH_PRIMARY_ENABLED, maxAgeMs: WASABI_AUTH_PRIMARY_MAX_SNAPSHOT_AGE_MS },
    { name: 'scopes', enabled: WASABI_SCOPES_PRIMARY_ENABLED, maxAgeMs: WASABI_SCOPES_PRIMARY_MAX_SNAPSHOT_AGE_MS },
    {
      name: 'permissionsTree',
      enabled: WASABI_PERMISSIONS_TREE_PRIMARY_ENABLED,
      maxAgeMs: WASABI_PERMISSIONS_TREE_PRIMARY_MAX_SNAPSHOT_AGE_MS
    },
    { name: 'records', enabled: WASABI_RECORDS_PRIMARY_ENABLED, maxAgeMs: WASABI_RECORDS_PRIMARY_MAX_SNAPSHOT_AGE_MS },
    {
      name: 'recordDetail',
      enabled: WASABI_RECORD_DETAIL_PRIMARY_ENABLED,
      maxAgeMs: WASABI_RECORD_DETAIL_PRIMARY_MAX_SNAPSHOT_AGE_MS
    },
    { name: 'pricing', enabled: WASABI_PRICING_PRIMARY_ENABLED, maxAgeMs: WASABI_PRICING_PRIMARY_MAX_SNAPSHOT_AGE_MS },
    { name: 'reports', enabled: WASABI_REPORTS_PRIMARY_ENABLED, maxAgeMs: WASABI_REPORTS_PRIMARY_MAX_SNAPSHOT_AGE_MS },
    { name: 'assets', enabled: WASABI_ASSETS_PRIMARY_ENABLED, maxAgeMs: WASABI_ASSETS_PRIMARY_MAX_SNAPSHOT_AGE_MS },
    {
      name: 'syncState',
      enabled: WASABI_SYNC_STATE_PRIMARY_ENABLED,
      maxAgeMs: WASABI_SYNC_STATE_PRIMARY_MAX_SNAPSHOT_AGE_MS
    },
    { name: 'users', enabled: WASABI_USERS_PRIMARY_ENABLED, maxAgeMs: WASABI_USERS_PRIMARY_MAX_SNAPSHOT_AGE_MS },
    {
      name: 'plannerScopeLookup',
      enabled: WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_ENABLED,
      maxAgeMs: WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_MAX_SNAPSHOT_AGE_MS
    },
    {
      name: 'autoImport',
      enabled: WASABI_AUTO_IMPORT_PRIMARY_ENABLED,
      maxAgeMs: WASABI_AUTO_IMPORT_PRIMARY_MAX_SNAPSHOT_AGE_MS
    },
    {
      name: 'portalData',
      enabled: WASABI_PORTAL_DATA_PRIMARY_ENABLED,
      maxAgeMs: WASABI_PORTAL_DATA_PRIMARY_MAX_SNAPSHOT_AGE_MS
    },
    {
      name: 'outlook',
      enabled: WASABI_OUTLOOK_PRIMARY_ENABLED,
      maxAgeMs: WASABI_OUTLOOK_PRIMARY_MAX_SNAPSHOT_AGE_MS
    },
    {
      name: 'signup',
      enabled: WASABI_SIGNUP_PRIMARY_ENABLED,
      maxAgeMs: WASABI_SIGNUP_PRIMARY_MAX_SNAPSHOT_AGE_MS
    }
  ];
}

function evaluateWasabiRuntimeReadiness(snapshot) {
  const meta = snapshotMeta(snapshot);
  const data = snapshot && snapshot.data && typeof snapshot.data === 'object' ? snapshot.data : {};
  const tableCounts = Object.fromEntries(
    Object.entries(data)
      .filter(([, value]) => Array.isArray(value))
      .map(([name, value]) => [name, value.length])
  );
  const domains = wasabiReadDomains();
  const freshnessByDomain = Object.fromEntries(
    domains.map((domain) => [
      domain.name,
      meta.ageMs != null && meta.ageMs <= Math.max(1000, Number(domain.maxAgeMs || 0))
    ])
  );
  const allEnabledDomainsFresh = domains
    .filter((domain) => domain.enabled)
    .every((domain) => freshnessByDomain[domain.name] === true);
  const requiredTables = [
    'users',
    'auth_sessions',
    'user_portal_scopes',
    'user_psr_scopes',
    'planner_records',
    'pricing_rates',
    'daily_reports',
    'jobsite_assets',
    'auto_import_projects',
    'auto_import_runs',
    'auto_import_row_cache',
    'auto_import_bindings',
    'auto_import_logs',
    'portal_path_grants',
    'portal_share_links',
    'portal_share_access_log',
    'portal_share_guest_sessions',
    'portal_upload_sessions',
    'portal_upload_session_parts',
    'user_outlook_tokens',
    'signup_verifications'
  ];
  const missingRequiredTables = requiredTables.filter((table) => !Array.isArray(data[table]));
  const readyForAllReadsPrimary = !!(
    wasabiStateClient &&
    WASABI_STATE_BUCKET &&
    meta.hasData &&
    allEnabledDomainsFresh &&
    missingRequiredTables.length === 0
  );
  return {
    snapshot: meta,
    tableCounts,
    freshnessByDomain,
    missingRequiredTables,
    readyForAllReadsPrimary
  };
}

async function listSnapshotTables() {
  const fallback = [
    'planner_records',
    'planner_changes',
    'users',
    'user_portal_scopes',
    'user_psr_scopes',
    'sessions',
    'portal_path_grants',
    'portal_share_links',
    'portal_share_access_log',
    'portal_share_guest_sessions',
    'portal_upload_sessions',
    'portal_upload_session_parts',
    'user_outlook_tokens',
    'signup_verifications',
    'auto_import_projects',
    'auto_import_runs',
    'auto_import_row_cache',
    'auto_import_bindings',
    'auto_import_logs'
  ];
  if (!WASABI_STATE_INCLUDE_ALL_TABLES) {
    return fallback.filter((name) => !WASABI_STATE_EXCLUDE_TABLES.has(name));
  }
  try {
    const q = await pool.query(
      `SELECT table_name
         FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
        ORDER BY table_name ASC`
    );
    const all = q.rows.map((row) => String(row.table_name || '').trim()).filter(Boolean);
    return all.filter((name) => !WASABI_STATE_EXCLUDE_TABLES.has(name));
  } catch (error) {
    console.warn('[wasabi-state] failed to list all tables, using fallback:', error?.message || error);
    return fallback.filter((name) => !WASABI_STATE_EXCLUDE_TABLES.has(name));
  }
}

function cloneSnapshotRows(rows) {
  if (!Array.isArray(rows)) return [];
  try {
    return typeof globalThis.structuredClone === 'function'
      ? globalThis.structuredClone(rows)
      : JSON.parse(JSON.stringify(rows));
  } catch {
    return [...rows];
  }
}

/** Tables whose canonical copy is Wasabi when in wasabi-only mode — never overwrite from (empty) Postgres during snapshot export. */
function wasabiSnapshotTablesPreservedFromLatest() {
  const set = new Set();
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    set.add('planner_records');
    set.add('pricing_rates');
    set.add('daily_reports');
    set.add('jobsite_assets');
  }
  if (PLANNER_STORE_WASABI_ONLY) {
    set.add('planner_records');
    set.add('user_psr_scopes');
  }
  return set;
}

async function runWasabiStateSnapshot() {
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) return;
  if (wasabiStateSnapshotBusy) return;
  wasabiStateSnapshotBusy = true;
  wasabiStateLastRunAt = Date.now();
  try {
    const tables = await listSnapshotTables();
    const preserveFromLatest = wasabiSnapshotTablesPreservedFromLatest();
    let previousSnapshot = null;
    if (preserveFromLatest.size > 0) {
      try {
        previousSnapshot = await loadWasabiLatestStateSnapshot(true);
      } catch {
        previousSnapshot = null;
      }
    }
    const data = {};
    for (const tableName of tables) {
      if (preserveFromLatest.has(tableName)) {
        const prevRows =
          previousSnapshot && previousSnapshot.data && Array.isArray(previousSnapshot.data[tableName])
            ? previousSnapshot.data[tableName]
            : [];
        data[tableName] = cloneSnapshotRows(prevRows);
        continue;
      }
      try {
        const q = await pool.query(`SELECT * FROM ${tableName}`);
        data[tableName] = q.rows;
      } catch (err) {
        data[tableName] = { error: String(err?.message || err) };
      }
    }
    const next = {
      generatedAt: nowIso(),
      source: 'horizon-backend',
      scope: { clientId: 'portal-users', jobId: '3' },
      data
    };
    await putWasabiStateObject(next);
  } catch (err) {
    console.warn('[wasabi-state] snapshot failed:', err && err.message ? err.message : err);
  } finally {
    wasabiStateSnapshotBusy = false;
  }
}

async function syncWasabiNow(reason = 'manual') {
  await flushWasabiSqlMirrorQueue();
  await runWasabiStateSnapshot();
  const latest = await loadWasabiLatestStateSnapshot(true);
  const readiness = evaluateWasabiRuntimeReadiness(latest);
  return {
    reason: String(reason || 'manual'),
    ...readiness,
    state: currentWasabiStateStatus(),
    sqlMirror: currentWasabiSqlMirrorStatus(),
    autoImport: currentWasabiAutoImportStatus(),
    portalData: currentWasabiPortalDataStatus(),
    outlook: currentWasabiOutlookStatus(),
    signup: currentWasabiSignupStatus()
  };
}

function queueWasabiStateSnapshot(reason) {
  if (!WASABI_STATE_SNAPSHOT_ON_WRITE) return;
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) return;
  wasabiStateLastQueuedAt = Date.now();
  wasabiStateLastReason = String(reason || '').trim() || 'mutation';
  if (wasabiStateSnapshotTimer) return;
  wasabiStateSnapshotTimer = setTimeout(async () => {
    wasabiStateSnapshotTimer = null;
    await runWasabiStateSnapshot();
  }, WASABI_STATE_WRITE_DEBOUNCE_MS);
}

function currentWasabiStateStatus() {
  return {
    enabled: !!(wasabiStateClient && WASABI_STATE_BUCKET),
    onWrite: WASABI_STATE_SNAPSHOT_ON_WRITE,
    bucket: WASABI_STATE_BUCKET || null,
    prefix: WASABI_STATE_PREFIX,
    intervalMs: WASABI_STATE_SNAPSHOT_MS,
    writeDebounceMs: WASABI_STATE_WRITE_DEBOUNCE_MS,
    includeAllTables: WASABI_STATE_INCLUDE_ALL_TABLES,
    excludedTables: Array.from(WASABI_STATE_EXCLUDE_TABLES),
    writesPrimaryEnabled: WASABI_WRITES_PRIMARY_ENABLED,
    writesPrimaryStrict: WASABI_WRITES_PRIMARY_STRICT,
    plannerStoreWasabiOnly: PLANNER_STORE_WASABI_ONLY,
    appDataStoreWasabiOnly: WASABI_APP_DATA_STORE_WASABI_ONLY,
    migrateAppDataFromPostgresOnBoot: MIGRATE_APP_DATA_FROM_POSTGRES_ON_BOOT,
    allReadsPrimaryEnabled: WASABI_ALL_READS_PRIMARY_ENABLED,
    allReadsPrimaryStrict: WASABI_ALL_READS_PRIMARY_STRICT,
    authFallbackEnabled: WASABI_AUTH_FALLBACK_ENABLED,
    authFallbackCacheMs: WASABI_AUTH_FALLBACK_CACHE_MS,
    authPrimaryEnabled: WASABI_AUTH_PRIMARY_ENABLED,
    authPrimaryStrict: WASABI_AUTH_PRIMARY_STRICT,
    authPrimaryMaxSnapshotAgeMs: WASABI_AUTH_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    scopesPrimaryEnabled: WASABI_SCOPES_PRIMARY_ENABLED,
    scopesPrimaryStrict: WASABI_SCOPES_PRIMARY_STRICT,
    scopesPrimaryMaxSnapshotAgeMs: WASABI_SCOPES_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    permissionsTreePrimaryEnabled: WASABI_PERMISSIONS_TREE_PRIMARY_ENABLED,
    permissionsTreePrimaryStrict: WASABI_PERMISSIONS_TREE_PRIMARY_STRICT,
    permissionsTreePrimaryMaxSnapshotAgeMs: WASABI_PERMISSIONS_TREE_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    loginFallbackEnabled: WASABI_LOGIN_FALLBACK_ENABLED,
    loginFallbackMaxSnapshotAgeMs: WASABI_LOGIN_FALLBACK_MAX_SNAPSHOT_AGE_MS,
    recordsPrimaryEnabled: WASABI_RECORDS_PRIMARY_ENABLED,
    recordsPrimaryStrict: WASABI_RECORDS_PRIMARY_STRICT,
    recordsPrimaryMaxSnapshotAgeMs: WASABI_RECORDS_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    recordDetailPrimaryEnabled: WASABI_RECORD_DETAIL_PRIMARY_ENABLED,
    recordDetailPrimaryStrict: WASABI_RECORD_DETAIL_PRIMARY_STRICT,
    recordDetailPrimaryMaxSnapshotAgeMs: WASABI_RECORD_DETAIL_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    pricingPrimaryEnabled: WASABI_PRICING_PRIMARY_ENABLED,
    pricingPrimaryStrict: WASABI_PRICING_PRIMARY_STRICT,
    pricingPrimaryMaxSnapshotAgeMs: WASABI_PRICING_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    reportsPrimaryEnabled: WASABI_REPORTS_PRIMARY_ENABLED,
    reportsPrimaryStrict: WASABI_REPORTS_PRIMARY_STRICT,
    reportsPrimaryMaxSnapshotAgeMs: WASABI_REPORTS_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    assetsPrimaryEnabled: WASABI_ASSETS_PRIMARY_ENABLED,
    assetsPrimaryStrict: WASABI_ASSETS_PRIMARY_STRICT,
    assetsPrimaryMaxSnapshotAgeMs: WASABI_ASSETS_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    syncStatePrimaryEnabled: WASABI_SYNC_STATE_PRIMARY_ENABLED,
    syncStatePrimaryStrict: WASABI_SYNC_STATE_PRIMARY_STRICT,
    syncStatePrimaryMaxSnapshotAgeMs: WASABI_SYNC_STATE_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    usersPrimaryEnabled: WASABI_USERS_PRIMARY_ENABLED,
    usersPrimaryStrict: WASABI_USERS_PRIMARY_STRICT,
    usersPrimaryMaxSnapshotAgeMs: WASABI_USERS_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    plannerScopeLookupPrimaryEnabled: WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_ENABLED,
    plannerScopeLookupPrimaryStrict: WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_STRICT,
    plannerScopeLookupPrimaryMaxSnapshotAgeMs: WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    autoImportPrimaryEnabled: WASABI_AUTO_IMPORT_PRIMARY_ENABLED,
    autoImportPrimaryStrict: WASABI_AUTO_IMPORT_PRIMARY_STRICT,
    autoImportPrimaryMaxSnapshotAgeMs: WASABI_AUTO_IMPORT_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    portalDataPrimaryEnabled: WASABI_PORTAL_DATA_PRIMARY_ENABLED,
    portalDataPrimaryStrict: WASABI_PORTAL_DATA_PRIMARY_STRICT,
    portalDataPrimaryMaxSnapshotAgeMs: WASABI_PORTAL_DATA_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    outlookPrimaryEnabled: WASABI_OUTLOOK_PRIMARY_ENABLED,
    outlookPrimaryStrict: WASABI_OUTLOOK_PRIMARY_STRICT,
    outlookPrimaryMaxSnapshotAgeMs: WASABI_OUTLOOK_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    signupPrimaryEnabled: WASABI_SIGNUP_PRIMARY_ENABLED,
    signupPrimaryStrict: WASABI_SIGNUP_PRIMARY_STRICT,
    signupPrimaryMaxSnapshotAgeMs: WASABI_SIGNUP_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    queuedAt: wasabiStateLastQueuedAt ? new Date(wasabiStateLastQueuedAt).toISOString() : null,
    lastRunAt: wasabiStateLastRunAt ? new Date(wasabiStateLastRunAt).toISOString() : null,
    lastReason: wasabiStateLastReason,
    busy: wasabiStateSnapshotBusy
  };
}

function detectSqlMutation(sqlText) {
  const sql = String(sqlText || '').trim();
  if (!sql) return null;
  const opMatch = sql.match(/^(insert|update|delete)\b/i);
  if (!opMatch) return null;
  const operation = String(opMatch[1] || '').toUpperCase();
  let table = null;
  if (operation === 'INSERT') {
    const m = sql.match(/^\s*insert\s+into\s+("?[\w.]+"?)/i);
    table = m && m[1] ? m[1] : null;
  } else if (operation === 'UPDATE') {
    const m = sql.match(/^\s*update\s+("?[\w.]+"?)/i);
    table = m && m[1] ? m[1] : null;
  } else if (operation === 'DELETE') {
    const m = sql.match(/^\s*delete\s+from\s+("?[\w.]+"?)/i);
    table = m && m[1] ? m[1] : null;
  }
  if (table) table = table.replace(/"/g, '');
  return { operation, table };
}

function normalizeMirrorParams(params) {
  if (!Array.isArray(params) || !WASABI_SQL_MIRROR_INCLUDE_PARAMS) return undefined;
  return params.slice(0, 100).map((value) => {
    if (value == null) return value;
    const t = typeof value;
    if (t === 'string') return value.length > 200 ? `${value.slice(0, 200)}...` : value;
    if (t === 'number' || t === 'boolean') return value;
    if (value instanceof Date) return value.toISOString();
    try {
      const json = JSON.stringify(value);
      return json.length > 300 ? `${json.slice(0, 300)}...` : json;
    } catch {
      return String(value);
    }
  });
}

async function flushWasabiSqlMirrorQueue() {
  if (!WASABI_SQL_MIRROR_ENABLED) return;
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) return;
  if (wasabiSqlMirrorBusy) return;
  if (!wasabiSqlMirrorEvents.length) return;
  wasabiSqlMirrorBusy = true;
  const batch = wasabiSqlMirrorEvents.splice(0, wasabiSqlMirrorEvents.length);
  try {
    const now = new Date();
    const yyyy = String(now.getUTCFullYear());
    const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(now.getUTCDate()).padStart(2, '0');
    const hh = String(now.getUTCHours()).padStart(2, '0');
    const mi = String(now.getUTCMinutes()).padStart(2, '0');
    const stamp = now.toISOString().replace(/[:.]/g, '-');
    const key = `${WASABI_SQL_MIRROR_PREFIX}/events/${yyyy}/${mm}/${dd}/${hh}/${mi}/batch-${stamp}-${crypto.randomUUID()}.json`;
    const payload = Buffer.from(
      JSON.stringify(
        {
          generatedAt: now.toISOString(),
          source: 'horizon-backend',
          scope: { clientId: 'portal-users', jobId: '3' },
          count: batch.length,
          events: batch
        },
        null,
        2
      ),
      'utf8'
    );
    await wasabiStateClient.send(
      new PutObjectCommand({
        Bucket: WASABI_STATE_BUCKET,
        Key: key,
        Body: payload,
        ContentType: 'application/json'
      })
    );
    wasabiSqlMirrorLastError = '';
    wasabiSqlMirrorTotalFlushed += batch.length;
    wasabiSqlMirrorLastFlushAt = Date.now();
  } catch (err) {
    wasabiSqlMirrorLastError = String(err?.message || err);
    console.warn('[wasabi-sql-mirror] flush failed:', wasabiSqlMirrorLastError);
    wasabiSqlMirrorEvents = batch.concat(wasabiSqlMirrorEvents).slice(0, WASABI_SQL_MIRROR_MAX_BUFFER);
  } finally {
    wasabiSqlMirrorBusy = false;
  }
}

function queueWasabiSqlMirrorEvent(event) {
  if (!WASABI_SQL_MIRROR_ENABLED) return;
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) return;
  wasabiSqlMirrorEvents.push(event);
  if (wasabiSqlMirrorEvents.length > WASABI_SQL_MIRROR_MAX_BUFFER) {
    wasabiSqlMirrorEvents = wasabiSqlMirrorEvents.slice(-WASABI_SQL_MIRROR_MAX_BUFFER);
  }
  if (wasabiSqlMirrorEvents.length >= 25) {
    void flushWasabiSqlMirrorQueue();
    return;
  }
  if (wasabiSqlMirrorTimer) return;
  wasabiSqlMirrorTimer = setTimeout(async () => {
    wasabiSqlMirrorTimer = null;
    await flushWasabiSqlMirrorQueue();
  }, WASABI_SQL_MIRROR_FLUSH_MS);
}

function currentWasabiSqlMirrorStatus() {
  return {
    enabled: !!(WASABI_SQL_MIRROR_ENABLED && wasabiStateClient && WASABI_STATE_BUCKET),
    includeParams: WASABI_SQL_MIRROR_INCLUDE_PARAMS,
    bucket: WASABI_STATE_BUCKET || null,
    prefix: WASABI_SQL_MIRROR_PREFIX,
    flushMs: WASABI_SQL_MIRROR_FLUSH_MS,
    maxBuffer: WASABI_SQL_MIRROR_MAX_BUFFER,
    buffered: wasabiSqlMirrorEvents.length,
    busy: wasabiSqlMirrorBusy,
    totalFlushed: wasabiSqlMirrorTotalFlushed,
    lastFlushAt: wasabiSqlMirrorLastFlushAt ? new Date(wasabiSqlMirrorLastFlushAt).toISOString() : null,
    lastError: wasabiSqlMirrorLastError || null
  };
}

function currentWasabiAutoImportStatus() {
  return {
    enabled: WASABI_AUTO_IMPORT_PRIMARY_ENABLED,
    strict: WASABI_AUTO_IMPORT_PRIMARY_STRICT,
    maxSnapshotAgeMs: WASABI_AUTO_IMPORT_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    handledByWasabi: wasabiAutoImportHandledByWasabi,
    fallbackToPostgres: wasabiAutoImportFallbackToPostgres,
    lastErrorAt: wasabiAutoImportLastErrorAt ? new Date(wasabiAutoImportLastErrorAt).toISOString() : null,
    lastError: wasabiAutoImportLastError || null,
    fallbackSamples: wasabiAutoImportFallbackSamples.slice(-20)
  };
}

function currentWasabiPortalDataStatus() {
  return {
    enabled: WASABI_PORTAL_DATA_PRIMARY_ENABLED,
    strict: WASABI_PORTAL_DATA_PRIMARY_STRICT,
    maxSnapshotAgeMs: WASABI_PORTAL_DATA_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    handledByWasabi: wasabiPortalDataHandledByWasabi,
    fallbackToPostgres: wasabiPortalDataFallbackToPostgres,
    lastErrorAt: wasabiPortalDataLastErrorAt ? new Date(wasabiPortalDataLastErrorAt).toISOString() : null,
    lastError: wasabiPortalDataLastError || null,
    fallbackSamples: wasabiPortalDataFallbackSamples.slice(-20)
  };
}

function currentWasabiOutlookStatus() {
  return {
    enabled: WASABI_OUTLOOK_PRIMARY_ENABLED,
    strict: WASABI_OUTLOOK_PRIMARY_STRICT,
    maxSnapshotAgeMs: WASABI_OUTLOOK_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    handledByWasabi: wasabiOutlookHandledByWasabi,
    fallbackToPostgres: wasabiOutlookFallbackToPostgres,
    lastErrorAt: wasabiOutlookLastErrorAt ? new Date(wasabiOutlookLastErrorAt).toISOString() : null,
    lastError: wasabiOutlookLastError || null,
    fallbackSamples: wasabiOutlookFallbackSamples.slice(-20)
  };
}

function currentWasabiSignupStatus() {
  return {
    enabled: WASABI_SIGNUP_PRIMARY_ENABLED,
    strict: WASABI_SIGNUP_PRIMARY_STRICT,
    maxSnapshotAgeMs: WASABI_SIGNUP_PRIMARY_MAX_SNAPSHOT_AGE_MS,
    handledByWasabi: wasabiSignupHandledByWasabi,
    fallbackToPostgres: wasabiSignupFallbackToPostgres,
    lastErrorAt: wasabiSignupLastErrorAt ? new Date(wasabiSignupLastErrorAt).toISOString() : null,
    lastError: wasabiSignupLastError || null,
    fallbackSamples: wasabiSignupFallbackSamples.slice(-20)
  };
}

const rawPoolQuery = pool.query.bind(pool);
pool.query = function patchedPoolQuery(text, values, callback) {
  if (typeof values === 'function' || typeof callback === 'function') {
    return rawPoolQuery(text, values, callback);
  }
  const sqlText = typeof text === 'string' ? text : text && typeof text.text === 'string' ? text.text : '';
  const mutation = detectSqlMutation(sqlText);
  const startedAt = Date.now();
  return rawPoolQuery(text, values)
    .then((result) => {
      if (mutation) {
        queueWasabiSqlMirrorEvent({
          id: crypto.randomUUID(),
          at: new Date().toISOString(),
          ok: true,
          operation: mutation.operation,
          table: mutation.table,
          rowCount: Number(result?.rowCount || 0),
          durationMs: Date.now() - startedAt,
          sql: String(sqlText || '').slice(0, 500),
          valuesCount: Array.isArray(values) ? values.length : 0,
          values: normalizeMirrorParams(values)
        });
      }
      return result;
    })
    .catch((error) => {
      if (mutation) {
        queueWasabiSqlMirrorEvent({
          id: crypto.randomUUID(),
          at: new Date().toISOString(),
          ok: false,
          operation: mutation.operation,
          table: mutation.table,
          rowCount: 0,
          durationMs: Date.now() - startedAt,
          sql: String(sqlText || '').slice(0, 500),
          valuesCount: Array.isArray(values) ? values.length : 0,
          values: normalizeMirrorParams(values),
          error: String(error?.message || error)
        });
      }
      throw error;
    });
};

const SESSION_TTL_MINUTES = Math.max(5, Math.min(7 * 24 * 60, Number(process.env.SESSION_TTL_MINUTES || 15)));
const SESSION_KEEP_TTL_MINUTES = Math.max(
  SESSION_TTL_MINUTES,
  Math.min(90 * 24 * 60, Number(process.env.SESSION_KEEP_TTL_MINUTES || 7 * 24 * 60))
);

function resolveSessionTtlMinutes(keepSession) {
  return keepSession ? SESSION_KEEP_TTL_MINUTES : SESSION_TTL_MINUTES;
}
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
    psrViewer: false,
    psrDataEntry: false,
    dataAutoSyncEmployee: false,
    pricingView: false,
    footageView: false,
    portalUpload: false,
    portalDownload: false,
    portalEdit: false,
    portalDelete: false
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
      psrViewer: value.psrViewer === true || value.psr_viewer === true,
      psrDataEntry: value.psrDataEntry === true || value.psr_data_entry === true,
      dataAutoSyncEmployee:
        value.dataAutoSyncEmployee === true ||
        value.data_auto_sync_employee === true ||
        value.employee === true,
      pricingView: value.pricingView === true || value.pricing === true,
      footageView: value.footageView === true || value.footage === true,
      portalUpload: value.portalUpload === true || value.portal_upload === true,
      portalDownload: value.portalDownload === true || value.portal_download === true,
      portalEdit: value.portalEdit === true || value.portal_edit === true,
      portalDelete: value.portalDelete === true || value.portal_delete === true
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
 * Defaults to `portal-users/4` per current production bucket layout.
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

function enforcePortalScopePolicyForUser(user, portalScopes) {
  if (!user || user.portalFilesAccessGranted !== true) return [];
  return dedupePortalScopes(portalScopes);
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

  const portalPermissionsAccessRaw = !!row.portal_permissions_access;
  const portalPermissionsAccess = portalPermissionsAccessRaw || portalPermissionsWhitelistHas(row.username);
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
    portalPermissionsAccessRaw,
    portalPermissionsAccess
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
  const recordId = cleanString(value.recordId || value.record_id || value.jobsiteId || value.record || '');
  const client = upperCleanString(value.client);
  const city = upperCleanString(value.city);
  const jobsite = normalizeJobsiteName(value.jobsite, value.street);
  if (!client || !city || !jobsite) return null;
  return { recordId: recordId || null, client, city, jobsite };
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
    const key = n.recordId ? `id:${n.recordId}` : `${n.client}::${n.city}::${n.jobsite}`;
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

/** When planner/PSR is Wasabi-only, PSR scopes always come from the snapshot (never Postgres), using a forced reload. */
async function mergePsrScopesFromWasabiWhenPlannerOnly(byUser, userIdList) {
  if (!PLANNER_STORE_WASABI_ONLY) return;
  const ids = new Set((userIdList || []).map((id) => String(id || '').trim()).filter(Boolean));
  if (!ids.size) return;
  for (const id of ids) {
    const e = byUser.get(id);
    if (e) e.psrScopes = [];
  }
  let snapshot = null;
  try {
    snapshot = await loadWasabiLatestStateSnapshot(true);
  } catch {
    snapshot = null;
  }
  for (const row of snapshotRows(snapshot, 'user_psr_scopes')) {
    const key = String(row.user_id || '').trim();
    if (!key || !byUser.has(key)) continue;
    byUser.get(key).psrScopes.push({
      recordId: cleanString(row.psr_record_id || '') || null,
      client: String(row.client || ''),
      city: String(row.city || ''),
      jobsite: String(row.jobsite || '')
    });
  }
  for (const id of ids) {
    const e = byUser.get(id);
    if (e) e.psrScopes = dedupePsrScopes(e.psrScopes);
  }
}

async function readScopesForUserIds(userIds) {
  const ids = [...new Set((Array.isArray(userIds) ? userIds : []).map((id) => String(id || '').trim()).filter(Boolean))];
  const byUser = new Map();
  for (const id of ids) byUser.set(id, { portalScopes: [], psrScopes: [] });
  if (!ids.length) return byUser;

  async function fromSnapshot() {
    const snapshot = await loadWasabiLatestStateSnapshot();
    if (!snapshotLooksFresh(snapshot, WASABI_SCOPES_PRIMARY_MAX_SNAPSHOT_AGE_MS)) return null;
    const portalRows = snapshotRows(snapshot, 'user_portal_scopes');
    for (const row of portalRows) {
      const key = String(row.user_id || '').trim();
      if (!key || !byUser.has(key)) continue;
      byUser.get(key).portalScopes.push({
        clientId: String(row.client_id || ''),
        jobId: String(row.job_id || '')
      });
    }
    if (!PLANNER_STORE_WASABI_ONLY) {
      const psrRows = snapshotRows(snapshot, 'user_psr_scopes');
      for (const row of psrRows) {
        const key = String(row.user_id || '').trim();
        if (!key || !byUser.has(key)) continue;
        byUser.get(key).psrScopes.push({
          recordId: cleanString(row.psr_record_id || '') || null,
          client: String(row.client || ''),
          city: String(row.city || ''),
          jobsite: String(row.jobsite || '')
        });
      }
    }
    return byUser;
  }

  async function fromPostgres() {
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

    if (!PLANNER_STORE_WASABI_ONLY) {
      const psrRes = await pool.query(
        `SELECT user_id::text AS user_id, client, city, jobsite, psr_record_id
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
          .psrScopes.push({
            recordId: cleanString(row.psr_record_id || '') || null,
            client: String(row.client || ''),
            city: String(row.city || ''),
            jobsite: String(row.jobsite || '')
          });
      }
    }
    return byUser;
  }

  if (WASABI_SCOPES_PRIMARY_ENABLED) {
    try {
      const snapshotResult = await fromSnapshot();
      if (snapshotResult) {
        await mergePsrScopesFromWasabiWhenPlannerOnly(byUser, ids);
        return byUser;
      }
      if (WASABI_SCOPES_PRIMARY_STRICT) {
        await mergePsrScopesFromWasabiWhenPlannerOnly(byUser, ids);
        return byUser;
      }
    } catch (error) {
      if (WASABI_SCOPES_PRIMARY_STRICT) throw error;
    }
  }

  await fromPostgres();
  await mergePsrScopesFromWasabiWhenPlannerOnly(byUser, ids);
  return byUser;
}

async function attachScopesToUsers(users) {
  const list = Array.isArray(users) ? users : [];
  const map = await readScopesForUserIds(list.map((u) => u.id));
  return list.map((u) => {
    const entry = map.get(String(u.id || '')) || { portalScopes: [], psrScopes: [] };
    return {
      ...u,
      portalScopes: enforcePortalScopePolicyForUser(u, entry.portalScopes),
      psrScopes: dedupePsrScopes(entry.psrScopes)
    };
  });
}

async function attachScopesToUser(user) {
  if (!user?.id) return { ...user, portalScopes: [], psrScopes: [] };
  const [withScopes] = await attachScopesToUsers([user]);
  return withScopes;
}

function snapshotRows(snapshot, tableName) {
  const rows = snapshot && snapshot.data ? snapshot.data[tableName] : null;
  return Array.isArray(rows) ? rows : [];
}

function attachScopesToUserFromSnapshot(user, snapshot) {
  if (!user?.id) return { ...user, portalScopes: [], psrScopes: [] };
  const uid = String(user.id || '');
  const portalScopes = snapshotRows(snapshot, 'user_portal_scopes')
    .filter((row) => String(row.user_id || '') === uid)
    .map((row) => ({
      clientId: String(row.client_id || ''),
      jobId: String(row.job_id || '')
    }));
  const psrScopes = snapshotRows(snapshot, 'user_psr_scopes')
    .filter((row) => String(row.user_id || '') === uid)
    .map((row) => ({
      recordId: cleanString(row.psr_record_id || '') || null,
      client: String(row.client || ''),
      city: String(row.city || ''),
      jobsite: String(row.jobsite || '')
    }));
  return {
    ...user,
    portalScopes: enforcePortalScopePolicyForUser(user, portalScopes),
    psrScopes: dedupePsrScopes(psrScopes)
  };
}

function snapshotLooksFresh(snapshot, maxAgeMs = WASABI_AUTH_PRIMARY_MAX_SNAPSHOT_AGE_MS) {
  const generatedAt = Date.parse(String(snapshot?.generatedAt || ''));
  if (!Number.isFinite(generatedAt)) return false;
  return Date.now() - generatedAt <= Math.max(1000, Number(maxAgeMs || 0));
}

function buildPermissionsTreesFromRows({ portalRows = [], portalPathRows = [], psrRows = [] }) {
  const pathMap = new Map();
  for (const row of portalPathRows) {
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
  for (const row of portalRows) {
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
  for (const row of psrRows) {
    const client = upperCleanString(row.client);
    const city = upperCleanString(row.city);
    const jobsite = normalizeJobsiteName(row.jobsite, row.street);
    const recordId = cleanString(row.id || '');
    if (!client || !city || !jobsite) continue;
    if (!psrMap.has(client)) psrMap.set(client, new Map());
    const cityMap = psrMap.get(client);
    if (!cityMap.has(city)) cityMap.set(city, []);
    cityMap.get(city).push({ recordId, jobsite });
  }
  const psrTree = [...psrMap.entries()].map(([client, cityMap]) => ({
    client,
    cities: [...cityMap.entries()].map(([city, jobsites]) => ({
      city,
      jobsites: jobsites
        .filter((item, idx, arr) => arr.findIndex((x) => x.recordId === item.recordId) === idx)
        .sort((a, b) => String(a.jobsite || '').localeCompare(String(b.jobsite || ''), undefined, { sensitivity: 'base' }))
    }))
  }));

  return { portalTree, psrTree };
}

/** Match portal scope pairs to planner rows for admin tree labels (client/city/jobsite display). */
function attachPlannerLabelsToScopeRows(scopePairRows, plannerRecords) {
  const plannerByClient = new Map();
  for (const row of plannerRecords) {
    const client = String(row.client || '').trim().toLowerCase();
    if (!client) continue;
    if (!plannerByClient.has(client)) plannerByClient.set(client, []);
    plannerByClient.get(client).push(row);
  }

  const portalRows = [];
  for (const row of scopePairRows) {
    const c = String(row.client_id || '').trim();
    const j = String(row.job_id || '').trim();
    const candidates = plannerByClient.get(c.toLowerCase()) || [];
    let best = null;
    for (const candidate of candidates) {
      const jobsite = String(candidate.jobsite || '').trim();
      const recId = String(candidate.id || '').trim();
      if (!jobsite && !recId) continue;
      if (jobsite.toLowerCase() === j.toLowerCase() || recId === j) {
        if (!best) {
          best = candidate;
          continue;
        }
        const bestTs = Date.parse(String(best.updated_at || best.created_at || '')) || 0;
        const candidateTs = Date.parse(String(candidate.updated_at || candidate.created_at || '')) || 0;
        if (candidateTs > bestTs) best = candidate;
      }
    }
    portalRows.push({
      client_id: c,
      job_id: j,
      label_client: best ? best.client : c,
      label_city: best ? best.city : 'NOT SET',
      label_jobsite: best ? best.jobsite : j
    });
  }
  return portalRows;
}

async function buildPermissionsTreesFromSnapshot() {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (!snapshotLooksFresh(snapshot, WASABI_PERMISSIONS_TREE_PRIMARY_MAX_SNAPSHOT_AGE_MS)) return null;
  const users = snapshotRows(snapshot, 'users');
  const userPortalScopes = snapshotRows(snapshot, 'user_portal_scopes');
  const portalPathGrants = snapshotRows(snapshot, 'portal_path_grants');
  const plannerRecords = snapshotRows(snapshot, 'planner_records');

  const scopeSet = new Map();
  const addScope = (clientIdValue, jobIdValue) => {
    const clientId = String(clientIdValue || '').trim();
    const jobId = String(jobIdValue || '').trim();
    if (!clientId || !jobId) return;
    scopeSet.set(`${clientId}|||${jobId}`, { client_id: clientId, job_id: jobId });
  };

  for (const row of userPortalScopes) addScope(row.client_id, row.job_id);
  for (const row of users) addScope(row.portal_files_client_id, row.portal_files_job_id);
  for (const row of portalPathGrants) addScope(row.client_id, row.job_id);

  const portalRows = attachPlannerLabelsToScopeRows([...scopeSet.values()], plannerRecords);

  const psrRows = plannerRecords
    .map((row) => ({
      id: row.id,
      client: row.client,
      city: row.city,
      jobsite: row.jobsite
    }))
    .filter(
      (row) =>
        String(row.client || '').trim() &&
        String(row.city || '').trim() &&
        String(row.jobsite || '').trim()
    );

  return buildPermissionsTreesFromRows({
    portalRows,
    portalPathRows: portalPathGrants,
    psrRows
  });
}

function snapshotUserMatchesLogin(user, submittedUsername) {
  const needle = String(submittedUsername || '').trim().toLowerCase();
  if (!needle) return false;
  const username = String(user?.username || '').trim().toLowerCase();
  const displayName = String(user?.display_name || user?.username || '').trim().toLowerCase();
  const email = String(user?.email || '').trim().toLowerCase();
  return username === needle || displayName === needle || (!!email && email === needle);
}

async function readLoginUserFromWasabiSnapshot(submittedUsername) {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (!snapshotLooksFresh(snapshot, WASABI_LOGIN_FALLBACK_MAX_SNAPSHOT_AGE_MS)) return null;
  const users = snapshotRows(snapshot, 'users');
  return users.find((row) => snapshotUserMatchesLogin(row, submittedUsername)) || null;
}

function sortPlannerRecordsForList(records) {
  return [...records].sort((a, b) => {
    const c = String(a.client || '').localeCompare(String(b.client || ''), undefined, { sensitivity: 'base' });
    if (c !== 0) return c;
    const d = String(a.city || '').localeCompare(String(b.city || ''), undefined, { sensitivity: 'base' });
    if (d !== 0) return d;
    const e = String(a.jobsite || '').localeCompare(String(b.jobsite || ''), undefined, { sensitivity: 'base' });
    if (e !== 0) return e;
    const r = String(b.record_date || '').localeCompare(String(a.record_date || ''));
    if (r !== 0) return r;
    const au = Date.parse(String(a.updated_at || '')) || 0;
    const bu = Date.parse(String(b.updated_at || '')) || 0;
    return bu - au;
  });
}

/** Merge Wasabi + Postgres planner rows by id so refresh never hides data that exists in only one store. */
function mergePlannerRecordsById(wasabiRecords, postgresRecords) {
  const map = new Map();
  const put = (rec) => {
    const id = String(rec?.id || '').trim();
    if (!id) return;
    const prev = map.get(id);
    if (!prev) {
      map.set(id, rec);
      return;
    }
    const ta = Date.parse(String(rec.updated_at || rec.created_at || '')) || 0;
    const tb = Date.parse(String(prev.updated_at || prev.created_at || '')) || 0;
    map.set(id, ta >= tb ? rec : prev);
  };
  (wasabiRecords || []).forEach(put);
  (postgresRecords || []).forEach(put);
  return [...map.values()];
}

function plannerRowToSnapshotShape(row) {
  const dataRaw = row.data;
  const dataObj =
    dataRaw && typeof dataRaw === 'object' && !Array.isArray(dataRaw)
      ? dataRaw
      : parseJsonObject(dataRaw, {});
  return {
    id: row.id,
    record_date: row.record_date,
    client: row.client,
    city: row.city,
    street: row.street,
    jobsite: row.jobsite,
    status: row.status || '',
    saved_by: row.saved_by || '',
    data: dataObj,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function pricingRowToSnapshotShape(row) {
  return {
    dia: upperCleanString(row.dia || ''),
    rate: Number(row.rate),
    updated_at: row.updated_at || nowIso()
  };
}

function dailyReportRowToSnapshotShape(row) {
  return {
    id: row.id,
    title: cleanString(row.title || ''),
    report_date: row.report_date,
    notes: cleanString(row.notes || ''),
    files: Array.isArray(row.files) ? row.files : parseJsonObject(row.files, []),
    created_by: cleanString(row.created_by || ''),
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function jobsiteAssetRowToSnapshotShape(row) {
  return {
    id: row.id,
    client: row.client,
    city: row.city,
    jobsite: row.jobsite,
    contact_name: cleanString(row.contact_name || ''),
    contact_phone: cleanString(row.contact_phone || ''),
    contact_email: cleanString(row.contact_email || ''),
    notes: cleanString(row.notes || ''),
    drive_url: cleanString(row.drive_url || ''),
    files: Array.isArray(row.files) ? row.files : parseJsonObject(row.files, []),
    created_by: cleanString(row.created_by || ''),
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function userPsrScopeMergeKey(row) {
  const uid = String(row.user_id || '').trim();
  const client = String(row.client || '').trim().toLowerCase();
  const city = String(row.city || '').trim().toLowerCase();
  const jobsite = String(row.jobsite || '').trim().toLowerCase();
  return `${uid}|||${client}|||${city}|||${jobsite}`;
}

function userPsrScopeRowToSnapshotShape(row) {
  return {
    user_id: String(row.user_id || '').trim(),
    client: String(row.client || '').trim(),
    city: String(row.city || '').trim(),
    jobsite: String(row.jobsite || '').trim(),
    psr_record_id: cleanString(row.psr_record_id || '') || null,
    created_at: row.created_at
  };
}

/** Merge Postgres business tables into Wasabi snapshot (Postgres row wins on duplicate key). Requires Wasabi write primary. */
async function migrateAppDataFromPostgresToWasabi() {
  const [plannerPg, pricingPg, reportsPg, assetsPg, psrPg] = await Promise.all([
    pool.query('SELECT * FROM planner_records'),
    pool.query('SELECT * FROM pricing_rates'),
    pool.query('SELECT * FROM daily_reports'),
    pool.query('SELECT * FROM jobsite_assets'),
    pool.query('SELECT * FROM user_psr_scopes')
  ]);
  await runWasabiStateWrite('migrate-app-data-pg-to-wasabi', async (data) => {
    const pRows = plannerPg.rows;
    const pBy = new Map();
    for (const r of ensureSnapshotTable(data, 'planner_records')) {
      pBy.set(String(r.id), r);
    }
    for (const row of pRows) {
      pBy.set(String(row.id), plannerRowToSnapshotShape(row));
    }
    data.planner_records = [...pBy.values()];

    const prBy = new Map();
    for (const r of ensureSnapshotTable(data, 'pricing_rates')) {
      prBy.set(String(r.dia || '').trim().toUpperCase(), r);
    }
    for (const row of pricingPg.rows) {
      const snap = pricingRowToSnapshotShape(row);
      prBy.set(String(snap.dia || '').trim().toUpperCase(), snap);
    }
    data.pricing_rates = [...prBy.values()];

    const repBy = new Map();
    for (const r of ensureSnapshotTable(data, 'daily_reports')) {
      repBy.set(String(r.id), r);
    }
    for (const row of reportsPg.rows) {
      repBy.set(String(row.id), dailyReportRowToSnapshotShape(row));
    }
    data.daily_reports = [...repBy.values()];

    const aBy = new Map();
    for (const r of ensureSnapshotTable(data, 'jobsite_assets')) {
      aBy.set(String(r.id), r);
    }
    for (const row of assetsPg.rows) {
      aBy.set(String(row.id), jobsiteAssetRowToSnapshotShape(row));
    }
    data.jobsite_assets = [...aBy.values()];

    const upsBy = new Map();
    for (const r of ensureSnapshotTable(data, 'user_psr_scopes')) {
      upsBy.set(userPsrScopeMergeKey(r), userPsrScopeRowToSnapshotShape(r));
    }
    for (const row of psrPg.rows) {
      upsBy.set(userPsrScopeMergeKey(row), userPsrScopeRowToSnapshotShape(row));
    }
    data.user_psr_scopes = [...upsBy.values()];
  });
  return {
    planner_records: plannerPg.rows.length,
    pricing_rates: pricingPg.rows.length,
    daily_reports: reportsPg.rows.length,
    jobsite_assets: assetsPg.rows.length,
    user_psr_scopes: psrPg.rows.length
  };
}

async function getTableSyncMetaFromWasabi(tableName) {
  try {
    const snapshot = await loadWasabiLatestStateSnapshot();
    const rows = snapshotRows(snapshot, tableName);
    let best = 0;
    let bestIso = new Date(0).toISOString();
    for (const r of rows) {
      const u = Date.parse(String(r.updated_at || r.created_at || '')) || 0;
      if (u >= best) {
        best = u;
        bestIso = String(r.updated_at || r.created_at || bestIso);
      }
    }
    return { count: rows.length, updated_at: best ? bestIso : new Date(0).toISOString() };
  } catch {
    return { count: 0, updated_at: new Date(0).toISOString() };
  }
}

async function getPlannerRecordsSyncMetaFromWasabi() {
  return getTableSyncMetaFromWasabi('planner_records');
}

async function readPlannerRecordsFromPostgresForUser(user) {
  const scopeFilter = buildPsrScopeWhere(user);
  const result = await pool.query(
    `SELECT id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at
     FROM planner_records
     WHERE ${scopeFilter.clause}
     ORDER BY LOWER(client), LOWER(city), LOWER(jobsite), record_date DESC, updated_at DESC`,
    scopeFilter.params
  );
  return result.rows.map(normalizeRecordRow);
}

async function readRecordsFromWasabiSnapshotForUser(user) {
  const snapshot = await loadWasabiLatestStateSnapshot();
  // Same as record-by-id: do not drop the whole list when snapshot age exceeds threshold — merge with Postgres covers drift.
  if (!snapshot || !snapshot.data) return [];
  const rows = snapshotRows(snapshot, 'planner_records');
  const normalized = rows.map((row) => normalizeRecordRow(row));
  return normalized.filter((record) => userCanAccessPsrScope(user, record));
}

async function fetchRecordByIdFromWasabiSnapshot(id) {
  const snapshot = await loadWasabiLatestStateSnapshot();
  // Do not gate on snapshot age here: stale snapshot data beats a false 404 when Postgres was never
  // mirrored (Wasabi-primary creates) or when clocks / generatedAt skew.
  if (!snapshot || !snapshot.data) return null;
  const rows = snapshotRows(snapshot, 'planner_records');
  const hit = rows.find((row) => String(row.id || '') === String(id || ''));
  if (!hit) return null;
  return normalizeRecordRow(hit);
}

async function readPricingRatesFromWasabiSnapshot() {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (
    !WASABI_APP_DATA_STORE_WASABI_ONLY &&
    !snapshotLooksFresh(snapshot, WASABI_PRICING_PRIMARY_MAX_SNAPSHOT_AGE_MS)
  ) {
    return null;
  }
  if (!snapshot?.data) return WASABI_APP_DATA_STORE_WASABI_ONLY ? [] : null;
  const rows = snapshotRows(snapshot, 'pricing_rates')
    .map((row) => ({
      dia: upperCleanString(row.dia || ''),
      rate: Number(row.rate),
      updated_at: row.updated_at || null
    }))
    .filter((row) => row.dia && Number.isFinite(row.rate))
    .sort((a, b) => String(a.dia).localeCompare(String(b.dia), undefined, { sensitivity: 'base' }));
  return rows;
}

async function readDailyReportsFromWasabiSnapshot() {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (
    !WASABI_APP_DATA_STORE_WASABI_ONLY &&
    !snapshotLooksFresh(snapshot, WASABI_REPORTS_PRIMARY_MAX_SNAPSHOT_AGE_MS)
  ) {
    return null;
  }
  if (!snapshot?.data) return WASABI_APP_DATA_STORE_WASABI_ONLY ? [] : null;
  const rows = snapshotRows(snapshot, 'daily_reports')
    .map((row) => ({
      ...row,
      files: Array.isArray(row.files) ? row.files : parseJsonObject(row.files, [])
    }))
    .sort((a, b) => {
      const ra = String(b.report_date || '').localeCompare(String(a.report_date || ''));
      if (ra !== 0) return ra;
      const au = Date.parse(String(a.updated_at || '')) || 0;
      const bu = Date.parse(String(b.updated_at || '')) || 0;
      return bu - au;
    });
  return rows;
}

async function readDailyReportByIdFromWasabiSnapshot(id) {
  const reports = await readDailyReportsFromWasabiSnapshot();
  if (reports == null) return null;
  return reports.find((row) => String(row.id || '') === String(id || '')) || null;
}

function nextNumericId(rows) {
  const numericIds = (Array.isArray(rows) ? rows : [])
    .map((row) => Number(row?.id))
    .filter((n) => Number.isFinite(n));
  return numericIds.length ? Math.max(...numericIds) + 1 : 1;
}

function isPlannerRecordUuid(id) {
  const s = String(id || '').trim();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
}

async function upsertPricingRate(dia, rate) {
  let out = null;
  const wrote = await tryWasabiStateWrite('upsert-pricing-rate', async (data) => {
    const rows = ensureSnapshotTable(data, 'pricing_rates');
    const key = String(dia || '').trim().toUpperCase();
    const idx = rows.findIndex((row) => String(row.dia || '').trim().toUpperCase() === key);
    const next = {
      dia: key,
      rate: Number(rate),
      updated_at: nowIso()
    };
    if (idx >= 0) rows[idx] = { ...rows[idx], ...next };
    else rows.push(next);
    out = next;
  });
  if (wrote && out) return out;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    throw new Error(
      'Pricing is stored only in Wasabi; write failed. Verify WASABI_WRITES_PRIMARY_ENABLED=1 and Wasabi bucket configuration.'
    );
  }
  const result = await pool.query(
    `INSERT INTO pricing_rates (dia, rate, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (dia)
     DO UPDATE SET rate = EXCLUDED.rate, updated_at = NOW()
     RETURNING dia, rate, updated_at`,
    [dia, Number(rate)]
  );
  return result.rows[0];
}

async function deletePricingRate(dia) {
  let deletedDia = null;
  const wrote = await tryWasabiStateWrite('delete-pricing-rate', async (data) => {
    const rows = ensureSnapshotTable(data, 'pricing_rates');
    const key = String(dia || '').trim().toUpperCase();
    data.pricing_rates = rows.filter((row) => {
      const keep = String(row.dia || '').trim().toUpperCase() !== key;
      if (!keep) deletedDia = row.dia;
      return keep;
    });
  });
  if (wrote) return deletedDia;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    return null;
  }
  const result = await pool.query('DELETE FROM pricing_rates WHERE dia = $1 RETURNING dia', [dia]);
  return result.rows.length ? result.rows[0].dia : null;
}

async function createDailyReport(reportInput) {
  let created = null;
  const wrote = await tryWasabiStateWrite('create-daily-report', async (data) => {
    const rows = ensureSnapshotTable(data, 'daily_reports');
    const now = nowIso();
    const newId = WASABI_APP_DATA_STORE_WASABI_ONLY ? crypto.randomUUID() : nextNumericId(rows);
    created = {
      id: newId,
      title: cleanString(reportInput.title),
      report_date: cleanString(reportInput.report_date || new Date().toISOString().slice(0, 10)),
      notes: cleanString(reportInput.notes),
      files: Array.isArray(reportInput.files) ? reportInput.files : [],
      created_by: cleanString(reportInput.created_by),
      created_at: now,
      updated_at: now
    };
    rows.push(created);
  });
  if (wrote && created) return created;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    throw new Error(
      'Daily reports are stored only in Wasabi; create failed. Verify WASABI_WRITES_PRIMARY_ENABLED=1 and Wasabi bucket configuration.'
    );
  }
  const result = await pool.query(
    `INSERT INTO daily_reports (title, report_date, notes, files, created_by)
     VALUES ($1, $2, $3, $4::jsonb, $5)
     RETURNING *`,
    [
      cleanString(reportInput.title),
      cleanString(reportInput.report_date || new Date().toISOString().slice(0, 10)),
      cleanString(reportInput.notes),
      JSON.stringify(Array.isArray(reportInput.files) ? reportInput.files : []),
      cleanString(reportInput.created_by)
    ]
  );
  return result.rows[0];
}

async function updateDailyReportById(id, patch) {
  let updated = null;
  const wrote = await tryWasabiStateWrite('update-daily-report', async (data) => {
    const rows = ensureSnapshotTable(data, 'daily_reports');
    const idx = rows.findIndex((row) => String(row.id || '') === String(id || ''));
    if (idx < 0) throw new Error('Daily report not found');
    updated = {
      ...rows[idx],
      title: cleanString(patch.title),
      report_date: cleanString(patch.report_date || rows[idx].report_date),
      notes: cleanString(patch.notes),
      files: Array.isArray(patch.files) ? patch.files : [],
      updated_at: nowIso()
    };
    rows[idx] = updated;
  });
  if (wrote && updated) return updated;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    throw new Error(
      'Daily reports are stored only in Wasabi; update failed. Verify WASABI_WRITES_PRIMARY_ENABLED=1 and Wasabi bucket configuration.'
    );
  }
  const result = await pool.query(
    `UPDATE daily_reports
     SET title = $1,
         report_date = $2,
         notes = $3,
         files = $4::jsonb,
         updated_at = NOW()
     WHERE id = $5
     RETURNING *`,
    [cleanString(patch.title), cleanString(patch.report_date), cleanString(patch.notes), JSON.stringify(patch.files || []), id]
  );
  if (!result.rows.length) throw new Error('Daily report not found');
  return result.rows[0];
}

async function deleteDailyReportById(id) {
  let deleted = false;
  const wrote = await tryWasabiStateWrite('delete-daily-report', async (data) => {
    const rows = ensureSnapshotTable(data, 'daily_reports');
    const next = rows.filter((row) => String(row.id || '') !== String(id || ''));
    deleted = next.length !== rows.length;
    data.daily_reports = next;
  });
  if (wrote) return deleted;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    throw new Error(
      'Daily reports are stored only in Wasabi; delete failed. Verify WASABI_WRITES_PRIMARY_ENABLED=1 and Wasabi bucket configuration.'
    );
  }
  const result = await pool.query('DELETE FROM daily_reports WHERE id = $1 RETURNING id', [id]);
  return result.rows.length > 0;
}

async function createJobsiteAsset(assetInput) {
  let created = null;
  const wrote = await tryWasabiStateWrite('create-jobsite-asset', async (data) => {
    const rows = ensureSnapshotTable(data, 'jobsite_assets');
    const now = nowIso();
    const newId = WASABI_APP_DATA_STORE_WASABI_ONLY ? crypto.randomUUID() : nextNumericId(rows);
    created = {
      id: newId,
      client: upperCleanString(assetInput.client),
      city: upperCleanString(assetInput.city),
      jobsite: normalizeJobsiteName(assetInput.jobsite),
      contact_name: cleanString(assetInput.contact_name),
      contact_phone: cleanString(assetInput.contact_phone),
      contact_email: cleanString(assetInput.contact_email),
      notes: cleanString(assetInput.notes),
      drive_url: cleanString(assetInput.drive_url),
      files: Array.isArray(assetInput.files) ? assetInput.files : [],
      created_by: cleanString(assetInput.created_by),
      created_at: now,
      updated_at: now
    };
    rows.push(created);
  });
  if (wrote && created) return created;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    throw new Error(
      'Jobsite assets are stored only in Wasabi; create failed. Verify WASABI_WRITES_PRIMARY_ENABLED=1 and Wasabi bucket configuration.'
    );
  }
  const result = await pool.query(
    `INSERT INTO jobsite_assets
     (client, city, jobsite, contact_name, contact_phone, contact_email, notes, drive_url, files, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
     RETURNING *`,
    [
      upperCleanString(assetInput.client),
      upperCleanString(assetInput.city),
      normalizeJobsiteName(assetInput.jobsite),
      cleanString(assetInput.contact_name),
      cleanString(assetInput.contact_phone),
      cleanString(assetInput.contact_email),
      cleanString(assetInput.notes),
      cleanString(assetInput.drive_url),
      JSON.stringify(Array.isArray(assetInput.files) ? assetInput.files : []),
      cleanString(assetInput.created_by)
    ]
  );
  return result.rows[0];
}

async function deleteJobsiteAssetById(id) {
  let deleted = false;
  const wrote = await tryWasabiStateWrite('delete-jobsite-asset', async (data) => {
    const rows = ensureSnapshotTable(data, 'jobsite_assets');
    const next = rows.filter((row) => String(row.id || '') !== String(id || ''));
    deleted = next.length !== rows.length;
    data.jobsite_assets = next;
  });
  if (wrote) return deleted;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    throw new Error(
      'Jobsite assets are stored only in Wasabi; delete failed. Verify WASABI_WRITES_PRIMARY_ENABLED=1 and Wasabi bucket configuration.'
    );
  }
  const result = await pool.query('DELETE FROM jobsite_assets WHERE id = $1 RETURNING id', [id]);
  return result.rows.length > 0;
}

async function deleteJobsiteAssetsByClient(client) {
  let deletedCount = 0;
  const wrote = await tryWasabiStateWrite('delete-jobsite-assets-by-client', async (data) => {
    const rows = ensureSnapshotTable(data, 'jobsite_assets');
    const target = String(client || '').toLowerCase();
    const next = rows.filter((row) => String(row.client || '').toLowerCase() !== target);
    deletedCount = rows.length - next.length;
    data.jobsite_assets = next;
  });
  if (wrote) return deletedCount;
  if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
    throw new Error(
      'Jobsite assets are stored only in Wasabi; bulk delete failed. Verify WASABI_WRITES_PRIMARY_ENABLED=1 and Wasabi bucket configuration.'
    );
  }
  const result = await pool.query('DELETE FROM jobsite_assets WHERE client = $1 RETURNING id', [client]);
  return Number(result.rowCount || 0);
}

async function readJobsiteAssetsFromWasabiSnapshotForUser(user) {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (
    !WASABI_APP_DATA_STORE_WASABI_ONLY &&
    !snapshotLooksFresh(snapshot, WASABI_ASSETS_PRIMARY_MAX_SNAPSHOT_AGE_MS)
  ) {
    return null;
  }
  if (!snapshot?.data) return WASABI_APP_DATA_STORE_WASABI_ONLY ? [] : null;
  const rows = snapshotRows(snapshot, 'jobsite_assets')
    .map((row) => ({
      ...row,
      files: Array.isArray(row.files) ? row.files : parseJsonObject(row.files, [])
    }))
    .filter((row) => userCanAccessPsrScope(user, row))
    .sort((a, b) => {
      const c = String(a.client || '').localeCompare(String(b.client || ''), undefined, { sensitivity: 'base' });
      if (c !== 0) return c;
      const d = String(a.city || '').localeCompare(String(b.city || ''), undefined, { sensitivity: 'base' });
      if (d !== 0) return d;
      const e = String(a.jobsite || '').localeCompare(String(b.jobsite || ''), undefined, { sensitivity: 'base' });
      if (e !== 0) return e;
      const au = Date.parse(String(a.updated_at || '')) || 0;
      const bu = Date.parse(String(b.updated_at || '')) || 0;
      return bu - au;
    });
  return rows;
}

function summarizeRowsForSyncState(rows) {
  const list = Array.isArray(rows) ? rows : [];
  let latestMs = 0;
  for (const row of list) {
    const ms = Date.parse(String(row?.updated_at || row?.created_at || '')) || 0;
    if (ms > latestMs) latestMs = ms;
  }
  return {
    count: list.length,
    updated_at: latestMs ? new Date(latestMs).toISOString() : new Date(0).toISOString()
  };
}

async function readSyncStateFromWasabiSnapshot() {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (!snapshotLooksFresh(snapshot, WASABI_SYNC_STATE_PRIMARY_MAX_SNAPSHOT_AGE_MS)) return null;
  const payload = {
    records: summarizeRowsForSyncState(snapshotRows(snapshot, 'planner_records')),
    pricing: summarizeRowsForSyncState(snapshotRows(snapshot, 'pricing_rates')),
    reports: summarizeRowsForSyncState(snapshotRows(snapshot, 'daily_reports')),
    assets: summarizeRowsForSyncState(snapshotRows(snapshot, 'jobsite_assets')),
    psr_scopes: summarizeRowsForSyncState(snapshotRows(snapshot, 'user_psr_scopes')),
    users: summarizeRowsForSyncState(snapshotRows(snapshot, 'users')),
    emails: summarizeRowsForSyncState(snapshotRows(snapshot, 'user_outlook_tokens'))
  };
  return payload;
}

async function readUsersFromWasabiSnapshot() {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (!snapshotLooksFresh(snapshot, WASABI_USERS_PRIMARY_MAX_SNAPSHOT_AGE_MS)) return null;
  const rows = snapshotRows(snapshot, 'users').map((row) => normalizeUser(row));
  rows.sort((a, b) => {
    const da = String(a.displayName || a.username || '').toLowerCase();
    const db = String(b.displayName || b.username || '').toLowerCase();
    const c = da.localeCompare(db);
    if (c !== 0) return c;
    return String(a.username || '').toLowerCase().localeCompare(String(b.username || '').toLowerCase());
  });
  return rows;
}

async function readUserByIdFromWasabiSnapshot(id) {
  const users = await readUsersFromWasabiSnapshot();
  if (!users) return null;
  return users.find((u) => String(u.id || '') === String(id || '')) || null;
}

async function countAdminsFromWasabiSnapshot() {
  const users = await readUsersFromWasabiSnapshot();
  if (!users) return null;
  return users.filter((u) => u.isAdmin === true).length;
}

function plannerScopeMatch(row, client, city, jobsite) {
  return (
    String(row?.client || '').trim().toLowerCase() === String(client || '').trim().toLowerCase() &&
    String(row?.city || '').trim().toLowerCase() === String(city || '').trim().toLowerCase() &&
    String(row?.jobsite || '').trim().toLowerCase() === String(jobsite || '').trim().toLowerCase()
  );
}

function sortRecordsByUpdatedDesc(records) {
  const list = Array.isArray(records) ? records.slice() : [];
  list.sort((a, b) => {
    const au = Date.parse(String(a?.updated_at || a?.created_at || '')) || 0;
    const bu = Date.parse(String(b?.updated_at || b?.created_at || '')) || 0;
    return bu - au;
  });
  return list;
}

async function findPlannerRecordsByScopeFromWasabiSnapshot(client, city, jobsite) {
  const snapshot = await loadWasabiLatestStateSnapshot();
  if (!snapshot || !snapshot.data) return PLANNER_STORE_WASABI_ONLY ? [] : null;
  if (
    !PLANNER_STORE_WASABI_ONLY &&
    !snapshotLooksFresh(snapshot, WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_MAX_SNAPSHOT_AGE_MS)
  ) {
    return null;
  }
  const rows = snapshotRows(snapshot, 'planner_records');
  const matched = rows.filter((row) => plannerScopeMatch(row, client, city, jobsite)).map((row) => normalizeRecordRow(row));
  return sortRecordsByUpdatedDesc(matched);
}

async function findPlannerRecordsByScope(client, city, jobsite, options = {}) {
  const latestOnly = options && options.latestOnly === true;
  const preferWasabiForScope = PLANNER_STORE_WASABI_ONLY || WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_ENABLED;
  if (preferWasabiForScope) {
    try {
      const snapshotRecords = await findPlannerRecordsByScopeFromWasabiSnapshot(client, city, jobsite);
      if (snapshotRecords !== null) return latestOnly ? snapshotRecords.slice(0, 1) : snapshotRecords;
      if (WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_STRICT && !PLANNER_STORE_WASABI_ONLY) return [];
    } catch (error) {
      if (WASABI_PLANNER_SCOPE_LOOKUP_PRIMARY_STRICT && !PLANNER_STORE_WASABI_ONLY) throw error;
    }
  }
  if (PLANNER_STORE_WASABI_ONLY) return [];
  const sql = latestOnly
    ? `SELECT * FROM planner_records
       WHERE LOWER(client) = LOWER($1)
         AND LOWER(city) = LOWER($2)
         AND LOWER(jobsite) = LOWER($3)
       ORDER BY updated_at DESC
       LIMIT 1`
    : `SELECT * FROM planner_records
       WHERE LOWER(client) = LOWER($1)
         AND LOWER(city) = LOWER($2)
         AND LOWER(jobsite) = LOWER($3)`;
  const result = await pool.query(sql, [client, city, jobsite]);
  return result.rows.map(normalizeRecordRow);
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

async function mirrorSessionToPostgres(token, userId, keepSession) {
  const ttlMinutes = resolveSessionTtlMinutes(keepSession);
  await pool.query(
    `INSERT INTO auth_sessions (token, user_id, keep_session, expires_at)
     VALUES ($1, $2, $3, NOW() + ($4 || ' minutes')::interval)
     ON CONFLICT (token) DO UPDATE
       SET user_id = EXCLUDED.user_id,
           keep_session = EXCLUDED.keep_session,
           expires_at = EXCLUDED.expires_at,
           updated_at = NOW()`,
    [token, String(userId), keepSession, ttlMinutes]
  );
}

async function issueSession(userId, options = {}) {
  const keepSession = options?.keepSession === true;
  const ttlMinutes = resolveSessionTtlMinutes(keepSession);
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAtIso = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
  const wasabiWrote = await tryWasabiStateWrite('issue-session', async (data) => {
    const sessions = ensureSnapshotTable(data, 'auth_sessions');
    const now = nowIso();
    sessions.push({
      token,
      user_id: String(userId),
      keep_session: keepSession,
      expires_at: expiresAtIso,
      created_at: now,
      updated_at: now
    });
  });
  if (wasabiWrote) {
    try {
      await mirrorSessionToPostgres(token, userId, keepSession);
    } catch (error) {
      console.warn(`[auth] postgres mirror write failed after Wasabi issue-session: ${error?.message || error}`);
    }
    return token;
  }
  await mirrorSessionToPostgres(token, userId, keepSession);
  return token;
}

async function readSessionFromWasabiSnapshot(token, snapshotOverride = null) {
  const snapshot = snapshotOverride || (await loadWasabiLatestStateSnapshot());
  if (!snapshot || !snapshot.data) return null;
  const sessions = snapshotRows(snapshot, 'auth_sessions');
  const users = snapshotRows(snapshot, 'users');
  const hit = sessions.find((s) => String(s.token || '') === String(token || ''));
  if (!hit) return null;
  if (new Date(hit.expires_at).getTime() < Date.now()) return null;
  const user = users.find((u) => String(u.id || '') === String(hit.user_id || ''));
  if (!user) return null;
  const normalized = normalizeUser({
    ...user,
    token: hit.token,
    user_id: hit.user_id,
    expires_at: hit.expires_at
  });
  return {
    user: attachScopesToUserFromSnapshot(normalized, snapshot),
    keepSession: hit.keep_session === true
  };
}

async function readFreshUserFromPostgresById(userId) {
  const id = String(userId || '').trim();
  if (!id) return null;
  const result = await pool.query(
    `SELECT id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id,
            portal_permissions_access, portal_files_access_granted, self_signup, email, first_name, last_name, company, title, phone, email_verified
     FROM users
     WHERE CAST(id AS text) = $1
     LIMIT 1`,
    [id]
  );
  if (!result.rows.length) return null;
  return attachScopesToUser(normalizeUser(result.rows[0]));
}

async function extendWasabiSessionExpiry(token, keepSession = false) {
  const ttlMinutes = resolveSessionTtlMinutes(keepSession);
  const wrote = await tryWasabiStateWrite('extend-session', async (data) => {
    const sessions = ensureSnapshotTable(data, 'auth_sessions');
    const idx = sessions.findIndex((s) => String(s.token || '') === String(token || ''));
    if (idx < 0) return;
    sessions[idx] = {
      ...sessions[idx],
      expires_at: new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString(),
      updated_at: nowIso()
    };
  });
  if (!wrote) {
    await pool.query(
      `UPDATE auth_sessions
       SET expires_at = NOW() + ($2 || ' minutes')::interval,
           updated_at = NOW()
       WHERE token = $1`,
      [token, ttlMinutes]
    );
  } else {
    try {
      await pool.query(
        `UPDATE auth_sessions
         SET expires_at = NOW() + ($2 || ' minutes')::interval,
             updated_at = NOW()
         WHERE token = $1`,
        [token, ttlMinutes]
      );
    } catch (error) {
      console.warn(`[auth] postgres mirror expiry update failed: ${error?.message || error}`);
    }
  }
}

async function readSessionFromPostgres(token) {
  await pool.query(`DELETE FROM auth_sessions WHERE expires_at < NOW()`);
  const result = await pool.query(
    `SELECT s.token, s.user_id, s.keep_session, s.expires_at, u.id, u.username, u.display_name, u.password,
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
  const keepSession = row.keep_session === true;
  const ttlMinutes = resolveSessionTtlMinutes(keepSession);
  await pool.query(
    `UPDATE auth_sessions
     SET expires_at = NOW() + ($2 || ' minutes')::interval,
         updated_at = NOW()
     WHERE token = $1`,
    [token, ttlMinutes]
  );
  return {
    user: await attachScopesToUser(normalizeUser(row)),
    keepSession
  };
}

/**
 * Remove a session token from Postgres and the Wasabi snapshot (best-effort).
 * Used when the user row no longer exists or auth must fail closed.
 */
async function revokeSessionToken(token, reason = '') {
  if (!token) return;
  try {
    await tryWasabiStateWrite('revoke-session', async (data) => {
      const sessions = ensureSnapshotTable(data, 'auth_sessions');
      data.auth_sessions = sessions.filter((row) => String(row.token || '') !== String(token));
    });
  } catch (error) {
    console.warn(`[auth] Wasabi session revoke failed: ${error?.message || error}`);
  }
  try {
    await pool.query('DELETE FROM auth_sessions WHERE token = $1', [token]);
  } catch (error) {
    console.warn(`[auth] Postgres session revoke failed: ${error?.message || error}`);
  }
  if (reason) {
    console.warn(`[auth] session token revoked: ${reason}`);
  }
}

async function readSession(token) {
  if (!token) return null;
  let wasabiPrimaryIssue = '';
  let triedWasabiPrimary = false;
  if (WASABI_AUTH_PRIMARY_ENABLED) {
    triedWasabiPrimary = true;
    try {
      const snapshot = await loadWasabiLatestStateSnapshot();
      const fresh = snapshotLooksFresh(snapshot);
      if (snapshot && snapshot.data) {
        const sessionHit = await readSessionFromWasabiSnapshot(token, snapshot);
        if (sessionHit) {
          if (!fresh) {
            console.warn('[auth] using stale Wasabi snapshot for session resolution');
          }
          let freshUser = null;
          let pgRefreshError = null;
          try {
            freshUser = await readFreshUserFromPostgresById(sessionHit.user?.id);
          } catch (error) {
            pgRefreshError = error;
            console.warn(`[auth] Postgres user refresh failed after Wasabi session hit: ${error?.message || error}`);
          }
          if (freshUser) {
            try {
              await extendWasabiSessionExpiry(token, sessionHit.keepSession);
            } catch (error) {
              if (WASABI_WRITES_PRIMARY_STRICT) throw error;
            }
            return freshUser;
          }
          if (!pgRefreshError) {
            await revokeSessionToken(token, 'postgres_user_missing_after_wasabi_hit');
            return null;
          }
        } else {
          wasabiPrimaryIssue = fresh ? 'snapshot_miss' : 'snapshot_stale_miss';
        }
      } else {
        wasabiPrimaryIssue = fresh ? 'snapshot_empty' : 'snapshot_stale';
      }
    } catch (error) {
      wasabiPrimaryIssue = `snapshot_error:${error?.message || error}`;
    }
    if (WASABI_AUTH_PRIMARY_STRICT && wasabiPrimaryIssue) {
      console.warn(
        `[auth] strict Wasabi primary miss (${wasabiPrimaryIssue}); falling back to Postgres lookup for session token`
      );
    }
  }
  try {
    const sessionHit = await readSessionFromPostgres(token);
    if (sessionHit) {
      if (triedWasabiPrimary && wasabiPrimaryIssue) {
        console.warn(`[auth] session resolved via Postgres fallback after Wasabi primary ${wasabiPrimaryIssue}`);
      }
      return sessionHit.user;
    }
    return null;
  } catch (error) {
    console.warn(`[auth] Postgres session lookup failed: ${error?.message || error}`);
    if (!WASABI_AUTH_FALLBACK_ENABLED) throw error;
    try {
      const fallback = await readSessionFromWasabiSnapshot(token);
      if (!fallback) {
        return null;
      }
      console.warn('[auth] using Wasabi session fallback for token lookup');
      let freshUser = null;
      try {
        freshUser = await readFreshUserFromPostgresById(fallback.user?.id);
      } catch (pgErr) {
        console.warn(`[auth] Postgres user refresh failed in Wasabi fallback: ${pgErr?.message || pgErr}`);
        return null;
      }
      if (freshUser) {
        return freshUser;
      }
      await revokeSessionToken(token, 'postgres_user_missing_wasabi_pg_fallback');
      return null;
    } catch (fallbackError) {
      throw error && fallbackError
        ? new Error(`${error?.message || error} | wasabi fallback failed: ${fallbackError?.message || fallbackError}`)
        : error;
    }
  }
}

async function requireAuth(req, res, next) {
  try {
    const token = currentToken(req);
    const tokenHint = token ? `${String(token).slice(0, 8)}...` : 'none';
    const user = await readSession(token);
    if (!user) {
      console.warn(
        `[auth] reject ${req.method || 'GET'} ${req.originalUrl || req.url || ''}: no session for token=${tokenHint}`
      );
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

/** Admin Panel + user/permission management (see `capabilities.canAccessAdminPanel`). */
function requireAdminPanelAccess(req, res, next) {
  const u = req.user;
  if (!u) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  if (canAccessAdminPanel(u)) return next();
  return res.status(403).json({ success: false, error: 'Admin access required' });
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
  ['psrPlanner', 'psrViewer', 'psrDataEntry', 'camera', 'vac', 'simpleVac', 'pricingView', 'footageView'],
  'Planner access is not enabled for this account'
);
const requirePsrViewerAccess = requireAnyRole(
  ['psrViewer', 'psrDataEntry', 'psrPlanner', 'camera', 'vac', 'simpleVac', 'pricingView', 'footageView'],
  'PSR viewer access is not enabled for this account'
);
const requirePsrDataEntryAccess = requireAnyRole(
  ['psrDataEntry', 'psrPlanner', 'camera', 'vac', 'simpleVac'],
  'PSR data entry access is not enabled for this account'
);
const requireDataAutoSyncEmployeeAccess = requireAnyRole(
  ['dataAutoSyncEmployee'],
  'DataAutoSync employee access is not enabled for this account'
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
  const recordId = cleanString(scope?.id || scope?.recordId || '');
  if (recordId) {
    return scopes.some((entry) => cleanString(entry.recordId || '') === recordId);
  }
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
    const rid = cleanString(scope.recordId || '');
    if (rid) {
      clauses.push(
        `(CAST(${prefix}id AS text) = $${index++} OR (LOWER(${prefix}client) = LOWER($${index++}) AND LOWER(${prefix}city) = LOWER($${index++}) AND LOWER(${prefix}jobsite) = LOWER($${index++})))`
      );
      params.push(rid, scope.client, scope.city, scope.jobsite);
    } else {
      clauses.push(
        `(LOWER(${prefix}client) = LOWER($${index++}) AND LOWER(${prefix}city) = LOWER($${index++}) AND LOWER(${prefix}jobsite) = LOWER($${index++}))`
      );
      params.push(scope.client, scope.city, scope.jobsite);
    }
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
      roles JSONB NOT NULL DEFAULT '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "psrViewer": false, "psrDataEntry": false, "dataAutoSyncEmployee": false, "pricingView": false, "footageView": false, "portalUpload": false, "portalDownload": false, "portalEdit": false, "portalDelete": false}'::jsonb,
      must_change_password BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const userAlters = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "psrViewer": false, "psrDataEntry": false, "dataAutoSyncEmployee": false, "pricingView": false, "footageView": false, "portalUpload": false, "portalDownload": false, "portalEdit": false, "portalDelete": false}'::jsonb`,
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
    `ALTER TABLE users ALTER COLUMN roles SET DEFAULT '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "psrViewer": false, "psrDataEntry": false, "dataAutoSyncEmployee": false, "pricingView": false, "footageView": false, "portalUpload": false, "portalDownload": false, "portalEdit": false, "portalDelete": false}'::jsonb`
  );
  await pool.query(`ALTER TABLE users ALTER COLUMN portal_files_access_granted SET DEFAULT false`);
  await pool.query(
    `UPDATE users
     SET roles = '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "psrViewer": false, "psrDataEntry": false, "dataAutoSyncEmployee": false, "pricingView": false, "footageView": false, "portalUpload": false, "portalDownload": false, "portalEdit": false, "portalDelete": false}'::jsonb
     WHERE roles IS NULL`
  );
  await pool.query(
    `UPDATE users
     SET roles = '{"camera": false, "vac": false, "simpleVac": false, "email": false, "psrPlanner": false, "psrViewer": false, "psrDataEntry": false, "dataAutoSyncEmployee": false, "pricingView": false, "footageView": false, "portalUpload": false, "portalDownload": false, "portalEdit": false, "portalDelete": false}'::jsonb
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
      psr_record_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, client, city, jobsite)
    )
  `);
  await pool.query(`ALTER TABLE user_psr_scopes ADD COLUMN IF NOT EXISTS psr_record_id TEXT`);
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
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_psr_scopes_record_id ON user_psr_scopes (psr_record_id)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      keep_session BOOLEAN NOT NULL DEFAULT false,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS keep_session BOOLEAN NOT NULL DEFAULT false`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions (user_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions (expires_at)`);

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

  /** Legacy DBs may still have planner_records.id as int4/int8; app inserts use UUID. */
  await pool.query(`
    DO $$
    DECLARE
      pkname TEXT;
      relid oid;
    BEGIN
      SELECT c.oid INTO relid
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname = 'planner_records' AND c.relkind = 'r';
      IF relid IS NULL THEN
        RETURN;
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'planner_records'
          AND column_name = 'id' AND udt_name IN ('int4', 'int8')
      ) THEN
        RETURN;
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'planner_records' AND column_name = 'id_uuid'
      ) THEN
        ALTER TABLE planner_records ADD COLUMN id_uuid uuid;
      END IF;
      UPDATE planner_records SET id_uuid = gen_random_uuid() WHERE id_uuid IS NULL;
      UPDATE user_psr_scopes ups
      SET psr_record_id = pr.id_uuid::text
      FROM planner_records pr
      WHERE pr.id_uuid IS NOT NULL
        AND ups.psr_record_id IS NOT NULL
        AND BTRIM(ups.psr_record_id) <> ''
        AND ups.psr_record_id = pr.id::text;
      SELECT c.conname INTO pkname
      FROM pg_constraint c
      WHERE c.conrelid = relid AND c.contype = 'p'
      LIMIT 1;
      IF pkname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE planner_records DROP CONSTRAINT %I', pkname);
      END IF;
      ALTER TABLE planner_records DROP COLUMN id;
      ALTER TABLE planner_records RENAME COLUMN id_uuid TO id;
      ALTER TABLE planner_records ADD PRIMARY KEY (id);
      ALTER TABLE planner_records ALTER COLUMN id SET DEFAULT gen_random_uuid();
      RAISE NOTICE 'planner_records.id migrated from integer to uuid';
    END $$;
  `);

  await pool.query(
    `INSERT INTO user_psr_scopes (user_id, client, city, jobsite, psr_record_id)
     SELECT DISTINCT CAST(u.id AS text), pr.client, pr.city, pr.jobsite, CAST(pr.id AS text)
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
  await pool.query(
    `UPDATE user_psr_scopes ups
     SET psr_record_id = CAST(pr.id AS text)
     FROM planner_records pr
     WHERE (ups.psr_record_id IS NULL OR BTRIM(ups.psr_record_id) = '')
       AND LOWER(BTRIM(ups.client)) = LOWER(BTRIM(pr.client))
       AND LOWER(BTRIM(ups.city)) = LOWER(BTRIM(pr.city))
       AND LOWER(BTRIM(ups.jobsite)) = LOWER(BTRIM(pr.jobsite))`
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

  await ensureOutlookSchema({ pool, query: queryOutlookDataWithWasabiFallback });

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

app.post('/admin/wasabi-state-snapshot', requireAuth, requireAdmin, async (req, res) => {
  try {
    await runWasabiStateSnapshot();
    res.json({
      success: true,
      ...currentWasabiStateStatus(),
      autoImport: currentWasabiAutoImportStatus(),
      portalData: currentWasabiPortalDataStatus(),
      outlook: currentWasabiOutlookStatus(),
      signup: currentWasabiSignupStatus()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error && error.message ? error.message : String(error),
      autoImport: currentWasabiAutoImportStatus(),
      portalData: currentWasabiPortalDataStatus(),
      outlook: currentWasabiOutlookStatus(),
      signup: currentWasabiSignupStatus()
    });
  }
});

app.get('/admin/wasabi-state-status', requireAuth, requireAdmin, async (req, res) => {
  res.json({
    success: true,
    ...currentWasabiStateStatus(),
    autoImport: currentWasabiAutoImportStatus(),
    portalData: currentWasabiPortalDataStatus(),
    outlook: currentWasabiOutlookStatus(),
    signup: currentWasabiSignupStatus()
  });
});

app.get('/admin/wasabi-sql-mirror-status', requireAuth, requireAdmin, async (req, res) => {
  res.json({
    success: true,
    ...currentWasabiSqlMirrorStatus()
  });
});

app.get('/admin/wasabi-auto-import-status', requireAuth, requireAdmin, async (req, res) => {
  res.json({
    success: true,
    ...currentWasabiAutoImportStatus()
  });
});

app.get('/admin/wasabi-portal-data-status', requireAuth, requireAdmin, async (req, res) => {
  res.json({
    success: true,
    ...currentWasabiPortalDataStatus()
  });
});

app.get('/admin/wasabi-outlook-status', requireAuth, requireAdmin, async (req, res) => {
  res.json({
    success: true,
    ...currentWasabiOutlookStatus()
  });
});

app.get('/admin/wasabi-signup-status', requireAuth, requireAdmin, async (req, res) => {
  res.json({
    success: true,
    ...currentWasabiSignupStatus()
  });
});

app.get('/admin/wasabi-runtime-readiness', requireAuth, requireAdmin, async (req, res) => {
  try {
    const forceRefresh = String(req.query?.force || '').trim() === '1';
    const snapshot = await loadWasabiLatestStateSnapshot(forceRefresh);
    const readiness = evaluateWasabiRuntimeReadiness(snapshot);
    res.json({
      success: true,
      bucket: WASABI_STATE_BUCKET || null,
      prefix: WASABI_STATE_PREFIX,
      forceRefresh,
      allReadsPrimaryEnabled: WASABI_ALL_READS_PRIMARY_ENABLED,
      allReadsPrimaryStrict: WASABI_ALL_READS_PRIMARY_STRICT,
      ...readiness,
      sqlMirror: currentWasabiSqlMirrorStatus(),
      autoImport: currentWasabiAutoImportStatus(),
      portalData: currentWasabiPortalDataStatus(),
      outlook: currentWasabiOutlookStatus(),
      signup: currentWasabiSignupStatus()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error && error.message ? error.message : String(error),
      bucket: WASABI_STATE_BUCKET || null,
      prefix: WASABI_STATE_PREFIX,
      autoImport: currentWasabiAutoImportStatus(),
      portalData: currentWasabiPortalDataStatus(),
      outlook: currentWasabiOutlookStatus(),
      signup: currentWasabiSignupStatus()
    });
  }
});

app.post('/admin/wasabi-sql-mirror-flush', requireAuth, requireAdmin, async (req, res) => {
  try {
    await flushWasabiSqlMirrorQueue();
    res.json({
      success: true,
      ...currentWasabiSqlMirrorStatus()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error && error.message ? error.message : String(error),
      ...currentWasabiSqlMirrorStatus()
    });
  }
});

app.post('/admin/wasabi-sync-now', requireAuth, requireAdmin, async (req, res) => {
  try {
    const reason = cleanString(req.body?.reason || 'manual-sync');
    const result = await syncWasabiNow(reason);
    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error && error.message ? error.message : String(error),
      state: currentWasabiStateStatus(),
      sqlMirror: currentWasabiSqlMirrorStatus(),
      autoImport: currentWasabiAutoImportStatus(),
      portalData: currentWasabiPortalDataStatus(),
      outlook: currentWasabiOutlookStatus(),
      signup: currentWasabiSignupStatus()
    });
  }
});

app.post('/admin/planner-migrate-postgres-to-wasabi', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!WASABI_WRITES_PRIMARY_ENABLED) {
      return res.status(400).json({
        success: false,
        error: 'Set WASABI_WRITES_PRIMARY_ENABLED=1 so the snapshot can be updated.'
      });
    }
    if (!wasabiStateClient || !WASABI_STATE_BUCKET) {
      return res.status(400).json({ success: false, error: 'Wasabi state bucket is not configured.' });
    }
    const result = await migrateAppDataFromPostgresToWasabi();
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('APP DATA MIGRATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message || String(error) });
  }
});

app.post('/admin/app-data-migrate-postgres-to-wasabi', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (!WASABI_WRITES_PRIMARY_ENABLED) {
      return res.status(400).json({
        success: false,
        error: 'Set WASABI_WRITES_PRIMARY_ENABLED=1 so the snapshot can be updated.'
      });
    }
    if (!wasabiStateClient || !WASABI_STATE_BUCKET) {
      return res.status(400).json({ success: false, error: 'Wasabi state bucket is not configured.' });
    }
    const result = await migrateAppDataFromPostgresToWasabi();
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('APP DATA MIGRATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message || String(error) });
  }
});

app.get('/sync-state', requireAuth, async (req, res) => {
  try {
    if (WASABI_SYNC_STATE_PRIMARY_ENABLED) {
      try {
        const snapshotState = await readSyncStateFromWasabiSnapshot();
        if (snapshotState) {
          const signature = crypto.createHash('sha256').update(JSON.stringify(snapshotState)).digest('hex');
          return res.json({ success: true, signature, state: snapshotState });
        }
        if (WASABI_SYNC_STATE_PRIMARY_STRICT) {
          const empty = {
            records: { count: 0, updated_at: new Date(0).toISOString() },
            pricing: { count: 0, updated_at: new Date(0).toISOString() },
            reports: { count: 0, updated_at: new Date(0).toISOString() },
            assets: { count: 0, updated_at: new Date(0).toISOString() },
            psr_scopes: { count: 0, updated_at: new Date(0).toISOString() },
            users: { count: 0, updated_at: new Date(0).toISOString() },
            emails: { count: 0, updated_at: new Date(0).toISOString() }
          };
          const signature = crypto.createHash('sha256').update(JSON.stringify(empty)).digest('hex');
          return res.json({ success: true, signature, state: empty });
        }
      } catch (error) {
        if (WASABI_SYNC_STATE_PRIMARY_STRICT) throw error;
      }
    }

    const recordsMetaPromise = PLANNER_STORE_WASABI_ONLY
      ? getPlannerRecordsSyncMetaFromWasabi().then((m) => ({ rows: [m] }))
      : pool.query(
          `SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM planner_records`
        );
    const pricingMetaPromise = WASABI_APP_DATA_STORE_WASABI_ONLY
      ? getTableSyncMetaFromWasabi('pricing_rates').then((m) => ({ rows: [m] }))
      : pool.query(
          `SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM pricing_rates`
        );
    const reportsMetaPromise = WASABI_APP_DATA_STORE_WASABI_ONLY
      ? getTableSyncMetaFromWasabi('daily_reports').then((m) => ({ rows: [m] }))
      : pool.query(
          `SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM daily_reports`
        );
    const assetsMetaPromise = WASABI_APP_DATA_STORE_WASABI_ONLY
      ? getTableSyncMetaFromWasabi('jobsite_assets').then((m) => ({ rows: [m] }))
      : pool.query(
          `SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM jobsite_assets`
        );
    const psrScopesMetaPromise = PLANNER_STORE_WASABI_ONLY
      ? getTableSyncMetaFromWasabi('user_psr_scopes').then((m) => ({ rows: [m] }))
      : pool.query(
          `SELECT COUNT(*)::int AS count, COALESCE(MAX(created_at), TO_TIMESTAMP(0)) AS updated_at FROM user_psr_scopes`
        );
    const [records, pricing, reports, assets, psr_scopes, users, emails] = await Promise.all([
      recordsMetaPromise,
      pricingMetaPromise,
      reportsMetaPromise,
      assetsMetaPromise,
      psrScopesMetaPromise,
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM users`),
      pool.query(`SELECT COUNT(*)::int AS count, COALESCE(MAX(updated_at), TO_TIMESTAMP(0)) AS updated_at FROM user_outlook_tokens`)
    ]);
    const payload = {
      records: records.rows[0],
      pricing: pricing.rows[0],
      reports: reports.rows[0],
      assets: assets.rows[0],
      psr_scopes: psr_scopes.rows[0],
      users: users.rows[0],
      emails: emails.rows[0]
    };
    const signature = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    res.json({ success: true, signature, state: payload });
  } catch (error) {
    console.error('SYNC STATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/users', requireAuth, async (req, res) => {
  try {
    const currentUser = req.user;
    /** Permissions UI must reflect Postgres immediately after saves — do not prefer stale Wasabi snapshots here. */
    const result = await pool.query(
      `SELECT id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, portal_permissions_access, self_signup
       FROM users
       ORDER BY LOWER(COALESCE(display_name, username)), LOWER(username)`
    );
    const normalizedRows = await attachScopesToUsers(result.rows.map((row) => normalizeUser(row)));
    const users = normalizedRows.map((normalized) => {
      if (!canAccessAdminPanel(currentUser)) {
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

app.get('/permissions/tree', requireAuth, requireAdminPanelAccess, async (req, res) => {
  try {
    /**
     * Portal scopes and path grants stay live from Postgres.
     * When planner canonical data is Wasabi-only, job labels and PSR tree come from the snapshot — not `planner_records` in Postgres.
     */
    const portalPathGrantsSql = `SELECT client_id, job_id, path_prefix
         FROM portal_path_grants
         WHERE client_id IS NOT NULL AND BTRIM(client_id) <> ''
           AND job_id IS NOT NULL AND BTRIM(job_id) <> ''
         ORDER BY client_id, job_id, path_prefix`;

    if (PLANNER_STORE_WASABI_ONLY) {
      const scopePairsSql = `WITH scope_pairs AS (
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
         )
         SELECT client_id, job_id
         FROM scope_pairs_clean
         ORDER BY client_id, job_id`;
      const [scopePairsRes, portalPathRows] = await Promise.all([
        pool.query(scopePairsSql),
        pool.query(portalPathGrantsSql)
      ]);
      const snapshot = await loadWasabiLatestStateSnapshot(true);
      const plannerRecords = snapshotRows(snapshot, 'planner_records');
      const portalRows = attachPlannerLabelsToScopeRows(scopePairsRes.rows, plannerRecords);
      const psrRows = plannerRecords
        .map((row) => ({
          id: row.id,
          client: row.client,
          city: row.city,
          jobsite: row.jobsite
        }))
        .filter(
          (row) =>
            String(row.client || '').trim() &&
            String(row.city || '').trim() &&
            String(row.jobsite || '').trim()
        );
      const trees = buildPermissionsTreesFromRows({
        portalRows,
        portalPathRows: portalPathRows.rows,
        psrRows
      });
      return res.json({ success: true, ...trees });
    }

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
      pool.query(portalPathGrantsSql),
      pool.query(
        `SELECT DISTINCT id, client, city, jobsite
         FROM planner_records
         WHERE BTRIM(client) <> '' AND BTRIM(city) <> '' AND BTRIM(jobsite) <> ''
         ORDER BY client, city, jobsite`
      )
    ]);
    const trees = buildPermissionsTreesFromRows({
      portalRows: portalRows.rows,
      portalPathRows: portalPathRows.rows,
      psrRows: psrRows.rows
    });
    res.json({ success: true, ...trees });
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
    let row = null;
    let userRowFromWasabi = false;
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
      row = result.rows[0] || null;
    } catch (queryError) {
      if (!WASABI_LOGIN_FALLBACK_ENABLED) throw queryError;
      row = await readLoginUserFromWasabiSnapshot(submittedUsername);
      userRowFromWasabi = !!row;
      if (!row) throw queryError;
      console.warn('[login] using Wasabi user lookup fallback');
    }

    if (!row) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

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

    if (needsRehash && !userRowFromWasabi) {
      const hash = await bcrypt.hash(submittedPassword, 10);
      const wasabiWrote = await tryWasabiStateWrite('login-rehash-password', async (data) => {
        const users = ensureSnapshotTable(data, 'users');
        const idx = users.findIndex((u) => String(u.id || '') === String(row.id || ''));
        if (idx < 0) return;
        users[idx] = {
          ...users[idx],
          password: hash,
          updated_at: nowIso()
        };
      });
      if (!wasabiWrote) {
        await pool.query('UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2', [hash, row.id]);
      }
    }

    const user = await attachScopesToUser(normalizeUser(row));
    const keepRaw = req.body?.keepSession;
    const keepSession = keepRaw === true || keepRaw === 1 || String(keepRaw || '').trim().toLowerCase() === 'true';
    const token = await issueSession(row.id, { keepSession });
    res.json({ success: true, user, token, capabilities: resolveCapabilities(user) });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/session', requireAuth, async (req, res) => {
  res.json({ success: true, user: req.user, capabilities: resolveCapabilities(req.user) });
});

app.get('/data-auto-sync/access', requireAuth, requireDataAutoSyncEmployeeAccess, async (req, res) => {
  res.json({ success: true, allowed: true });
});

/** WinCan / desktop EXE pushes rows using the same session token as the web planner (not a static API key). */
app.post('/auto-import-plugin/push', requireAuth, requireDataAutoSyncEmployeeAccess, async (req, res) => {
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
    const wasabiWrote = await tryWasabiStateWrite('logout', async (data) => {
      const sessions = ensureSnapshotTable(data, 'auth_sessions');
      data.auth_sessions = sessions.filter((row) => String(row.token || '') !== String(req.sessionToken || ''));
    });
    if (wasabiWrote) {
      return res.json({ success: true });
    }
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
    let row = null;
    if (WASABI_USERS_PRIMARY_ENABLED) {
      try {
        const snapshotUser = await readUserByIdFromWasabiSnapshot(req.user.id);
        if (snapshotUser) {
          row = {
            id: snapshotUser.id,
            password: snapshotUser.password,
            must_change_password: snapshotUser.mustChangePassword
          };
        } else if (WASABI_USERS_PRIMARY_STRICT) {
          return res.status(404).json({ success: false, error: 'User not found' });
        }
      } catch (error) {
        if (WASABI_USERS_PRIMARY_STRICT) throw error;
      }
    }
    if (!row) {
      const result = await pool.query(
        'SELECT id, password, must_change_password FROM users WHERE id = $1 LIMIT 1',
        [req.user.id]
      );
      if (!result.rows.length) {
        return res.status(404).json({ success: false, error: 'User not found' });
      }
      row = result.rows[0];
    }
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
    const wasabiWrote = await tryWasabiStateWrite('change-password', async (data) => {
      const users = ensureSnapshotTable(data, 'users');
      const idx = users.findIndex((u) => String(u.id || '') === String(req.user.id || ''));
      if (idx < 0) {
        throw new Error('User not found in Wasabi state');
      }
      users[idx] = {
        ...users[idx],
        password: hash,
        must_change_password: false,
        updated_at: nowIso()
      };
    });
    if (!wasabiWrote) {
      await pool.query(
        'UPDATE users SET password = $1, must_change_password = false, updated_at = NOW() WHERE id = $2',
        [hash, req.user.id]
      );
    }

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

app.post('/create-user', requireAuth, requireAdminPanelAccess, async (req, res) => {
  const username = cleanString(req.body?.username);
  const displayName = cleanString(req.body?.displayName || username);
  const password = cleanString(req.body?.password || '1234');
  let isAdmin = !!req.body?.isAdmin;
  if (!req.user?.isAdmin) {
    isAdmin = false;
  }
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
    if (WASABI_WRITES_PRIMARY_ENABLED) {
      let createdRow = null;
      const wrote = await tryWasabiStateWrite('create-user', async (data) => {
        const users = ensureSnapshotTable(data, 'users');
        const usernameLower = String(username).trim().toLowerCase();
        const duplicate = users.some((u) => String(u.username || '').trim().toLowerCase() === usernameLower);
        if (duplicate) {
          const err = new Error('Username already exists');
          err.code = '23505';
          throw err;
        }
        const numericIds = users
          .map((u) => Number(u.id))
          .filter((n) => Number.isFinite(n))
          .sort((a, b) => b - a);
        const nextId = numericIds.length ? numericIds[0] + 1 : 1;
        createdRow = {
          id: nextId,
          username,
          display_name: displayName,
          password: hash,
          is_admin: isAdmin === true,
          roles: normalizeRoles(roles),
          must_change_password: true,
          portal_files_client_id: null,
          portal_files_job_id: null,
          portal_files_access_granted: false,
          self_signup: false,
          portal_permissions_access: false,
          email_verified: true,
          created_at: nowIso(),
          updated_at: nowIso()
        };
        users.push(createdRow);
      });
      if (wrote) {
        const user = await attachScopesToUser(normalizeUser(createdRow));
        return res.status(201).json({
          success: true,
          user,
          message: 'User created with no access. Assign roles/portal scope to enable.'
        });
      }
    }
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

app.put('/users/:id', requireAuth, requireAdminPanelAccess, async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'User id is required' });
  }
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
    let current = null;
    const currentResult = await pool.query(
      'SELECT id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, portal_permissions_access, self_signup FROM users WHERE id = $1 LIMIT 1',
      [id]
    );
    if (currentResult.rows.length) {
      current = currentResult.rows[0];
    } else if (WASABI_USERS_PRIMARY_ENABLED) {
      try {
        const snapshotUser = await readUserByIdFromWasabiSnapshot(id);
        if (snapshotUser) {
          current = {
            id: snapshotUser.id,
            username: snapshotUser.username,
            display_name: snapshotUser.displayName,
            is_admin: snapshotUser.isAdmin,
            roles: snapshotUser.roles,
            must_change_password: snapshotUser.mustChangePassword,
            portal_files_client_id: snapshotUser.portalFilesClientId,
            portal_files_job_id: snapshotUser.portalFilesJobId,
            portal_files_access_granted: snapshotUser.portalFilesAccessGranted,
            portal_permissions_access: snapshotUser.portalPermissionsAccessRaw ?? snapshotUser.portalPermissionsAccess,
            self_signup: snapshotUser.selfSignup
          };
        } else if (WASABI_USERS_PRIMARY_STRICT) {
          return res.status(404).json({ success: false, error: 'User not found' });
        }
      } catch (error) {
        if (WASABI_USERS_PRIMARY_STRICT) throw error;
      }
    }
    if (!current) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    const scopeMap = await readScopesForUserIds([id]);
    const currentScopes = scopeMap.get(String(id)) || { portalScopes: [], psrScopes: [] };

    const nextDisplayName = displayName || current.display_name || current.username;
    let nextIsAdmin = isAdmin === null ? !!current.is_admin : !!isAdmin;
    const actorIsGlobalAdmin = req.user?.isAdmin === true;
    if (!actorIsGlobalAdmin && current.is_admin && String(req.user?.id || '') !== String(id)) {
      return res.status(403).json({
        success: false,
        error: 'Only global admins can edit Horizon admin accounts.'
      });
    }
    if (!actorIsGlobalAdmin) {
      nextIsAdmin = !!current.is_admin;
    }
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
    if (nextPortalFilesAccessGranted !== true) {
      nextPortalScopes = [];
      nextPortalFilesClientId = null;
      nextPortalFilesJobId = null;
    }

    if (hasPsrScopesPayload && PLANNER_STORE_WASABI_ONLY && !WASABI_WRITES_PRIMARY_ENABLED) {
      return res.status(503).json({
        success: false,
        error:
          'PSR scopes are stored only in Wasabi when WASABI_PLANNER_STORE_WASABI_ONLY or WASABI_APP_DATA_STORE_WASABI_ONLY is set. Enable WASABI_WRITES_PRIMARY_ENABLED=1 to save them.'
      });
    }

    const passwordHash = password ? await bcrypt.hash(password, 10) : null;

    /**
     * GET /users always reads Postgres (permissions UI). When WASABI_WRITES_PRIMARY_ENABLED, the snapshot
     * is updated separately — without mirroring here, the next refresh would show stale toggles.
     */
    async function persistUserUpdateToPostgres() {
      const updatedCoreResult = await pool.query(
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
         WHERE id = $9
         RETURNING id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, portal_permissions_access, self_signup`,
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

      if (!updatedCoreResult.rowCount) {
        console.error('[update-user] Postgres UPDATE matched 0 rows — permissions UI reads pool; check user id / replica.', {
          id
        });
        throw new Error(
          'Could not update user in database (no matching row). Permissions list may not reflect this account until the database is in sync.'
        );
      }

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

      if (hasPsrScopesPayload && !PLANNER_STORE_WASABI_ONLY) {
        await pool.query('DELETE FROM user_psr_scopes WHERE user_id = $1', [String(id)]);
        for (const scope of nextPsrScopes) {
          await pool.query(
            `INSERT INTO user_psr_scopes (user_id, client, city, jobsite, psr_record_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (user_id, client, city, jobsite) DO NOTHING`,
            [String(id), scope.client, scope.city, scope.jobsite, cleanString(scope.recordId || '') || null]
          );
        }
      }

      let updatedRow = updatedCoreResult.rows[0];
      if (passwordHash) {
        const pwResult = await pool.query(
          `UPDATE users
           SET password = $1,
               must_change_password = false,
               updated_at = NOW()
           WHERE id = $2
           RETURNING id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, portal_permissions_access, self_signup`,
          [passwordHash, id]
        );
        updatedRow = pwResult.rows[0];
      }

      await pool.query('DELETE FROM auth_sessions WHERE user_id = $1', [String(id)]);
      return updatedRow;
    }

    if (WASABI_WRITES_PRIMARY_ENABLED) {
      await runWasabiStateWrite('update-user', async (data) => {
        const users = ensureSnapshotTable(data, 'users');
        const idx = users.findIndex((u) => String(u.id || '') === String(id || ''));
        if (idx < 0) throw new Error('User not found');
        const currentUserRow = users[idx];
        users[idx] = {
          ...currentUserRow,
          display_name: nextDisplayName,
          is_admin: nextIsAdmin === true,
          roles: normalizeRoles(nextRoles),
          portal_files_client_id: nextPortalFilesClientId || null,
          portal_files_job_id: nextPortalFilesJobId || null,
          portal_files_access_granted: nextPortalFilesAccessGranted === true,
          self_signup: nextSelfSignup === true,
          portal_permissions_access: nextPortalPermissionsAccess === true,
          updated_at: nowIso()
        };

        if (passwordHash) {
          users[idx] = {
            ...users[idx],
            password: passwordHash,
            must_change_password: false,
            updated_at: nowIso()
          };
        }

        if (hasPortalScopesPayload || hasPortalScopeInPayload) {
          const portalScopes = ensureSnapshotTable(data, 'user_portal_scopes');
          data.user_portal_scopes = portalScopes.filter((row) => String(row.user_id || '') !== String(id || ''));
          for (const scope of nextPortalScopes) {
            data.user_portal_scopes.push({
              user_id: String(id),
              client_id: scope.clientId,
              job_id: scope.jobId
            });
          }
        }

        if (hasPsrScopesPayload) {
          const psrScopes = ensureSnapshotTable(data, 'user_psr_scopes');
          data.user_psr_scopes = psrScopes.filter((row) => String(row.user_id || '') !== String(id || ''));
          for (const scope of nextPsrScopes) {
            data.user_psr_scopes.push({
              user_id: String(id),
              client: scope.client,
              city: scope.city,
              jobsite: scope.jobsite,
              psr_record_id: cleanString(scope.recordId || '') || null
            });
          }
        }

        const sessions = ensureSnapshotTable(data, 'auth_sessions');
        data.auth_sessions = sessions.filter((row) => String(row.user_id || '') !== String(id || ''));
      });
    }

    const pgRow = await persistUserUpdateToPostgres();
    const updatedResult = { rows: [pgRow] };

    const user = await attachScopesToUser(normalizeUser(updatedResult.rows[0]));
    res.json({ success: true, user });
  } catch (error) {
    console.error('UPDATE USER ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/users/:id', requireAuth, requireAdminPanelAccess, async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'User id is required' });
  }
  if (String(req.user?.id || '') === id) {
    return res.status(400).json({ success: false, error: 'You cannot delete your own account.' });
  }
  try {
    let target = null;
    if (WASABI_USERS_PRIMARY_ENABLED) {
      try {
        const snapshotUser = await readUserByIdFromWasabiSnapshot(id);
        if (snapshotUser) {
          target = {
            id: snapshotUser.id,
            username: snapshotUser.username,
            is_admin: snapshotUser.isAdmin
          };
        } else if (WASABI_USERS_PRIMARY_STRICT) {
          return res.status(404).json({ success: false, error: 'User not found' });
        }
      } catch (error) {
        if (WASABI_USERS_PRIMARY_STRICT) throw error;
      }
    }
    if (!target) {
      const targetResult = await pool.query(
        'SELECT id, username, is_admin FROM users WHERE id = $1 LIMIT 1',
        [id]
      );
      if (!targetResult.rows.length) {
        return res.status(404).json({ success: false, error: 'User not found' });
      }
      target = targetResult.rows[0];
    }
    if (!req.user?.isAdmin && target.is_admin) {
      return res.status(403).json({
        success: false,
        error: 'Only global admins can delete Horizon admin accounts.'
      });
    }
    if (target.is_admin) {
      let adminCount = null;
      if (WASABI_USERS_PRIMARY_ENABLED) {
        try {
          const snapshotCount = await countAdminsFromWasabiSnapshot();
          if (Number.isFinite(snapshotCount)) adminCount = Number(snapshotCount);
          else if (WASABI_USERS_PRIMARY_STRICT) adminCount = 0;
        } catch (error) {
          if (WASABI_USERS_PRIMARY_STRICT) throw error;
        }
      }
      if (adminCount == null) {
        const admins = await pool.query('SELECT COUNT(*)::int AS count FROM users WHERE is_admin = true');
        adminCount = Number(admins.rows?.[0]?.count || 0);
      }
      if (adminCount <= 1) {
        return res
          .status(400)
          .json({ success: false, error: 'Cannot delete the last admin account.' });
      }
    }
    if (WASABI_WRITES_PRIMARY_ENABLED) {
      await runWasabiStateWrite('delete-user', async (data) => {
        const sessions = ensureSnapshotTable(data, 'auth_sessions');
        data.auth_sessions = sessions.filter((row) => String(row.user_id || '') !== String(id || ''));

        const portalScopes = ensureSnapshotTable(data, 'user_portal_scopes');
        data.user_portal_scopes = portalScopes.filter((row) => String(row.user_id || '') !== String(id || ''));

        const psrScopes = ensureSnapshotTable(data, 'user_psr_scopes');
        data.user_psr_scopes = psrScopes.filter((row) => String(row.user_id || '') !== String(id || ''));

        const users = ensureSnapshotTable(data, 'users');
        data.users = users.filter((row) => String(row.id || '') !== String(id || ''));
      });
    } else {
      await pool.query('DELETE FROM auth_sessions WHERE user_id = $1', [id]);
      await pool.query('DELETE FROM users WHERE id = $1', [id]);
    }
    return res.json({ success: true, deletedUserId: id, username: target.username });
  } catch (error) {
    console.error('DELETE USER ERROR:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/records', requireAuth, requirePsrViewerAccess, async (req, res) => {
  try {
    if (PLANNER_STORE_WASABI_ONLY) {
      let snapshotRecords = [];
      try {
        snapshotRecords = await readRecordsFromWasabiSnapshotForUser(req.user);
      } catch (error) {
        if (WASABI_RECORDS_PRIMARY_STRICT) throw error;
      }
      return res.json({ success: true, records: sortPlannerRecordsForList(snapshotRecords) });
    }

    const pgRecords = await readPlannerRecordsFromPostgresForUser(req.user);

    if (!WASABI_RECORDS_PRIMARY_ENABLED) {
      return res.json({ success: true, records: sortPlannerRecordsForList(pgRecords) });
    }

    let snapshotRecords = [];
    try {
      snapshotRecords = await readRecordsFromWasabiSnapshotForUser(req.user);
    } catch (error) {
      if (WASABI_RECORDS_PRIMARY_STRICT) throw error;
    }

    const merged = mergePlannerRecordsById(snapshotRecords, pgRecords);
    return res.json({ success: true, records: sortPlannerRecordsForList(merged) });
  } catch (error) {
    console.error('GET RECORDS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records', requireAuth, requirePsrDataEntryAccess, async (req, res) => {
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

    const saved = await createPlannerRecord(record);
    res.status(201).json({ success: true, record: saved });
  } catch (error) {
    console.error('CREATE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

async function fetchRecordById(id) {
  const readWasabiFirst =
    WASABI_RECORD_DETAIL_PRIMARY_ENABLED || PLANNER_STORE_WASABI_ONLY;
  if (readWasabiFirst) {
    try {
      const snapshotRecord = await fetchRecordByIdFromWasabiSnapshot(id);
      if (snapshotRecord) return snapshotRecord;
    } catch (error) {
      if (WASABI_RECORD_DETAIL_PRIMARY_STRICT && !PLANNER_STORE_WASABI_ONLY) throw error;
    }
  }
  if (PLANNER_STORE_WASABI_ONLY) {
    return null;
  }
  const result = await pool.query('SELECT * FROM planner_records WHERE CAST(id AS text) = $1 LIMIT 1', [String(id)]);
  if (!result.rows.length) return null;
  return normalizeRecordRow(result.rows[0]);
}

async function persistRecord(record) {
  let savedRow = null;
  const wasabiWrote = await tryWasabiStateWrite('persist-record', async (data) => {
    const rows = ensureSnapshotTable(data, 'planner_records');
    const idx = rows.findIndex((row) => String(row.id || '') === String(record.id || ''));
    const now = nowIso();
    if (idx < 0) {
      // Row exists in Postgres but not yet in Wasabi snapshot — append instead of failing.
      savedRow = {
        id: record.id,
        record_date: cleanString(record.record_date),
        client: upperCleanString(record.client),
        city: upperCleanString(record.city),
        street: upperCleanString(record.street),
        jobsite: normalizeJobsiteName(record.jobsite, record.street),
        status: cleanString(record.status || ''),
        saved_by: cleanString(record.saved_by || ''),
        data: serializeRecordData(record),
        created_at: now,
        updated_at: now
      };
      rows.push(savedRow);
    } else {
      savedRow = {
        ...rows[idx],
        record_date: cleanString(record.record_date),
        client: upperCleanString(record.client),
        city: upperCleanString(record.city),
        street: upperCleanString(record.street),
        jobsite: normalizeJobsiteName(record.jobsite, record.street),
        status: cleanString(record.status || ''),
        saved_by: cleanString(record.saved_by || ''),
        data: serializeRecordData(record),
        updated_at: nowIso()
      };
      rows[idx] = savedRow;
    }
  });
  if (wasabiWrote && savedRow) {
    return normalizeRecordRow(savedRow);
  }
  if (PLANNER_STORE_WASABI_ONLY) {
    throw new Error('Planner data is stored only in Wasabi; persist write failed. Check WASABI_WRITES_PRIMARY_ENABLED and bucket credentials.');
  }
  const payload = [
    record.record_date,
    record.client,
    record.city,
    record.street,
    normalizeJobsiteName(record.jobsite, record.street),
    record.status || '',
    record.saved_by || '',
    JSON.stringify(serializeRecordData(record)),
    String(record.id)
  ];
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
    payload
  );
  if (result.rows.length) {
    return normalizeRecordRow(result.rows[0]);
  }
  // Wasabi-only or pre-migration row: no PG row to UPDATE — upsert when id is a UUID.
  if (!isPlannerRecordUuid(record.id)) {
    throw new Error('Record not found');
  }
  const ins = await pool.query(
    `INSERT INTO planner_records (id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at)
     VALUES ($9::uuid, $1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW(), NOW())
     ON CONFLICT (id) DO UPDATE SET
       record_date = EXCLUDED.record_date,
       client = EXCLUDED.client,
       city = EXCLUDED.city,
       street = EXCLUDED.street,
       jobsite = EXCLUDED.jobsite,
       status = EXCLUDED.status,
       saved_by = EXCLUDED.saved_by,
       data = EXCLUDED.data,
       updated_at = NOW()
     RETURNING *`,
    payload
  );
  return normalizeRecordRow(ins.rows[0]);
}

async function createPlannerRecord(record) {
  const id = crypto.randomUUID();
  let createdRow = null;
  const wasabiWrote = await tryWasabiStateWrite('create-planner-record', async (data) => {
    const rows = ensureSnapshotTable(data, 'planner_records');
    const now = nowIso();
    createdRow = {
      id,
      record_date: cleanString(record.record_date),
      client: upperCleanString(record.client),
      city: upperCleanString(record.city),
      street: upperCleanString(record.street),
      jobsite: normalizeJobsiteName(record.jobsite, record.street),
      status: cleanString(record.status || ''),
      saved_by: cleanString(record.saved_by || ''),
      data: serializeRecordData(record),
      created_at: now,
      updated_at: now
    };
    rows.push(createdRow);
  });
  if (PLANNER_STORE_WASABI_ONLY) {
    if (!wasabiWrote || !createdRow) {
      throw new Error(
        'Planner data is stored only in Wasabi; create failed. Enable WASABI_WRITES_PRIMARY_ENABLED=1 and configure Wasabi bucket keys.'
      );
    }
    return normalizeRecordRow(createdRow);
  }
  const result = await pool.query(
    `INSERT INTO planner_records (id, record_date, client, city, street, jobsite, status, saved_by, data)
     VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
     RETURNING *`,
    [
      id,
      cleanString(record.record_date),
      upperCleanString(record.client),
      upperCleanString(record.city),
      upperCleanString(record.street),
      normalizeJobsiteName(record.jobsite, record.street),
      cleanString(record.status || ''),
      cleanString(record.saved_by || ''),
      JSON.stringify(serializeRecordData(record))
    ]
  );
  return normalizeRecordRow(result.rows[0]);
}

async function deletePlannerRecordById(id) {
  let deletedId = null;
  const wasabiWrote = await tryWasabiStateWrite('delete-planner-record-by-id', async (data) => {
    const rows = ensureSnapshotTable(data, 'planner_records');
    const next = rows.filter((row) => {
      const keep = String(row.id || '') !== String(id || '');
      if (!keep) deletedId = row.id;
      return keep;
    });
    data.planner_records = next;
  });
  if (wasabiWrote) return deletedId;
  if (PLANNER_STORE_WASABI_ONLY) {
    return null;
  }
  const result = await pool.query('DELETE FROM planner_records WHERE CAST(id AS text) = $1 RETURNING id', [String(id)]);
  return result.rows.length ? result.rows[0].id : null;
}

async function deletePlannerRecordsByClient(client) {
  let deletedCount = 0;
  const wasabiWrote = await tryWasabiStateWrite('delete-planner-records-by-client', async (data) => {
    const rows = ensureSnapshotTable(data, 'planner_records');
    const target = String(client || '').toLowerCase();
    const next = rows.filter((row) => String(row.client || '').toLowerCase() !== target);
    deletedCount = rows.length - next.length;
    data.planner_records = next;
  });
  if (wasabiWrote) return deletedCount;
  if (PLANNER_STORE_WASABI_ONLY) {
    return 0;
  }
  const result = await pool.query('DELETE FROM planner_records WHERE client = $1 RETURNING id', [client]);
  return Number(result.rowCount || 0);
}

app.put('/records/:id', requireAuth, requirePsrDataEntryAccess, async (req, res) => {
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
    const deletedId = await deletePlannerRecordById(req.params.id);
    if (!deletedId) {
      return res.status(404).json({ success: false, error: 'Record not found' });
    }
    res.json({ success: true, deletedId });
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

    const saved = await createPlannerRecord({
      record_date: new Date().toISOString().slice(0, 10),
      client,
      city,
      street,
      jobsite,
      status: '',
      saved_by: req.user.displayName || req.user.username,
      systems: { storm: [], sanitary: [] }
    });
    res.status(201).json({ success: true, record: saved });
  } catch (error) {
    console.error('CREATE CLIENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/clients/:client', requireAuth, requireAdmin, async (req, res) => {
  try {
    const client = upperCleanString(req.params.client);
    await deleteJobsiteAssetsByClient(client);
    const deletedCount = await deletePlannerRecordsByClient(client);
    res.json({ success: true, deletedCount });
  } catch (error) {
    console.error('DELETE CLIENT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records/:id/segments', requireAuth, requirePsrDataEntryAccess, async (req, res) => {
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

app.post('/records/:id/segments/bulk', requireAuth, requirePsrDataEntryAccess, async (req, res) => {
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

app.put('/records/:id/segments/:segmentId', requireAuth, requirePsrDataEntryAccess, async (req, res) => {
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
    const inferredProject = cleanString(source?.jobsite || 'NOT SET');
    const targetJobsite = normalizeJobsiteName(req.body?.targetJobsite || inferredProject || 'NOT SET');
    const targetSystem = cleanString(req.body?.targetSystem || movingSegment.system || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';

    if (!targetClient || !targetCity || !targetJobsite) {
      return res.status(400).json({ success: false, error: 'Target client, city, and jobsite are required' });
    }

    let target = null;
    const targetMatches = await findPlannerRecordsByScope(targetClient, targetCity, targetJobsite, { latestOnly: true });
    if (targetMatches.length) {
      target = targetMatches[0];
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
      target = await createPlannerRecord(target);
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
    if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
      const rates = (await readPricingRatesFromWasabiSnapshot()) || [];
      return res.json({ success: true, rates });
    }
    if (WASABI_PRICING_PRIMARY_ENABLED) {
      try {
        const snapshotRates = await readPricingRatesFromWasabiSnapshot();
        if (snapshotRates) {
          return res.json({ success: true, rates: snapshotRates });
        }
        if (WASABI_PRICING_PRIMARY_STRICT) {
          return res.json({ success: true, rates: [] });
        }
      } catch (error) {
        if (WASABI_PRICING_PRIMARY_STRICT) throw error;
      }
    }
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
    const saved = await upsertPricingRate(dia, Number(rate.toFixed(2)));
    res.json({ success: true, rate: saved });
  } catch (error) {
    console.error('UPSERT PRICING RATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/pricing-rates/:dia', requireAuth, requireAdmin, async (req, res) => {
  try {
    const deletedDia = await deletePricingRate(req.params.dia);
    if (!deletedDia) return res.status(404).json({ success: false, error: 'DIA rate not found' });
    res.json({ success: true, deletedDia });
  } catch (error) {
    console.error('DELETE PRICING RATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/daily-reports', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
      const reports = (await readDailyReportsFromWasabiSnapshot()) || [];
      return res.json({ success: true, reports });
    }
    if (WASABI_REPORTS_PRIMARY_ENABLED) {
      try {
        const snapshotReports = await readDailyReportsFromWasabiSnapshot();
        if (snapshotReports) {
          return res.json({ success: true, reports: snapshotReports });
        }
        if (WASABI_REPORTS_PRIMARY_STRICT) {
          return res.json({ success: true, reports: [] });
        }
      } catch (error) {
        if (WASABI_REPORTS_PRIMARY_STRICT) throw error;
      }
    }

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
    const created = await createDailyReport({
      title: cleanString(req.body?.title),
      report_date: cleanString(req.body?.report_date || new Date().toISOString().slice(0, 10)),
      notes: cleanString(req.body?.notes),
      files,
      created_by: req.user.displayName || req.user.username
    });
    res.status(201).json({ success: true, report: created });
  } catch (error) {
    console.error('CREATE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/daily-reports/:id', requireAuth, requireAdmin, upload.array('files'), async (req, res) => {
  try {
    let current = null;
    if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
      current = await readDailyReportByIdFromWasabiSnapshot(req.params.id);
      if (!current) return res.status(404).json({ success: false, error: 'Daily report not found' });
    } else if (WASABI_REPORTS_PRIMARY_ENABLED) {
      try {
        const snapshotReport = await readDailyReportByIdFromWasabiSnapshot(req.params.id);
        if (snapshotReport) {
          current = snapshotReport;
        } else if (WASABI_REPORTS_PRIMARY_STRICT) {
          return res.status(404).json({ success: false, error: 'Daily report not found' });
        }
      } catch (error) {
        if (WASABI_REPORTS_PRIMARY_STRICT) throw error;
      }
    }
    if (!current) {
      const existingResult = await pool.query('SELECT * FROM daily_reports WHERE id = $1 LIMIT 1', [req.params.id]);
      if (!existingResult.rows.length) return res.status(404).json({ success: false, error: 'Daily report not found' });
      current = existingResult.rows[0];
    }
    const currentFiles = Array.isArray(current.files) ? current.files : parseJsonObject(current.files, []);
    const keepIds = new Set([].concat(req.body?.keepFileIds || []).filter(Boolean));
    const keptFiles = keepIds.size ? currentFiles.filter((file) => keepIds.has(file.id)) : currentFiles;
    const addedFiles = (req.files || []).map(fileToStoredJson);
    const nextFiles = [...keptFiles, ...addedFiles];
    const updated = await updateDailyReportById(req.params.id, {
      title: cleanString(req.body?.title),
      report_date: cleanString(req.body?.report_date || current.report_date),
      notes: cleanString(req.body?.notes),
      files: nextFiles
    });
    res.json({ success: true, report: updated });
  } catch (error) {
    console.error('UPDATE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/daily-reports/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const ok = await deleteDailyReportById(req.params.id);
    if (!ok) return res.status(404).json({ success: false, error: 'Daily report not found' });
    res.json({ success: true });
  } catch (error) {
    console.error('DELETE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/jobsite-assets', requireAuth, requireFootageAccess, async (req, res) => {
  try {
    if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
      const assets = (await readJobsiteAssetsFromWasabiSnapshotForUser(req.user)) || [];
      return res.json({ success: true, assets });
    }
    if (WASABI_ASSETS_PRIMARY_ENABLED) {
      try {
        const snapshotAssets = await readJobsiteAssetsFromWasabiSnapshotForUser(req.user);
        if (snapshotAssets) {
          return res.json({ success: true, assets: snapshotAssets });
        }
        if (WASABI_ASSETS_PRIMARY_STRICT) {
          return res.json({ success: true, assets: [] });
        }
      } catch (error) {
        if (WASABI_ASSETS_PRIMARY_STRICT) throw error;
      }
    }

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
    const created = await createJobsiteAsset({
      client: req.body?.assetClient || req.body?.client,
      city: req.body?.assetCity || req.body?.city,
      jobsite: req.body?.assetJobsite || req.body?.jobsite,
      contact_name: req.body?.assetContactName || req.body?.contactName,
      contact_phone: req.body?.assetContactPhone || req.body?.contactPhone,
      contact_email: req.body?.assetContactEmail || req.body?.contactEmail,
      notes: req.body?.assetNotes || req.body?.notes,
      drive_url: req.body?.assetDriveUrl || req.body?.driveUrl,
      files,
      created_by: req.user.displayName || req.user.username
    });
    res.status(201).json({ success: true, asset: created });
  } catch (error) {
    console.error('CREATE JOBSITE ASSET ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/jobsite-assets/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const ok = await deleteJobsiteAssetById(req.params.id);
    if (!ok) return res.status(404).json({ success: false, error: 'Asset not found' });
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

    const existingRecords = await findPlannerRecordsByScope(
      targetClient || '',
      targetCity || '',
      targetJobsite || 'NOT SET',
      { latestOnly: false }
    );
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

    let record;
    const existingMatches = await findPlannerRecordsByScope(targetClient, targetCity, targetJobsite, { latestOnly: true });
    if (existingMatches.length) {
      record = existingMatches[0];
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
      record = await createPlannerRecord(record);
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

function normalizeSqlForAutoImport(text) {
  return String(text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function pgRows(rows) {
  const list = Array.isArray(rows) ? rows : [];
  return { rows: list, rowCount: list.length };
}

function safeJsonParse(value, fallback = {}) {
  if (value == null) return fallback;
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(String(value));
  } catch {
    return fallback;
  }
}

function tsMs(value) {
  const ms = Date.parse(String(value || ''));
  return Number.isFinite(ms) ? ms : 0;
}

function descByTimestamp(a, b) {
  return tsMs(b?.updated_at || b?.created_at || b?.last_seen_at) - tsMs(a?.updated_at || a?.created_at || a?.last_seen_at);
}

function findAutoImportProjectByScope(snapshot, client, city, jobsite) {
  const projects = snapshotRows(snapshot, 'planner_records')
    .filter(
      (row) =>
        String(row.client || '').toLowerCase() === String(client || '').toLowerCase() &&
        String(row.city || '').toLowerCase() === String(city || '').toLowerCase() &&
        String(row.jobsite || '').toLowerCase() === String(jobsite || '').toLowerCase()
    )
    .sort(descByTimestamp);
  return projects[0] || null;
}

async function runAutoImportWasabiQuery(text, params = []) {
  const sql = normalizeSqlForAutoImport(text);
  if (!sql) return null;

  // Schema calls are no-ops in Wasabi mode.
  if (sql.startsWith('create table if not exists auto_import_') || sql.startsWith('create index if not exists idx_auto_import_')) {
    return pgRows([]);
  }

  let snapshotCache = null;
  async function requireFreshSnapshot() {
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot();
    if (!snapshotLooksFresh(snapshotCache, WASABI_AUTO_IMPORT_PRIMARY_MAX_SNAPSHOT_AGE_MS)) {
      throw new Error('Auto import snapshot is missing or stale');
    }
    return snapshotCache;
  }

  if (sql.startsWith('select * from auto_import_projects where source_key = $1')) {
    const snapshot = await requireFreshSnapshot();
    const sourceKey = String(params[0] || '');
    const rows = snapshotRows(snapshot, 'auto_import_projects').filter((row) => String(row.source_key || '') === sourceKey).slice(0, 1);
    return pgRows(rows);
  }
  if (sql.startsWith('select * from auto_import_projects where id = $1')) {
    const snapshot = await requireFreshSnapshot();
    const id = String(params[0] || '');
    const rows = snapshotRows(snapshot, 'auto_import_projects').filter((row) => String(row.id || '') === id).slice(0, 1);
    return pgRows(rows);
  }
  if (sql.startsWith('select * from auto_import_projects order by coalesce(last_seen_at, created_at) desc')) {
    const snapshot = await requireFreshSnapshot();
    const rows = [...snapshotRows(snapshot, 'auto_import_projects')].sort((a, b) => {
      const sortA = tsMs(a?.last_seen_at || a?.created_at);
      const sortB = tsMs(b?.last_seen_at || b?.created_at);
      if (sortB !== sortA) return sortB - sortA;
      return String(a?.display_name || '').localeCompare(String(b?.display_name || ''), undefined, { sensitivity: 'base' });
    });
    return pgRows(rows);
  }
  if (sql.startsWith('select id from auto_import_bindings where project_id = $1')) {
    const snapshot = await requireFreshSnapshot();
    const projectId = String(params[0] || '');
    const rows = snapshotRows(snapshot, 'auto_import_bindings')
      .filter((row) => String(row.project_id || '') === projectId)
      .slice(0, 1)
      .map((row) => ({ id: row.id }));
    return pgRows(rows);
  }
  if (sql.startsWith('select * from auto_import_bindings where project_id = $1')) {
    const snapshot = await requireFreshSnapshot();
    const projectId = String(params[0] || '');
    const rows = snapshotRows(snapshot, 'auto_import_bindings').filter((row) => String(row.project_id || '') === projectId).slice(0, 1);
    return pgRows(rows);
  }
  if (sql.startsWith('select * from auto_import_bindings order by updated_at desc')) {
    const snapshot = await requireFreshSnapshot();
    const rows = [...snapshotRows(snapshot, 'auto_import_bindings')].sort((a, b) => tsMs(b?.updated_at) - tsMs(a?.updated_at));
    return pgRows(rows);
  }
  if (sql.startsWith('select id, row_hash from auto_import_row_cache where project_id = $1 and row_key = $2')) {
    const snapshot = await requireFreshSnapshot();
    const projectId = String(params[0] || '');
    const rowKey = String(params[1] || '');
    const rows = snapshotRows(snapshot, 'auto_import_row_cache')
      .filter((row) => String(row.project_id || '') === projectId && String(row.row_key || '') === rowKey)
      .slice(0, 1)
      .map((row) => ({ id: row.id, row_hash: row.row_hash }));
    return pgRows(rows);
  }
  if (sql.startsWith('select * from auto_import_runs where project_id = $1 order by started_at desc limit 1')) {
    const snapshot = await requireFreshSnapshot();
    const projectId = String(params[0] || '');
    const rows = [...snapshotRows(snapshot, 'auto_import_runs')]
      .filter((row) => String(row.project_id || '') === projectId)
      .sort((a, b) => tsMs(b?.started_at || b?.created_at) - tsMs(a?.started_at || a?.created_at))
      .slice(0, 1);
    return pgRows(rows);
  }
  if (sql.startsWith('select * from auto_import_runs where project_id = $1 order by started_at desc limit 100')) {
    const snapshot = await requireFreshSnapshot();
    const projectId = String(params[0] || '');
    const rows = [...snapshotRows(snapshot, 'auto_import_runs')]
      .filter((row) => String(row.project_id || '') === projectId)
      .sort((a, b) => tsMs(b?.started_at || b?.created_at) - tsMs(a?.started_at || a?.created_at))
      .slice(0, 100);
    return pgRows(rows);
  }
  if (sql.startsWith('select * from auto_import_logs where project_id = $1 or project_id is null')) {
    const snapshot = await requireFreshSnapshot();
    const projectId = String(params[0] || '');
    const limit = Math.max(1, Number(params[1] || 200));
    const rows = [...snapshotRows(snapshot, 'auto_import_logs')]
      .filter((row) => String(row.project_id || '') === projectId || row.project_id == null)
      .sort((a, b) => tsMs(b?.created_at) - tsMs(a?.created_at))
      .slice(0, limit);
    return pgRows(rows);
  }
  if (sql.startsWith('select id from planner_records where lower(client) = lower($1) and lower(city) = lower($2) and lower(jobsite) = lower($3)')) {
    const snapshot = await requireFreshSnapshot();
    const hit = findAutoImportProjectByScope(snapshot, params[0], params[1], params[2]);
    return pgRows(hit ? [{ id: hit.id }] : []);
  }
  if (sql.startsWith('select id, client, city, jobsite from planner_records order by lower(client), lower(city), lower(jobsite)')) {
    const snapshot = await requireFreshSnapshot();
    const rows = snapshotRows(snapshot, 'planner_records')
      .map((row) => ({
        id: row.id,
        client: row.client,
        city: row.city,
        jobsite: row.jobsite
      }))
      .sort((a, b) => {
        const c = String(a.client || '').localeCompare(String(b.client || ''), undefined, { sensitivity: 'base' });
        if (c !== 0) return c;
        const d = String(a.city || '').localeCompare(String(b.city || ''), undefined, { sensitivity: 'base' });
        if (d !== 0) return d;
        return String(a.jobsite || '').localeCompare(String(b.jobsite || ''), undefined, { sensitivity: 'base' });
      });
    return pgRows(rows);
  }

  let outRows = null;
  const wrote = await tryWasabiStateWrite('auto-import-plugin-query', async (data) => {
    const now = nowIso();
    const projects = ensureSnapshotTable(data, 'auto_import_projects');
    const bindings = ensureSnapshotTable(data, 'auto_import_bindings');
    const rowCache = ensureSnapshotTable(data, 'auto_import_row_cache');
    const runs = ensureSnapshotTable(data, 'auto_import_runs');
    const logs = ensureSnapshotTable(data, 'auto_import_logs');

    if (sql.startsWith('update auto_import_projects set display_name = $2')) {
      const sourceKey = String(params[0] || '');
      const idx = projects.findIndex((row) => String(row.source_key || '') === sourceKey);
      if (idx >= 0) {
        projects[idx] = {
          ...projects[idx],
          display_name: params[1],
          db3_path: params[2],
          last_seen_at: now,
          updated_at: now
        };
        outRows = [projects[idx]];
      } else {
        outRows = [];
      }
      return;
    }
    if (sql.startsWith('insert into auto_import_projects')) {
      const row = {
        id: params[0],
        source_key: params[1],
        display_name: params[2],
        db3_path: params[3],
        status: 'idle',
        detection_mode: 'auto',
        detected_job_client: '',
        detected_job_city: '',
        detected_jobsite: '',
        last_seen_at: now,
        last_scan_at: null,
        last_switch_at: null,
        last_error: '',
        metadata: {},
        created_at: now,
        updated_at: now
      };
      projects.push(row);
      outRows = [row];
      return;
    }
    if (sql.startsWith('update auto_import_projects set detected_job_city = $2')) {
      const id = String(params[0] || '');
      const idx = projects.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) {
        projects[idx] = {
          ...projects[idx],
          detected_job_city: cleanString(params[1]),
          detected_jobsite: cleanString(params[2]),
          metadata: safeJsonParse(params[3], {}),
          last_scan_at: now,
          status: 'discovered',
          updated_at: now
        };
      }
      outRows = [];
      return;
    }
    if (sql.startsWith('update auto_import_projects set status = \'running\'')) {
      const id = String(params[0] || '');
      const idx = projects.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) {
        projects[idx] = { ...projects[idx], status: 'running', last_error: '', updated_at: now };
        outRows = [projects[idx]];
      } else outRows = [];
      return;
    }
    if (sql.startsWith('update auto_import_projects set status = \'idle\'')) {
      const id = String(params[0] || '');
      const idx = projects.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) {
        projects[idx] = { ...projects[idx], status: 'idle', updated_at: now };
        outRows = [projects[idx]];
      } else outRows = [];
      return;
    }
    if (sql.startsWith('update auto_import_projects set detection_mode = $2')) {
      const id = String(params[0] || '');
      const idx = projects.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) {
        projects[idx] = { ...projects[idx], detection_mode: cleanString(params[1]) || 'auto', updated_at: now };
        outRows = [projects[idx]];
      } else outRows = [];
      return;
    }
    if (sql.startsWith('update auto_import_projects set status = \'synced\'')) {
      const id = String(params[0] || '');
      const idx = projects.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) {
        projects[idx] = { ...projects[idx], status: 'synced', last_scan_at: now, last_error: '', updated_at: now };
      }
      outRows = [];
      return;
    }
    if (sql.startsWith('update auto_import_projects set status = \'error\'')) {
      const id = String(params[0] || '');
      const idx = projects.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) {
        projects[idx] = { ...projects[idx], status: 'error', last_error: String(params[1] || ''), updated_at: now };
      }
      outRows = [];
      return;
    }
    if (sql.startsWith('update auto_import_bindings set client = $2')) {
      const projectId = String(params[0] || '');
      const idx = bindings.findIndex((row) => String(row.project_id || '') === projectId);
      if (idx >= 0) {
        bindings[idx] = {
          ...bindings[idx],
          client: cleanString(params[1]),
          city: cleanString(params[2]),
          jobsite: cleanString(params[3]),
          system_type: cleanString(params[4]) || 'storm',
          pinned: !!params[5],
          created_by: cleanString(bindings[idx].created_by || '') || cleanString(params[6]) || 'System',
          updated_at: now
        };
        outRows = [bindings[idx]];
      } else outRows = [];
      return;
    }
    if (sql.startsWith('insert into auto_import_bindings')) {
      const row = {
        id: params[0],
        project_id: params[1],
        client: cleanString(params[2]),
        city: cleanString(params[3]),
        jobsite: cleanString(params[4]),
        system_type: cleanString(params[5]) || 'storm',
        pinned: !!params[6],
        created_by: cleanString(params[7]) || 'System',
        created_at: now,
        updated_at: now
      };
      const existingIdx = bindings.findIndex((item) => String(item.project_id || '') === String(row.project_id || ''));
      if (existingIdx >= 0) bindings[existingIdx] = { ...bindings[existingIdx], ...row, created_at: bindings[existingIdx].created_at || now };
      else bindings.push(row);
      outRows = [existingIdx >= 0 ? bindings[existingIdx] : row];
      return;
    }
    if (sql.startsWith('update auto_import_row_cache set last_seen_at = now() where id = $1')) {
      const id = String(params[0] || '');
      const idx = rowCache.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) rowCache[idx] = { ...rowCache[idx], last_seen_at: now };
      outRows = [];
      return;
    }
    if (sql.startsWith('update auto_import_row_cache set row_hash = $3')) {
      const projectId = String(params[0] || '');
      const rowKey = String(params[1] || '');
      const idx = rowCache.findIndex(
        (row) => String(row.project_id || '') === projectId && String(row.row_key || '') === rowKey
      );
      if (idx >= 0) {
        rowCache[idx] = {
          ...rowCache[idx],
          row_hash: params[2],
          system_type: cleanString(params[3]) || 'storm',
          reference: cleanString(params[4]),
          upstream: cleanString(params[5]),
          downstream: cleanString(params[6]),
          dia: cleanString(params[7]),
          material: cleanString(params[8]),
          length: Number(params[9] || 0),
          footage: Number(params[10] || 0),
          source_payload: safeJsonParse(params[11], {}),
          last_seen_at: now
        };
      }
      outRows = [];
      return;
    }
    if (sql.startsWith('insert into auto_import_row_cache')) {
      rowCache.push({
        id: params[0],
        project_id: params[1],
        row_key: params[2],
        row_hash: params[3],
        system_type: cleanString(params[4]) || 'storm',
        reference: cleanString(params[5]),
        upstream: cleanString(params[6]),
        downstream: cleanString(params[7]),
        dia: cleanString(params[8]),
        material: cleanString(params[9]),
        length: Number(params[10] || 0),
        footage: Number(params[11] || 0),
        source_payload: safeJsonParse(params[12], {}),
        first_seen_at: now,
        last_seen_at: now
      });
      outRows = [];
      return;
    }
    if (sql.startsWith('insert into auto_import_runs')) {
      runs.push({
        id: params[0],
        project_id: params[1],
        started_at: now,
        completed_at: now,
        active_db3_path: cleanString(params[2]),
        switch_reason: cleanString(params[3]),
        rows_found: Number(params[4] || 0),
        rows_changed: Number(params[5] || 0),
        rows_inserted: Number(params[6] || 0),
        rows_updated: Number(params[7] || 0),
        notes: '',
        payload: safeJsonParse(params[8], {})
      });
      outRows = [];
      return;
    }
    if (sql.startsWith('insert into auto_import_logs')) {
      logs.push({
        id: params[0],
        project_id: params[1] || null,
        source: cleanString(params[2] || 'server') || 'server',
        level: cleanString(params[3] || 'info') || 'info',
        message: cleanString(params[4]),
        payload: safeJsonParse(params[5], {}),
        created_at: now
      });
      outRows = [];
      return;
    }

    outRows = null;
  });

  if (!wrote) return null;
  if (outRows === null) return null;
  return pgRows(outRows);
}

async function queryAutoImportWithWasabiFallback(text, params = []) {
  const normalizedSql = normalizeSqlForAutoImport(text);
  if (!WASABI_AUTO_IMPORT_PRIMARY_ENABLED) {
    return pool.query(text, params);
  }
  try {
    const result = await runAutoImportWasabiQuery(text, params);
    if (result) {
      wasabiAutoImportHandledByWasabi += 1;
      return result;
    }
    if (WASABI_AUTO_IMPORT_PRIMARY_STRICT) {
      wasabiAutoImportLastErrorAt = Date.now();
      wasabiAutoImportLastError = 'Auto import Wasabi adapter does not support this query shape';
      throw new Error('Auto import Wasabi adapter does not support this query shape');
    }
    wasabiAutoImportFallbackToPostgres += 1;
    wasabiAutoImportFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'unsupported-query-shape',
      sql: normalizedSql.slice(0, 260)
    });
    if (wasabiAutoImportFallbackSamples.length > 50) {
      wasabiAutoImportFallbackSamples = wasabiAutoImportFallbackSamples.slice(-50);
    }
  } catch (error) {
    wasabiAutoImportLastErrorAt = Date.now();
    wasabiAutoImportLastError = String(error?.message || error || '');
    if (WASABI_AUTO_IMPORT_PRIMARY_STRICT) throw error;
    console.warn('[wasabi-auto-import] query failed, falling back to postgres:', error?.message || error);
    wasabiAutoImportFallbackToPostgres += 1;
    wasabiAutoImportFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'adapter-error',
      sql: normalizedSql.slice(0, 260),
      error: String(error?.message || error || '')
    });
    if (wasabiAutoImportFallbackSamples.length > 50) {
      wasabiAutoImportFallbackSamples = wasabiAutoImportFallbackSamples.slice(-50);
    }
  }
  return pool.query(text, params);
}

function normalizeSqlForPortalData(text) {
  return String(text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/**
 * Resumable multipart metadata must stay on Postgres: it is high-churn, needs immediate read-after-write,
 * and Wasabi snapshot routing (staleness checks + tryWasabiStateWrite) breaks uploads when portal-data-primary is on.
 * Object bytes still go to Wasabi S3 via portal-files.routes.js.
 */
function portalUploadMetadataSql(text) {
  const sql = normalizeSqlForPortalData(text);
  if (!sql) return false;
  return sql.includes('portal_upload_sessions') || sql.includes('portal_upload_session_parts');
}

/**
 * Share links + guest access must use live Postgres when portal-data-primary is on:
 * `runPortalDataWasabiQuery` handles INSERTs only via Wasabi snapshot (no `pool.query`), so rows
 * never appeared in Postgres while guest routes read with `aclPool` → 404 on `/meta`.
 * Also route the share-access report SELECT so it matches rows written here.
 */
function portalShareDataLivePostgresSql(text) {
  const sql = normalizeSqlForPortalData(text);
  if (!sql) return false;
  if (sql === 'begin' || sql === 'commit' || sql === 'rollback') return true;
  if (sql.startsWith('select * from portal_share_links where token = $1')) return true;
  if (sql.startsWith('select 1 from portal_share_guest_sessions where guest_token = $1 and share_link_id = $2'))
    return true;
  if (
    sql.startsWith(
      'select a.id, a.email, a.first_name as "firstname", a.last_name as "lastname", a.role, a.company, a.accessed_at as "accessedat", l.kind, l.token, l.created_at as "linkcreatedat" from portal_share_access_log a join portal_share_links l on l.id = a.share_link_id where l.client_id = $1 and l.job_id = $2 order by a.accessed_at desc limit 500'
    )
  )
    return true;
  if (
    sql.startsWith(
      'insert into portal_share_links (id, token, client_id, job_id, kind, created_by_username, payload) values'
    )
  )
    return true;
  if (sql.startsWith('insert into portal_share_access_log')) return true;
  if (sql.startsWith('insert into portal_share_guest_sessions')) return true;
  return false;
}

async function runPortalDataWasabiQuery(text, params = []) {
  const sql = normalizeSqlForPortalData(text);
  if (!sql) return null;
  if (sql === 'begin' || sql === 'commit' || sql === 'rollback') {
    return pgRows([]);
  }
  if (
    sql.startsWith('create table if not exists portal_upload_sessions') ||
    sql.startsWith('create table if not exists portal_upload_session_parts') ||
    sql.startsWith('create index if not exists idx_portal_upload_sessions_user_status') ||
    sql.startsWith('create index if not exists idx_portal_upload_sessions_scope') ||
    sql.startsWith('alter table portal_upload_session_parts add column if not exists sha256 text')
  ) {
    return pgRows([]);
  }

  let snapshotCache = null;
  async function requireFreshSnapshot() {
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot();
    if (!snapshotLooksFresh(snapshotCache, WASABI_PORTAL_DATA_PRIMARY_MAX_SNAPSHOT_AGE_MS)) {
      throw new Error('Portal data snapshot is missing or stale');
    }
    return snapshotCache;
  }

  if (sql.startsWith('select 1 from portal_path_grants where client_id = $1 and job_id = $2 limit 1')) {
    const snapshot = await requireFreshSnapshot();
    const clientId = String(params[0] || '');
    const jobId = String(params[1] || '');
    const hasGrant = snapshotRows(snapshot, 'portal_path_grants').some(
      (row) => String(row.client_id || '') === clientId && String(row.job_id || '') === jobId
    );
    return pgRows(hasGrant ? [{ '?column?': 1 }] : []);
  }
  if (
    sql.startsWith(
      'select path_prefix, coalesce(recursive, true) as recursive, coalesce(access_mode, \'full\') as access_mode from portal_path_grants where client_id = $1 and job_id = $2 and ( lower(trim(username)) = lower(trim($3)) or ($4 <> \'\' and lower(trim(username)) = lower(trim($4))) )'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const clientId = String(params[0] || '');
    const jobId = String(params[1] || '');
    const u = String(params[2] || '').trim().toLowerCase();
    const em = String(params[3] || '').trim().toLowerCase();
    const rows = snapshotRows(snapshot, 'portal_path_grants')
      .filter((row) => {
        if (String(row.client_id || '') !== clientId || String(row.job_id || '') !== jobId) return false;
        const run = String(row.username || '').trim().toLowerCase();
        if (u && run === u) return true;
        if (em && run === em) return true;
        return false;
      })
      .map((row) => ({
        path_prefix: String(row.path_prefix || ''),
        recursive: row.recursive !== false,
        access_mode: String(row.access_mode || 'full') || 'full'
      }));
    return pgRows(rows);
  }
  if (
    sql.startsWith(
      'select path_prefix, coalesce(recursive, true) as recursive, coalesce(access_mode, \'full\') as access_mode from portal_path_grants where client_id = $1 and job_id = $2 and lower(trim(username)) = lower(trim($3))'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const clientId = String(params[0] || '');
    const jobId = String(params[1] || '');
    const username = String(params[2] || '').trim().toLowerCase();
    const rows = snapshotRows(snapshot, 'portal_path_grants')
      .filter(
        (row) =>
          String(row.client_id || '') === clientId &&
          String(row.job_id || '') === jobId &&
          String(row.username || '').trim().toLowerCase() === username
      )
      .map((row) => ({
        path_prefix: String(row.path_prefix || ''),
        recursive: row.recursive !== false,
        access_mode: String(row.access_mode || 'full') || 'full'
      }));
    return pgRows(rows);
  }
  if (sql.startsWith('select id, path_prefix from portal_path_grants where client_id = $1 and job_id = $2')) {
    const snapshot = await requireFreshSnapshot();
    const clientId = String(params[0] || '');
    const jobId = String(params[1] || '');
    const rows = snapshotRows(snapshot, 'portal_path_grants')
      .filter((row) => String(row.client_id || '') === clientId && String(row.job_id || '') === jobId)
      .map((row) => ({ id: row.id, path_prefix: row.path_prefix }));
    return pgRows(rows);
  }
  if (
    sql.startsWith(
      'select id, username, path_prefix as "pathprefix", recursive, coalesce(access_mode, \'full\') as "accessmode", created_at as "createdat" from portal_path_grants where client_id = $1 and job_id = $2 order by lower(username), path_prefix'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const clientId = String(params[0] || '');
    const jobId = String(params[1] || '');
    const rows = snapshotRows(snapshot, 'portal_path_grants')
      .filter((row) => String(row.client_id || '') === clientId && String(row.job_id || '') === jobId)
      .map((row) => ({
        id: row.id,
        username: row.username,
        pathPrefix: row.path_prefix,
        recursive: row.recursive !== false,
        accessMode: String(row.access_mode || 'full') || 'full',
        createdAt: row.created_at || null
      }))
      .sort((a, b) => {
        const c = String(a.username || '').localeCompare(String(b.username || ''), undefined, { sensitivity: 'base' });
        if (c !== 0) return c;
        return String(a.pathPrefix || '').localeCompare(String(b.pathPrefix || ''), undefined, { sensitivity: 'base' });
      });
    return pgRows(rows);
  }
  if (
    sql.startsWith(
      'select a.id, a.email, a.first_name as "firstname", a.last_name as "lastname", a.role, a.company, a.accessed_at as "accessedat", l.kind, l.token, l.created_at as "linkcreatedat" from portal_share_access_log a join portal_share_links l on l.id = a.share_link_id where l.client_id = $1 and l.job_id = $2 order by a.accessed_at desc limit 500'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const clientId = String(params[0] || '');
    const jobId = String(params[1] || '');
    const links = snapshotRows(snapshot, 'portal_share_links').filter(
      (row) => String(row.client_id || '') === clientId && String(row.job_id || '') === jobId
    );
    const linkById = new Map(links.map((row) => [String(row.id || ''), row]));
    const rows = snapshotRows(snapshot, 'portal_share_access_log')
      .filter((row) => linkById.has(String(row.share_link_id || '')))
      .map((row) => {
        const link = linkById.get(String(row.share_link_id || '')) || {};
        return {
          id: row.id,
          email: row.email,
          firstName: row.first_name || '',
          lastName: row.last_name || '',
          role: row.role || '',
          company: row.company || '',
          accessedAt: row.accessed_at || null,
          kind: link.kind || null,
          token: link.token || null,
          linkCreatedAt: link.created_at || null
        };
      })
      .sort((a, b) => tsMs(b.accessedAt) - tsMs(a.accessedAt))
      .slice(0, 500);
    return pgRows(rows);
  }
  if (
    sql.startsWith(
      'select id, client_id, job_id, folder_path, file_name, file_size, mime_type, object_key, chunk_size, updated_at from portal_upload_sessions where '
    ) &&
    sql.includes("status = 'uploading'") &&
    sql.endsWith('order by updated_at desc limit 500')
  ) {
    const snapshot = await requireFreshSnapshot();
    const userId = String(params[0] || '');
    const clientId = params.length >= 2 ? String(params[1] || '') : '';
    const jobId = params.length >= 3 ? String(params[2] || '') : '';
    const rows = snapshotRows(snapshot, 'portal_upload_sessions')
      .filter((row) => String(row.user_id || '') === userId)
      .filter((row) => String(row.status || '') === 'uploading')
      .filter((row) => (!clientId ? true : String(row.client_id || '') === clientId))
      .filter((row) => (!jobId ? true : String(row.job_id || '') === jobId))
      .sort((a, b) => tsMs(b.updated_at || b.created_at) - tsMs(a.updated_at || a.created_at))
      .slice(0, 500)
      .map((row) => ({
        id: row.id,
        client_id: row.client_id,
        job_id: row.job_id,
        folder_path: row.folder_path || '',
        file_name: row.file_name,
        file_size: row.file_size,
        mime_type: row.mime_type,
        object_key: row.object_key,
        chunk_size: row.chunk_size,
        updated_at: row.updated_at || null
      }));
    return pgRows(rows);
  }
  if (
    sql.startsWith(
      'select id, multipart_upload_id, chunk_size, object_key, file_size, file_name, mime_type, sha256 from portal_upload_sessions where user_id = $1 and client_id = $2 and job_id = $3 and folder_path = $4 and file_name = $5 and file_size = $6 and status = \'uploading\' order by updated_at desc limit 1'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const userId = String(params[0] || '');
    const clientId = String(params[1] || '');
    const jobId = String(params[2] || '');
    const folderPath = String(params[3] || '');
    const fileName = String(params[4] || '');
    const fileSize = Number(params[5] || 0);
    const hit = snapshotRows(snapshot, 'portal_upload_sessions')
      .filter(
        (row) =>
          String(row.user_id || '') === userId &&
          String(row.client_id || '') === clientId &&
          String(row.job_id || '') === jobId &&
          String(row.folder_path || '') === folderPath &&
          String(row.file_name || '') === fileName &&
          Number(row.file_size || 0) === fileSize &&
          String(row.status || '') === 'uploading'
      )
      .sort((a, b) => tsMs(b.updated_at || b.created_at) - tsMs(a.updated_at || a.created_at))[0];
    if (!hit) return pgRows([]);
    return pgRows([
      {
        id: hit.id,
        multipart_upload_id: hit.multipart_upload_id,
        chunk_size: hit.chunk_size,
        object_key: hit.object_key,
        file_size: hit.file_size,
        file_name: hit.file_name,
        mime_type: hit.mime_type,
        sha256: hit.sha256 || null
      }
    ]);
  }
  if (sql.startsWith('select * from portal_upload_sessions where id = $1 and user_id = $2 limit 1')) {
    const snapshot = await requireFreshSnapshot();
    const sessionId = String(params[0] || '');
    const userId = String(params[1] || '');
    const rows = snapshotRows(snapshot, 'portal_upload_sessions')
      .filter((row) => String(row.id || '') === sessionId && String(row.user_id || '') === userId)
      .slice(0, 1);
    return pgRows(rows);
  }
  if (sql.startsWith('select part_number, size from portal_upload_session_parts where session_id = $1 order by part_number')) {
    const snapshot = await requireFreshSnapshot();
    const sessionId = String(params[0] || '');
    const rows = snapshotRows(snapshot, 'portal_upload_session_parts')
      .filter((row) => String(row.session_id || '') === sessionId)
      .map((row) => ({
        part_number: Number(row.part_number || 0),
        size: Number(row.size || 0)
      }))
      .sort((a, b) => Number(a.part_number || 0) - Number(b.part_number || 0));
    return pgRows(rows);
  }
  if (
    sql.startsWith(
      'select part_number, etag, size from portal_upload_session_parts where session_id = $1 order by part_number'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const sessionId = String(params[0] || '');
    const rows = snapshotRows(snapshot, 'portal_upload_session_parts')
      .filter((row) => String(row.session_id || '') === sessionId)
      .map((row) => ({
        part_number: Number(row.part_number || 0),
        etag: row.etag || '',
        size: Number(row.size || 0)
      }))
      .sort((a, b) => Number(a.part_number || 0) - Number(b.part_number || 0));
    return pgRows(rows);
  }

  let outRows = null;
  const wrote = await tryWasabiStateWrite('portal-data-query', async (data) => {
    const rows = ensureSnapshotTable(data, 'portal_path_grants');
    const shareLinks = ensureSnapshotTable(data, 'portal_share_links');
    const shareAccessLog = ensureSnapshotTable(data, 'portal_share_access_log');
    const guestSessions = ensureSnapshotTable(data, 'portal_share_guest_sessions');
    const uploadSessions = ensureSnapshotTable(data, 'portal_upload_sessions');
    const uploadParts = ensureSnapshotTable(data, 'portal_upload_session_parts');
    const now = nowIso();

    if (sql.startsWith('update portal_path_grants set path_prefix = $1 where id = $2')) {
      const pathPrefix = String(params[0] || '');
      const id = String(params[1] || '');
      const idx = rows.findIndex((row) => String(row.id || '') === id);
      if (idx >= 0) {
        rows[idx] = {
          ...rows[idx],
          path_prefix: pathPrefix
        };
      }
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'delete from portal_path_grants where client_id = $1 and job_id = $2 and (path_prefix = $3 or path_prefix like $4)'
      )
    ) {
      const clientId = String(params[0] || '');
      const jobId = String(params[1] || '');
      const root = String(params[2] || '');
      data.portal_path_grants = rows.filter((row) => {
        if (String(row.client_id || '') !== clientId || String(row.job_id || '') !== jobId) return true;
        const p = String(row.path_prefix || '');
        return !(p === root || p.startsWith(`${root}/`));
      });
      outRows = [];
      return;
    }
    if (sql.startsWith('delete from portal_path_grants where client_id = $1 and job_id = $2')) {
      const clientId = String(params[0] || '');
      const jobId = String(params[1] || '');
      data.portal_path_grants = rows.filter(
        (row) => String(row.client_id || '') !== clientId || String(row.job_id || '') !== jobId
      );
      outRows = [];
      return;
    }
    if (sql.startsWith('insert into portal_path_grants (client_id, job_id, username, path_prefix, recursive, access_mode) values ($1,$2,$3,$4,$5,$6)')) {
      rows.push({
        id: crypto.randomUUID(),
        client_id: String(params[0] || ''),
        job_id: String(params[1] || ''),
        username: String(params[2] || ''),
        path_prefix: String(params[3] || ''),
        recursive: params[4] !== false,
        access_mode: String(params[5] || 'full') || 'full',
        created_at: now
      });
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'insert into portal_share_links (id, token, client_id, job_id, kind, created_by_username, payload) values ($1,$2,$3,$4,$5,$6,$7::jsonb)'
      )
    ) {
      shareLinks.push({
        id: String(params[0] || ''),
        token: String(params[1] || ''),
        client_id: String(params[2] || ''),
        job_id: String(params[3] || ''),
        kind: String(params[4] || ''),
        created_by_username: String(params[5] || ''),
        payload: safeJsonParse(params[6], {}),
        created_at: now
      });
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'insert into portal_share_access_log (share_link_id, email, first_name, last_name, role, company, ip_inet, user_agent) values ($1,$2,$3,$4,$5,$6,$7,$8)'
      )
    ) {
      shareAccessLog.push({
        id: crypto.randomUUID(),
        share_link_id: String(params[0] || ''),
        email: String(params[1] || ''),
        first_name: String(params[2] || ''),
        last_name: String(params[3] || ''),
        role: String(params[4] || ''),
        company: String(params[5] || ''),
        ip_inet: params[6] == null ? null : String(params[6]),
        user_agent: params[7] == null ? null : String(params[7]),
        accessed_at: now
      });
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'insert into portal_share_guest_sessions (guest_token, share_link_id, email, first_name, last_name, role, company) values ($1,$2,$3,$4,$5,$6,$7)'
      )
    ) {
      guestSessions.push({
        guest_token: String(params[0] || ''),
        share_link_id: String(params[1] || ''),
        email: String(params[2] || ''),
        first_name: String(params[3] || ''),
        last_name: String(params[4] || ''),
        role: String(params[5] || ''),
        company: String(params[6] || ''),
        created_at: now
      });
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'insert into portal_upload_sessions (user_id, client_id, job_id, folder_path, file_name, file_size, mime_type, object_key, multipart_upload_id, chunk_size, sha256, status) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,\'uploading\') returning id'
      )
    ) {
      const id = crypto.randomUUID();
      uploadSessions.push({
        id,
        user_id: String(params[0] || ''),
        client_id: String(params[1] || ''),
        job_id: String(params[2] || ''),
        folder_path: String(params[3] || ''),
        file_name: String(params[4] || ''),
        file_size: Number(params[5] || 0),
        mime_type: String(params[6] || ''),
        object_key: String(params[7] || ''),
        multipart_upload_id: String(params[8] || ''),
        chunk_size: Number(params[9] || 0),
        sha256: params[10] == null ? null : String(params[10]),
        status: 'uploading',
        created_at: now,
        updated_at: now,
        completed_at: null
      });
      outRows = [{ id }];
      return;
    }
    if (
      sql.startsWith(
        'insert into portal_upload_session_parts (session_id, part_number, etag, sha256, size) values ($1,$2,$3,$4,$5) on conflict (session_id, part_number) do update set etag = excluded.etag, sha256 = excluded.sha256, size = excluded.size, created_at = now()'
      )
    ) {
      const sessionId = String(params[0] || '');
      const partNumber = Number(params[1] || 0);
      const idx = uploadParts.findIndex(
        (row) => String(row.session_id || '') === sessionId && Number(row.part_number || 0) === partNumber
      );
      const next = {
        session_id: sessionId,
        part_number: partNumber,
        etag: String(params[2] || ''),
        sha256: params[3] == null ? null : String(params[3]),
        size: Number(params[4] || 0),
        created_at: now
      };
      if (idx >= 0) uploadParts[idx] = { ...uploadParts[idx], ...next };
      else uploadParts.push(next);
      outRows = [];
      return;
    }
    if (sql.startsWith('update portal_upload_sessions set updated_at = now() where id = $1')) {
      const sessionId = String(params[0] || '');
      const idx = uploadSessions.findIndex((row) => String(row.id || '') === sessionId);
      if (idx >= 0) uploadSessions[idx] = { ...uploadSessions[idx], updated_at: now };
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'update portal_upload_sessions set status = \'failed\', sha256 = $2, updated_at = now() where id = $1'
      )
    ) {
      const sessionId = String(params[0] || '');
      const idx = uploadSessions.findIndex((row) => String(row.id || '') === sessionId);
      if (idx >= 0) {
        uploadSessions[idx] = {
          ...uploadSessions[idx],
          status: 'failed',
          sha256: String(params[1] || ''),
          updated_at: now
        };
      }
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'update portal_upload_sessions set status = \'completed\', sha256 = $2, completed_at = now(), updated_at = now() where id = $1'
      )
    ) {
      const sessionId = String(params[0] || '');
      const idx = uploadSessions.findIndex((row) => String(row.id || '') === sessionId);
      if (idx >= 0) {
        uploadSessions[idx] = {
          ...uploadSessions[idx],
          status: 'completed',
          sha256: String(params[1] || ''),
          completed_at: now,
          updated_at: now
        };
      }
      outRows = [];
      return;
    }
    if (sql.startsWith('update portal_upload_sessions set status = \'aborted\', updated_at = now() where id = $1')) {
      const sessionId = String(params[0] || '');
      const idx = uploadSessions.findIndex((row) => String(row.id || '') === sessionId);
      if (idx >= 0) {
        uploadSessions[idx] = {
          ...uploadSessions[idx],
          status: 'aborted',
          updated_at: now
        };
      }
      outRows = [];
      return;
    }

    outRows = null;
  });

  if (!wrote) return null;
  if (outRows === null) return null;
  return pgRows(outRows);
}

async function queryPortalDataWithWasabiFallback(text, params = []) {
  if (portalUploadMetadataSql(text)) {
    return pool.query(text, params);
  }
  if (portalShareDataLivePostgresSql(text)) {
    return pool.query(text, params);
  }
  const normalizedSql = normalizeSqlForPortalData(text);
  if (!WASABI_PORTAL_DATA_PRIMARY_ENABLED) {
    return pool.query(text, params);
  }
  try {
    const result = await runPortalDataWasabiQuery(text, params);
    if (result) {
      wasabiPortalDataHandledByWasabi += 1;
      return result;
    }
    if (WASABI_PORTAL_DATA_PRIMARY_STRICT) {
      wasabiPortalDataLastErrorAt = Date.now();
      wasabiPortalDataLastError = 'Portal Wasabi adapter does not support this query shape';
      throw new Error('Portal Wasabi adapter does not support this query shape');
    }
    wasabiPortalDataFallbackToPostgres += 1;
    wasabiPortalDataFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'unsupported-query-shape',
      sql: normalizedSql.slice(0, 260)
    });
    if (wasabiPortalDataFallbackSamples.length > 50) {
      wasabiPortalDataFallbackSamples = wasabiPortalDataFallbackSamples.slice(-50);
    }
  } catch (error) {
    wasabiPortalDataLastErrorAt = Date.now();
    wasabiPortalDataLastError = String(error?.message || error || '');
    if (WASABI_PORTAL_DATA_PRIMARY_STRICT) throw error;
    console.warn('[wasabi-portal-data] query failed, falling back to postgres:', error?.message || error);
    wasabiPortalDataFallbackToPostgres += 1;
    wasabiPortalDataFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'adapter-error',
      sql: normalizedSql.slice(0, 260),
      error: String(error?.message || error || '')
    });
    if (wasabiPortalDataFallbackSamples.length > 50) {
      wasabiPortalDataFallbackSamples = wasabiPortalDataFallbackSamples.slice(-50);
    }
  }
  return pool.query(text, params);
}

function normalizeSqlForOutlookData(text) {
  return String(text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

async function runOutlookDataWasabiQuery(text, params = []) {
  const sql = normalizeSqlForOutlookData(text);
  if (!sql) return null;
  if (sql.startsWith('create table if not exists user_outlook_tokens')) {
    return pgRows([]);
  }

  let snapshotCache = null;
  async function requireFreshSnapshot() {
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot();
    if (!snapshotLooksFresh(snapshotCache, WASABI_OUTLOOK_PRIMARY_MAX_SNAPSHOT_AGE_MS)) {
      throw new Error('Outlook snapshot is missing or stale');
    }
    return snapshotCache;
  }

  if (sql.startsWith('select * from user_outlook_tokens where user_id = $1 limit 1')) {
    const snapshot = await requireFreshSnapshot();
    const userId = String(params[0] || '');
    const rows = snapshotRows(snapshot, 'user_outlook_tokens').filter((row) => String(row.user_id || '') === userId).slice(0, 1);
    return pgRows(rows);
  }

  let outRows = null;
  const wrote = await tryWasabiStateWrite('outlook-data-query', async (data) => {
    const rows = ensureSnapshotTable(data, 'user_outlook_tokens');
    const now = nowIso();

    if (
      sql.startsWith(
        'insert into user_outlook_tokens (user_id, email_address, display_name, access_token, refresh_token, token_type, scope, expires_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,now()) on conflict (user_id) do update set'
      )
    ) {
      const userId = String(params[0] || '');
      const next = {
        user_id: userId,
        email_address: String(params[1] || ''),
        display_name: String(params[2] || ''),
        access_token: String(params[3] || ''),
        refresh_token: String(params[4] || ''),
        token_type: String(params[5] || 'Bearer'),
        scope: String(params[6] || ''),
        expires_at: params[7] || null,
        updated_at: now
      };
      const idx = rows.findIndex((row) => String(row.user_id || '') === userId);
      if (idx >= 0) {
        rows[idx] = {
          ...rows[idx],
          ...next,
          refresh_token: next.refresh_token === '' ? String(rows[idx].refresh_token || '') : next.refresh_token
        };
      } else {
        rows.push({
          ...next,
          created_at: now
        });
      }
      outRows = [];
      return;
    }
    if (sql.startsWith('delete from user_outlook_tokens where user_id = $1')) {
      const userId = String(params[0] || '');
      data.user_outlook_tokens = rows.filter((row) => String(row.user_id || '') !== userId);
      outRows = [];
      return;
    }

    outRows = null;
  });

  if (!wrote) return null;
  if (outRows === null) return null;
  return pgRows(outRows);
}

async function queryOutlookDataWithWasabiFallback(text, params = []) {
  const normalizedSql = normalizeSqlForOutlookData(text);
  if (!WASABI_OUTLOOK_PRIMARY_ENABLED) {
    return pool.query(text, params);
  }
  try {
    const result = await runOutlookDataWasabiQuery(text, params);
    if (result) {
      wasabiOutlookHandledByWasabi += 1;
      return result;
    }
    if (WASABI_OUTLOOK_PRIMARY_STRICT) {
      wasabiOutlookLastErrorAt = Date.now();
      wasabiOutlookLastError = 'Outlook Wasabi adapter does not support this query shape';
      throw new Error('Outlook Wasabi adapter does not support this query shape');
    }
    wasabiOutlookFallbackToPostgres += 1;
    wasabiOutlookFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'unsupported-query-shape',
      sql: normalizedSql.slice(0, 260)
    });
    if (wasabiOutlookFallbackSamples.length > 50) {
      wasabiOutlookFallbackSamples = wasabiOutlookFallbackSamples.slice(-50);
    }
  } catch (error) {
    wasabiOutlookLastErrorAt = Date.now();
    wasabiOutlookLastError = String(error?.message || error || '');
    if (WASABI_OUTLOOK_PRIMARY_STRICT) throw error;
    console.warn('[wasabi-outlook] query failed, falling back to postgres:', error?.message || error);
    wasabiOutlookFallbackToPostgres += 1;
    wasabiOutlookFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'adapter-error',
      sql: normalizedSql.slice(0, 260),
      error: String(error?.message || error || '')
    });
    if (wasabiOutlookFallbackSamples.length > 50) {
      wasabiOutlookFallbackSamples = wasabiOutlookFallbackSamples.slice(-50);
    }
  }
  return pool.query(text, params);
}

function normalizeSqlForSignupData(text) {
  return String(text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

async function runSignupDataWasabiQuery(text, params = []) {
  const sql = normalizeSqlForSignupData(text);
  if (!sql) return null;

  let snapshotCache = null;
  async function requireFreshSnapshot() {
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot();
    if (!snapshotLooksFresh(snapshotCache, WASABI_SIGNUP_PRIMARY_MAX_SNAPSHOT_AGE_MS)) {
      throw new Error('Signup snapshot is missing or stale');
    }
    return snapshotCache;
  }

  if (
    sql.startsWith(
      'select id, username, display_name, email, is_admin, roles, portal_files_access_granted, portal_permissions_access from users where lower(trim(username)) = lower(trim($1)) or (email is not null and btrim(email) <> \'\' and lower(trim(email)) = lower(trim($1))) limit 1'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const identifier = String(params[0] || '').trim().toLowerCase();
    const hit = snapshotRows(snapshot, 'users').find((row) => {
      const username = String(row.username || '').trim().toLowerCase();
      const email = String(row.email || '').trim().toLowerCase();
      return username === identifier || (!!email && email === identifier);
    });
    return pgRows(hit ? [hit] : []);
  }
  if (
    sql.startsWith(
      'select id from users where lower(trim(username)) = $1 or (email is not null and btrim(email) <> \'\' and lower(trim(email)) = $1) limit 1'
    )
  ) {
    const snapshot = await requireFreshSnapshot();
    const identifier = String(params[0] || '').trim().toLowerCase();
    const hit = snapshotRows(snapshot, 'users').find((row) => {
      const username = String(row.username || '').trim().toLowerCase();
      const email = String(row.email || '').trim().toLowerCase();
      return username === identifier || (!!email && email === identifier);
    });
    return pgRows(hit ? [{ id: hit.id }] : []);
  }
  if (sql.startsWith('select created_at from signup_verifications where email_normalized = $1 limit 1')) {
    const snapshot = await requireFreshSnapshot();
    const email = String(params[0] || '');
    const hit = snapshotRows(snapshot, 'signup_verifications').find(
      (row) => String(row.email_normalized || '') === email
    );
    return pgRows(hit ? [{ created_at: hit.created_at || null }] : []);
  }
  if (sql.startsWith('select * from signup_verifications where email_normalized = $1 limit 1 for update')) {
    const snapshot = await requireFreshSnapshot();
    const email = String(params[0] || '');
    const hit = snapshotRows(snapshot, 'signup_verifications').find(
      (row) => String(row.email_normalized || '') === email
    );
    return pgRows(hit ? [hit] : []);
  }

  let outRows = null;
  const wrote = await tryWasabiStateWrite('signup-data-query', async (data) => {
    const rows = ensureSnapshotTable(data, 'signup_verifications');
    const now = nowIso();

    if (sql.startsWith('delete from signup_verifications where email_normalized = $1')) {
      const email = String(params[0] || '');
      data.signup_verifications = rows.filter((row) => String(row.email_normalized || '') !== email);
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'insert into signup_verifications ( email_normalized, pin_hash, password_hash, first_name, last_name, company, title, phone, expires_at ) values ($1, $2, $3, $4, $5, $6, $7, $8, now() + ($9::int * interval \'1 minute\'))'
      )
    ) {
      const ttlMin = Math.max(1, Number(params[8] || 30));
      rows.push({
        email_normalized: String(params[0] || ''),
        pin_hash: String(params[1] || ''),
        password_hash: String(params[2] || ''),
        first_name: String(params[3] || ''),
        last_name: String(params[4] || ''),
        company: String(params[5] || ''),
        title: params[6] == null ? null : String(params[6]),
        phone: params[7] == null ? null : String(params[7]),
        expires_at: new Date(Date.now() + ttlMin * 60 * 1000).toISOString(),
        created_at: now
      });
      outRows = [];
      return;
    }
    if (
      sql.startsWith(
        'insert into users ( username, display_name, password, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup, email, first_name, last_name, company, title, phone, email_verified ) values ($1, $2, $3, false, $4::jsonb, false, null, null, false, true, $5, $6, $7, $8, $9, $10, true) returning id, username, display_name, is_admin, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup, email, first_name, last_name, company, title, phone, email_verified'
      )
    ) {
      const username = String(params[0] || '').trim().toLowerCase();
      const userEmail = String(params[4] || '').trim().toLowerCase();
      const users = ensureSnapshotTable(data, 'users');
      const duplicate = users.some((row) => {
        const u = String(row.username || '').trim().toLowerCase();
        const e = String(row.email || '').trim().toLowerCase();
        return u === username || (!!userEmail && e === userEmail);
      });
      if (duplicate) {
        const err = new Error('duplicate key value violates unique constraint');
        err.code = '23505';
        throw err;
      }
      const id = nextNumericId(users);
      const user = {
        id,
        username,
        display_name: String(params[1] || ''),
        password: String(params[2] || ''),
        is_admin: false,
        roles: parseJsonObject(params[3], {}),
        must_change_password: false,
        portal_files_client_id: null,
        portal_files_job_id: null,
        portal_files_access_granted: false,
        self_signup: true,
        email: String(params[4] || ''),
        first_name: String(params[5] || ''),
        last_name: String(params[6] || ''),
        company: String(params[7] || ''),
        title: params[8] == null ? null : String(params[8]),
        phone: params[9] == null ? null : String(params[9]),
        email_verified: true,
        portal_permissions_access: false,
        created_at: now,
        updated_at: now
      };
      users.push(user);
      outRows = [user];
      return;
    }

    outRows = null;
  });

  if (!wrote) return null;
  if (outRows === null) return null;
  return pgRows(outRows);
}

async function querySignupDataWithWasabiFallback(text, params = []) {
  const normalizedSql = normalizeSqlForSignupData(text);
  if (!WASABI_SIGNUP_PRIMARY_ENABLED) {
    return pool.query(text, params);
  }
  try {
    const result = await runSignupDataWasabiQuery(text, params);
    if (result) {
      wasabiSignupHandledByWasabi += 1;
      return result;
    }
    if (WASABI_SIGNUP_PRIMARY_STRICT) {
      wasabiSignupLastErrorAt = Date.now();
      wasabiSignupLastError = 'Signup Wasabi adapter does not support this query shape';
      throw new Error('Signup Wasabi adapter does not support this query shape');
    }
    wasabiSignupFallbackToPostgres += 1;
    wasabiSignupFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'unsupported-query-shape',
      sql: normalizedSql.slice(0, 260)
    });
    if (wasabiSignupFallbackSamples.length > 50) {
      wasabiSignupFallbackSamples = wasabiSignupFallbackSamples.slice(-50);
    }
  } catch (error) {
    wasabiSignupLastErrorAt = Date.now();
    wasabiSignupLastError = String(error?.message || error || '');
    if (WASABI_SIGNUP_PRIMARY_STRICT) throw error;
    console.warn('[wasabi-signup] query failed, falling back to postgres:', error?.message || error);
    wasabiSignupFallbackToPostgres += 1;
    wasabiSignupFallbackSamples.push({
      at: new Date().toISOString(),
      reason: 'adapter-error',
      sql: normalizedSql.slice(0, 260),
      error: String(error?.message || error || '')
    });
    if (wasabiSignupFallbackSamples.length > 50) {
      wasabiSignupFallbackSamples = wasabiSignupFallbackSamples.slice(-50);
    }
  }
  return pool.query(text, params);
}

async function verifySignupWithWasabi({ email, pin }) {
  if (!WASABI_SIGNUP_PRIMARY_ENABLED) return null;
  let response = null;
  const wrote = await tryWasabiStateWrite('signup-verify', async (data) => {
    const verifications = ensureSnapshotTable(data, 'signup_verifications');
    const users = ensureSnapshotTable(data, 'users');
    const emailNeedle = String(email || '').trim().toLowerCase();
    const idx = verifications.findIndex(
      (row) => String(row.email_normalized || '').trim().toLowerCase() === emailNeedle
    );
    if (idx < 0) {
      response = {
        status: 400,
        body: { success: false, error: 'No pending sign-up for this email. Start again.' }
      };
      return;
    }
    const row = verifications[idx];
    if (new Date(String(row.expires_at || '')).getTime() < Date.now()) {
      verifications.splice(idx, 1);
      response = {
        status: 400,
        body: { success: false, error: 'That code has expired. Request a new one.' }
      };
      return;
    }

    const pinOk = await bcrypt.compare(String(pin || ''), String(row.pin_hash || ''));
    if (!pinOk) {
      response = {
        status: 400,
        body: { success: false, error: 'Invalid verification code' }
      };
      return;
    }

    const duplicate = users.some((user) => {
      const username = String(user.username || '').trim().toLowerCase();
      const userEmail = String(user.email || '').trim().toLowerCase();
      return username === emailNeedle || (!!userEmail && userEmail === emailNeedle);
    });
    if (duplicate) {
      response = {
        status: 409,
        body: { success: false, error: 'An account with this email already exists' }
      };
      return;
    }

    const roles = normalizeRoles({
      camera: false,
      vac: false,
      simpleVac: false,
      email: false,
      psrPlanner: false,
      pricingView: false,
      footageView: false
    });
    const displayName = `${String(row.first_name || '')} ${String(row.last_name || '')}`.trim() || emailNeedle;
    const now = nowIso();
    const id = nextNumericId(users);
    const userRow = {
      id,
      username: emailNeedle,
      display_name: displayName,
      password: String(row.password_hash || ''),
      is_admin: false,
      roles,
      must_change_password: false,
      portal_files_client_id: null,
      portal_files_job_id: null,
      portal_files_access_granted: false,
      self_signup: true,
      portal_permissions_access: false,
      email: emailNeedle,
      first_name: String(row.first_name || ''),
      last_name: String(row.last_name || ''),
      company: String(row.company || ''),
      title: row.title == null ? null : String(row.title),
      phone: row.phone == null ? null : String(row.phone),
      email_verified: true,
      created_at: now,
      updated_at: now
    };
    users.push(userRow);
    verifications.splice(idx, 1);
    response = {
      status: 200,
      body: {
        success: true,
        user: normalizeUser(userRow),
        requiresApproval: true,
        message: 'Account created. An administrator must grant access before you can sign in.'
      }
    };
  });
  if (wrote && response) return response;
  return null;
}

registerOutlookRoutes(app, {
  pool,
  query: queryOutlookDataWithWasabiFallback,
  requireAuth,
  currentToken,
  corsOrigins: CORS_ORIGINS
});
registerPortalFilesRoutes(app, { pool, query: queryPortalDataWithWasabiFallback, requireAuth, requireAdmin });
registerSignupRoutes(app, {
  pool,
  query: querySignupDataWithWasabiFallback,
  verifySignupWithWasabi,
  cleanString,
  normalizeRoles,
  issueSession,
  normalizeUser
});

const autoImportPlugin = createAutoImportPlugin({
  pool,
  query: queryAutoImportWithWasabiFallback,
  requireMike: requireDataAutoSyncEmployeeAccess,
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

let shutdownInProgress = false;
async function flushWasabiStateOnShutdown(signal) {
  if (shutdownInProgress) return;
  shutdownInProgress = true;
  try {
    console.log(`[shutdown] ${signal}: flushing Wasabi mirror/state buffers...`);
    await flushWasabiSqlMirrorQueue();
    await runWasabiStateSnapshot();
  } catch (error) {
    console.warn('[shutdown] flush failed:', error?.message || error);
  } finally {
    process.exit(0);
  }
}

process.on('SIGINT', () => {
  void flushWasabiStateOnShutdown('SIGINT');
});

process.on('SIGTERM', () => {
  void flushWasabiStateOnShutdown('SIGTERM');
});

ensureSchema()
  .then(async () => {
    await autoImportPlugin.initSchema();
    if (wasabiStateClient && WASABI_STATE_BUCKET) {
      await runWasabiStateSnapshot();
      if (PLANNER_STORE_WASABI_ONLY || WASABI_APP_DATA_STORE_WASABI_ONLY) {
        if (!WASABI_WRITES_PRIMARY_ENABLED) {
          console.error(
            '[wasabi-app-data] Wasabi-only business data requires WASABI_WRITES_PRIMARY_ENABLED=1 or creates/updates/deletes will fail.'
          );
        }
        if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
          console.log(
            '[wasabi-app-data] WASABI_APP_DATA_STORE_WASABI_ONLY=1: planner, pricing, reports, jobsite assets, and user_psr_scopes are authoritative in Wasabi; periodic snapshots preserve those tables from the latest object (not from Postgres).'
          );
        } else if (PLANNER_STORE_WASABI_ONLY) {
          console.log(
            '[wasabi-app-data] WASABI_PLANNER_STORE_WASABI_ONLY=1: planner_records and user_psr_scopes are authoritative in Wasabi (PSR tool). Copy any legacy Postgres rows with POST /admin/planner-migrate-postgres-to-wasabi or WASABI_*_MIGRATE_FROM_POSTGRES_ON_BOOT=1.'
          );
        }
        if (MIGRATE_APP_DATA_FROM_POSTGRES_ON_BOOT && WASABI_WRITES_PRIMARY_ENABLED) {
          try {
            const m = await migrateAppDataFromPostgresToWasabi();
            console.log('[wasabi-app-data-migrate] boot:', m);
          } catch (error) {
            console.error('[wasabi-app-data-migrate] boot failed:', error?.message || error);
          }
        }
      }
      try {
        const readiness = evaluateWasabiRuntimeReadiness(await loadWasabiLatestStateSnapshot(true));
        if (WASABI_ALL_READS_PRIMARY_ENABLED && !readiness.readyForAllReadsPrimary) {
          console.warn(
            `[wasabi-readiness] all-reads-primary enabled but not ready; missingTables=${readiness.missingRequiredTables.join(',') || 'none'}`
          );
        } else {
          console.log(
            `[wasabi-readiness] ready=${readiness.readyForAllReadsPrimary ? 'yes' : 'no'} snapshotAgeMs=${readiness.snapshot.ageMs ?? 'n/a'}`
          );
        }
      } catch (error) {
        console.warn('[wasabi-readiness] boot readiness check failed:', error?.message || error);
      }
      setInterval(() => {
        void runWasabiStateSnapshot();
      }, WASABI_STATE_SNAPSHOT_MS);
      setInterval(() => {
        void flushWasabiSqlMirrorQueue();
      }, WASABI_SQL_MIRROR_FLUSH_MS);
      console.log(
        `[wasabi-state] snapshots enabled: bucket=${WASABI_STATE_BUCKET} prefix=${WASABI_STATE_PREFIX} every=${WASABI_STATE_SNAPSHOT_MS}ms`
      );
      console.log(
        `[wasabi-sql-mirror] enabled=${WASABI_SQL_MIRROR_ENABLED ? 'yes' : 'no'} prefix=${WASABI_SQL_MIRROR_PREFIX} flush=${WASABI_SQL_MIRROR_FLUSH_MS}ms buffer=${WASABI_SQL_MIRROR_MAX_BUFFER}`
      );
    } else {
      console.warn('[wasabi-state] snapshots disabled: configure WASABI_* and WASABI_BUCKET');
    }
    app.listen(PORT, () => {
      console.log(`Horizon backend listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('BOOT ERROR:', error);
    process.exit(1);
  });
