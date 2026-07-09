require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const multer = require('multer');
const initSqlJs = require('sql.js');
const { Pool } = require('pg');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { ensureOutlookSchema, registerOutlookRoutes } = require('./outlook');
const { registerPortalFilesRoutes } = require('./portal-files.routes');
const { registerCompanyPermissionsRoutes } = require('./company-permissions.routes');
const {
  nextDb3DuplicateReference,
  isDb3DuplicateExcludeDecision,
  isDb3DuplicateIncludeDecision,
  rowHasJobsiteDuplicateFlag
} = require('./lib/db3-jobsite-duplicate');
const { registerUserGrantsRoutes } = require('./user-grants.routes');
const { createAutoImportPlugin } = require('./auto-import-plugin.routes');
const { registerSignupRoutes } = require('./signup.routes');
const { registerAccountRoutes } = require('./account.routes');
const { registerSaasTenantRoutes } = require('./saas-tenant.routes');
const { registerSaasBillingWebhook, registerSaasBillingRoutes } = require('./saas-billing.routes');
const { registerPlatformReleaseRoutes } = require('./platform-release.routes');
const {
  createPlatformReleaseS3Client,
  resolvePlatformReleaseBucket
} = require('./lib/platform-release-storage');
const { registerOvhOpsWebhook, registerOvhOpsRoutes } = require('./ovh-ops.routes');
const { registerCustomerSupportRoutes } = require('./customer-support.routes');
const { startMetricsCollector, isOvhOpsEnabled } = require('./ovh-ops.service');
const { loadUserCompanyMembership, normalizeAppFeatures } = require('./company-permissions.service');
const {
  ACCOUNT_TYPES,
  EMPLOYEE_ROLES,
  normalizeAccountType,
  normalizeEmployeeRole,
  deriveAccountModel,
  legacyRolesForAccountModel,
  resolveCapabilities,
  canAccessAdminPanel,
  canManagePortalExtras,
  isAdminUser,
  looksLikeMike,
  resolveHostingTier,
  HOSTING_TIERS
} = require('./capabilities');
const {
  resolveDeploymentProfile,
  getPublicDeploymentConfig,
  renderDeploymentBootstrapJs,
  logDeploymentProfileAtStartup,
  deploymentMode
} = require('./lib/deployment-profile');
const { resolveStorageBackend } = require('./lib/portal-storage-backend');
const {
  buildAdminAttachmentStorageKey,
  buildPipesyncPlanPageStorageKey,
  buildPipesyncPlanWorkspaceSaveStorageKey,
  isAllowedAdminAttachmentContentType,
  isValidPipesyncPlanPageStorageKey,
  isValidPipesyncPlanWorkspaceSaveStorageKey,
  presignAdminAttachmentPut,
  presignAdminAttachmentGet,
  deleteAdminAttachmentKeys,
  deletePipesyncPlanPageKeys,
  collectAdminAttachmentStorageKeysFromFiles,
  storageKeysRemovedBetweenFileLists,
  normalizeAdminFilesForPersist,
  hydrateAdminReportOrAssetRows
} = require('./admin-attachments-wasabi');
const {
  resolveTenantStorageContext,
  assertKeyWithinTenantRoot
} = require('./lib/tenant-storage-context');
const { evaluateSaasCustomerLoginAccess } = require('./lib/saas-customer-access');
const { parseSaasTenantSlugFromHost } = require('./lib/saas-tenant-access-urls');
const {
  isSaasTenantOwner,
  getSaasOwnerSessionContext,
  refreshSaasTenantOwnerAccess
} = require('./lib/saas-tenant-owner');
const {
  findTenantByOwnerUserId,
  getStripe,
  syncTenantSubscriptionFromStripe
} = require('./saas-billing.service');
const {
  userHasGlobalPsrBypass,
  isTenantBoundUser,
  resolveTenantWasabiStateScope,
  loadTenantWasabiStateSnapshot,
  putTenantWasabiStateSnapshot,
  emptyTenantAppSnapshot,
  seedTenantAppDataSnapshot
} = require('./lib/tenant-wasabi-state');
const { tenantSlugFromWasabiRoot } = require('./lib/saas-tenant-access-urls');
const { upsertTenantOwnerAuthSnapshot, upsertTenantAuthUserFromRow, removeTenantAuthUser } = require('./lib/saas-tenant-auth-store');
const { upsertTenantDraft } = require('./tenant-provisioning.service');
const { isSaasTenantCorsOrigin } = require('./lib/saas-cors');
const {
  TENANT_USERS_WHERE_SQL,
  userCanManageTenantUsers,
  tenantUserFilterParams,
  resolveActorTenantScope,
  assertUserIdInTenantScope,
  assertLoginEnvironmentAccess,
  assertAuthenticatedEnvironmentAccess,
  assertUsernameAvailableForCreate,
  resolveLoginUserRow,
  loadTenantScopeByHost
} = require('./lib/saas-tenant-scope');
const {
  mirrorUserToTenantLoginSchema,
  removeUserFromTenantLoginSchema
} = require('./lib/saas-tenant-postgres');

const app = express();
app.set('trust proxy', 1);
/** Express defaults to weak ETags on res.json(); browsers cache GET /records etc. and revalidate with If-None-Match → 304 with an empty body. fetch() then fails or yields no JSON, and the planner clears after a silent refresh. */
app.set('etag', false);

/** Comma-separated list, or a single `*` to reflect any Origin (Bearer auth still required for data). */
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

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
    if (isSaasTenantCorsOrigin(origin)) {
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
    'X-Horizon-Client',
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
    'Accept-Ranges',
    'Content-Encoding',
    'Vary'
  ]
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

function clampHttpCompressionInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

/** When false, skip `compression` middleware entirely (Render CPU vs egress tradeoff). */
const HTTP_COMPRESSION_ENABLED = String(process.env.HTTP_COMPRESSION || '1').trim() !== '0';
/** Bytes; 0 = always attempt (tiny JSON may grow slightly — rare). Default 256 so repetitive file-list JSON is gzipped. */
const HTTP_COMPRESSION_THRESHOLD = clampHttpCompressionInt(
  process.env.HTTP_COMPRESSION_THRESHOLD,
  0,
  1024 * 1024,
  256
);
/** zlib gzip level 1 (fast) … 9 (smaller). Default 6; use 7–8 for heavier JSON APIs if CPU allows. */
const HTTP_COMPRESSION_LEVEL = clampHttpCompressionInt(process.env.HTTP_COMPRESSION_LEVEL, 1, 9, 6);

/**
 * Do not gzip Wasabi→client proxy streams (video/range); wastes CPU and can break length semantics.
 * Presigned JSON and /api/files/tree still compress normally.
 */
function shouldSkipHttpCompressionForStreamingDownload(req) {
  const method = String(req.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return false;
  const p = req.path || '';
  if (p.startsWith('/api/files/download/')) return true;
  if (/^\/api\/files\/share-view\/[^/]+\/download\//.test(p)) return true;
  if (/^\/api\/guest\/share\/[^/]+\/download\//.test(p)) return true;
  return false;
}

try {
  // eslint-disable-next-line global-require
  const compression = require('compression');
  if (HTTP_COMPRESSION_ENABLED) {
    app.use(
      compression({
        threshold: HTTP_COMPRESSION_THRESHOLD,
        level: HTTP_COMPRESSION_LEVEL,
        chunkSize: 32 * 1024,
        filter: (req, res) => {
          if (req.headers['x-no-compression']) return false;
          if (shouldSkipHttpCompressionForStreamingDownload(req)) return false;
          return compression.filter(req, res);
        }
      })
    );
    console.info(
      `[http] Response compression: gzip enabled (threshold=${HTTP_COMPRESSION_THRESHOLD}b, level=${HTTP_COMPRESSION_LEVEL}). Set HTTP_COMPRESSION=0 to disable.`
    );
  } else {
    console.info('[http] Response compression disabled (HTTP_COMPRESSION=0).');
  }
} catch {
  console.warn('[http] Install optional `compression` (npm i) to gzip JSON/text API responses and cut HTTP egress.');
}
app.use((req, res, next) => {
  res.on('finish', () => {
    const method = String(req.method || '').toUpperCase();
    const writable = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
    if (!writable) return;
    if (res.statusCode >= 500) return;
    if (requestPathSkipsWasabiStateSnapshot(req)) return;
    queueWasabiStateSnapshot(req);
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

registerSaasBillingWebhook(app, { pool });
registerOvhOpsWebhook(app);
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

function createWasabiStateClient() {
  const accessKeyId = String(process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY || '').trim();
  const secretAccessKey = String(process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY || '').trim();
  const region = String(process.env.WASABI_REGION || 'us-east-1').trim();
  const endpoint = String(process.env.WASABI_ENDPOINT || '').trim().replace(/^http:\/\//i, 'https://');
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
/** Upper cap for timed snapshot interval (Render env); default 24h. Lower with `WASABI_STATE_SNAPSHOT_MAX_MS` if needed. */
const WASABI_STATE_SNAPSHOT_MAX_MS = Math.max(
  60000,
  Math.min(86400000, Number(process.env.WASABI_STATE_SNAPSHOT_MAX_MS || 86400000))
);
const WASABI_STATE_SNAPSHOT_MS = Math.max(
  10000,
  Math.min(WASABI_STATE_SNAPSHOT_MAX_MS, Number(process.env.WASABI_STATE_SNAPSHOT_MS || 3600000))
);
const WASABI_STATE_SNAPSHOT_ON_WRITE =
  String(process.env.WASABI_STATE_SNAPSHOT_ON_WRITE || '0').trim().toLowerCase() !== '0';
/** PipeSync / staff APIs and everything not classified as portal or autosync (short debounce). */
const WASABI_STATE_WRITE_DEBOUNCE_MS = Math.max(
  1000,
  Math.min(60000, Number(process.env.WASABI_STATE_WRITE_DEBOUNCE_MS || 8000))
);
/**
 * PipeShare + file explorer (`/api/files` mutations except fast-path rows below): long debounce so bursts of
 * folder ops/uploads do not schedule full-state Wasabi exports often.
 */
const WASABI_STATE_WRITE_DEBOUNCE_PORTAL_MS = Math.max(
  5000,
  Math.min(600000, Number(process.env.WASABI_STATE_WRITE_DEBOUNCE_PORTAL_MS || 300000))
);
/** Data Auto Sync desktop (`X-Horizon-Client: horizon-data-autosync`): longest debounce (optional third tier). */
const WASABI_STATE_WRITE_DEBOUNCE_AUTOSYNC_MS = Math.max(
  5000,
  Math.min(900000, Number(process.env.WASABI_STATE_WRITE_DEBOUNCE_AUTOSYNC_MS || 180000))
);
/** Duplicate full JSON to `history/snapshot-*.json` on each state write (doubles Wasabi upload). Set `1` to enable archives. Default `0` keeps Wasabi writes lighter. */
const WASABI_STATE_ARCHIVE_SNAPSHOTS =
  String(process.env.WASABI_STATE_ARCHIVE_SNAPSHOTS || '0').trim().toLowerCase() === '1';
/** When true, gzip `latest.json` (and archives) before PUT; reads accept gzip or legacy plain JSON. Set `WASABI_STATE_SNAPSHOT_GZIP=0` to disable. */
const WASABI_STATE_SNAPSHOT_GZIP =
  String(process.env.WASABI_STATE_SNAPSHOT_GZIP || '1').trim().toLowerCase() !== '0';
/** In-memory TTL for repeated reads of `latest.json` (non-force); lowers Wasabi download volume. */
const WASABI_LATEST_STATE_CACHE_MS = Math.max(
  1000,
  Math.min(300000, Number(process.env.WASABI_LATEST_STATE_CACHE_MS || 120000))
);
/** POST paths that must not trigger on-write Wasabi state snapshots (high volume, no app-table mutations). */
function normalizeWasabiSnapshotHttpSkipPath(p) {
  const s = String(p || '')
    .trim()
    .toLowerCase()
    .replace(/\/+$/, '');
  return s || '/';
}
const WASABI_STATE_SNAPSHOT_HTTP_SKIP_PATH_SET = new Set(
  [
    '/api/files/check-paths',
    '/api/files/find-hash-paths',
    '/api/files/upload/presign',
    '/api/files/upload/multipart/init',
    '/api/files/upload/multipart/sign-parts',
    '/api/files/upload/multipart/complete',
    '/api/files/upload/multipart/abort',
    '/api/files/upload/register-sha256',
    '/api/files/upload/resumable/init',
    '/api/files/upload/resumable/sign-part',
    '/api/files/upload/resumable/part-complete',
    '/api/files/upload/resumable/complete',
    '/api/files/upload/resumable/abort',
    '/api/files/folders/zip-manifest',
    '/api/files/presign-batch',
    '/admin/attachments/upload-presign',
    '/pipesync/plan-view/upload-presign',
    '/pipesync/plan-view/read-url',
    '/pipesync/plan-view/workspace-saves/active',
    '/pipesync/plan-view/workspace-saves/mine',
    '/pipesync/plan-view/workspace-saves/mine/latest',
    ...String(process.env.WASABI_STATE_SNAPSHOT_HTTP_SKIP_PATHS || '')
      .split(',')
      .map((s) => normalizeWasabiSnapshotHttpSkipPath(s))
      .filter((s) => s !== '/')
  ].map((s) => normalizeWasabiSnapshotHttpSkipPath(s))
);
function requestPathSkipsWasabiStateSnapshot(req) {
  const raw = String(req.originalUrl || req.url || '').split('?')[0].split('#')[0];
  const n = normalizeWasabiSnapshotHttpSkipPath(raw);
  if (WASABI_STATE_SNAPSHOT_HTTP_SKIP_PATH_SET.has(n)) return true;
  /* Desktop telemetry / heartbeats: no app-wide snapshot (indexing + uploads already skip most /api/files paths). */
  if (n.startsWith('/auto-import-plugin/')) return true;
  return false;
}

function readHorizonClientHeader(req) {
  try {
    const h = req.get && req.get('x-horizon-client');
    return h ? String(h).trim().toLowerCase() : '';
  } catch {
    return '';
  }
}

/** Portal ACL + share links: keep PipeSync-class debounce so permission editors see backups reasonably soon. */
const WASABI_STATE_SNAPSHOT_PORTAL_FAST_DEBOUNCE_PATHS = String(
  process.env.WASABI_STATE_SNAPSHOT_PORTAL_FAST_DEBOUNCE_PATHS ||
    '/api/files/permissions,/api/files/shares,/api/files/share-view'
)
  .split(',')
  .map((s) => normalizeWasabiSnapshotHttpSkipPath(s))
  .filter((s) => s && s !== '/');

/**
 * Optional extra path prefixes (normalized) that must use PipeSync debounce (`WASABI_STATE_WRITE_DEBOUNCE_MS`).
 * Leave unset: every route that is not `/api/files`, `/api/guest`, or a portal-fast path already uses PipeSync timing.
 * Set when you introduce a new top-level API and want to force the short debounce explicitly.
 */
const WASABI_STATE_SNAPSHOT_PIPESYNC_DEBOUNCE_PREFIXES = String(
  process.env.WASABI_STATE_SNAPSHOT_PIPESYNC_DEBOUNCE_PREFIXES || ''
)
  .split(',')
  .map((s) => normalizeWasabiSnapshotHttpSkipPath(s))
  .filter((s) => s && s !== '/');

function wasabiSnapshotDebounceMsForRequest(req) {
  const hc = readHorizonClientHeader(req);
  if (
    hc &&
    (hc.includes('dataautosync') ||
      hc.includes('horizon-data-autosync') ||
      hc.includes('java-desktop') ||
      hc === 'autosync')
  ) {
    return WASABI_STATE_WRITE_DEBOUNCE_AUTOSYNC_MS;
  }
  if (hc && (hc.includes('pipeshare') || hc.includes('file-explorer') || hc.includes('portal-files'))) {
    return WASABI_STATE_WRITE_DEBOUNCE_PORTAL_MS;
  }
  const raw = String(req.originalUrl || req.url || '').split('?')[0].split('#')[0];
  const p = normalizeWasabiSnapshotHttpSkipPath(raw);
  for (const sp of WASABI_STATE_SNAPSHOT_PORTAL_FAST_DEBOUNCE_PATHS) {
    if (p === sp || p.startsWith(`${sp}/`)) return WASABI_STATE_WRITE_DEBOUNCE_MS;
  }
  for (const hp of WASABI_STATE_SNAPSHOT_PIPESYNC_DEBOUNCE_PREFIXES) {
    if (p === hp || p.startsWith(`${hp}/`)) return WASABI_STATE_WRITE_DEBOUNCE_MS;
  }
  if (p.startsWith('/api/files') || p.startsWith('/api/guest')) return WASABI_STATE_WRITE_DEBOUNCE_PORTAL_MS;
  return WASABI_STATE_WRITE_DEBOUNCE_MS;
}
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
/** Base table name for skip matching (`public.foo` → `foo`). */
function sqlMirrorSkipBaseTable(raw) {
  const t = String(raw || '')
    .trim()
    .replace(/"/g, '');
  if (!t) return '';
  const i = t.lastIndexOf('.');
  return (i >= 0 ? t.slice(i + 1) : t).toLowerCase();
}
/**
 * Comma-separated base table names whose INSERT/UPDATE/DELETE should not enqueue Wasabi SQL-mirror batches.
 * Unset: default skips high-churn portal upload metadata (`portal_object_sha256`, resumable session tables).
 * `none` or empty: mirror all mutations again.
 */
function buildWasabiSqlMirrorSkipTableSet() {
  const raw = process.env.WASABI_SQL_MIRROR_SKIP_TABLES;
  const defaults = ['portal_object_sha256', 'portal_upload_sessions', 'portal_upload_session_parts'];
  if (raw === undefined) return new Set(defaults);
  const trimmed = String(raw).trim();
  if (!trimmed || trimmed.toLowerCase() === 'none') return new Set();
  const out = new Set();
  for (const piece of trimmed.split(',')) {
    const b = sqlMirrorSkipBaseTable(piece);
    if (b) out.add(b);
  }
  return out;
}
const WASABI_SQL_MIRROR_SKIP_TABLE_SET = buildWasabiSqlMirrorSkipTableSet();
const WASABI_AUTH_FALLBACK_ENABLED =
  String(process.env.WASABI_AUTH_FALLBACK_ENABLED || '1').trim().toLowerCase() !== '0';
const WASABI_AUTH_FALLBACK_CACHE_MS = Math.max(
  1000,
  Math.min(60000, Number(process.env.WASABI_AUTH_FALLBACK_CACHE_MS || 5000))
);
function readEnvTriState(key) {
  const raw = String(process.env[key] ?? '').trim().toLowerCase();
  if (raw === '0' || raw === 'false' || raw === 'no') return false;
  if (raw === '1' || raw === 'true' || raw === 'yes') return true;
  return null;
}
const WASABI_AUTH_PRIMARY_ENABLED = (() => {
  const explicit = readEnvTriState('WASABI_AUTH_PRIMARY_ENABLED');
  if (explicit === false) return false;
  if (explicit === true) return true;
  return WASABI_ALL_READS_PRIMARY_ENABLED;
})();
const WASABI_AUTH_PRIMARY_STRICT =
  WASABI_AUTH_PRIMARY_ENABLED &&
  (readEnvTriState('WASABI_AUTH_PRIMARY_STRICT') ?? WASABI_ALL_READS_PRIMARY_STRICT);
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
/** In-process cache for GET /sync-state (PipeSync polls; avoids repeated meta queries). 0 disables. */
const SYNC_STATE_HTTP_CACHE_MS = Math.max(0, Math.min(120000, Number(process.env.SYNC_STATE_HTTP_CACHE_MS ?? 4000)));
let syncStateHttpCache = { expiresAt: 0, payload: null };
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

const ADMIN_ATTACHMENT_MAX_BYTES = Math.max(
  1024,
  Math.min(50 * 1024 * 1024, Number(process.env.ADMIN_ATTACHMENT_MAX_BYTES || 25 * 1024 * 1024))
);
/**
 * Plan Viewer uploads go directly browser -> Wasabi via presigned PUT (single-part).
 * Keep app-level limits aligned to storage capabilities, not tiny admin attachment defaults.
 */
const PIPESYNC_PLAN_VIEW_UPLOAD_MAX_BYTES = Math.max(
  1024 * 1024,
  Math.min(5 * 1024 * 1024 * 1024, Number(process.env.PIPESYNC_PLAN_VIEW_UPLOAD_MAX_BYTES || 5 * 1024 * 1024 * 1024))
);
const ADMIN_ATTACHMENT_UPLOAD_TTL_SECONDS = Math.max(
  60,
  Math.min(86400, Number(process.env.ADMIN_ATTACHMENT_UPLOAD_TTL_SECONDS || 3600))
);
const ADMIN_ATTACHMENT_VIEW_TTL_SECONDS = Math.max(
  300,
  Math.min(604800, Number(process.env.ADMIN_ATTACHMENT_VIEW_TTL_SECONDS || 86400))
);

function adminAttachmentsWasabiConfigured() {
  return !!(wasabiStateClient && WASABI_STATE_BUCKET);
}

async function hydrateDailyReportsResponseRows(reports) {
  const list = Array.isArray(reports) ? reports : [];
  if (!adminAttachmentsWasabiConfigured()) return list;
  return hydrateAdminReportOrAssetRows(
    wasabiStateClient,
    WASABI_STATE_BUCKET,
    list,
    'files',
    ADMIN_ATTACHMENT_VIEW_TTL_SECONDS
  );
}

async function hydrateJobsiteAssetsResponseRows(assets) {
  const list = Array.isArray(assets) ? assets : [];
  if (!adminAttachmentsWasabiConfigured()) return list;
  return hydrateAdminReportOrAssetRows(
    wasabiStateClient,
    WASABI_STATE_BUCKET,
    list,
    'files',
    ADMIN_ATTACHMENT_VIEW_TTL_SECONDS
  );
}

async function hydratePlanBoardPageRow(p, planStorage) {
  if (!p || typeof p !== 'object') return p;
  const copy = { ...p };
  delete copy.viewUrl;
  const sk = String(copy.storageKey || '').trim();
  const s3 = planStorage?.client || wasabiStateClient;
  const bucket = String(planStorage?.bucket || WASABI_STATE_BUCKET || '').trim();
  if (sk && isPersistablePlanPdfStorageKey(sk) && s3 && bucket) {
    try {
      const { url } = await presignAdminAttachmentGet(
        s3,
        bucket,
        sk,
        ADMIN_ATTACHMENT_VIEW_TTL_SECONDS
      );
      copy.src = url;
    } catch {
      copy.src = '';
    }
  }
  return copy;
}

async function hydratePlanBoardLegacyPieceRow(p, planStorage) {
  if (!p || typeof p !== 'object') return p;
  const copy = { ...p };
  const sk = String(copy.storageKey || '').trim();
  const s3 = planStorage?.client || wasabiStateClient;
  const bucket = String(planStorage?.bucket || WASABI_STATE_BUCKET || '').trim();
  if (sk && isPersistablePlanPdfStorageKey(sk) && s3 && bucket) {
    try {
      const { url } = await presignAdminAttachmentGet(
        s3,
        bucket,
        sk,
        ADMIN_ATTACHMENT_VIEW_TTL_SECONDS
      );
      copy.viewUrl = url;
    } catch {
      copy.viewUrl = '';
    }
  }
  return copy;
}

async function hydratePlanBoardLegacyPlanRow(d, planStorage) {
  if (!d || typeof d !== 'object') return d;
  const copy = { ...d };
  const sk = String(copy.storageKey || '').trim();
  const s3 = planStorage?.client || wasabiStateClient;
  const bucket = String(planStorage?.bucket || WASABI_STATE_BUCKET || '').trim();
  if (sk && isPersistablePlanPdfStorageKey(sk) && s3 && bucket) {
    try {
      const { url } = await presignAdminAttachmentGet(
        s3,
        bucket,
        sk,
        ADMIN_ATTACHMENT_VIEW_TTL_SECONDS
      );
      copy.viewUrl = url;
    } catch {
      copy.viewUrl = '';
    }
  }
  if (Array.isArray(copy.pieces)) {
    const pieces = [];
    for (const p of copy.pieces) {
      if (!p || typeof p !== 'object') continue;
      pieces.push(await hydratePlanBoardLegacyPieceRow(p, planStorage));
    }
    copy.pieces = pieces;
  }
  return copy;
}

async function hydratePlanBoardWorkspacePages(workspaces, planStorage) {
  if (!Array.isArray(workspaces)) return workspaces;
  const out = [];
  for (const w of workspaces) {
    if (!w || typeof w !== 'object') continue;
    const wCopy = { ...w };
    if (Array.isArray(wCopy.pages)) {
      const wp = [];
      for (const p of wCopy.pages) {
        if (!p || typeof p !== 'object') continue;
        wp.push(await hydratePlanBoardPageRow(p, planStorage));
      }
      wCopy.pages = wp;
    }
    out.push(wCopy);
  }
  return out;
}

async function hydratePlanBoardBranch(branch, planStorage) {
  if (!branch || typeof branch !== 'object') return branch;
  if (!adminAttachmentsWasabiConfigured() && !(planStorage?.client && planStorage?.bucket)) return branch;
  const next = { ...branch };
  if (Array.isArray(branch.pages)) {
    const pages = [];
    for (const p of branch.pages) {
      pages.push(await hydratePlanBoardPageRow(p, planStorage));
    }
    next.pages = pages;
  } else if (!Array.isArray(next.pages)) {
    next.pages = [];
  }
  if (Array.isArray(branch.mapWorkspaces)) {
    next.mapWorkspaces = await hydratePlanBoardWorkspacePages(branch.mapWorkspaces, planStorage);
  }
  if (Array.isArray(branch.legacyPlans)) {
    const legacyPlans = [];
    for (const d of branch.legacyPlans) {
      if (!d || typeof d !== 'object') continue;
      legacyPlans.push(await hydratePlanBoardLegacyPlanRow(d, planStorage));
    }
    next.legacyPlans = legacyPlans;
  }
  return next;
}

async function hydratePlanViewPayloadForResponse(payload, req) {
  if (!payload || typeof payload !== 'object') return payload;
  const planStorage = req ? await planViewWasabiForRequest(req) : null;
  if (payload.v === 2 && payload.imagePlan && payload.pdfMap) {
    const imagePlan = await hydratePlanBoardBranch(payload.imagePlan, planStorage);
    const pdfMap = await hydratePlanBoardBranch(payload.pdfMap, planStorage);
    return { ...payload, v: 2, imagePlan, pdfMap };
  }
  return hydratePlanBoardBranch(payload, planStorage);
}

function isLegacyPlanPdfStorageKey(key) {
  const norm = String(key || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .toLowerCase();
  return norm.startsWith('clients/');
}

function isPersistablePlanPdfStorageKey(key, rootPrefix = '') {
  const sk = String(key || '').trim();
  if (!sk) return false;
  return isValidPipesyncPlanPageStorageKey(sk, rootPrefix) || isLegacyPlanPdfStorageKey(sk);
}

async function tenantWasabiRootForRequest(req) {
  const requestHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').trim();
  const ctx = await resolveTenantStorageContext(pool, req.user?.id, { requestHost });
  return ctx?.wasabiRootPrefix || '';
}

/** Plan-view PDF/image uploads: SaaS hosts use SAAS_WASABI_BUCKET; tenant users get Tenants/{slug}/ prefix. */
async function planViewWasabiForRequest(req) {
  const backend = resolveStorageBackend(req);
  const tenantRoot = await tenantWasabiRootForRequest(req);
  const rootPrefix = tenantRoot || backend.rootPrefix || '';
  const client = backend.s3 || wasabiStateClient;
  const bucket = String(backend.bucket || WASABI_STATE_BUCKET || '').trim();
  return { client, bucket, rootPrefix, configured: !!(client && bucket) };
}

function sanitizePlanBoardBranch(branch) {
  if (!branch || typeof branch !== 'object') return branch;
  let clone;
  try {
    clone = JSON.parse(JSON.stringify(branch));
  } catch {
    return branch;
  }
  if (Array.isArray(clone.pages)) {
    clone.pages = clone.pages
      .map((p) => {
        if (!p || typeof p !== 'object') return null;
        const o = { ...p };
        delete o.viewUrl;
        const sk = String(o.storageKey || '').trim();
        if (String(o.kind) === 'pdf') {
          if (sk && isValidPipesyncPlanPageStorageKey(sk)) {
            delete o.src;
            return o;
          }
          if (sk && isLegacyPlanPdfStorageKey(sk)) return o;
          return null;
        }
        if (sk && isValidPipesyncPlanPageStorageKey(sk)) {
          delete o.src;
          return o;
        }
        if (sk) delete o.storageKey;
        return o;
      })
      .filter(Boolean);
  } else {
    clone.pages = [];
  }
  if (Array.isArray(clone.mapWorkspaces)) {
    clone.mapWorkspaces = clone.mapWorkspaces
      .map((w) => {
        if (!w || typeof w !== 'object') return w;
        const wn = { ...w };
        if (Array.isArray(wn.pages)) {
          wn.pages = wn.pages
            .map((p) => {
              if (!p || typeof p !== 'object') return null;
              const o = { ...p };
              delete o.viewUrl;
              const sk = String(o.storageKey || '').trim();
              if (String(o.kind) === 'pdf') {
                if (sk && isValidPipesyncPlanPageStorageKey(sk)) {
                  delete o.src;
                  return o;
                }
                if (sk && isLegacyPlanPdfStorageKey(sk)) return o;
                return null;
              }
              if (sk && isValidPipesyncPlanPageStorageKey(sk)) {
                delete o.src;
                return o;
              }
              if (sk) delete o.storageKey;
              return o;
            })
            .filter(Boolean);
        }
        return wn;
      })
      .filter(Boolean);
  }
  if (Array.isArray(clone.legacyPlans)) {
    clone.legacyPlans = clone.legacyPlans
      .map((d) => {
        if (!d || typeof d !== 'object') return null;
        const o = { ...d };
        const sk = String(o.storageKey || '').trim();
        if (sk && !isPersistablePlanPdfStorageKey(sk)) return null;
        if (sk && isValidPipesyncPlanPageStorageKey(sk)) delete o.viewUrl;
        if (Array.isArray(o.pieces)) {
          o.pieces = o.pieces
            .map((p) => {
              if (!p || typeof p !== 'object') return null;
              const piece = { ...p };
              const psk = String(piece.storageKey || '').trim();
              if (!isPersistablePlanPdfStorageKey(psk)) return null;
              if (isValidPipesyncPlanPageStorageKey(psk)) delete piece.viewUrl;
              return piece;
            })
            .filter(Boolean);
        } else {
          o.pieces = [];
        }
        if (!o.pieces.length) return null;
        if (!isPersistablePlanPdfStorageKey(sk)) {
          // Keep split-page metadata for docs whose original archive sync is still pending.
          // Without this, PDF doc identity disappears across saves and breaks unassigned parity.
          delete o.storageKey;
        }
        return o;
      })
      .filter(Boolean);
  }
  return clone;
}

function sanitizePlanViewPayloadForPersist(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  let clone;
  try {
    clone = JSON.parse(JSON.stringify(payload));
  } catch {
    return payload;
  }
  if (clone.v === 2 && clone.imagePlan && clone.pdfMap) {
    return {
      v: 2,
      imagePlan: sanitizePlanBoardBranch(clone.imagePlan),
      pdfMap: sanitizePlanBoardBranch(clone.pdfMap)
    };
  }
  return sanitizePlanBoardBranch(clone);
}

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

function decodeWasabiStateSnapshotBody(raw, contentEncoding) {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || []);
  const enc = String(contentEncoding || '').toLowerCase();
  const gzipMagic = buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  if (enc.includes('gzip') || gzipMagic) {
    return zlib.gunzipSync(buf).toString('utf8');
  }
  return buf.toString('utf8');
}

async function loadWasabiLatestStateSnapshot(force = false) {
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) return null;
  const now = Date.now();
  if (!force && wasabiLatestStateCache && now - wasabiLatestStateCacheAt <= WASABI_LATEST_STATE_CACHE_MS) {
    return wasabiLatestStateCache;
  }
  const out = await wasabiStateClient.send(
    new GetObjectCommand({
      Bucket: WASABI_STATE_BUCKET,
      Key: `${WASABI_STATE_PREFIX}/latest.json`
    })
  );
  const raw = await bodyToBuffer(out.Body);
  const jsonText = decodeWasabiStateSnapshotBody(raw, out.ContentEncoding);
  const parsed = JSON.parse(jsonText);
  wasabiLatestStateCache = parsed;
  wasabiLatestStateCacheAt = now;
  return parsed;
}

async function loadWasabiStateForRequest(req, force = false) {
  const tenantScope = await resolveTenantWasabiStateScope(pool, req);
  if (tenantScope) {
    const snapshot = await loadTenantWasabiStateSnapshot(tenantScope, force);
    return { snapshot, tenantScope, isTenant: true };
  }
  if (isTenantBoundUser(req?.user)) {
    return { snapshot: null, tenantScope: null, isTenant: true };
  }
  const snapshot = await loadWasabiLatestStateSnapshot(force);
  return { snapshot, tenantScope: null, isTenant: false };
}

async function runWasabiStateWriteForRequest(req, reason, mutator) {
  if (!WASABI_WRITES_PRIMARY_ENABLED) {
    throw new Error('WASABI_WRITES_PRIMARY_ENABLED is off');
  }
  const tenantScope = await resolveTenantWasabiStateScope(pool, req);
  if (tenantScope) {
    const existing =
      (await loadTenantWasabiStateSnapshot(tenantScope, true)) ||
      emptyTenantAppSnapshot(tenantScope.tenantSlug);
    const next = snapshotStateShape(existing);
    await mutator(next.data);
    next.generatedAt = nowIso();
    next.reason = String(reason || 'mutation');
    await putTenantWasabiStateSnapshot(tenantScope, next);
    return next;
  }
  if (isTenantBoundUser(req?.user)) {
    throw new Error('Tenant Wasabi state is not available for this account on this host.');
  }
  return runWasabiStateWrite(reason, mutator);
}

async function wasabiStateConfiguredForRequest(req) {
  if (isTenantBoundUser(req?.user)) {
    const scope = await resolveTenantWasabiStateScope(pool, req);
    return !!(scope?.s3 && scope?.bucket);
  }
  return !!(wasabiStateClient && WASABI_STATE_BUCKET);
}

async function loadSnapshotTablesForRequest(req, force = false) {
  const { snapshot, isTenant } = await loadWasabiStateForRequest(req, force);
  if (isTenant && !snapshot) return {};
  return readWasabiSnapshotDataTables(snapshot || {}, { strict: false });
}

async function syncSaasSubscriptionOnLogin(userId) {
  const id = String(userId || '').trim();
  if (!id) return;
  try {
    let tenant = await findTenantByOwnerUserId(pool, id);
    if (!tenant) return;
    const stripe = getStripe();
    if (stripe && tenant.stripeCustomerId) {
      tenant = (await syncTenantSubscriptionFromStripe(stripe, pool, tenant)) || tenant;
    }
  } catch (error) {
    console.warn('[login] SaaS subscription sync failed:', error?.message || error);
  }
}

function nowIso() {
  return new Date().toISOString();
}

async function putWasabiStateObject(stateObject) {
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) {
    throw new Error('Wasabi state client is not configured');
  }
  const stamp = nowIso().replace(/[:.]/g, '-');
  const rawJson = Buffer.from(JSON.stringify(stateObject), 'utf8');
  let payload = rawJson;
  let contentEncoding;
  if (WASABI_STATE_SNAPSHOT_GZIP) {
    payload = zlib.gzipSync(rawJson);
    contentEncoding = 'gzip';
  }
  const latestKey = `${WASABI_STATE_PREFIX}/latest.json`;
  const archiveKey = `${WASABI_STATE_PREFIX}/history/snapshot-${stamp}.json`;
  const putBase = {
    Bucket: WASABI_STATE_BUCKET,
    Body: payload,
    ContentType: 'application/json'
  };
  if (contentEncoding) putBase.ContentEncoding = contentEncoding;
  await wasabiStateClient.send(
    new PutObjectCommand({
      ...putBase,
      Key: latestKey
    })
  );
  if (WASABI_STATE_ARCHIVE_SNAPSHOTS) {
    await wasabiStateClient.send(
      new PutObjectCommand({
        ...putBase,
        Key: archiveKey
      })
    );
  }
  wasabiLatestStateCache = stateObject;
  wasabiLatestStateCacheAt = Date.now();
}

/**
 * Read the mutable tables blob from a loaded Wasabi `latest.json`.
 * JS treats `typeof null === 'object'`, so `data: null` must not become `{}` on incremental writes
 * (that would replace the snapshot with an empty `data` object and make planner/PSR edits vanish after refresh).
 */
function readWasabiSnapshotDataTables(snapshot, options = {}) {
  const strict = options.strict === true;
  if (!snapshot || typeof snapshot !== 'object') return {};
  const inner = snapshot.data;
  if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
    return inner;
  }
  const skipMeta = new Set(['generatedAt', 'source', 'scope', 'reason', 'data']);
  const legacy = {};
  for (const key of Object.keys(snapshot)) {
    if (skipMeta.has(key)) continue;
    const v = snapshot[key];
    if (Array.isArray(v)) legacy[key] = v;
    else if (v && typeof v === 'object' && !Array.isArray(v)) legacy[key] = v;
  }
  if (Object.keys(legacy).length) {
    console.warn('[wasabi-state] snapshot missing usable .data object; using top-level table keys as data');
    return legacy;
  }
  if (Object.prototype.hasOwnProperty.call(snapshot, 'data') && snapshot.data === null) {
    const msg =
      'Wasabi latest.json has data:null with no recoverable table keys — refusing incremental write that would erase planner/auth state. Repair latest.json or run a full snapshot export.';
    if (strict) throw new Error(msg);
    console.warn(`[wasabi-state] ${msg}`);
  }
  return {};
}

function snapshotStateShape(snapshot) {
  const raw = snapshot && typeof snapshot === 'object' ? snapshot : {};
  const data = readWasabiSnapshotDataTables(raw, { strict: true });
  return {
    generatedAt: nowIso(),
    source: 'horizon-backend',
    scope:
      raw.scope && typeof raw.scope === 'object' && !Array.isArray(raw.scope)
        ? raw.scope
        : { clientId: 'portal-users', jobId: '3' },
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
  const tables = readWasabiSnapshotDataTables(snapshot || {}, { strict: false });
  return {
    generatedAt: Number.isFinite(generatedAtMs) ? new Date(generatedAtMs).toISOString() : null,
    ageMs,
    hasData: Object.keys(tables).length > 0
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
  const data = readWasabiSnapshotDataTables(snapshot || {}, { strict: false });
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

/** PipeSync Plan view markup — stored only in Wasabi `latest.json` under `data.pipesync_plan_views` (no Postgres table). */
const PIPESYNC_PLAN_VIEW_TABLE = 'pipesync_plan_views';
const PIPESYNC_PLAN_VIEW_MAX_BYTES = 14 * 1024 * 1024;
const PIPESYNC_PRICING_STATE_TABLE = 'pipesync_pricing_state';
const PIPESYNC_PRICING_STATE_MAX_BYTES = 768 * 1024;
const PIPESYNC_PRICING_SNAPSHOTS_MAX = 48;
const PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE = 'pipesync_plan_workspace_saves';
const PIPESYNC_PLAN_WORKSPACE_SAVE_MAX_BYTES = 14 * 1024 * 1024;
const PIPESYNC_PLAN_WORKSPACE_SAVE_MAX_PER_USER_BOARD = 40;
const PIPESYNC_PLAN_WORKSPACE_BOARDS = new Set(['planView', 'pdfMapView']);

function pipesyncPlanViewUsernameKey(user) {
  const u = cleanString(user?.username || user?.displayName || '').toLowerCase();
  return u ? u.slice(0, 200) : '';
}

function sanitizePricingHourlyForPersist(raw) {
  const o = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  return {
    vacRate: String(o.vacRate ?? '').slice(0, 60),
    cameraRate: String(o.cameraRate ?? '').slice(0, 60),
    vacHours: String(o.vacHours ?? '').slice(0, 60),
    cameraHours: String(o.cameraHours ?? '').slice(0, 60)
  };
}

function sanitizePricingSnapshotFiltersForPersist(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const [k, v] of Object.entries(raw)) {
    if (!k) continue;
    const key = String(k).slice(0, 80);
    if (!key) continue;
    if (typeof v === 'boolean') {
      out[key] = v;
      continue;
    }
    out[key] = String(v ?? '').slice(0, 160);
  }
  return out;
}

function sanitizePricingSnapshotForPersist(raw) {
  const o = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const pickFinite = (v) => {
    const n = Number(v);
    return Number.isFinite(n) ? Number(n.toFixed(2)) : null;
  };
  const savedAtRaw = String(o.savedAt || '').trim();
  const savedAtParsed = Date.parse(savedAtRaw);
  return {
    id: String(o.id || '').slice(0, 120) || crypto.randomUUID(),
    label: String(o.label || '').slice(0, 180),
    savedAt: Number.isFinite(savedAtParsed) ? new Date(savedAtParsed).toISOString() : nowIso(),
    filters: sanitizePricingSnapshotFiltersForPersist(o.filters),
    hourly: sanitizePricingHourlyForPersist(o.hourly),
    capturedFootRevenue: pickFinite(o.capturedFootRevenue),
    capturedTruckTotal: pickFinite(o.capturedTruckTotal),
    capturedCombined: pickFinite(o.capturedCombined)
  };
}

function sanitizePricingStatePayloadForPersist(payload) {
  const o = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
  const snapshotsRaw = Array.isArray(o.snapshots) ? o.snapshots : [];
  return {
    hourly: sanitizePricingHourlyForPersist(o.hourly),
    snapshots: snapshotsRaw.slice(0, PIPESYNC_PRICING_SNAPSHOTS_MAX).map(sanitizePricingSnapshotForPersist)
  };
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
    const prevData = readWasabiSnapshotDataTables(previousSnapshot || {}, { strict: false });
    for (const tableName of tables) {
      if (preserveFromLatest.has(tableName)) {
        const prevRows = Array.isArray(prevData[tableName]) ? prevData[tableName] : null;
        if (prevRows !== null) {
          data[tableName] = cloneSnapshotRows(prevRows);
          continue;
        }
        // No Wasabi rows yet for this preserved table — pull Postgres once instead of writing [] over latest.json.
      }
      try {
        const q = await pool.query(`SELECT * FROM ${tableName}`);
        data[tableName] = q.rows;
      } catch (err) {
        data[tableName] = { error: String(err?.message || err) };
      }
    }
    // Wasabi-only rows (no Postgres mirror) — merge from current latest so periodic snapshots never erase plan markup.
    try {
      let mergeSource = previousSnapshot;
      if (!mergeSource) {
        try {
          mergeSource = await loadWasabiLatestStateSnapshot(false);
        } catch {
          mergeSource = null;
        }
      }
      const mergeTables = readWasabiSnapshotDataTables(mergeSource || {}, { strict: false });
      if (Array.isArray(mergeTables[PIPESYNC_PLAN_VIEW_TABLE])) {
        data[PIPESYNC_PLAN_VIEW_TABLE] = cloneSnapshotRows(mergeTables[PIPESYNC_PLAN_VIEW_TABLE]);
      } else if (!Array.isArray(data[PIPESYNC_PLAN_VIEW_TABLE])) {
        data[PIPESYNC_PLAN_VIEW_TABLE] = [];
      }
      if (Array.isArray(mergeTables[PIPESYNC_PRICING_STATE_TABLE])) {
        data[PIPESYNC_PRICING_STATE_TABLE] = cloneSnapshotRows(mergeTables[PIPESYNC_PRICING_STATE_TABLE]);
      } else if (!Array.isArray(data[PIPESYNC_PRICING_STATE_TABLE])) {
        data[PIPESYNC_PRICING_STATE_TABLE] = [];
      }
    } catch {
      if (!Array.isArray(data[PIPESYNC_PLAN_VIEW_TABLE])) data[PIPESYNC_PLAN_VIEW_TABLE] = [];
      if (!Array.isArray(data[PIPESYNC_PRICING_STATE_TABLE])) data[PIPESYNC_PRICING_STATE_TABLE] = [];
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

function queueWasabiStateSnapshot(req) {
  if (!WASABI_STATE_SNAPSHOT_ON_WRITE) return;
  if (!wasabiStateClient || !WASABI_STATE_BUCKET) return;
  const debounceMs = wasabiSnapshotDebounceMsForRequest(req);
  wasabiStateLastQueuedAt = Date.now();
  const path = String(req.originalUrl || req.url || '').split('?')[0] || '';
  wasabiStateLastReason = `${String(req.method || '').toUpperCase()} ${path} @debounce=${debounceMs}ms`;
  if (wasabiStateSnapshotTimer) clearTimeout(wasabiStateSnapshotTimer);
  wasabiStateSnapshotTimer = setTimeout(async () => {
    wasabiStateSnapshotTimer = null;
    await runWasabiStateSnapshot();
  }, debounceMs);
}

function currentWasabiStateStatus() {
  return {
    enabled: !!(wasabiStateClient && WASABI_STATE_BUCKET),
    onWrite: WASABI_STATE_SNAPSHOT_ON_WRITE,
    archiveSnapshots: WASABI_STATE_ARCHIVE_SNAPSHOTS,
    snapshotGzip: WASABI_STATE_SNAPSHOT_GZIP,
    latestStateCacheMs: WASABI_LATEST_STATE_CACHE_MS,
    bucket: WASABI_STATE_BUCKET || null,
    prefix: WASABI_STATE_PREFIX,
    intervalMs: WASABI_STATE_SNAPSHOT_MS,
    maxIntervalMs: WASABI_STATE_SNAPSHOT_MAX_MS,
    writeDebounceMsPipesync: WASABI_STATE_WRITE_DEBOUNCE_MS,
    writeDebounceMsPortal: WASABI_STATE_WRITE_DEBOUNCE_PORTAL_MS,
    writeDebounceMsAutosync: WASABI_STATE_WRITE_DEBOUNCE_AUTOSYNC_MS,
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
    skipTables: Array.from(WASABI_SQL_MIRROR_SKIP_TABLE_SET).sort(),
    skipTablesFromEnv: process.env.WASABI_SQL_MIRROR_SKIP_TABLES !== undefined,
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
        const skipBase = sqlMirrorSkipBaseTable(mutation.table);
        if (!WASABI_SQL_MIRROR_SKIP_TABLE_SET.has(skipBase)) {
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
      }
      return result;
    })
    .catch((error) => {
      if (mutation) {
        const skipBase = sqlMirrorSkipBaseTable(mutation.table);
        if (!WASABI_SQL_MIRROR_SKIP_TABLE_SET.has(skipBase)) {
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
    jobsiteContactsView: false,
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
      jobsiteContactsView:
        value.jobsiteContactsView === true || value.jobsite_contacts_view === true,
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
 * Access assignment signal used for UI/admin reporting.
 * Login itself is gated by credentials + email verification, not by this flag.
 */
function userHasAnyAssignedAccess(row) {
  const accountModel = deriveAccountModel({
    accountType: row?.account_type ?? row?.accountType,
    employeeRole: row?.employee_role ?? row?.employeeRole,
    isAdmin: row?.is_admin ?? row?.isAdmin,
    roles: row?.roles,
    username: row?.username,
    display_name: row?.display_name,
    displayName: row?.displayName,
    email: row?.email
  });
  if (accountModel.accountType === ACCOUNT_TYPES.EMPLOYEE && accountModel.employeeRole) return true;
  const isCustomerModel = accountModel.accountType === ACCOUNT_TYPES.CUSTOMER;
  if (!isCustomerModel && row?.is_admin) return true;
  const roles = normalizeRoles(row?.roles);
  const hasRoleAccess = !isCustomerModel && Object.values(roles).some((v) => v === true);
  const hasPortalFiles = row?.portal_files_access_granted === true;
  const hasAutosyncMaster = row?.autosync_master_granted === true;
  const hasPortalPermissionUi = !!row?.portal_permissions_access || canManagePortalExtras(row);
  return hasRoleAccess || hasPortalFiles || hasAutosyncMaster || hasPortalPermissionUi;
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
/** Unified Permissions scope picker roots for portal-users (Folder 2 + Folder 8 only). */
const UNIFIED_PORTAL_SCOPE_ALLOWED_JOB_IDS = new Set(['2', '8']);
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
  if (!user || (user.portalFilesAccessGranted !== true && user.autosyncMasterGranted !== true)) return [];
  return dedupePortalScopes(portalScopes);
}

function parseProductTutorialsSeen(row) {
  const raw = row?.product_tutorials_seen ?? row?.productTutorialsSeen;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { pipeshare: false, pipesync: false };
  }
  return {
    pipeshare: raw.pipeshare === true,
    pipesync: raw.pipesync === true
  };
}

function parsePortalWorkspaceLayouts(row) {
  const raw = row?.portal_workspace_layouts ?? row?.portalWorkspaceLayouts;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {};
  }
  const out = {};
  for (const key of ['desktop', 'mobile']) {
    const bundle = raw[key];
    if (!bundle || typeof bundle !== 'object' || !Array.isArray(bundle.tabs) || !bundle.tabs.length) continue;
    out[key] = {
      version: Number(bundle.version) || 3,
      activeTabId: typeof bundle.activeTabId === 'string' ? bundle.activeTabId : String(bundle.tabs[0]?.id || 't0'),
      tabs: bundle.tabs.slice(0, 12)
    };
  }
  return out;
}

const USER_PREFS_MAX_DEPTH = 8;
const USER_PREFS_MAX_KEYS = 400;
const USER_PREFS_MAX_STRING = 8000;
const USER_PREFS_MAX_ARRAY = 64;

function sanitizeUserPrefsValue(value, depth = 0, stats = null) {
  const counter = stats || { keys: 0 };
  if (depth > USER_PREFS_MAX_DEPTH) return undefined;
  if (value === null || value === undefined) return null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string') {
    return value.length > USER_PREFS_MAX_STRING ? value.slice(0, USER_PREFS_MAX_STRING) : value;
  }
  if (Array.isArray(value)) {
    const out = [];
    for (const item of value.slice(0, USER_PREFS_MAX_ARRAY)) {
      if (counter.keys > USER_PREFS_MAX_KEYS) break;
      const next = sanitizeUserPrefsValue(item, depth + 1, counter);
      if (next !== undefined) out.push(next);
    }
    return out;
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (counter.keys > USER_PREFS_MAX_KEYS) break;
      const key = String(k).slice(0, 64);
      if (!key) continue;
      counter.keys += 1;
      const next = sanitizeUserPrefsValue(v, depth + 1, counter);
      if (next !== undefined) out[key] = next;
    }
    return out;
  }
  return undefined;
}

function parseUserPrefs(row) {
  const raw = row?.user_prefs ?? row?.userPrefs;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const sanitized = sanitizeUserPrefsValue(raw, 0, { keys: 0 });
  return sanitized && typeof sanitized === 'object' && !Array.isArray(sanitized) ? sanitized : {};
}

function deepMergePlainObjects(base, patch, depth = 0) {
  const out = base && typeof base === 'object' && !Array.isArray(base) ? { ...base } : {};
  const p = patch && typeof patch === 'object' && !Array.isArray(patch) ? patch : {};
  if (depth >= USER_PREFS_MAX_DEPTH) return out;
  for (const [k, v] of Object.entries(p)) {
    const key = String(k).slice(0, 64);
    if (!key) continue;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      out[key] = deepMergePlainObjects(
        out[key] && typeof out[key] === 'object' && !Array.isArray(out[key]) ? out[key] : {},
        v,
        depth + 1
      );
    } else {
      out[key] = v;
    }
  }
  return out;
}

function mergeUserPrefsPatch(current, patch) {
  const merged = deepMergePlainObjects(parseUserPrefs({ user_prefs: current }), patch);
  merged.savedAt = Date.now();
  return parseUserPrefs({ user_prefs: merged });
}

function normalizeUser(row, context = {}) {
  let isSaasOwner = context.saasTenantOwner === true;
  let isTenantPurchaser = context.tenantPurchaser === true;
  if (looksLikeMike(row)) {
    isSaasOwner = false;
    isTenantPurchaser = false;
  }
  const accountModel = deriveAccountModel({
    accountType: row?.account_type,
    employeeRole: row?.employee_role,
    isAdmin: row?.is_admin,
    roles: row?.roles,
    username: row?.username,
    display_name: row?.display_name,
    email: row?.email,
    self_signup: row?.self_signup,
    selfSignup: row?.self_signup === true,
    saasTenantOwner: isSaasOwner
  });
  const legacyRoles = normalizeRoles(row?.roles);
  const canonicalRoles = legacyRolesForAccountModel(accountModel, legacyRoles);
  const canonicalIsAdmin =
    !isSaasOwner &&
    accountModel.accountType === ACCOUNT_TYPES.EMPLOYEE &&
    (accountModel.employeeRole === EMPLOYEE_ROLES.ADMIN || accountModel.employeeRole === EMPLOYEE_ROLES.SUPERADMIN);

  const id = row.id;
  let selfSignup = row?.self_signup === true;
  if (looksLikeMike(row)) {
    selfSignup = false;
  }
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
  const autosyncMasterGranted =
    row.autosync_master_granted === true || row.autosyncMasterGranted === true;
  const portalScopeDefaultsOk = portalFilesAccessGranted || autosyncMasterGranted;

  let portalFilesClientId;
  let portalFilesJobId;
  if (!portalScopeDefaultsOk) {
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
  const portalPermissionsAccess = portalPermissionsAccessRaw || canManagePortalExtras({
    ...row,
    accountType: accountModel.accountType,
    employeeRole: accountModel.employeeRole,
    isAdmin: canonicalIsAdmin
  });
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
    tenantPurchaser: isTenantPurchaser,
    subscriptionStatus: context.subscriptionStatus || undefined,
    saasTenantOwner: isSaasOwner,
    isAdmin: canonicalIsAdmin,
    isSuperAdmin:
      !isSaasOwner &&
      accountModel.accountType === ACCOUNT_TYPES.EMPLOYEE &&
      accountModel.employeeRole === EMPLOYEE_ROLES.SUPERADMIN,
    accountType: accountModel.accountType,
    employeeRole: accountModel.employeeRole,
    roles: canonicalRoles,
    mustChangePassword: !!row.must_change_password,
    selfSignup,
    hostingTier: resolveHostingTier({
      ...row,
      selfSignup,
      self_signup: selfSignup,
      saasTenantOwner: isSaasOwner
    }),
    portalFilesAccessGranted,
    autosyncMasterGranted,
    portalFilesClientId,
    portalFilesJobId,
    portalScopes: [],
    psrScopes: [],
    portalPermissionsAccessRaw,
    portalPermissionsAccess,
    productTutorialsSeen: parseProductTutorialsSeen(row),
    portalWorkspaceLayouts: parsePortalWorkspaceLayouts(row),
    userPrefs: parseUserPrefs(row)
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

async function attachCompanyToUsers(users) {
  const list = Array.isArray(users) ? users : [];
  if (!list.length) return list;
  const ids = list.map((u) => String(u.id || '')).filter(Boolean);
  const r = await pool.query(
    `SELECT m.user_id, m.company_id, m.role_key, c.name AS company_name, c.app_features, c.customer_enabled
     FROM user_company_membership m
     JOIN companies c ON c.id = m.company_id
     WHERE m.user_id = ANY($1::text[])`,
    [ids]
  );
  const byUser = new Map();
  for (const row of r.rows) {
    byUser.set(String(row.user_id), {
      companyId: row.company_id,
      companyName: row.company_name,
      roleKey: row.role_key,
      appFeatures: normalizeAppFeatures(row.app_features),
      customerEnabled: row.customer_enabled === true
    });
  }
  return list.map((u) => ({
    ...u,
    companyMembership: byUser.get(String(u.id || '')) || null
  }));
}

async function attachScopesToUsers(users) {
  const list = Array.isArray(users) ? users : [];
  const map = await readScopesForUserIds(list.map((u) => u.id));
  const withScopes = list.map((u) => {
    const entry = map.get(String(u.id || '')) || { portalScopes: [], psrScopes: [] };
    return {
      ...u,
      portalScopes: enforcePortalScopePolicyForUser(u, entry.portalScopes),
      psrScopes: dedupePsrScopes(entry.psrScopes)
    };
  });
  return attachCompanyToUsers(withScopes);
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

function isUnifiedPortalScopeAllowed(clientIdValue, jobIdValue) {
  const clientId = String(clientIdValue || '').trim().toLowerCase();
  const jobId = String(jobIdValue || '').trim();
  if (!clientId || !jobId) return false;
  if (clientId !== 'portal-users') return true;
  return UNIFIED_PORTAL_SCOPE_ALLOWED_JOB_IDS.has(jobId);
}

function ensureUnifiedPortalScopeRoots(portalRows) {
  const rows = Array.isArray(portalRows) ? portalRows : [];
  const existing = new Set(
    rows
      .map((row) => ({
        clientId: String(row?.client_id || '').trim().toLowerCase(),
        jobId: String(row?.job_id || '').trim()
      }))
      .filter((row) => row.clientId && row.jobId)
      .map((row) => `${row.clientId}|||${row.jobId}`)
  );
  for (const jobId of UNIFIED_PORTAL_SCOPE_ALLOWED_JOB_IDS) {
    const key = `portal-users|||${jobId}`;
    if (existing.has(key)) continue;
    rows.push({
      client_id: 'portal-users',
      job_id: jobId,
      label_client: 'portal-users',
      label_city: 'NOT SET',
      label_jobsite: jobId
    });
  }
  return rows;
}

function buildPermissionsTreesFromRows({ portalRows = [], portalPathRows = [], psrRows = [] }) {
  const pathMap = new Map();
  for (const row of portalPathRows) {
    const clientId = String(row.client_id || '').trim();
    const jobId = String(row.job_id || '').trim();
    if (!clientId || !jobId) continue;
    if (!isUnifiedPortalScopeAllowed(clientId, jobId)) continue;
    const key = `${clientId}|||${jobId}`;
    if (!pathMap.has(key)) pathMap.set(key, new Set());
    const p = String(row.path_prefix || '')
      .replace(/\\/g, '/')
      .replace(/^\/+|\/+$/g, '')
      .replace(/\/+/g, '/');
    pathMap.get(key).add(p || '/');
  }

  const portalMap = new Map();
  for (const row of ensureUnifiedPortalScopeRoots(portalRows)) {
    const clientId = String(row.client_id || '').trim();
    const jobId = String(row.job_id || '').trim();
    if (!clientId || !jobId) continue;
    if (!isUnifiedPortalScopeAllowed(clientId, jobId)) continue;
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

async function readLoginUserFromWasabiSnapshot(submittedUsername, force = false) {
  const snapshot = await loadWasabiLatestStateSnapshot(force);
  if (!snapshot) return null;
  const users = snapshotRows(snapshot, 'users');
  return users.find((row) => snapshotUserMatchesLogin(row, submittedUsername)) || null;
}

/** Persist Wasabi self-signup users in Postgres so login survives snapshot merges/refreshes. */
async function mirrorSelfSignupUserToPostgres(userRow) {
  if (!userRow || userRow.self_signup !== true) return;
  const id = Number(userRow.id);
  if (!Number.isFinite(id) || id <= 0) return;
  const email = String(userRow.email || userRow.username || '')
    .trim()
    .toLowerCase();
  if (!email) return;
  const roles = normalizeRoles(userRow.roles);
  await pool.query(
    `INSERT INTO users (
       id, username, display_name, password, is_admin, account_type, employee_role, roles,
       must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted,
       self_signup, email, first_name, last_name, company, title, phone, email_verified
     ) VALUES (
       $1, $2, $3, $4, false, 'customer', NULL, $5::jsonb, false, NULL, NULL, false,
       true, $6, $7, $8, $9, $10, $11, true
     )
     ON CONFLICT (id) DO UPDATE SET
       username = EXCLUDED.username,
       display_name = EXCLUDED.display_name,
       password = EXCLUDED.password,
       email = EXCLUDED.email,
       first_name = EXCLUDED.first_name,
       last_name = EXCLUDED.last_name,
       company = EXCLUDED.company,
       self_signup = true,
       email_verified = true,
       updated_at = NOW()`,
    [
      id,
      email,
      String(userRow.display_name || userRow.displayName || email),
      String(userRow.password || ''),
      JSON.stringify(roles),
      email,
      String(userRow.first_name || userRow.firstName || ''),
      String(userRow.last_name || userRow.lastName || ''),
      String(userRow.company || ''),
      userRow.title == null ? null : String(userRow.title),
      userRow.phone == null ? null : String(userRow.phone)
    ]
  );
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

async function readRecordsFromWasabiSnapshotForUser(user, req) {
  /** Force S3 read: each Node process caches latest.json; another dyno may have written — stale cache looks like "not saving". */
  const loaded = req
    ? await loadWasabiStateForRequest(req, true)
    : { snapshot: await loadWasabiLatestStateSnapshot(true), isTenant: false };
  const snapshot = loaded.snapshot;
  // Same as record-by-id: do not drop the whole list when snapshot age exceeds threshold — merge with Postgres covers drift.
  if (!snapshot || !snapshot.data) return [];
  const rows = snapshotRows(snapshot, 'planner_records');
  // Scope checks must use persisted planner fields (same as POST / Postgres), not display-only fields
  // from normalizeRecordRow (e.g. jobsite coerced to NOT SET when it matches a segment street).
  const filteredRaw = rows.filter((row) => userCanAccessPsrScope(user, row));
  const filtered = filteredRaw.map((row) => normalizeRecordRow(row));
  const normalizedThenFilterCount = rows
    .map((row) => normalizeRecordRow(row))
    .filter((record) => userCanAccessPsrScope(user, record)).length;
dbgPsrFileLog({
    hypothesisId: 'F',
    location: 'readRecordsFromWasabiSnapshotForUser',
    uid: String(user?.id || ''),
    isAdmin: !!user?.isAdmin,
    plannerStoreWasabiOnly: !!PLANNER_STORE_WASABI_ONLY,
    recordsPrimary: !!WASABI_RECORDS_PRIMARY_ENABLED,
    scopeEntryCount: Array.isArray(user?.psrScopes) ? user.psrScopes.length : 0,
    rawRowCount: rows.length,
    afterFilterCount: filtered.length,
    normalizedThenFilterCount
  });
  return filtered;
}

async function fetchRecordByIdFromWasabiSnapshot(id) {
  const snapshot = await loadWasabiLatestStateSnapshot(true);
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
  let filesToPurge = [];
  try {
    const snapRow = await readDailyReportByIdFromWasabiSnapshot(id);
    if (snapRow && Array.isArray(snapRow.files)) filesToPurge = snapRow.files;
  } catch {
    /* ignore */
  }
  if (!filesToPurge.length && !WASABI_APP_DATA_STORE_WASABI_ONLY) {
    try {
      const r = await pool.query('SELECT files FROM daily_reports WHERE id = $1', [id]);
      if (r.rows[0]) {
        filesToPurge = Array.isArray(r.rows[0].files) ? r.rows[0].files : parseJsonObject(r.rows[0].files, []);
      }
    } catch {
      /* ignore */
    }
  }
  if (adminAttachmentsWasabiConfigured()) {
    await deleteAdminAttachmentKeys(
      wasabiStateClient,
      WASABI_STATE_BUCKET,
      collectAdminAttachmentStorageKeysFromFiles(filesToPurge)
    );
  }

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
  let filesToPurge = [];
  try {
    const snapshot = await loadWasabiLatestStateSnapshot();
    if (snapshot?.data) {
      const rows = snapshotRows(snapshot, 'jobsite_assets');
      const hit = rows.find((row) => String(row.id || '') === String(id || ''));
      if (hit && Array.isArray(hit.files)) filesToPurge = hit.files;
    }
  } catch {
    /* ignore */
  }
  if (!filesToPurge.length && !WASABI_APP_DATA_STORE_WASABI_ONLY) {
    try {
      const r = await pool.query('SELECT files FROM jobsite_assets WHERE id = $1', [id]);
      if (r.rows[0]) {
        filesToPurge = Array.isArray(r.rows[0].files) ? r.rows[0].files : parseJsonObject(r.rows[0].files, []);
      }
    } catch {
      /* ignore */
    }
  }
  if (adminAttachmentsWasabiConfigured()) {
    await deleteAdminAttachmentKeys(
      wasabiStateClient,
      WASABI_STATE_BUCKET,
      collectAdminAttachmentStorageKeysFromFiles(filesToPurge)
    );
  }

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
  const target = String(client || '').toLowerCase();
  const keysToDelete = [];
  try {
    const snapshot = await loadWasabiLatestStateSnapshot();
    if (snapshot?.data) {
      for (const row of snapshotRows(snapshot, 'jobsite_assets')) {
        if (String(row.client || '').toLowerCase() !== target) continue;
        keysToDelete.push(...collectAdminAttachmentStorageKeysFromFiles(row.files));
      }
    }
  } catch {
    /* ignore */
  }
  if (!WASABI_APP_DATA_STORE_WASABI_ONLY) {
    try {
      const r = await pool.query('SELECT files FROM jobsite_assets WHERE LOWER(client) = $1', [target]);
      for (const row of r.rows) {
        const files = Array.isArray(row.files) ? row.files : parseJsonObject(row.files, []);
        keysToDelete.push(...collectAdminAttachmentStorageKeysFromFiles(files));
      }
    } catch {
      /* ignore */
    }
  }
  if (adminAttachmentsWasabiConfigured()) {
    await deleteAdminAttachmentKeys(wasabiStateClient, WASABI_STATE_BUCKET, keysToDelete);
  }

  let deletedCount = 0;
  const wrote = await tryWasabiStateWrite('delete-jobsite-assets-by-client', async (data) => {
    const rows = ensureSnapshotTable(data, 'jobsite_assets');
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

async function readJobsiteAssetsFromWasabiSnapshotForUser(user, req) {
  const tenantScope = req ? await resolveTenantWasabiStateScope(pool, req) : null;
  if (isTenantBoundUser(user) && !tenantScope) return [];
  const snapshot = tenantScope
    ? await loadTenantWasabiStateSnapshot(tenantScope, false)
    : await loadWasabiLatestStateSnapshot();
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
  const snapshot = await loadWasabiLatestStateSnapshot(true);
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

function dbgPsrFileLog(payload) {
  try {
    fs.appendFileSync(
      path.join(__dirname, 'debug-2228ee.log'),
      `${JSON.stringify({ sessionId: '2228ee', timestamp: Date.now(), ...payload })}\n`
    );
  } catch {
    // ignore disk errors (read-only deploy dir, etc.)
  }
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

function sanitizeDb3ImportedObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    const key = String(k || '')
      .trim()
      .slice(0, 120);
    if (!key || /^__proto__$/i.test(key)) continue;
    if (v == null) continue;
    const str = typeof v === 'number' && Number.isFinite(v) ? String(v) : String(v).trim();
    if (!str) continue;
    out[key.toUpperCase()] = str.slice(0, 4000);
  }
  return Object.keys(out).length ? out : null;
}

/** Snapshot fields for “possible double entry” comparison (import queue vs placed segment). */
function sanitizeDuplicateComparison(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c)) return {};
  const pick = (k, max) => cleanString(c[k]).slice(0, max);
  return {
    reference: pick('reference', 240),
    upstream: pick('upstream', 240),
    downstream: pick('downstream', 240),
    dia: pick('dia', 120),
    material: pick('material', 120),
    shape: pick('shape', 120),
    length: pick('length', 80),
    street: pick('street', 400),
    latestStatus: pick('latestStatus', 120),
    latestNotes: pick('latestNotes', 2000),
    recordedDate: pick('recordedDate', 32),
    savedBy: pick('savedBy', 200)
  };
}

function sanitizeDb3DuplicateOf(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const recordId = cleanString(raw.recordId).slice(0, 128);
  const segmentId = cleanString(raw.segmentId).slice(0, 128);
  if (!recordId || !segmentId) return null;
  return {
    recordId,
    segmentId,
    client: cleanString(raw.client).slice(0, 400),
    city: cleanString(raw.city).slice(0, 400),
    jobsite: cleanString(raw.jobsite).slice(0, 400),
    street: cleanString(raw.street).slice(0, 400),
    system: cleanString(raw.system).slice(0, 32),
    comparison: sanitizeDuplicateComparison(raw.comparison)
  };
}

function duplicateComparisonFromSegmentJson(seg) {
  if (!seg || typeof seg !== 'object') return sanitizeDuplicateComparison({});
  const versions = Array.isArray(seg.versions) ? seg.versions : [];
  const last = versions.length ? versions[versions.length - 1] : {};
  return sanitizeDuplicateComparison({
    reference: seg.reference,
    upstream: seg.upstream,
    downstream: seg.downstream,
    dia: seg.dia,
    material: seg.material,
    shape: seg.shape,
    length: seg.length ?? seg.footage,
    street: seg.street,
    latestStatus: statusLabel(last.status),
    latestNotes: last.notes,
    recordedDate: last.recordedDate,
    savedBy: last.savedBy
  });
}

function buildDb3DuplicatePayloadFromPlacedRow(row) {
  const seg = row.seg && typeof row.seg === 'object' ? row.seg : parseJsonObject(row.seg, {});
  return sanitizeDb3DuplicateOf({
    recordId: String(row.rid ?? ''),
    segmentId: String(seg.id ?? ''),
    client: row.client,
    city: row.city,
    jobsite: row.jobsite,
    street: row.street,
    system: row.sys,
    comparison: duplicateComparisonFromSegmentJson(seg)
  });
}

/**
 * For each WinCan OBJ_Key (segment.reference), find a matching segment on planner records in the **same jobsite**
 * (client + city + jobsite; latest `updated_at` wins). Never matches across jobsites.
 * @param {string[]} referenceLowers lowercased trimmed references
 * @param {{ client?: string, city?: string, jobsite?: string }} scope import target jobsite identity
 * @returns {Promise<Map<string, ReturnType<typeof sanitizeDb3DuplicateOf>>>}
 */
async function findPlacedDuplicatePayloadsByReferences(referenceLowers, scope = {}) {
  const map = new Map();
  const uniq = [...new Set((referenceLowers || []).map((s) => String(s || '').trim().toLowerCase()).filter(Boolean))];
  if (!uniq.length) return map;
  const scopeClient = cleanString(scope.client);
  const scopeCity = cleanString(scope.city);
  const scopeJobsite = normalizeJobsiteName(scope.jobsite || 'NOT SET');
  if (!scopeClient || !scopeJobsite || scopeJobsite === 'NOT SET') return map;
  if (typeof pool?.query !== 'function') return map;
  try {
    const { rows: hits } = await pool.query(
      `SELECT rid, client, city, jobsite, street, updated_at, sys, seg FROM (
         SELECT pr.id AS rid, pr.client, pr.city, pr.jobsite, pr.street, pr.updated_at,
                'storm'::text AS sys, seg
         FROM planner_records pr,
         LATERAL jsonb_array_elements(COALESCE(pr.data->'systems'->'storm', '[]'::jsonb)) seg
         WHERE LOWER(BTRIM(pr.client)) = LOWER(BTRIM($1))
           AND LOWER(BTRIM(COALESCE(pr.city, ''))) = LOWER(BTRIM($2))
           AND LOWER(BTRIM(COALESCE(pr.jobsite, ''))) = LOWER(BTRIM($3))
           AND LOWER(BTRIM(COALESCE(seg->>'reference',''))) = ANY($4::text[])
       UNION ALL
         SELECT pr.id, pr.client, pr.city, pr.jobsite, pr.street, pr.updated_at,
                'sanitary'::text, seg
         FROM planner_records pr,
         LATERAL jsonb_array_elements(COALESCE(pr.data->'systems'->'sanitary', '[]'::jsonb)) seg
         WHERE LOWER(BTRIM(pr.client)) = LOWER(BTRIM($1))
           AND LOWER(BTRIM(COALESCE(pr.city, ''))) = LOWER(BTRIM($2))
           AND LOWER(BTRIM(COALESCE(pr.jobsite, ''))) = LOWER(BTRIM($3))
           AND LOWER(BTRIM(COALESCE(seg->>'reference',''))) = ANY($4::text[])
       ) q`,
      [scopeClient, scopeCity, scopeJobsite, uniq]
    );
    for (const row of hits) {
      const seg = row.seg && typeof row.seg === 'object' ? row.seg : parseJsonObject(row.seg, {});
      const refKey = String(seg.reference || '').trim().toLowerCase();
      if (!refKey) continue;
      const ts = Date.parse(row.updated_at) || 0;
      const prev = map.get(refKey);
      if (prev && prev._ts >= ts) continue;
      const dup = buildDb3DuplicatePayloadFromPlacedRow(row);
      if (dup) map.set(refKey, { _ts: ts, dup });
    }
  } catch (error) {
    console.error('findPlacedDuplicatePayloadsByReferences:', error?.message || error);
  }
  const out = new Map();
  for (const [k, v] of map) out.set(k, v.dup);
  return out;
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
    shape: upperCleanString(raw.shape),
    length: cleanString(raw.length ?? raw.footage),
    footage: cleanString(raw.footage ?? raw.length),
    street: upperCleanString(raw.street),
    system: cleanString(raw.system),
    versions,
    selectedVersionId: raw.selectedVersionId || versions[versions.length - 1].id,
    db3Imported: sanitizeDb3ImportedObject(raw.db3Imported),
    db3DuplicateOf: sanitizeDb3DuplicateOf(raw.db3DuplicateOf),
    db3DedupeKey: cleanString(raw.db3DedupeKey).slice(0, 240),
    db3RowHash: cleanString(raw.db3RowHash).slice(0, 120).toLowerCase(),
    linkedPortalDb3FileId: cleanString(raw.linkedPortalDb3FileId).slice(0, 128),
    linkedPortalDb3FolderPath: cleanString(raw.linkedPortalDb3FolderPath).slice(0, 800),
    linkedPortalDb3ClientId: cleanString(raw.linkedPortalDb3ClientId).slice(0, 128),
    linkedPortalDb3JobId: cleanString(raw.linkedPortalDb3JobId).slice(0, 128)
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

/** PipeSync planner client code for WinCan imports staged under “Imported — ready to sort”. */
const PSR_IMPORT_QUEUE_CLIENT = '__HP_IMPORT_QUEUE__';

function resolveWincanImportScope(body, rows) {
  const targetRecordId = cleanString(body?.targetRecordId || body?.recordId || '');
  let targetClient = cleanString(body?.targetClient);
  let targetCity = cleanString(body?.targetCity);
  if (!targetClient) targetClient = PSR_IMPORT_QUEUE_CLIENT;
  if (!targetCity) targetCity = '';
  let targetJobsite = normalizeJobsiteName(body?.targetJobsite || 'NOT SET');
  const projectRow = Array.isArray(rows) ? rows.find((r) => r && cleanString(r.project)) : null;
  const projectName = projectRow ? cleanString(projectRow.project) : '';
  if ((!targetJobsite || targetJobsite === 'NOT SET') && projectName) {
    targetJobsite = normalizeJobsiteName(projectName);
  }
  const targetSystem = cleanString(body?.targetSystem || 'storm').toLowerCase() === 'sanitary' ? 'sanitary' : 'storm';
  return { targetClient, targetCity, targetJobsite, targetSystem, targetRecordId };
}

function db3NormalizedValue(value) {
  return String(value == null ? '' : value)
    .trim()
    .replace(/\s+/g, ' ')
    .toUpperCase();
}

function db3StableKeyFromImported(imported) {
  if (!imported || typeof imported !== 'object' || Array.isArray(imported)) return '';
  const pick = (...keys) => {
    for (const key of keys) {
      const raw = imported[key];
      const v = db3NormalizedValue(raw);
      if (v) return v;
    }
    return '';
  };
  const guid = pick('OBJ_GUID', 'SECTION_GUID', 'GUID');
  if (guid) return `GUID:${guid}`;
  const objPk = pick('OBJ_PK', 'OBJ_ID', 'SECTION_ID');
  if (objPk) return `OBJ:${objPk}`;
  return '';
}

function db3RowFingerprintHash(row) {
  const importedObj =
    row && row.db3Imported && typeof row.db3Imported === 'object' && !Array.isArray(row.db3Imported) ? row.db3Imported : {};
  const importedPairs = Object.entries(importedObj)
    .map(([k, v]) => `${db3NormalizedValue(k)}=${db3NormalizedValue(v)}`)
    .filter((line) => line && !line.endsWith('='))
    .sort();
  const materialized = [
    db3NormalizedValue(row?.project),
    db3NormalizedValue(row?.reference),
    db3NormalizedValue(row?.city),
    db3NormalizedValue(row?.street),
    db3NormalizedValue(row?.upstream),
    db3NormalizedValue(row?.downstream),
    db3NormalizedValue(row?.material),
    db3NormalizedValue(row?.shape),
    db3NormalizedValue(row?.dia),
    db3NormalizedValue(row?.length),
    ...importedPairs
  ].join('|');
  return crypto.createHash('sha256').update(materialized).digest('hex');
}

function buildDb3DeterministicIdentity(row) {
  const ref = db3NormalizedValue(row?.reference);
  if (ref) return { dedupeKey: `REF:${ref}`, dedupeHash: db3RowFingerprintHash(row) };
  const importedStable = db3StableKeyFromImported(row?.db3Imported);
  if (importedStable) return { dedupeKey: importedStable, dedupeHash: db3RowFingerprintHash(row) };
  return { dedupeKey: '', dedupeHash: db3RowFingerprintHash(row) };
}

function collectRecordDb3IdentitySets(record, targetSystem) {
  const systemRows = record && record.systems && Array.isArray(record.systems[targetSystem]) ? record.systems[targetSystem] : [];
  const dedupeKeys = new Set();
  const dedupeHashes = new Set();
  const references = new Set();
  for (const seg of systemRows) {
    const ref = db3NormalizedValue(seg?.reference);
    if (ref) {
      references.add(ref.toLowerCase());
      dedupeKeys.add(`REF:${ref}`);
    }
    const key = db3NormalizedValue(seg?.db3DedupeKey);
    if (key) dedupeKeys.add(key);
    const hash = String(seg?.db3RowHash || '').trim().toLowerCase();
    if (hash) dedupeHashes.add(hash);
  }
  return { dedupeKeys, dedupeHashes, references };
}

function ensureImportTargetSystemBranch(record, targetSystem) {
  if (!record || typeof record !== 'object') return;
  const system = targetSystem === 'sanitary' ? 'sanitary' : 'storm';
  if (!record.systems || typeof record.systems !== 'object') record.systems = { storm: [], sanitary: [] };
  if (!Array.isArray(record.systems.storm)) record.systems.storm = [];
  if (!Array.isArray(record.systems.sanitary)) record.systems.sanitary = [];
  const nextBranches = {
    ...(record.systemBranches && typeof record.systemBranches === 'object' ? record.systemBranches : {}),
    [system]: true
  };
  record.systemBranches = coerceSystemBranchesForStorage(nextBranches, record.systems);
}

/** Persisted under planner record `data.systemBranches` — which top-level folders show under a jobsite. */
function coerceSystemBranchesForStorage(branches, systems) {
  const st = (systems?.storm || []).length > 0;
  const sa = (systems?.sanitary || []).length > 0;
  const b = branches && typeof branches === 'object' ? branches : {};
  let storm = b.storm !== false;
  let sanitary = b.sanitary === true;
  if (st) storm = true;
  if (sa) sanitary = true;
  if (!storm && !sanitary && !st && !sa) storm = true;
  return { storm, sanitary };
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

  const systemBranches = coerceSystemBranchesForStorage(data.systemBranches, systems);

  const psrScopeClient = upperCleanString(row.client || data.client);
  const psrScopeCity = upperCleanString(row.city || data.city);
  const psrScopeJobsite = normalizeJobsiteName(rawJobsite, rawStreet);

  return {
    id: String(row.id),
    record_date: String(row.record_date || '').slice(0, 10),
    client: psrScopeClient,
    city: psrScopeCity,
    street: upperCleanString(fallbackStreet),
    jobsite: looksLikeStreetOnly ? 'NOT SET' : psrScopeJobsite,
    psrScopeClient,
    psrScopeCity,
    psrScopeJobsite,
    status: cleanString(row.status || data.status),
    saved_by: cleanString(row.saved_by || data.saved_by),
    systems,
    systemBranches,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function serializeRecordData(record) {
  const systems = {
    storm: (record.systems?.storm || []).map((segment) => normalizeSegment(segment, record.saved_by || 'System')),
    sanitary: (record.systems?.sanitary || []).map((segment) => normalizeSegment(segment, record.saved_by || 'System'))
  };
  return {
    systems,
    systemBranches: coerceSystemBranchesForStorage(record.systemBranches || {}, systems)
  };
}

/** Jobsite persisted to Wasabi/Postgres must use the scope key (psrScopeJobsite), not display jobsite coerced to NOT SET. */
function persistedPlannerJobsiteForWrite(record) {
  const street = upperCleanString(record?.street);
  const display = cleanString(record?.jobsite ?? '');
  const scope = cleanString(record?.psrScopeJobsite ?? record?.authJobsiteForPsrScope ?? '');
  const displayIsUnset = !display || display.toUpperCase() === 'NOT SET';
  if (scope && displayIsUnset) {
    return normalizeJobsiteName(scope, street);
  }
  return normalizeJobsiteName(record?.jobsite, street);
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

async function readFreshUserFromPostgresById(userId, options = {}) {
  const id = String(userId || '').trim();
  if (!id) return null;
  if (options.refreshSaasAccess !== false) {
    await refreshSaasTenantOwnerAccess(pool, id);
  }
  const ownerCtx = await getSaasOwnerSessionContext(pool, id);
  const result = await pool.query(
    `SELECT id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id,
            portal_permissions_access, portal_files_access_granted, autosync_master_granted, self_signup, email, first_name, last_name, company, title, phone, email_verified,
            product_tutorials_seen, portal_workspace_layouts, user_prefs
     FROM users
     WHERE CAST(id AS text) = $1
     LIMIT 1`,
    [id]
  );
  if (!result.rows.length) return null;
  return attachScopesToUser(
    normalizeUser(result.rows[0], {
      tenantPurchaser: ownerCtx.tenantPurchaser,
      saasTenantOwner: ownerCtx.saasTenantOwner,
      subscriptionStatus: ownerCtx.subscriptionStatus
    })
  );
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
            u.is_admin, u.account_type, u.employee_role, u.roles, u.must_change_password, u.portal_files_client_id, u.portal_files_job_id,
            u.portal_permissions_access, u.portal_files_access_granted, u.autosync_master_granted, u.self_signup, u.email, u.first_name, u.last_name, u.company, u.title, u.phone, u.email_verified,
            u.product_tutorials_seen, u.portal_workspace_layouts, u.user_prefs
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
    user: await readFreshUserFromPostgresById(row.id, { refreshSaasAccess: false }),
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
    const requestHost = requestHostFromReq(req);
    const envAccess = await assertAuthenticatedEnvironmentAccess(pool, user, requestHost);
    if (!envAccess.allowed) {
      console.warn(
        `[auth] environment reject ${req.method || 'GET'} ${req.originalUrl || req.url || ''}: user=${String(user.id || '')} host=${requestHost}`
      );
      return res.status(403).json({
        success: false,
        error: envAccess.error,
        code: envAccess.code || 'ENVIRONMENT_ACCESS_DENIED'
      });
    }
    req.user = await enrichUserScopesForTenantRequest(user, req);
    req.sessionToken = token;
    return next();
  } catch (error) {
    console.error('AUTH ERROR:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
}

function requireAdmin(req, res, next) {
  if (!isAdminUser(req.user)) {
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

function requestHostFromReq(req) {
  return String(req.headers['x-forwarded-host'] || req.headers.host || '').trim();
}

async function syncTenantUserMirrors(scope, userRow) {
  if (!scope || scope.mode !== 'tenant' || !userRow) return;
  const slug = scope.tenantSlug;
  if (slug) {
    try {
      await upsertTenantAuthUserFromRow(slug, userRow);
    } catch (error) {
      console.warn('[tenant-sync] auth snapshot failed:', error?.message || error);
    }
  }
  if (scope.postgresSchema) {
    try {
      await mirrorUserToTenantLoginSchema(pool, scope.postgresSchema, userRow);
    } catch (error) {
      console.warn('[tenant-sync] postgres mirror failed:', error?.message || error);
    }
  }
}

/** Platform admin panel or SaaS tenant owner managing users inside their virtualbox only. */
async function requireAdminPanelOrTenantUserManagement(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    if (canAccessAdminPanel(req.user)) {
      req.tenantScope = { mode: 'platform' };
      return next();
    }
    const scope = await resolveActorTenantScope(pool, req.user, { requestHost: requestHostFromReq(req) });
    req.tenantScope = scope;
    if (scope.mode === 'tenant' && userCanManageTenantUsers(req.user, scope)) {
      return next();
    }
    return res.status(403).json({ success: false, error: 'Admin access required' });
  } catch (error) {
    console.error('TENANT ADMIN AUTH ERROR:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
}

function userRoleEnabled(user, roleKey) {
  if (!user || !roleKey) return false;
  if (isAdminUser(user)) return true;
  const roles = normalizeRoles(user.roles);
  return roles[roleKey] === true;
}

function requireAnyRole(roleKeys, message = 'Access denied for this feature') {
  const keys = Array.isArray(roleKeys) ? roleKeys.filter(Boolean) : [];
  return function requireAnyRoleMiddleware(req, res, next) {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    if (isAdminUser(req.user)) return next();
    const allowed = keys.some((k) => userRoleEnabled(req.user, k));
    if (!allowed) {
      return res.status(403).json({ success: false, error: message });
    }
    return next();
  };
}

function customerHasAssignedPsrScopes(user) {
  return normalizeAccountType(user?.accountType) === ACCOUNT_TYPES.CUSTOMER && Array.isArray(user?.psrScopes) && user.psrScopes.length > 0;
}
const requirePlannerAccess = (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, error: 'Authentication required' });
  if (isAdminUser(req.user)) return next();
  if (customerHasAssignedPsrScopes(req.user)) return next();
  const allowed = ['psrPlanner', 'psrViewer', 'psrDataEntry', 'camera', 'vac', 'simpleVac', 'pricingView', 'footageView'].some((k) =>
    userRoleEnabled(req.user, k)
  );
  if (allowed) return next();
  return res.status(403).json({ success: false, error: 'Planner access is not enabled for this account' });
};
const requirePsrViewerAccess = (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, error: 'Authentication required' });
  if (isAdminUser(req.user)) return next();
  if (customerHasAssignedPsrScopes(req.user)) return next();
  const allowed = ['psrViewer', 'psrDataEntry', 'psrPlanner', 'camera', 'vac', 'simpleVac', 'pricingView', 'footageView'].some((k) =>
    userRoleEnabled(req.user, k)
  );
  if (allowed) return next();
  return res.status(403).json({ success: false, error: 'PSR viewer access is not enabled for this account' });
};
const requirePsrDataEntryAccess = (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, error: 'Authentication required' });
  if (isAdminUser(req.user)) return next();
  if (customerHasAssignedPsrScopes(req.user)) return next();
  const allowed = ['psrDataEntry', 'psrPlanner', 'camera', 'vac', 'simpleVac'].some((k) => userRoleEnabled(req.user, k));
  if (allowed) return next();
  return res.status(403).json({ success: false, error: 'PSR data entry access is not enabled for this account' });
};
const requireDataAutoSyncEmployeeAccess = requireAnyRole(
  ['dataAutoSyncEmployee'],
  'DataAutoSync employee access is not enabled for this account'
);

/** Same users who can use portal Data Auto Sync (not only the dataAutoSyncEmployee role bit). */
function requireDataAutoSyncDesktopHeartbeatAccess(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  const u = req.user;
  const roles = normalizeRoles(u.roles);
  if (roles.dataAutoSyncEmployee === true) return next();
  if (u.dataAutoSyncEmployee === true) return next();
  if (canManagePortalExtras(u)) return next();
  if (u.portalFilesAccessGranted === true) return next();
  if (u.autosyncMasterGranted === true) return next();
  if (u.isAdmin === true) return next();
  return res.status(403).json({
    success: false,
    error:
      'Desktop status requires Data Auto Sync access (dataAutoSyncEmployee, portal admin, portalFilesAccessGranted, autosyncMasterGranted, or administrator).'
  });
}
const requirePricingAccess = requireAnyRole(
  ['pricingView'],
  'Pricing access is not enabled for this account'
);
const requireFootageAccess = requireAnyRole(
  ['footageView'],
  'Footage access is not enabled for this account'
);

function userCanAccessPsrScope(user, scope) {
  if (userHasGlobalPsrBypass(user)) return true;
  const scopes = dedupePsrScopes(user?.psrScopes || []);
  if (!scopes.length) return false;
  const data =
    scope && scope.data && typeof scope.data === 'object' && !Array.isArray(scope.data)
      ? scope.data
      : parseJsonObject(scope?.data, {});
  const recId = cleanString(scope?.id || scope?.recordId || '');
  /** Persisted planner row triple (matches POST / SQL). NOT display jobsite (e.g. segment UI may coerce jobsite to NOT SET). */
  const client = upperCleanString(
    scope?.psrScopeClient ?? scope?.authClientForPsrScope ?? scope?.client ?? data.client
  );
  const city = upperCleanString(scope?.psrScopeCity ?? scope?.authCityForPsrScope ?? scope?.city ?? data.city);
  const persistedJobsite = cleanString(scope?.psrScopeJobsite ?? scope?.authJobsiteForPsrScope ?? '');
  const jobsite = persistedJobsite
    ? persistedJobsite
    : normalizeJobsiteName(scope?.jobsite || data.jobsite, scope?.street || data.street);
  const tripleReady = !!(client && city && jobsite);
  return scopes.some((entry) => {
    const eRid = cleanString(entry.recordId || '');
    const triple =
      tripleReady &&
      String(entry.client || '').toLowerCase() === client.toLowerCase() &&
      String(entry.city || '').toLowerCase() === city.toLowerCase() &&
      String(entry.jobsite || '').toLowerCase() === jobsite.toLowerCase();
    if (eRid) {
      return (recId && eRid === recId) || triple;
    }
    return triple;
  });
}

function buildPsrScopeWhere(user, alias = '') {
  if (userHasGlobalPsrBypass(user)) return { clause: 'TRUE', params: [] };
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

/** SaaS tenant workspace users with planner/data-entry roles may create jobs in their tenant snapshot. */
function userHasTenantPsrWorkspaceAccess(user) {
  if (!isTenantBoundUser(user)) return false;
  return ['psrDataEntry', 'psrPlanner', 'psrViewer'].some((k) => userRoleEnabled(user, k));
}

function userCanCreatePsrRecord(user, record) {
  if (userHasGlobalPsrBypass(user)) return true;
  if (userCanAccessPsrScope(user, record)) return true;
  if (userHasTenantPsrWorkspaceAccess(user)) return true;
  return false;
}

async function enrichUserScopesForTenantRequest(user, req) {
  if (!user?.id || !req || !isTenantBoundUser(user)) return user;
  try {
    const { snapshot } = await loadWasabiStateForRequest({ user, headers: req.headers }, false);
    if (!snapshot?.data) return user;
    const uid = String(user.id || '');
    const tenantScopes = snapshotRows(snapshot, 'user_psr_scopes')
      .filter((row) => String(row.user_id || '') === uid)
      .map((row) => ({
        recordId: cleanString(row.psr_record_id || '') || null,
        client: String(row.client || ''),
        city: String(row.city || ''),
        jobsite: String(row.jobsite || '')
      }));
    if (!tenantScopes.length) return user;
    return {
      ...user,
      psrScopes: dedupePsrScopes([...(user.psrScopes || []), ...tenantScopes])
    };
  } catch {
    return user;
  }
}

function requireMike(req, res, next) {
  if (!isMikeStricklandUser(req.user)) {
    return res.status(403).json({ success: false, error: 'Mike-only importer access' });
  }
  return next();
}

function isMikeStricklandUser(user) {
  return looksLikeMike(user);
}

function isVacLineOperator(user) {
  const model = deriveAccountModel(user || {});
  if (model.accountType !== ACCOUNT_TYPES.EMPLOYEE) return false;
  return model.employeeRole === EMPLOYEE_ROLES.VAC_OPERATOR || model.employeeRole === EMPLOYEE_ROLES.SIMPLE_VAC;
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

function sqliteTableList(db) {
  try {
    const r = db.exec("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    return (r[0]?.values || []).map((row) => String(row[0] || '')).filter(Boolean);
  } catch {
    return [];
  }
}

function sqliteObjectType(db, objectName) {
  const target = cleanString(objectName);
  if (!target) return '';
  let stmt;
  try {
    stmt = db.prepare("SELECT type FROM sqlite_master WHERE lower(name) = lower(?) LIMIT 1");
    stmt.bind([target]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      return cleanString(row.type).toLowerCase();
    }
  } catch {
    return '';
  } finally {
    try {
      stmt?.free();
    } catch {
      /* ignore */
    }
  }
  return '';
}

function pickSqliteTable(actualNames, ...wanted) {
  const set = new Set(actualNames);
  const byLower = new Map(actualNames.map((n) => [n.toLowerCase(), n]));
  for (const w of wanted) {
    if (set.has(w)) return w;
    const hit = byLower.get(String(w).toLowerCase());
    if (hit) return hit;
  }
  return '';
}

function sqlIdentQuoted(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

/**
 * When SECTION is missing, infer common mis-uploads (WinCan catalog / META DB vs pipe project DB).
 * @param {string[]} tables
 */
function explainMissingSectionDb3(tables) {
  const lower = new Set(tables.map((t) => String(t).toLowerCase()));
  const hasMeta = [...lower].some((t) => t.startsWith('meta'));
  const hasDirectory = lower.has('directory');
  const hasRehab = lower.has('rehabilitation');
  const hasEquipment = lower.has('equipment');
  const hasWorkgroup = lower.has('workgroup');
  const looksCatalogOrSupport =
    (hasMeta && (hasDirectory || lower.has('metaclass') || lower.has('metaobj'))) ||
    (hasEquipment && hasRehab && !lower.has('node')) ||
    (hasWorkgroup && hasEquipment && !lower.has('node'));

  if (looksCatalogOrSupport) {
    return (
      ' This file looks like a WinCan catalog, workgroup, equipment, or support database (META*, DIRECTORY, REHABILITATION, etc.) — not a pipe inspection project. ' +
      'Use the WinCan **project** .db3 for the jobsite run (the database that opens with your pipe sections; it must contain SECTION and NODE tables). ' +
      'That file is usually beside your inspection videos in the job folder, not the global WinCan catalog database.'
    );
  }
  return '';
}

/** WinCan SECTION columns already surfaced on the main import row — omit from `db3Imported` to avoid duplication. */
const DB3_SECTION_CORE_PHYSICAL_COLS = new Set(
  [
    'OBJ_KEY',
    'OBJ_LENGTH',
    'OBJ_CITY',
    'OBJ_STREET',
    'OBJ_FROMNODE_REF',
    'OBJ_TONODE_REF',
    'OBJ_MATERIAL',
    'OBJ_SHAPE',
    'OBJ_SIZE1',
    'OBJ_SIZE2',
    'OBJ_PK',
    'OBJ_ID',
    'OBJ_GUID'
  ].map((s) => s.toUpperCase())
);

const DB3_INSPECTOR_HINT_KEYS = new Set(
  [
    'INS_OPERATOR_REF',
    'INS_Operator_REF',
    'OP_KEY',
    'OP_Key',
    'OBJ_SURVEYEDBY',
    'OBJ_SURVEYOR',
    'OBJ_SURVEYORNAME',
    'OBJ_INSPECTOR',
    'OBJ_INSPECTORNAME',
    'OBJ_INSPECTIONBY',
    'OBJ_INSPECTEDBY',
    'INS_INSPECTOR',
    'INS_INSPECTORNAME',
    'INS_INSPECTOR_NAME',
    'INS_INSPECTIONBY',
    'INS_INSPECTEDBY',
    'INS_SURVEYOR',
    'INS_SURVEYORNAME',
    'INS_OPERATOR',
    'INS_OPERATORNAME',
    'INS_OPERATOR_NAME',
    'INS_TECHNICIAN',
    'INS_TECHNICIANNAME',
    'INS_CREWLEADER',
    'INS_CREW_LEADER',
    'INS_FIELDLEAD',
    'INS_FIELD_LEAD',
    'INS_COMPLETEDBY'
  ].map((k) => String(k).toUpperCase())
);

const DB3_INSPECTOR_ALIAS_MAP = new Map([
  ['thomas', 'Mike Thomas'],
  ['m thomas', 'Mike Thomas'],
  ['mike thomas', 'Mike Thomas'],
  ['mike s', 'Mike Strickland'],
  ['m strickland', 'Mike Strickland'],
  ['strickland', 'Mike Strickland'],
  ['mike strickland', 'Mike Strickland'],
  ['alec beck', 'Alec Beck']
]);

/** Guard against extremely wide SECINSP schemas generating huge OR predicates in sql.js. */
const DB3_SECINSP_MAX_FK_COLUMNS = 32;
const DB3_SECINSP_MAX_KEY_COLUMNS = 24;
const DB3_SECINSP_SPLIT_QUERY_LIMIT = 6;
const DB3_SECINSP_DIAG_ONCE = new Set();
const DB3_PREVIEW_STRATEGY_VERSION = 'secinsp-split-only-v2';

function db3InspectorAliasKey(value) {
  return String(value == null ? '' : value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function db3InspectorDisplay(value) {
  return String(value == null ? '' : value)
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function db3ValueLooksLikeOperatorDisplayName(value) {
  const s = cleanString(value);
  if (!s) return false;
  if (/^\d+$/.test(s)) return false;
  return /[A-Za-z]/.test(s);
}

/**
 * Resolve WinCan Operator display name from SECINSP FK (INS_Operator_REF / OP_Key → WCMETA.OPERATOR.OP_PK).
 * @param {any} db
 * @param {string[]} tables
 * @param {Record<string, string>} imported
 */
function enrichDb3ImportedOperatorFromWcmeta(db, tables, imported) {
  const out = imported && typeof imported === 'object' ? { ...imported } : {};
  const existing = cleanString(out.HP_INSPECTOR_DISPLAY) || cleanString(out.HP_INSPECTOR_RAW);
  if (db3ValueLooksLikeOperatorDisplayName(existing)) return out;

  const operatorTable =
    pickSqliteTable(tables, 'OPERATOR') ||
    tables.find((t) => String(t || '').toUpperCase() === 'WCMETA.OPERATOR') ||
    tables.find((t) => /OPERATOR$/i.test(String(t || '')) && !/SECINSP|SECTION/i.test(String(t || ''))) ||
    '';
  if (!operatorTable || sqliteObjectType(db, operatorTable) === 'view') return out;

  const refKeys = ['INS_Operator_REF', 'INS_OPERATOR_REF', 'OP_Key', 'OP_KEY', 'INS_OPERATOR'];
  let bindVal = '';
  for (const k of refKeys) {
    const ku = String(k).toUpperCase();
    const hit = Object.keys(out).find((key) => String(key).toUpperCase() === ku);
    const v = hit ? out[hit] : '';
    const s = typeof v === 'number' && Number.isFinite(v) ? String(v) : cleanString(v);
    if (s) {
      bindVal = s;
      break;
    }
  }
  if (!bindVal) return out;

  const cols = sqlitePragmaColumns(db, operatorTable);
  if (!cols.length) return out;
  const colNames = cols.map((c) => c.name);
  const colSet = new Set(colNames.map((n) => String(n).toUpperCase()));
  const pkCol =
    colNames.find((n) => String(n).toUpperCase() === 'OP_PK') ||
    colNames.find((n) => String(n).toUpperCase() === 'OPERATOR_PK') ||
    colNames.find((n) => /_PK$/i.test(String(n))) ||
    'OP_PK';
  const nameCandidates = ['OP_Name', 'OP_NAME', 'OP_Key', 'OP_KEY', 'NAME', 'OPERATOR_NAME', 'OPERATOR'];
  let nameCol = '';
  for (const want of nameCandidates) {
    const hit = colNames.find((n) => String(n).toUpperCase() === want.toUpperCase());
    if (hit) {
      nameCol = hit;
      break;
    }
  }
  if (!nameCol) {
    nameCol = colNames.find((n) => /NAME|LABEL|DESCRIPTION/i.test(String(n))) || '';
  }
  if (!nameCol || !colSet.has(String(pkCol).toUpperCase())) return out;

  const OT = sqlIdentQuoted(operatorTable);
  let stmt;
  try {
    stmt = db.prepare(
      `SELECT ${sqlIdentQuoted(nameCol)} AS operator_name FROM ${OT} WHERE ${sqlIdentQuoted(pkCol)} = ? LIMIT 1`
    );
    stmt.bind([bindVal]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      const resolved = db3InspectorDisplay(row.operator_name);
      if (db3ValueLooksLikeOperatorDisplayName(resolved)) {
        out.HP_INSPECTOR_RAW = resolved;
        out.HP_INSPECTOR_DISPLAY = resolved;
        out.HP_INSPECTOR_KEY = db3InspectorAliasKey(resolved);
        out.OPERATOR_NAME = resolved.slice(0, 4000);
      }
    }
  } catch {
    /* non-fatal */
  } finally {
    try {
      stmt?.free();
    } catch {
      /* ignore */
    }
  }
  return out;
}

function db3InspectorIdentityFromImported(imported) {
  const imp = imported && typeof imported === 'object' && !Array.isArray(imported) ? imported : {};
  const read = (k) => {
    const v = imp[k];
    return typeof v === 'number' && Number.isFinite(v) ? String(v) : cleanString(v);
  };
  let raw = read('HP_INSPECTOR_RAW') || read('HP_EDIT_INSPECTED_BY') || read('HP_INSPECTOR_DISPLAY') || read('OPERATOR_NAME');
  if (!raw) {
    for (const [k, v] of Object.entries(imp)) {
      const ku = String(k || '').toUpperCase();
      const vv = typeof v === 'number' && Number.isFinite(v) ? String(v) : cleanString(v);
      if (!vv) continue;
      if (DB3_INSPECTOR_HINT_KEYS.has(ku)) {
        if ((ku === 'INS_OPERATOR_REF' || ku === 'INS_Operator_REF'.toUpperCase() || ku === 'OP_KEY') && !db3ValueLooksLikeOperatorDisplayName(vv)) {
          continue;
        }
        raw = vv;
        break;
      }
    }
  }
  if (!raw) {
    for (const [k, v] of Object.entries(imp)) {
      const ku = String(k || '').toUpperCase();
      const vv = typeof v === 'number' && Number.isFinite(v) ? String(v) : cleanString(v);
      if (!vv) continue;
      if (/^INS_(PK|ID)$/.test(ku)) continue;
      if (/INSPECT|SURVEY|OPERATOR|TECHNICIAN|CREW|FIELD.?LEAD|COMPLETEDBY/.test(ku)) {
        raw = vv;
        break;
      }
    }
  }
  raw = db3InspectorDisplay(raw);
  if (!raw) return null;
  const alias = db3InspectorAliasKey(raw);
  const canonical = db3InspectorDisplay(DB3_INSPECTOR_ALIAS_MAP.get(alias) || raw);
  const key = db3InspectorAliasKey(canonical) || alias;
  return { raw, canonical, key };
}

/**
 * @param {any} db sql.js Database
 * @param {string} tableName
 * @returns {{ name: string, type: string }[]}
 */
function sqlitePragmaColumns(db, tableName) {
  const out = [];
  let stmt;
  try {
    stmt = db.prepare(`PRAGMA table_info(${sqlIdentQuoted(tableName)})`);
    while (stmt.step()) {
      const o = stmt.getAsObject();
      const name = String(o.name || '');
      const type = String(o.type || '').toUpperCase();
      if (!name) continue;
      if (type.includes('BLOB')) continue;
      out.push({ name, type });
    }
  } catch {
    return [];
  } finally {
    try {
      stmt?.free();
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Extra SECTION columns as SQL select list + parallel original column names for alias decode.
 * @param {any} db sql.js Database
 * @param {string} sectionTable
 * @returns {{ sql: string, aliasNames: string[] }}
 */
function buildDb3SectionExtraSelect(db, sectionTable) {
  const cols = sqlitePragmaColumns(db, sectionTable);
  const parts = [];
  /** @type {string[]} */
  const aliasNames = [];
  for (const { name } of cols) {
    if (DB3_SECTION_CORE_PHYSICAL_COLS.has(name.toUpperCase())) continue;
    const idx = aliasNames.length;
    parts.push(`s.${sqlIdentQuoted(name)} AS ${sqlIdentQuoted(`__db3_${idx}`)}`);
    aliasNames.push(name);
  }
  if (!parts.length) return { sql: '', aliasNames: [] };
  return { sql: parts.join(', '), aliasNames };
}

/**
 * @param {Record<string, unknown>} raw
 * @param {string[]} aliasNames
 * @returns {Record<string, string>}
 */
function extractDb3ImportedFromRow(raw, aliasNames) {
  if (!raw || !Array.isArray(aliasNames) || !aliasNames.length) return {};
  const out = {};
  const keys = Object.keys(raw);
  for (let i = 0; i < aliasNames.length; i++) {
    const want = `__db3_${i}`;
    const hit = keys.find((k) => k.toLowerCase() === want.toLowerCase());
    if (!hit) continue;
    const v = raw[hit];
    if (v == null || v === '') continue;
    const col = aliasNames[i];
    const key = String(col).toUpperCase();
    const str = typeof v === 'number' && Number.isFinite(v) ? String(v) : String(v).trim();
    if (!str) continue;
    out[key] = str.slice(0, 4000);
  }
  return out;
}

/**
 * SECTION.OBJ_Key → primary key for joining SECINSP (WinCan variants).
 * @param {any} db
 * @param {string} sectionTable
 * @param {string} reference
 * @returns {string|number|null}
 */
function resolveSectionPrimaryKeyForReference(db, sectionTable, reference) {
  const S = sqlIdentQuoted(sectionTable);
  const ref = cleanString(reference);
  if (!ref) return null;
  const secCols = sqlitePragmaColumns(db, sectionTable).map((c) => c.name.toUpperCase());
  const pkCol = secCols.includes('OBJ_PK') ? 'OBJ_PK' : secCols.includes('OBJ_ID') ? 'OBJ_ID' : '';
  if (!pkCol) return null;
  let stmt;
  try {
    stmt = db.prepare(`SELECT ${sqlIdentQuoted(pkCol)} AS spk FROM ${S} WHERE OBJ_Key = ? LIMIT 1`);
    stmt.bind([ref]);
    if (stmt.step()) {
      const v = stmt.getAsObject().spk;
      stmt.free();
      if (v != null && String(v).trim() !== '') return v;
    } else {
      stmt.free();
    }
  } catch {
    try {
      stmt?.free();
    } catch {
      /* ignore */
    }
  }
  return null;
}

/**
 * Merge first matching SECINSP row into db3Imported (inspector, certificate, etc. often live here).
 * Does not overwrite keys already populated from SECTION extras.
 * @param {any} db
 * @param {string} sectionTable
 * @param {string} secinspTable
 * @param {string} reference SECTION.OBJ_Key
 * @param {Record<string, string>} imported
 */
function mergeSecinspRowIntoDb3Imported(db, sectionTable, secinspTable, reference, imported) {
  const out = imported && typeof imported === 'object' ? { ...imported } : {};
  if (!secinspTable) return out;
  const spk = resolveSectionPrimaryKeyForReference(db, sectionTable, reference);
  if (spk == null) return out;
  const cols = sqlitePragmaColumns(db, secinspTable);
  if (!cols.length) return out;
  const wantFks = [
    'INS_Section_FK',
    'INS_SECTION_FK',
    'INS_SectionId',
    'INS_SECTION_ID',
    'INS_SECTION_OBJ_PK',
    'INS_SEC_FK',
    'INS_SECTIONREF',
    'INS_SECTION_REF',
    'OBJ_ID',
    'OBJ_PK',
    'INS_ObjectId',
    'INS_OBJECTID'
  ];
  /** @type {string[]} */
  const fkCols = [];
  for (const w of wantFks) {
    const hit = cols.find((c) => String(c.name).toUpperCase() === w.toUpperCase());
    if (hit && !fkCols.includes(hit.name)) fkCols.push(hit.name);
  }
  if (!fkCols.length) {
    for (const c of cols) {
      const u = String(c.name).toUpperCase();
      if (u.includes('SECTION') && (u.includes('FK') || u.includes('REF'))) fkCols.push(c.name);
    }
  }
  if (!fkCols.length) return out;
  if (fkCols.length > DB3_SECINSP_MAX_FK_COLUMNS) {
    fkCols.splice(DB3_SECINSP_MAX_FK_COLUMNS);
  }
  const SI = sqlIdentQuoted(secinspTable);
  const ref = cleanString(reference);

  /**
   * @param {Record<string, unknown>} row
   */
  const applyRow = (row) => {
    for (const [k, v] of Object.entries(row)) {
      if (v == null || v === '') continue;
      const ku = String(k).toUpperCase();
      if (out[ku] && String(out[ku]).trim() !== '') continue;
      const str = typeof v === 'number' && Number.isFinite(v) ? String(v) : String(v).trim();
      if (!str) continue;
      out[ku] = str.slice(0, 4000);
    }
  };

  function logSecinspStrategyOnce(strategy, detail = {}) {
    const key = `${String(secinspTable || '').toLowerCase()}|${strategy}|${fkCols.length}`;
    if (DB3_SECINSP_DIAG_ONCE.has(key)) return;
    DB3_SECINSP_DIAG_ONCE.add(key);
    console.warn('[db3-preview][secinsp-probe]', {
      table: secinspTable,
      strategy,
      fkColumns: fkCols.length,
      ...detail
    });
  }

  /**
   * @param {string|number|null|undefined} bindVal
   */
  const mergeForBindSplit = (bindVal) => {
    if (bindVal == null || bindVal === '') return;
    logSecinspStrategyOnce('split-only', { reason: 'or-disabled-hardening', strategyVersion: DB3_PREVIEW_STRATEGY_VERSION });
    for (const fkCol of fkCols) {
      let stmt;
      try {
        stmt = db.prepare(`SELECT * FROM ${SI} WHERE ${sqlIdentQuoted(fkCol)} = ? LIMIT ${DB3_SECINSP_SPLIT_QUERY_LIMIT}`);
        stmt.bind([bindVal]);
        while (stmt.step()) {
          applyRow(stmt.getAsObject());
        }
        stmt.free();
      } catch (error) {
        const msg = String(error?.message || error || '');
        logSecinspStrategyOnce('split-column-error', {
          reason: 'column-query-error',
          fkColumn: String(fkCol || ''),
          message: msg.slice(0, 220),
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION
        });
        try {
          stmt?.free();
        } catch {
          /* ignore */
        }
      }
    }
  };

  try {
    mergeForBindSplit(spk);
    /* Some WinCan builds store the section OBJ_Key string in SECINSP FK columns instead of OBJ_PK. */
    if (ref && String(spk) !== String(ref)) mergeForBindSplit(ref);
  } catch {
    /* ignore */
  }
  return out;
}

/**
 * Merge SECINSP rows where a text column holds SECTION.OBJ_Key (string link).
 * @param {any} db
 * @param {string} secinspTable
 * @param {string} reference SECTION.OBJ_Key
 * @param {Record<string, string>} imported
 */
function mergeSecinspBySectionObjKeyColumn(db, secinspTable, reference, imported) {
  const out = imported && typeof imported === 'object' ? { ...imported } : {};
  const ref = cleanString(reference);
  if (!ref || !secinspTable) return out;
  const cols = sqlitePragmaColumns(db, secinspTable);
  const keyCols = cols
    .map((c) => c.name)
    .filter((name) => {
      const u = String(name).toUpperCase();
      if (u === 'SECTION_KEY' || u === 'INS_SECTIONKEY' || u === 'SECTION_OBJ_KEY') return true;
      if (u.includes('SECTION') && u.includes('KEY') && !u.includes('FOREIGN') && !u.includes('PRIM')) return true;
      return false;
    });
  if (!keyCols.length) return out;
  if (keyCols.length > DB3_SECINSP_MAX_KEY_COLUMNS) {
    keyCols.splice(DB3_SECINSP_MAX_KEY_COLUMNS);
  }
  const SI = sqlIdentQuoted(secinspTable);
  for (const kcol of keyCols) {
    let stmt;
    try {
      stmt = db.prepare(`SELECT * FROM ${SI} WHERE ${sqlIdentQuoted(kcol)} = ?`);
      stmt.bind([ref]);
      while (stmt.step()) {
        const row = stmt.getAsObject();
        for (const [k, v] of Object.entries(row)) {
          if (v == null || v === '') continue;
          const ku = String(k).toUpperCase();
          if (out[ku] && String(out[ku]).trim() !== '') continue;
          const str = typeof v === 'number' && Number.isFinite(v) ? String(v) : String(v).trim();
          if (!str) continue;
          out[ku] = str.slice(0, 4000);
        }
      }
      stmt.free();
    } catch {
      try {
        stmt?.free();
      } catch {
        /* ignore */
      }
    }
  }
  return out;
}

function injectDb3ExtrasBeforeOrderBy(sql, extraSql) {
  if (!extraSql) return sql;
  const trimmed = String(sql || '').trimEnd();
  const m = /\sORDER\s+BY\s/i.exec(trimmed);
  if (m && m.index >= 0) {
    return `${trimmed.slice(0, m.index)}, ${extraSql}${trimmed.slice(m.index)}`;
  }
  return `${trimmed}, ${extraSql}`;
}

function mapDb3SectionRow(row, projectName) {
  const dia = row.size2
    ? `${String(row.size1).replace(/\.0+$/, '')}/${String(row.size2).replace(/\.0+$/, '')}`
    : String(row.size1 || '').replace(/\.0+$/, '');
  return {
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
  };
}

function isDb3FromClauseOverflowError(error) {
  const msg = String(error?.message || error || '');
  return /too many from clause terms/i.test(msg) || /from clause terms,\s*max:\s*200/i.test(msg);
}

function resolveDb3NodeKeyByRef(db, nodeTable, rawRef) {
  const ref = rawRef == null ? '' : String(rawRef).trim();
  if (!ref || !nodeTable) return '';
  const cols = sqlitePragmaColumns(db, nodeTable).map((c) => String(c.name || '').toUpperCase());
  const hasPk = cols.includes('OBJ_PK');
  const hasId = cols.includes('OBJ_ID');
  if (!hasPk && !hasId) return '';
  const N = sqlIdentQuoted(nodeTable);
  const readObjKey = (colName) => {
    let stmt;
    try {
      stmt = db.prepare(`SELECT COALESCE(OBJ_Key, '') AS obj_key FROM ${N} WHERE ${sqlIdentQuoted(colName)} = ? LIMIT 1`);
      stmt.bind([ref]);
      if (stmt.step()) {
        const row = stmt.getAsObject();
        const key = cleanString(row.obj_key);
        stmt.free();
        return key;
      }
      stmt.free();
    } catch {
      try {
        stmt?.free();
      } catch {
        /* ignore */
      }
    }
    return '';
  };
  if (hasPk) {
    const key = readObjKey('OBJ_PK');
    if (key) return key;
  }
  if (hasId) {
    const key = readObjKey('OBJ_ID');
    if (key) return key;
  }
  return '';
}

async function parseDb3(buffer) {
  const SQL = await sqlJsPromise;
  const db = new SQL.Database(new Uint8Array(buffer));
  const tables = sqliteTableList(db);
  const preferredSection = pickSqliteTable(tables, 'SECTION');
  let sectionT = preferredSection;
  const preferredSectionType = sectionT ? sqliteObjectType(db, sectionT) : '';
  if (sectionT && preferredSectionType === 'view') {
    console.warn('[db3-preview][section-source]', {
      strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
      branch: 'reject-preferred-view',
      preferredSection,
      preferredSectionType
    });
    sectionT = '';
  }
  if (!sectionT) {
    /** @type {{ name: string, score: number }[]} */
    const candidates = [];
    for (const tableName of tables) {
      if (!tableName) continue;
      if (tableName === preferredSection) continue;
      if (sqliteObjectType(db, tableName) !== 'table') continue;
      const cols = sqlitePragmaColumns(db, tableName).map((c) => String(c.name || '').toUpperCase());
      const set = new Set(cols);
      if (!set.has('OBJ_KEY')) continue;
      let score = 0;
      if (String(tableName).toUpperCase().includes('SECTION')) score += 6;
      if (set.has('OBJ_LENGTH')) score += 3;
      if (set.has('OBJ_FROMNODE_REF')) score += 2;
      if (set.has('OBJ_TONODE_REF')) score += 2;
      if (set.has('OBJ_MATERIAL')) score += 1;
      if (set.has('OBJ_SHAPE')) score += 1;
      if (set.has('OBJ_SIZE1')) score += 1;
      if (set.has('OBJ_SIZE2')) score += 1;
      candidates.push({ name: tableName, score });
    }
    candidates.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return String(a.name || '').localeCompare(String(b.name || ''), undefined, { sensitivity: 'base' });
    });
    if (candidates.length) sectionT = candidates[0].name;
  }
  if (!sectionT) {
    db.close();
    const preview = tables.slice(0, 40).join(', ') || '(none)';
    const hint = explainMissingSectionDb3(tables);
    throw new Error(
      `Not a WinCan-style pipe DB3: missing SECTION table.${hint} Tables in file: ${preview}${tables.length > 40 ? ' …' : ''}`
    );
  }
  const extraFrag = buildDb3SectionExtraSelect(db, sectionT);
  console.warn('[db3-preview][section-source]', {
    strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
    branch: 'selected-section-source',
    selectedSection: sectionT,
    preferredSection: preferredSection || '',
    preferredSectionType: preferredSectionType || ''
  });
  const nodeT = pickSqliteTable(tables, 'NODE');
  const nodeType = nodeT ? sqliteObjectType(db, nodeT) : '';
  const nodeRuntimeTable = nodeT && nodeType !== 'view' ? nodeT : '';
  const secinspT = pickSqliteTable(tables, 'SECINSP');
  const secinspType = secinspT ? sqliteObjectType(db, secinspT) : '';
  const secinspSafeForJoin = !!secinspT && secinspType !== 'view';
  const secinspRuntimeTable = secinspSafeForJoin ? secinspT : '';
  const projectT = pickSqliteTable(tables, 'PROJECT');

  let projectName = '';
  if (projectT) {
    try {
      const projectStmt = db.prepare(
        `SELECT COALESCE(MAX(PRJ_Key), '') AS project_name FROM ${sqlIdentQuoted(projectT)}`
      );
      if (projectStmt.step()) {
        const row = projectStmt.getAsObject();
        projectName = cleanString(row.project_name);
      }
      projectStmt.free();
    } catch {
      projectName = '';
    }
  }

  const S = sqlIdentQuoted(sectionT);
  const N = nodeRuntimeTable ? sqlIdentQuoted(nodeRuntimeTable) : '';

  const coreCols = `
      s.OBJ_Key AS reference,
      COALESCE(si.inspected_length, s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(n1.OBJ_Key, '') AS upstream,
      COALESCE(n2.OBJ_Key, '') AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;

  const coreColsNoInsp = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(n1.OBJ_Key, '') AS upstream,
      COALESCE(n2.OBJ_Key, '') AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;

  const coreColsBare = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      '' AS upstream,
      '' AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;

  /** @type {string[]} */
  const sqlVariants = [];
  if (secinspSafeForJoin && nodeRuntimeTable) {
    const SI = sqlIdentQuoted(secinspT);
    sqlVariants.push(`
    SELECT ${coreCols}
    FROM ${S} s
    LEFT JOIN (
      SELECT INS_Section_FK AS si_fk, MAX(COALESCE(INS_InspectedLength, INS_EstimatedLength, 0)) AS inspected_length
      FROM ${SI}
      GROUP BY INS_Section_FK
    ) si ON si.si_fk = s.OBJ_PK
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
    sqlVariants.push(`
    SELECT ${coreCols}
    FROM ${S} s
    LEFT JOIN (
      SELECT OBJ_ID AS si_fk, MAX(COALESCE(INS_InspectedLength, INS_EstimatedLength, 0)) AS inspected_length
      FROM ${SI}
      GROUP BY OBJ_ID
    ) si ON si.si_fk = s.OBJ_ID
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
    sqlVariants.push(`
    SELECT ${coreCols}
    FROM ${S} s
    LEFT JOIN (
      SELECT OBJ_ID AS si_fk, MAX(COALESCE(INS_InspectedLength, INS_EstimatedLength, 0)) AS inspected_length
      FROM ${SI}
      GROUP BY OBJ_ID
    ) si ON si.si_fk = s.OBJ_PK
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
  }
  if (nodeRuntimeTable) {
    sqlVariants.push(`
    SELECT ${coreColsNoInsp}
    FROM ${S} s
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
  }
  sqlVariants.push(`
    SELECT ${coreColsBare}
    FROM ${S} s
    ORDER BY s.OBJ_Key`);

  let lastErr = 'no query variant succeeded';
  let sawFromClauseOverflow = false;
  for (const sql of sqlVariants) {
    const sqlWithExtras = injectDb3ExtrasBeforeOrderBy(sql, extraFrag.sql);
    let stmt;
    try {
      stmt = db.prepare(sqlWithExtras);
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
      if (isDb3FromClauseOverflowError(e)) {
        sawFromClauseOverflow = true;
        console.warn('[db3-preview][variant-overflow]', {
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
          branch: 'variant-prepare',
          hasNodeTable: !!nodeRuntimeTable,
          hasSecinspTable: !!secinspRuntimeTable,
          message: String(lastErr || '').slice(0, 220)
        });
      }
      continue;
    }
    try {
      const rows = [];
      while (stmt.step()) {
        const raw = stmt.getAsObject();
        const mapped = mapDb3SectionRow(raw, projectName);
        let imported = extractDb3ImportedFromRow(raw, extraFrag.aliasNames);
        if (secinspRuntimeTable) {
          imported = mergeSecinspRowIntoDb3Imported(db, sectionT, secinspRuntimeTable, mapped.reference, imported);
          imported = mergeSecinspBySectionObjKeyColumn(db, secinspRuntimeTable, mapped.reference, imported);
        }
        imported = enrichDb3ImportedOperatorFromWcmeta(db, tables, imported);
        const inspector = db3InspectorIdentityFromImported(imported);
        if (inspector) {
          imported.HP_INSPECTOR_RAW = inspector.raw;
          imported.HP_INSPECTOR_DISPLAY = inspector.canonical;
          imported.HP_INSPECTOR_KEY = inspector.key;
          mapped.inspectorRaw = inspector.raw;
          mapped.inspector = inspector.canonical;
          mapped.inspectorKey = inspector.key;
        }
        if (Object.keys(imported).length) {
          mapped.db3Imported = imported;
        }
        rows.push(mapped);
      }
      stmt.free();
      console.warn('[db3-preview][strategy-select]', {
        strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
        strategy: 'sql-variant-v1',
        hasNodeTable: !!nodeRuntimeTable,
        hasSecinspTable: !!secinspRuntimeTable,
        usesSectionExtras: !!extraFrag.sql
      });
      db.close();
      return rows;
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
      if (isDb3FromClauseOverflowError(e)) {
        sawFromClauseOverflow = true;
        console.warn('[db3-preview][variant-overflow]', {
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
          branch: 'variant-step',
          hasNodeTable: !!nodeRuntimeTable,
          hasSecinspTable: !!secinspRuntimeTable,
          message: String(lastErr || '').slice(0, 220)
        });
      }
      try {
        stmt.free();
      } catch {
        /* ignore */
      }
    }
  }
  if (sawFromClauseOverflow) {
    let splitStmt;
    try {
      const splitCoreCols = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(s.OBJ_FromNode_REF, '') AS from_node_ref,
      COALESCE(s.OBJ_ToNode_REF, '') AS to_node_ref,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;
      const splitSql = injectDb3ExtrasBeforeOrderBy(
        `
        SELECT ${splitCoreCols}
        FROM ${S} s
        ORDER BY s.OBJ_Key`,
        extraFrag.sql
      );
      console.warn('[db3-preview][variant-fallback]', {
        strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
        strategy: 'section-split-probe-v1',
        hasNodeTable: !!nodeRuntimeTable,
        hasSecinspTable: !!secinspRuntimeTable
      });
      splitStmt = db.prepare(splitSql);
      const rows = [];
      const nodeCache = new Map();
      const lookupNode = (rawRef) => {
        const key = rawRef == null ? '' : String(rawRef).trim();
        if (!key || !nodeRuntimeTable) return '';
        if (nodeCache.has(key)) return nodeCache.get(key) || '';
        const hit = resolveDb3NodeKeyByRef(db, nodeRuntimeTable, key);
        nodeCache.set(key, hit || '');
        return hit || '';
      };
      while (splitStmt.step()) {
        const raw = splitStmt.getAsObject();
        const mapped = mapDb3SectionRow(raw, projectName);
        mapped.upstream = lookupNode(raw.from_node_ref);
        mapped.downstream = lookupNode(raw.to_node_ref);
        let imported = extractDb3ImportedFromRow(raw, extraFrag.aliasNames);
        if (secinspRuntimeTable) {
          imported = mergeSecinspRowIntoDb3Imported(db, sectionT, secinspRuntimeTable, mapped.reference, imported);
          imported = mergeSecinspBySectionObjKeyColumn(db, secinspRuntimeTable, mapped.reference, imported);
        }
        imported = enrichDb3ImportedOperatorFromWcmeta(db, tables, imported);
        const inspector = db3InspectorIdentityFromImported(imported);
        if (inspector) {
          imported.HP_INSPECTOR_RAW = inspector.raw;
          imported.HP_INSPECTOR_DISPLAY = inspector.canonical;
          imported.HP_INSPECTOR_KEY = inspector.key;
          mapped.inspectorRaw = inspector.raw;
          mapped.inspector = inspector.canonical;
          mapped.inspectorKey = inspector.key;
        }
        if (Object.keys(imported).length) mapped.db3Imported = imported;
        rows.push(mapped);
      }
      splitStmt.free();
      console.warn('[db3-preview][strategy-select]', {
        strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
        strategy: 'section-split-probe-v1',
        hasNodeTable: !!nodeRuntimeTable,
        hasSecinspTable: !!secinspRuntimeTable,
        usesSectionExtras: !!extraFrag.sql
      });
      db.close();
      return rows;
    } catch (fallbackErr) {
      lastErr = fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr);
      if (isDb3FromClauseOverflowError(fallbackErr)) {
        console.warn('[db3-preview][variant-overflow]', {
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
          branch: 'split-fallback',
          hasNodeTable: !!nodeRuntimeTable,
          hasSecinspTable: !!secinspRuntimeTable,
          message: String(lastErr || '').slice(0, 220)
        });
        let bareStmt;
        try {
          const bareSplitCoreCols = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(s.OBJ_FromNode_REF, '') AS from_node_ref,
      COALESCE(s.OBJ_ToNode_REF, '') AS to_node_ref,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;
          const bareSplitSql = `
        SELECT ${bareSplitCoreCols}
        FROM ${S} s
        ORDER BY s.OBJ_Key`;
          console.warn('[db3-preview][variant-fallback]', {
            strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
            strategy: 'section-split-no-extras-v1',
            hasNodeTable: !!nodeRuntimeTable,
            hasSecinspTable: !!secinspRuntimeTable
          });
          bareStmt = db.prepare(bareSplitSql);
          const rows = [];
          const nodeCache = new Map();
          const lookupNode = (rawRef) => {
            const key = rawRef == null ? '' : String(rawRef).trim();
            if (!key || !nodeRuntimeTable) return '';
            if (nodeCache.has(key)) return nodeCache.get(key) || '';
            const hit = resolveDb3NodeKeyByRef(db, nodeRuntimeTable, key);
            nodeCache.set(key, hit || '');
            return hit || '';
          };
          while (bareStmt.step()) {
            const raw = bareStmt.getAsObject();
            const mapped = mapDb3SectionRow(raw, projectName);
            mapped.upstream = lookupNode(raw.from_node_ref);
            mapped.downstream = lookupNode(raw.to_node_ref);
            let imported = {};
            if (secinspRuntimeTable) {
              imported = mergeSecinspRowIntoDb3Imported(db, sectionT, secinspRuntimeTable, mapped.reference, imported);
              imported = mergeSecinspBySectionObjKeyColumn(db, secinspRuntimeTable, mapped.reference, imported);
            }
            imported = enrichDb3ImportedOperatorFromWcmeta(db, tables, imported);
            const inspector = db3InspectorIdentityFromImported(imported);
            if (inspector) {
              imported.HP_INSPECTOR_RAW = inspector.raw;
              imported.HP_INSPECTOR_DISPLAY = inspector.canonical;
              imported.HP_INSPECTOR_KEY = inspector.key;
              mapped.inspectorRaw = inspector.raw;
              mapped.inspector = inspector.canonical;
              mapped.inspectorKey = inspector.key;
            }
            if (Object.keys(imported).length) mapped.db3Imported = imported;
            rows.push(mapped);
          }
          bareStmt.free();
          console.warn('[db3-preview][strategy-select]', {
            strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
            strategy: 'section-split-no-extras-v1',
            hasNodeTable: !!nodeRuntimeTable,
            hasSecinspTable: !!secinspRuntimeTable,
            usesSectionExtras: false
          });
          db.close();
          return rows;
        } catch (bareErr) {
          lastErr = bareErr instanceof Error ? bareErr.message : String(bareErr);
          console.warn('[db3-preview][variant-fallback-error]', {
            strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
            strategy: 'section-split-no-extras-v1',
            message: String(lastErr || '').slice(0, 220)
          });
          try {
            bareStmt?.free();
          } catch {
            /* ignore */
          }
        }
      }
      try {
        splitStmt?.free();
      } catch {
        /* ignore */
      }
    }
  }
  db.close();
  throw new Error(
    lastErr ||
      'Could not read SECTION rows from this DB3 (unsupported WinCan schema or missing OBJ_Key / length columns).'
  );
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
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS account_type TEXT NOT NULL DEFAULT 'employee'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_role TEXT`,
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
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS autosync_master_granted BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS self_signup BOOLEAN NOT NULL DEFAULT false`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS product_tutorials_seen JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_workspace_layouts JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS user_prefs JSONB NOT NULL DEFAULT '{}'::jsonb`
  ];
  for (const query of userAlters) await pool.query(query);
  await pool.query(`
    DO $$ BEGIN
      ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;
    EXCEPTION WHEN undefined_object THEN NULL;
    END $$;
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_portal_scope
    ON users (
      LOWER(TRIM(username)),
      COALESCE(NULLIF(BTRIM(portal_files_client_id), ''), '__global__')
    )
  `);
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
  await pool.query(`ALTER TABLE users ALTER COLUMN account_type SET DEFAULT 'employee'`);
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
     SET account_type = CASE
       WHEN LOWER(TRIM(COALESCE(username, ''))) IN ('mik', 'mike strickland')
         OR LOWER(TRIM(COALESCE(display_name, ''))) = 'mike strickland'
         OR LOWER(TRIM(COALESCE(email, ''))) = 'mike@horizonpipe.com'
         OR is_admin = true
         OR LOWER(COALESCE(roles ->> 'camera', 'false')) = 'true'
         OR LOWER(COALESCE(roles ->> 'vac', 'false')) = 'true'
         OR LOWER(COALESCE(roles ->> 'simpleVac', 'false')) = 'true'
         OR LOWER(COALESCE(roles ->> 'psrPlanner', 'false')) = 'true'
         OR LOWER(COALESCE(roles ->> 'psrDataEntry', 'false')) = 'true'
         OR LOWER(COALESCE(roles ->> 'psrViewer', 'false')) = 'true'
         OR LOWER(COALESCE(roles ->> 'dataAutoSyncEmployee', 'false')) = 'true'
         THEN 'employee'
       ELSE 'customer'
     END
     WHERE account_type IS NULL
        OR BTRIM(account_type) = ''
        OR LOWER(BTRIM(account_type)) NOT IN ('employee', 'customer')`
  );
  await pool.query(
    `UPDATE users
     SET employee_role = CASE
       WHEN LOWER(TRIM(COALESCE(username, ''))) IN ('mik', 'mike strickland')
         OR LOWER(TRIM(COALESCE(display_name, ''))) = 'mike strickland'
         OR LOWER(TRIM(COALESCE(email, ''))) = 'mike@horizonpipe.com'
         THEN 'superadmin'
       WHEN is_admin = true THEN 'admin'
       WHEN LOWER(COALESCE(roles ->> 'simpleVac', 'false')) = 'true' THEN 'simple_vac'
       WHEN LOWER(COALESCE(roles ->> 'vac', 'false')) = 'true' THEN 'vac_operator'
       WHEN LOWER(COALESCE(roles ->> 'camera', 'false')) = 'true' THEN 'camera_operator'
       WHEN LOWER(COALESCE(account_type, 'employee')) = 'employee' THEN COALESCE(NULLIF(BTRIM(employee_role), ''), 'camera_operator')
       ELSE NULL
     END`
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days'),
      revoked_at TIMESTAMPTZ,
      revoked_by_username TEXT
    )
  `);
  await pool.query(
    `ALTER TABLE portal_share_links ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days')`
  );
  await pool.query(`ALTER TABLE portal_share_links ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE portal_share_links ADD COLUMN IF NOT EXISTS revoked_by_username TEXT`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_portal_share_links_cj ON portal_share_links (client_id, job_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_portal_share_links_expires ON portal_share_links (expires_at)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_portal_share_links_revoked ON portal_share_links (revoked_at)`);

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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS companies (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL UNIQUE,
      slug TEXT NOT NULL DEFAULT '',
      app_features JSONB NOT NULL DEFAULT '{"pipeshare":true,"pipesync":true,"autosync":false,"planview":true}'::jsonb,
      customer_enabled BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_companies_slug ON companies (lower(slug))`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS company_roles (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      role_key TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (company_id, role_key)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_company_roles_company ON company_roles (company_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS company_folder_grants (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      role_key TEXT NOT NULL,
      client_id TEXT NOT NULL,
      job_id TEXT NOT NULL,
      path_prefix TEXT NOT NULL DEFAULT '',
      enabled BOOLEAN NOT NULL DEFAULT true,
      can_view BOOLEAN NOT NULL DEFAULT true,
      can_edit BOOLEAN NOT NULL DEFAULT false,
      can_delete BOOLEAN NOT NULL DEFAULT false,
      can_upload BOOLEAN NOT NULL DEFAULT false,
      can_download BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (company_id, role_key, client_id, job_id, path_prefix)
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_company_folder_grants_lookup ON company_folder_grants (company_id, role_key, client_id, job_id)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_folder_grants (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT NOT NULL,
      app TEXT NOT NULL DEFAULT 'pipeshare',
      client_id TEXT NOT NULL,
      job_id TEXT NOT NULL DEFAULT '',
      path_prefix TEXT NOT NULL DEFAULT '',
      psr_scope_level TEXT NOT NULL DEFAULT '',
      psr_city TEXT NOT NULL DEFAULT '',
      recursive BOOLEAN NOT NULL DEFAULT true,
      enabled BOOLEAN NOT NULL DEFAULT true,
      can_view BOOLEAN NOT NULL DEFAULT true,
      can_edit BOOLEAN NOT NULL DEFAULT false,
      can_delete BOOLEAN NOT NULL DEFAULT false,
      can_upload BOOLEAN NOT NULL DEFAULT false,
      can_download BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, app, client_id, job_id, path_prefix, psr_scope_level, psr_city)
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_folder_grants_user_job ON user_folder_grants (user_id, app, client_id, job_id)`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_user_folder_grants_scope ON user_folder_grants (app, client_id, job_id, path_prefix, psr_scope_level, psr_city)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_company_membership (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT NOT NULL UNIQUE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      role_key TEXT NOT NULL DEFAULT 'employee',
      override_folder_grants JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `ALTER TABLE user_company_membership DROP CONSTRAINT IF EXISTS user_company_membership_user_id_fkey`
  );
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'user_company_membership'
          AND column_name = 'user_id'
          AND data_type <> 'text'
      ) THEN
        EXECUTE 'ALTER TABLE user_company_membership ALTER COLUMN user_id TYPE TEXT USING user_id::text';
      END IF;
    END $$;
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_company_membership_company ON user_company_membership (company_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS trash_bin_entries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID REFERENCES companies(id) ON DELETE SET NULL,
      client_id TEXT NOT NULL,
      job_id TEXT NOT NULL,
      item_type TEXT NOT NULL CHECK (item_type IN ('file', 'folder')),
      item_id TEXT,
      rel_path TEXT NOT NULL DEFAULT '',
      original_parent_path TEXT NOT NULL DEFAULT '',
      skeleton_path TEXT NOT NULL DEFAULT '',
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      deleted_by_user_id TEXT,
      deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      restored_at TIMESTAMPTZ
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_trash_bin_entries_active ON trash_bin_entries (deleted_at DESC) WHERE restored_at IS NULL`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS company_plan_share_links (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      token TEXT NOT NULL UNIQUE,
      created_by_user_id TEXT,
      payload JSONB NOT NULL DEFAULT '{"folderPaths":[],"planView":true}'::jsonb,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_company_plan_share_links_company ON company_plan_share_links (company_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS saas_tenant_instances (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      owner_user_id TEXT NOT NULL UNIQUE,
      website_url TEXT NOT NULL DEFAULT '',
      wasabi_root_prefix TEXT NOT NULL DEFAULT '',
      portal_client_id TEXT NOT NULL DEFAULT '',
      portal_job_id TEXT NOT NULL DEFAULT '1',
      branding JSONB NOT NULL DEFAULT '{}'::jsonb,
      subscription_status TEXT NOT NULL DEFAULT 'expired'
        CHECK (subscription_status IN ('pending', 'expired', 'trialing', 'active', 'past_due', 'canceled')),
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      setup_status TEXT NOT NULL DEFAULT 'draft'
        CHECK (setup_status IN ('draft', 'provisioning', 'ready', 'failed')),
      setup_completed_at TIMESTAMPTZ,
      provisioning_error TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (company_id)
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_saas_tenant_instances_owner ON saas_tenant_instances (owner_user_id)`
  );
  await pool.query(`
    ALTER TABLE saas_tenant_instances
    ADD COLUMN IF NOT EXISTS postgres_schema TEXT NOT NULL DEFAULT ''
  `);
  await pool.query(`
    DO $$ BEGIN
      ALTER TABLE saas_tenant_instances DROP CONSTRAINT IF EXISTS saas_tenant_instances_subscription_status_check;
    EXCEPTION WHEN undefined_object THEN NULL;
    END $$;
  `);
  await pool.query(`
    ALTER TABLE saas_tenant_instances
    ADD CONSTRAINT saas_tenant_instances_subscription_status_check
    CHECK (subscription_status IN ('pending', 'expired', 'trialing', 'active', 'past_due', 'canceled'))
  `);
  await pool.query(`
    ALTER TABLE saas_tenant_instances
    ALTER COLUMN subscription_status SET DEFAULT 'expired'
  `);
  await pool.query(`
    UPDATE saas_tenant_instances
    SET subscription_status = 'expired', updated_at = NOW()
    WHERE subscription_status = 'pending'
      AND COALESCE(stripe_subscription_id, '') = ''
      AND COALESCE(stripe_customer_id, '') = ''
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS platform_release_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      version TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK (event_type IN ('published', 'applied', 'heartbeat')),
      actor_user_id TEXT NOT NULL DEFAULT '',
      deployment_mode TEXT NOT NULL DEFAULT '',
      notes TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_platform_release_events_version ON platform_release_events (version)`
  );

  const companyCountResult = await pool.query('SELECT COUNT(*)::int AS count FROM companies');
  if (companyCountResult.rows[0].count === 0) {
    const seedCompanies = ['Horizon Pipe', 'AJJ', 'JUM', 'Dirt Works'];
    for (const name of seedCompanies) {
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const inserted = await pool.query(
        `INSERT INTO companies (name, slug) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING RETURNING id`,
        [name, slug]
      );
      if (inserted.rows[0]?.id) {
        for (const roleKey of ['admin', 'employee', 'customer']) {
          await pool.query(
            `INSERT INTO company_roles (company_id, role_key, enabled) VALUES ($1, $2, $3) ON CONFLICT (company_id, role_key) DO NOTHING`,
            [inserted.rows[0].id, roleKey, roleKey !== 'customer']
          );
        }
      }
    }
  }

  await ensureOutlookSchema({ pool, query: queryOutlookDataWithWasabiFallback });

  const countResult = await pool.query('SELECT COUNT(*)::int AS count FROM users');
  if (countResult.rows[0].count === 0) {
    const defaults = [
      {
        username: 'mik',
        displayName: 'Mike Strickland',
        isAdmin: true,
        accountType: 'employee',
        employeeRole: 'superadmin',
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
        accountType: 'employee',
        employeeRole: 'admin',
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
        accountType: 'employee',
        employeeRole: 'admin',
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
        `INSERT INTO users (username, display_name, password, is_admin, account_type, employee_role, roles, must_change_password)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, true)`,
        [user.username, user.displayName, hash, user.isAdmin, user.accountType, user.employeeRole, JSON.stringify(user.roles)]
      );
    }
  }

  await pool.query(`
    UPDATE users
    SET is_admin = true, updated_at = NOW()
    WHERE LOWER(TRIM(username)) = 'mik'
       OR LOWER(TRIM(COALESCE(display_name, ''))) LIKE 'mike strickland%'
  `);
  await pool.query(`
    UPDATE users
    SET self_signup = false,
        account_type = 'employee',
        employee_role = 'superadmin',
        is_admin = true,
        portal_files_client_id = CASE
          WHEN portal_files_client_id IS NULL OR BTRIM(portal_files_client_id) = ''
            OR LOWER(BTRIM(portal_files_client_id)) = 'portal-users'
            THEN portal_files_client_id
          WHEN LOWER(BTRIM(portal_files_client_id)) LIKE 'tenant-%'
            THEN COALESCE(NULLIF(BTRIM($1::text), ''), 'portal-users')
          ELSE portal_files_client_id
        END,
        portal_files_job_id = CASE
          WHEN LOWER(BTRIM(COALESCE(portal_files_client_id, ''))) LIKE 'tenant-%'
            THEN COALESCE(NULLIF(BTRIM($2::text), ''), portal_files_job_id)
          ELSE portal_files_job_id
        END,
        portal_files_access_granted = true,
        portal_permissions_access = true,
        updated_at = NOW()
    WHERE LOWER(TRIM(COALESCE(username, ''))) IN ('mik', 'mike strickland')
       OR LOWER(TRIM(COALESCE(display_name, ''))) = 'mike strickland'
       OR LOWER(TRIM(COALESCE(email, ''))) = 'mike@horizonpipe.com'
  `, [
    String(process.env.PORTAL_SHARED_DEFAULT_CLIENT_ID || 'portal-users').trim(),
    String(process.env.PORTAL_SHARED_DEFAULT_JOB_ID || '8').trim()
  ]);
  await pool.query(`
    DELETE FROM saas_tenant_instances
    WHERE CAST(owner_user_id AS text) IN (
      SELECT CAST(id AS text) FROM users
      WHERE LOWER(TRIM(COALESCE(username, ''))) IN ('mik', 'mike strickland')
         OR LOWER(TRIM(COALESCE(display_name, ''))) = 'mike strickland'
         OR LOWER(TRIM(COALESCE(email, ''))) = 'mike@horizonpipe.com'
    )
  `);
  await pool.query(`
    DELETE FROM user_company_membership
    WHERE CAST(user_id AS text) IN (
      SELECT CAST(id AS text) FROM users
      WHERE LOWER(TRIM(COALESCE(username, ''))) IN ('mik', 'mike strickland')
         OR LOWER(TRIM(COALESCE(display_name, ''))) = 'mike strickland'
         OR LOWER(TRIM(COALESCE(email, ''))) = 'mike@horizonpipe.com'
    )
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

/** Public bootstrap — same profile on base and SaaS; host-aware tenant slug detection. */
app.get('/public/deployment-config.json', (req, res) => {
  res.set('Cache-Control', 'public, max-age=60');
  res.json(getPublicDeploymentConfig({ requestHost: req.headers['x-forwarded-host'] || req.headers.host }));
});

app.get('/public/deployment-bootstrap.js', (req, res) => {
  res.type('application/javascript');
  res.set('Cache-Control', 'public, max-age=60');
  res.send(
    renderDeploymentBootstrapJs({ requestHost: req.headers['x-forwarded-host'] || req.headers.host })
  );
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
    const syncStateNow = Date.now();
    if (
      SYNC_STATE_HTTP_CACHE_MS > 0 &&
      syncStateHttpCache.payload &&
      syncStateHttpCache.expiresAt > syncStateNow
    ) {
      res.set('X-Sync-State-Cache', 'hit');
      return res.json(syncStateHttpCache.payload);
    }
    if (WASABI_SYNC_STATE_PRIMARY_ENABLED) {
      try {
        const snapshotState = await readSyncStateFromWasabiSnapshot();
        if (snapshotState) {
          const signature = crypto.createHash('sha256').update(JSON.stringify(snapshotState)).digest('hex');
          const out = { success: true, signature, state: snapshotState };
          if (SYNC_STATE_HTTP_CACHE_MS > 0) {
            syncStateHttpCache = { expiresAt: Date.now() + SYNC_STATE_HTTP_CACHE_MS, payload: out };
          }
          return res.json(out);
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
          const out = { success: true, signature, state: empty };
          if (SYNC_STATE_HTTP_CACHE_MS > 0) {
            syncStateHttpCache = { expiresAt: Date.now() + SYNC_STATE_HTTP_CACHE_MS, payload: out };
          }
          return res.json(out);
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
    const out = { success: true, signature, state: payload };
    if (SYNC_STATE_HTTP_CACHE_MS > 0) {
      syncStateHttpCache = { expiresAt: Date.now() + SYNC_STATE_HTTP_CACHE_MS, payload: out };
    }
    res.json(out);
  } catch (error) {
    console.error('SYNC STATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/users', requireAuth, async (req, res) => {
  try {
    const currentUser = req.user;
    const scope = await resolveActorTenantScope(pool, currentUser, {
      requestHost: requestHostFromReq(req)
    });
    const canPlatformList = canAccessAdminPanel(currentUser) && scope.mode !== 'tenant';
    const canTenantList = scope.mode === 'tenant' && userCanManageTenantUsers(currentUser, scope);

    if (!canPlatformList && !canTenantList) {
      const self = normalizeUser(currentUser);
      return res.json({
        success: true,
        users: [{ id: self.id, username: self.username, displayName: self.displayName }]
      });
    }

    let sql = `SELECT id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, autosync_master_granted, portal_permissions_access, self_signup
       FROM users`;
    const params = [];
    if (scope.mode === 'tenant') {
      sql += ` WHERE ${TENANT_USERS_WHERE_SQL}`;
      params.push(...tenantUserFilterParams(scope));
    }
    sql += ` ORDER BY LOWER(COALESCE(display_name, username)), LOWER(username)`;

    const result = await pool.query(sql, params);
    const normalizedRows = await attachScopesToUsers(result.rows.map((row) => normalizeUser(row)));
    const users = normalizedRows.map((normalized) => normalized);
    res.json({ success: true, users });
  } catch (error) {
    console.error('USERS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/permissions/tree', requireAuth, requireAdminPanelOrTenantUserManagement, async (req, res) => {
  try {
    const tenantScope = req.tenantScope || { mode: 'platform' };
    const tenantFilterSql =
      tenantScope.mode === 'tenant'
        ? ` AND company_id = $1::uuid AND client_id = $2`
        : '';
    const tenantFilterParams =
      tenantScope.mode === 'tenant'
        ? [tenantScope.companyId, tenantScope.portalClientId]
        : [];
    /**
     * Portal scopes and path grants stay live from Postgres.
     * When planner canonical data is Wasabi-only, job labels and PSR tree come from the snapshot — not `planner_records` in Postgres.
     */
    const portalPathGrantsSql = `SELECT client_id, job_id, path_prefix
         FROM company_folder_grants
         WHERE enabled = true
           AND client_id IS NOT NULL AND BTRIM(client_id) <> ''
           AND job_id IS NOT NULL AND BTRIM(job_id) <> ''${tenantFilterSql}
         ORDER BY client_id, job_id, path_prefix`;

    if (PLANNER_STORE_WASABI_ONLY) {
      const scopePairsSql = `WITH scope_pairs AS (
           SELECT client_id, job_id
           FROM company_folder_grants
           WHERE enabled = true${tenantFilterSql}
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
        tenantFilterParams.length
          ? pool.query(scopePairsSql, tenantFilterParams)
          : pool.query(scopePairsSql),
        tenantFilterParams.length
          ? pool.query(portalPathGrantsSql, tenantFilterParams)
          : pool.query(portalPathGrantsSql)
      ]);
      const snapshot =
        tenantScope.mode === 'tenant'
          ? await loadTenantWasabiStateSnapshot(pool, req.user?.id, {
              requestHost: requestHostFromReq(req)
            })
          : await loadWasabiLatestStateSnapshot(true);
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
           SELECT client_id, job_id
           FROM company_folder_grants
           WHERE enabled = true
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
    const requestHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').trim();
    let row = null;
    let userRowFromWasabi = false;
    try {
      row = await resolveLoginUserRow(pool, submittedUsername, requestHost);
    } catch (queryError) {
      if (!WASABI_LOGIN_FALLBACK_ENABLED) throw queryError;
      const hostScope = await loadTenantScopeByHost(pool, requestHost);
      if (hostScope.mode === 'tenant') throw queryError;
      row = await readLoginUserFromWasabiSnapshot(submittedUsername, true);
      userRowFromWasabi = !!row;
      if (!row) throw queryError;
      console.warn('[login] using Wasabi user lookup fallback (postgres query error)');
    }

    if (!row && WASABI_LOGIN_FALLBACK_ENABLED) {
      const hostScope = await loadTenantScopeByHost(pool, requestHost);
      if (hostScope.mode !== 'tenant') {
        row = await readLoginUserFromWasabiSnapshot(submittedUsername, true);
        userRowFromWasabi = !!row;
        if (row) console.warn('[login] using Wasabi user lookup (self-signup user not mirrored in Postgres)');
      }
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

    const envLogin = await assertLoginEnvironmentAccess(pool, row, requestHost);
    if (!envLogin.allowed) {
      return res.status(403).json({ success: false, error: envLogin.error });
    }

    const loginContext = cleanString(req.body?.loginContext).toLowerCase();
    const loginProfile = getPublicDeploymentConfig({ requestHost });
    const tenantSlugOnHost =
      loginProfile.tenantSlugFromHost || parseSaasTenantSlugFromHost(requestHost);
    const gateSaasCustomer =
      loginContext === 'saas-customer' ||
      (loginProfile.features?.saasCustomerLoginGate === true && !!tenantSlugOnHost);
    if (gateSaasCustomer) {
      const accountModel = deriveAccountModel({
        accountType: row.account_type,
        employeeRole: row.employee_role,
        isAdmin: row.is_admin,
        selfSignup: row.self_signup,
        roles: row.roles
      });
      if (loginContext === 'saas-customer' || accountModel.accountType === ACCOUNT_TYPES.CUSTOMER) {
        const access = await evaluateSaasCustomerLoginAccess(pool, row.id);
        if (!access.allowed) {
          const status = access.code === 'INVALID_LICENSE' ? 402 : 403;
          return res.status(status).json({
            success: false,
            error: access.message || 'Access denied',
            code: access.code || 'ACCESS_DENIED'
          });
        }
      }
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

    const user = await (async () => {
      await syncSaasSubscriptionOnLogin(row.id);
      return readFreshUserFromPostgresById(row.id);
    })();
    if (!user) {
      return res.status(500).json({ success: false, error: 'Account could not be loaded' });
    }
    const keepRaw = req.body?.keepSession;
    const keepSession = keepRaw === true || keepRaw === 1 || String(keepRaw || '').trim().toLowerCase() === 'true';
    const token = await issueSession(row.id, { keepSession });
    res.json({
      success: true,
      user,
      token,
      capabilities: resolveCapabilities(user),
      deploymentMode: loginProfile.mode,
      deploymentProfile: loginProfile
    });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/session', requireAuth, async (req, res) => {
  const requestHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').trim();
  const deploymentProfile = getPublicDeploymentConfig({ requestHost });
  res.json({
    success: true,
    user: req.user,
    capabilities: resolveCapabilities(req.user),
    deploymentMode: deploymentProfile.mode,
    deploymentProfile
  });
});

app.get('/me/user-prefs', requireAuth, async (req, res) => {
  const prefs = req.user?.userPrefs && typeof req.user.userPrefs === 'object' ? req.user.userPrefs : {};
  res.json({ success: true, prefs });
});

app.patch('/me/user-prefs', requireAuth, async (req, res) => {
  const userId = String(req.user?.id || '').trim();
  if (!userId) {
    return res.status(400).json({ success: false, error: 'Missing user id' });
  }
  const patch = req.body?.patch;
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    return res.status(400).json({ success: false, error: 'patch object is required' });
  }
  try {
    const current = parseUserPrefs({ user_prefs: req.user?.userPrefs });
    const merged = mergeUserPrefsPatch(current, patch);
    await pool.query(
      `UPDATE users
       SET user_prefs = $2::jsonb,
           updated_at = NOW()
       WHERE CAST(id AS text) = $1`,
      [userId, JSON.stringify(merged)]
    );
    await tryWasabiStateWrite('patch-user-prefs', async (data) => {
      const users = ensureSnapshotTable(data, 'users');
      const idx = users.findIndex((u) => String(u.id || '') === userId);
      if (idx < 0) return;
      users[idx] = {
        ...users[idx],
        user_prefs: merged,
        updated_at: nowIso()
      };
    });
    const fresh = await readFreshUserFromPostgresById(userId);
    if (!fresh) {
      return res.status(404).json({ success: false, error: 'User not found after update' });
    }
    res.json({ success: true, user: fresh, prefs: fresh.userPrefs || merged });
  } catch (error) {
    console.error('[me/user-prefs]', error);
    res.status(500).json({ success: false, error: error.message || 'Server error' });
  }
});

/**
 * Mark guided product tutorial completion per account (PipeShare / PipeSync).
 * Body: `{ product: 'pipeshare' | 'pipesync', completed?: boolean }` — `completed` defaults to true; false removes the flag so the tour can auto-run again.
 */
function normalizePortalWorkspaceViewport(raw) {
  const v = cleanString(raw).toLowerCase();
  return v === 'mobile' ? 'mobile' : v === 'desktop' ? 'desktop' : '';
}

function sanitizePortalWorkspaceBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || !Array.isArray(bundle.tabs) || !bundle.tabs.length) {
    return null;
  }
  const tabs = bundle.tabs.slice(0, 12).map((row, i) => {
    const id = cleanString(row?.id) || `t${i}`;
    const title = cleanString(row?.title).slice(0, 40) || `Layout ${i + 1}`;
    const locked = row?.locked === true;
    const visible = row?.visible && typeof row.visible === 'object' && !Array.isArray(row.visible) ? row.visible : {};
    const rects = row?.rects && typeof row.rects === 'object' && !Array.isArray(row.rects) ? row.rects : {};
    return { id, title, locked, visible, rects };
  });
  let activeTabId = cleanString(bundle.activeTabId) || tabs[0].id;
  if (!tabs.some((t) => t.id === activeTabId)) activeTabId = tabs[0].id;
  const savedAt =
    typeof bundle.savedAt === 'number' && Number.isFinite(bundle.savedAt) ? bundle.savedAt : Date.now();
  return { version: 3, savedAt, activeTabId, tabs };
}

app.get('/me/portal-workspace-layout', requireAuth, async (req, res) => {
  const viewport = normalizePortalWorkspaceViewport(req.query?.viewport);
  if (!viewport) {
    return res.status(400).json({ success: false, error: 'viewport must be desktop or mobile' });
  }
  const layouts = req.user?.portalWorkspaceLayouts || {};
  const bundle = layouts[viewport] || null;
  res.json({ success: true, viewport, bundle });
});

app.put('/me/portal-workspace-layout', requireAuth, async (req, res) => {
  const viewport = normalizePortalWorkspaceViewport(req.body?.viewport);
  if (!viewport) {
    return res.status(400).json({ success: false, error: 'viewport must be desktop or mobile' });
  }
  const bundle = sanitizePortalWorkspaceBundle(req.body?.bundle);
  if (!bundle) {
    return res.status(400).json({ success: false, error: 'Invalid workspace bundle' });
  }
  const userId = String(req.user?.id || '').trim();
  if (!userId) {
    return res.status(400).json({ success: false, error: 'Missing user id' });
  }
  try {
    await pool.query(
      `UPDATE users
       SET portal_workspace_layouts = COALESCE(portal_workspace_layouts, '{}'::jsonb) || $2::jsonb,
           updated_at = NOW()
       WHERE CAST(id AS text) = $1`,
      [userId, JSON.stringify({ [viewport]: bundle })]
    );
    const fresh = await readFreshUserFromPostgresById(userId);
    if (!fresh) {
      return res.status(404).json({ success: false, error: 'User not found after update' });
    }
    res.json({ success: true, user: fresh, viewport, bundle });
  } catch (error) {
    console.error('[me/portal-workspace-layout]', error);
    res.status(500).json({ success: false, error: error.message || 'Server error' });
  }
});

app.post('/me/product-tutorials-seen', requireAuth, async (req, res) => {
  const product = cleanString(req.body?.product).toLowerCase();
  if (product !== 'pipeshare' && product !== 'pipesync') {
    return res.status(400).json({ success: false, error: 'product must be pipeshare or pipesync' });
  }
  const completed = req.body?.completed !== false;
  const userId = String(req.user?.id || '').trim();
  if (!userId) {
    return res.status(400).json({ success: false, error: 'Missing user id' });
  }
  try {
    if (completed) {
      await pool.query(
        `UPDATE users
         SET product_tutorials_seen = COALESCE(product_tutorials_seen, '{}'::jsonb) || $2::jsonb,
             updated_at = NOW()
         WHERE CAST(id AS text) = $1`,
        [userId, JSON.stringify({ [product]: true })]
      );
    } else {
      await pool.query(
        `UPDATE users
         SET product_tutorials_seen = COALESCE(product_tutorials_seen, '{}'::jsonb) - $2::text,
             updated_at = NOW()
         WHERE CAST(id AS text) = $1`,
        [userId, product]
      );
    }
    const fresh = await readFreshUserFromPostgresById(userId);
    if (!fresh) {
      return res.status(404).json({ success: false, error: 'User not found after update' });
    }
    res.json({ success: true, user: fresh });
  } catch (error) {
    console.error('[me/product-tutorials-seen]', error);
    res.status(500).json({ success: false, error: error.message || 'Server error' });
  }
});

/** Admin: clear guided-tutorial flags for another account (both products). */
app.post('/users/:id/product-tutorials-reset', requireAuth, requireAdminPanelAccess, async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'User id is required' });
  }
  try {
    await pool.query(`UPDATE users SET product_tutorials_seen = '{}'::jsonb, updated_at = NOW() WHERE CAST(id AS text) = $1`, [
      id
    ]);
    const fresh = await readFreshUserFromPostgresById(id);
    if (!fresh) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true, user: fresh });
  } catch (error) {
    console.error('[users/:id/product-tutorials-reset]', error);
    res.status(500).json({ success: false, error: error.message || 'Server error' });
  }
});

app.get('/data-auto-sync/access', requireAuth, requireDataAutoSyncEmployeeAccess, async (req, res) => {
  res.json({ success: true, allowed: true });
});

/** WinCan / desktop EXE pushes rows using the same session token as the web planner (not a static API key). */
app.post('/auto-import-plugin/push', requireAuth, requireDataAutoSyncEmployeeAccess, async (req, res) => {
  try {
    const body = req.body || {};
    const source = String(body.source || 'desktop').trim() || 'desktop';
    const rows = Array.isArray(body.rows) ? body.rows : [];
    const rowCount = rows.length;

    /**
     * The DAS monitor reads `auto_import_projects` + `auto_import_logs` from Postgres first. This route used to be
     * a no-op JSON ack, so the queue + live log stayed empty even when uploads "worked". Persist a log line (and
     * optionally touch a project row when `db3Path` is sent) on **live Postgres** so the portal monitor reflects activity.
     */
    const logId = crypto.randomUUID();
    const msg =
      cleanString(body.message || '').slice(0, 2000) ||
      (rowCount ? `Push received: ${rowCount} row(s)` : 'Push received (ping)');
    const payloadJson = JSON.stringify({
      rowCount,
      username: req.user?.username || '',
      db3Path: body.db3Path != null ? String(body.db3Path).slice(0, 800) : ''
    });
    try {
      await pool.query(
        `INSERT INTO auto_import_logs (id, project_id, source, level, message, payload)
         VALUES ($1, NULL, $2, 'info', $3, $4::jsonb)`,
        [logId, source.slice(0, 64), msg, payloadJson]
      );
    } catch (e) {
      console.warn('[auto-import-plugin/push] log insert skipped:', e?.message || e);
    }

    const db3Raw = cleanString(body.db3Path || '');
    if (db3Raw) {
      try {
        const absPath = path.resolve(db3Raw);
        const sourceKey = crypto.createHash('sha1').update(absPath).digest('hex');
        const displayName = cleanString(body.displayName || '') || path.basename(absPath);
        const existing = await pool.query('SELECT id FROM auto_import_projects WHERE source_key = $1 LIMIT 1', [
          sourceKey
        ]);
        if (existing.rows[0]) {
          await pool.query(
            `UPDATE auto_import_projects
             SET display_name = COALESCE(NULLIF($2::text, ''), display_name),
                 db3_path = $3,
                 last_seen_at = NOW(),
                 updated_at = NOW()
             WHERE source_key = $1`,
            [sourceKey, displayName, absPath]
          );
        } else {
          const projectId = crypto.randomUUID();
          await pool.query(
            `INSERT INTO auto_import_projects (
              id, source_key, display_name, db3_path, status, last_seen_at, metadata, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, 'idle', NOW(), '{}'::jsonb, NOW(), NOW())`,
            [projectId, sourceKey, displayName, absPath]
          );
        }
      } catch (e) {
        console.warn('[auto-import-plugin/push] project touch skipped:', e?.message || e);
      }
    }

    return res.json({
      success: true,
      message: rowCount ? 'Auto import payload received.' : 'Auto import test received.',
      received: {
        source,
        rowCount
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
    const mustChange =
      req.user?.mustChangePassword === true ||
      row.must_change_password === true ||
      row.must_change_password === 'true';

    let currentOk = false;
    if (mustChange) {
      // First-login / default-password flow: session already authenticated; new password only.
      currentOk = true;
    } else if (!currentPassword) {
      return res.status(400).json({ success: false, error: 'Current password is required' });
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
    try {
      await pool.query(
        'UPDATE users SET password = $1, must_change_password = false, updated_at = NOW() WHERE id = $2',
        [hash, req.user.id]
      );
    } catch (pgErr) {
      if (!wasabiWrote) throw pgErr;
      console.warn(
        `[change-password] Postgres mirror failed after Wasabi write: ${pgErr?.message || pgErr}`
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

app.post('/create-user', requireAuth, requireAdminPanelOrTenantUserManagement, async (req, res) => {
  const username = cleanString(req.body?.username);
  const displayName = cleanString(req.body?.displayName || username);
  const password = cleanString(req.body?.password || '1234');
  const hasAdminAccessPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'adminAccess');
  const hasSuperAdminAccessPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'superAdminAccess');
  const accountType = normalizeAccountType(req.body?.accountType || ACCOUNT_TYPES.EMPLOYEE);
  const requestedEmployeeRoleRaw = normalizeEmployeeRole(req.body?.employeeRole || '');
  const requestedRoleIsLegacyAdmin =
    requestedEmployeeRoleRaw === EMPLOYEE_ROLES.ADMIN || requestedEmployeeRoleRaw === EMPLOYEE_ROLES.SUPERADMIN;
  let adminAccess = hasAdminAccessPayload ? !!req.body?.adminAccess : requestedRoleIsLegacyAdmin;
  let superAdminAccess = hasSuperAdminAccessPayload
    ? !!req.body?.superAdminAccess
    : requestedEmployeeRoleRaw === EMPLOYEE_ROLES.SUPERADMIN;
  if (!adminAccess) superAdminAccess = false;
  let employeeRole = null;
  if (accountType === ACCOUNT_TYPES.EMPLOYEE) {
    const requestedWorkerRole =
      requestedEmployeeRoleRaw === EMPLOYEE_ROLES.CAMERA_OPERATOR ||
      requestedEmployeeRoleRaw === EMPLOYEE_ROLES.VAC_OPERATOR ||
      requestedEmployeeRoleRaw === EMPLOYEE_ROLES.SIMPLE_VAC
        ? requestedEmployeeRoleRaw
        : EMPLOYEE_ROLES.CAMERA_OPERATOR;
    employeeRole = superAdminAccess ? EMPLOYEE_ROLES.SUPERADMIN : adminAccess ? EMPLOYEE_ROLES.ADMIN : requestedWorkerRole;
  }
  const actorIsMike = isMikeStricklandUser(req.user);
  const targetLooksMike =
    looksLikeMike({ username, displayName, email: req.body?.email }) || username.toLowerCase() === 'mik';
  if (employeeRole === EMPLOYEE_ROLES.SUPERADMIN) {
    if (!actorIsMike || !targetLooksMike) {
      return res.status(403).json({
        success: false,
        error: 'SuperAdmin can only be assigned by Mike Strickland to Mike Strickland.'
      });
    }
  }
  if (accountType === ACCOUNT_TYPES.CUSTOMER) employeeRole = null;
  const isAdmin = employeeRole === EMPLOYEE_ROLES.ADMIN || employeeRole === EMPLOYEE_ROLES.SUPERADMIN;
  const roles = legacyRolesForAccountModel({ accountType, employeeRole }, normalizeRoles(req.body?.roles));

  if (!username) {
    return res.status(400).json({ success: false, error: 'Username is required' });
  }

  let insertedPgId = null;
  try {
    const hash = await bcrypt.hash(password, 10);

    const usernameCheck = await assertUsernameAvailableForCreate(pool, username, req.tenantScope);
    if (!usernameCheck.ok) {
      return res.status(409).json({ success: false, error: usernameCheck.error });
    }

    if (WASABI_WRITES_PRIMARY_ENABLED && req.tenantScope?.mode !== 'tenant') {
      try {
        const snapshot = await loadWasabiLatestStateSnapshot(true);
        const usernameLower = String(username).trim().toLowerCase();
        if (
          snapshotRows(snapshot, 'users').some(
            (u) => String(u.username || '').trim().toLowerCase() === usernameLower
          )
        ) {
          return res.status(409).json({ success: false, error: 'Username already exists' });
        }
      } catch (preSnapErr) {
        console.warn('[create-user] Could not pre-check Wasabi users list:', preSnapErr?.message || preSnapErr);
      }
    }

    const result = await pool.query(
      `INSERT INTO users (
         username, display_name, password, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, true, $8, $9, $10, false)
       RETURNING id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, autosync_master_granted, self_signup`,
      [
        username,
        displayName,
        hash,
        isAdmin,
        accountType,
        employeeRole,
        JSON.stringify(roles),
        req.tenantScope?.mode === 'tenant' ? req.tenantScope.portalClientId : null,
        req.tenantScope?.mode === 'tenant' ? req.tenantScope.portalJobId || '1' : null,
        false
      ]
    );
    insertedPgId = result.rows[0].id;

    if (req.tenantScope?.mode === 'tenant') {
      await pool.query(
        `INSERT INTO user_company_membership (user_id, company_id, role_key, override_folder_grants)
         VALUES ($1, $2, 'employee', '[]'::jsonb)
         ON CONFLICT (user_id) DO UPDATE
         SET company_id = EXCLUDED.company_id,
             updated_at = NOW()`,
        [String(insertedPgId), req.tenantScope.companyId]
      );
    }

    /**
     * GET /users reads Postgres for the permissions UI. When Wasabi writes are primary, mirror new users into the
     * snapshot using the same id as Postgres so PUT /users/:id stays aligned with the snapshot.
     */
    if (WASABI_WRITES_PRIMARY_ENABLED && req.tenantScope?.mode !== 'tenant') {
      const wrote = await tryWasabiStateWrite('create-user', async (data) => {
        const users = ensureSnapshotTable(data, 'users');
        const usernameLower = String(username).trim().toLowerCase();
        const duplicate = users.some((u) => String(u.username || '').trim().toLowerCase() === usernameLower);
        if (duplicate) {
          const err = new Error('Username already exists');
          err.code = '23505';
          throw err;
        }
        users.push({
          id: insertedPgId,
          username,
          display_name: displayName,
          password: hash,
          is_admin: isAdmin === true,
          account_type: accountType,
          employee_role: employeeRole,
          roles: normalizeRoles(roles),
          must_change_password: true,
          portal_files_client_id: null,
          portal_files_job_id: null,
          portal_files_access_granted: false,
          autosync_master_granted: false,
          self_signup: false,
          portal_permissions_access: false,
          email_verified: true,
          created_at: nowIso(),
          updated_at: nowIso()
        });
      });
      if (!wrote) {
        console.warn(
          '[create-user] Wasabi snapshot was not updated; user row exists in Postgres (admin list / GET /users).'
        );
      }
    }

    const user = await attachScopesToUser(normalizeUser(result.rows[0]));
    if (req.tenantScope?.mode === 'tenant') {
      await syncTenantUserMirrors(req.tenantScope, result.rows[0]);
    }
    const assignedAtCreate = userHasAnyAssignedAccess({
      account_type: user?.accountType,
      employee_role: user?.employeeRole,
      is_admin: user?.isAdmin === true,
      roles: user?.roles || {},
      portal_files_access_granted: user?.portalFilesAccessGranted === true,
      autosync_master_granted: user?.autosyncMasterGranted === true,
      portal_permissions_access: user?.portalPermissionsAccessRaw === true,
      username: user?.username || ''
    });
    res.status(201).json({
      success: true,
      user,
      message: assignedAtCreate
        ? 'User created. They can sign in immediately with the assigned roles/permissions.'
        : 'User created. They can sign in now, but no work access is assigned yet.'
    });
  } catch (error) {
    if (insertedPgId) {
      await pool.query('DELETE FROM users WHERE id = $1', [insertedPgId]).catch(() => {});
    }
    console.error('CREATE USER ERROR:', error);
    if (error.code === '23505') {
      return res.status(409).json({ success: false, error: 'Username already exists' });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/users/:id', requireAuth, requireAdminPanelOrTenantUserManagement, async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'User id is required' });
  }
  if (req.tenantScope?.mode === 'tenant') {
    const allowed = await assertUserIdInTenantScope(pool, id, req.tenantScope);
    if (!allowed) {
      return res.status(403).json({ success: false, error: 'User is outside your workspace' });
    }
  }
  const displayName = cleanString(req.body?.displayName || req.body?.name);
  const hasAccountTypePayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'accountType');
  const hasEmployeeRolePayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'employeeRole');
  const hasAdminAccessPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'adminAccess');
  const hasSuperAdminAccessPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'superAdminAccess');
  const legacyIsAdmin = req.body?.isAdmin === undefined ? null : !!req.body.isAdmin;
  const legacyRolesInput = req.body?.roles === undefined ? null : normalizeRoles(req.body.roles);
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
  const hasAutosyncMasterPayload = Object.prototype.hasOwnProperty.call(
    req.body || {},
    'autosyncMasterGranted'
  );
  const hasSelfSignupPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'selfSignup');
  const hasPortalPermissionsPayload = Object.prototype.hasOwnProperty.call(
    req.body || {},
    'portalPermissionsAccess'
  );
  const hasPortalScopesPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'portalScopes');
  const hasPsrScopesPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'psrScopes');
  const hasLegacyScopeMutationPayload = hasPortalScopesPayload || hasPsrScopesPayload;
  const hasCompanyPayload = Object.prototype.hasOwnProperty.call(req.body || {}, 'companyId');
  const hasCompanyRolePayload =
    Object.prototype.hasOwnProperty.call(req.body || {}, 'companyRoleKey') ||
    Object.prototype.hasOwnProperty.call(req.body || {}, 'roleKey');

  try {
    let current = null;
    const currentResult = await pool.query(
      'SELECT id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, autosync_master_granted, portal_permissions_access, self_signup FROM users WHERE id = $1 LIMIT 1',
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
            account_type: snapshotUser.accountType,
            employee_role: snapshotUser.employeeRole,
            roles: snapshotUser.roles,
            must_change_password: snapshotUser.mustChangePassword,
            portal_files_client_id: snapshotUser.portalFilesClientId,
            portal_files_job_id: snapshotUser.portalFilesJobId,
            portal_files_access_granted: snapshotUser.portalFilesAccessGranted,
            autosync_master_granted: snapshotUser.autosyncMasterGranted === true,
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
    const legacyScopeWarnings = [];
    if (hasLegacyScopeMutationPayload) {
      console.warn('[update-user] legacy scope payload ignored', {
        userId: id,
        hasPortalScopesPayload,
        hasPsrScopesPayload
      });
      if (hasPortalScopesPayload) legacyScopeWarnings.push('portalScopes payload ignored (legacy scopes disabled)');
      if (hasPsrScopesPayload) legacyScopeWarnings.push('psrScopes payload ignored (legacy scopes disabled)');
    }

    const nextDisplayName = displayName || current.display_name || current.username;
    const actorIsGlobalAdmin = isAdminUser(req.user);
    const actorIsMike = isMikeStricklandUser(req.user);
    const currentModel = deriveAccountModel({
      accountType: current.account_type,
      employeeRole: current.employee_role,
      isAdmin: current.is_admin,
      roles: current.roles,
      username: current.username,
      display_name: current.display_name
    });
    let nextAccountType = hasAccountTypePayload
      ? normalizeAccountType(req.body?.accountType)
      : currentModel.accountType;
    const currentIsAdminRole =
      currentModel.employeeRole === EMPLOYEE_ROLES.ADMIN || currentModel.employeeRole === EMPLOYEE_ROLES.SUPERADMIN;
    const currentIsSuperAdminRole = currentModel.employeeRole === EMPLOYEE_ROLES.SUPERADMIN;
    const requestedEmployeeRoleRaw = hasEmployeeRolePayload ? normalizeEmployeeRole(req.body?.employeeRole || '') : '';
    const requestedRoleIsLegacyAdmin =
      requestedEmployeeRoleRaw === EMPLOYEE_ROLES.ADMIN || requestedEmployeeRoleRaw === EMPLOYEE_ROLES.SUPERADMIN;
    let adminAccess = hasAdminAccessPayload ? !!req.body?.adminAccess : currentIsAdminRole;
    let superAdminAccess = hasSuperAdminAccessPayload ? !!req.body?.superAdminAccess : currentIsSuperAdminRole;
    if (!hasAdminAccessPayload && !hasSuperAdminAccessPayload && hasEmployeeRolePayload && requestedRoleIsLegacyAdmin) {
      adminAccess = true;
      superAdminAccess = requestedEmployeeRoleRaw === EMPLOYEE_ROLES.SUPERADMIN;
    }
    if (!adminAccess) superAdminAccess = false;
    const currentWorkerRole =
      currentModel.employeeRole === EMPLOYEE_ROLES.CAMERA_OPERATOR ||
      currentModel.employeeRole === EMPLOYEE_ROLES.VAC_OPERATOR ||
      currentModel.employeeRole === EMPLOYEE_ROLES.SIMPLE_VAC
        ? currentModel.employeeRole
        : EMPLOYEE_ROLES.CAMERA_OPERATOR;
    const requestedWorkerRole =
      requestedEmployeeRoleRaw === EMPLOYEE_ROLES.CAMERA_OPERATOR ||
      requestedEmployeeRoleRaw === EMPLOYEE_ROLES.VAC_OPERATOR ||
      requestedEmployeeRoleRaw === EMPLOYEE_ROLES.SIMPLE_VAC
        ? requestedEmployeeRoleRaw
        : currentWorkerRole;
    let nextEmployeeRole = null;
    if (nextAccountType === ACCOUNT_TYPES.EMPLOYEE) {
      nextEmployeeRole = superAdminAccess
        ? EMPLOYEE_ROLES.SUPERADMIN
        : adminAccess
          ? EMPLOYEE_ROLES.ADMIN
          : (hasEmployeeRolePayload ? requestedWorkerRole : currentWorkerRole);
      if (!nextEmployeeRole) nextEmployeeRole = EMPLOYEE_ROLES.CAMERA_OPERATOR;
    } else {
      nextEmployeeRole = null;
      adminAccess = false;
      superAdminAccess = false;
    }
    if (!hasAccountTypePayload && !hasEmployeeRolePayload && (legacyIsAdmin !== null || legacyRolesInput !== null)) {
      if (legacyIsAdmin === true) {
        nextAccountType = ACCOUNT_TYPES.EMPLOYEE;
        nextEmployeeRole = EMPLOYEE_ROLES.ADMIN;
      } else if (legacyRolesInput?.simpleVac) {
        nextAccountType = ACCOUNT_TYPES.EMPLOYEE;
        nextEmployeeRole = EMPLOYEE_ROLES.SIMPLE_VAC;
      } else if (legacyRolesInput?.vac) {
        nextAccountType = ACCOUNT_TYPES.EMPLOYEE;
        nextEmployeeRole = EMPLOYEE_ROLES.VAC_OPERATOR;
      } else if (legacyRolesInput?.camera) {
        nextAccountType = ACCOUNT_TYPES.EMPLOYEE;
        nextEmployeeRole = EMPLOYEE_ROLES.CAMERA_OPERATOR;
      } else {
        nextAccountType = ACCOUNT_TYPES.CUSTOMER;
        nextEmployeeRole = null;
      }
    }
    if (looksLikeMike({ username: current.username, display_name: current.display_name, email: current.email })) {
      nextAccountType = ACCOUNT_TYPES.EMPLOYEE;
      adminAccess = true;
      superAdminAccess = true;
      nextEmployeeRole = EMPLOYEE_ROLES.SUPERADMIN;
    }
    if (nextEmployeeRole === EMPLOYEE_ROLES.SUPERADMIN) {
      const targetLooksMike = looksLikeMike({ username: current.username, display_name: nextDisplayName, email: current.email });
      if (!actorIsMike || !targetLooksMike) {
        return res.status(403).json({
          success: false,
          error: 'SuperAdmin can only be assigned by Mike Strickland to Mike Strickland.'
        });
      }
    }
    const nextIsAdmin = nextEmployeeRole === EMPLOYEE_ROLES.ADMIN || nextEmployeeRole === EMPLOYEE_ROLES.SUPERADMIN;
    if (!actorIsGlobalAdmin && current.is_admin && String(req.user?.id || '') !== String(id)) {
      return res.status(403).json({
        success: false,
        error: 'Only global admins can edit Horizon admin accounts.'
      });
    }
    const nextRoles = legacyRolesForAccountModel(
      { accountType: nextAccountType, employeeRole: nextEmployeeRole },
      legacyRolesInput === null ? normalizeRoles(current.roles) : legacyRolesInput
    );
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
    let nextPortalFilesAccessGranted = current.portal_files_access_granted === true;
    if (hasAccessPayload) {
      nextPortalFilesAccessGranted = !!req.body.portalFilesAccessGranted;
    } else if (hasPortalScopeInPayload && portalFilesClientId && portalFilesJobId) {
      nextPortalFilesAccessGranted = true;
    }
    let nextAutosyncMasterGranted = current.autosync_master_granted === true;
    if (hasAutosyncMasterPayload) {
      nextAutosyncMasterGranted = !!req.body.autosyncMasterGranted;
    }
    let nextSelfSignup = current.self_signup === true;
    if (hasSelfSignupPayload) {
      nextSelfSignup = !!req.body.selfSignup;
    }
    // When an admin approves/assigns access, this account should no longer be treated as locked self-signup.
    if (nextPortalFilesAccessGranted === true || nextAutosyncMasterGranted === true || nextIsAdmin === true) {
      nextSelfSignup = false;
    }
    if (looksLikeMike({ username: current.username, display_name: current.display_name, email: current.email })) {
      nextSelfSignup = false;
    }

    const nextPortalPermissionsAccess =
      nextIsAdmin && (hasPortalPermissionsPayload ? !!req.body.portalPermissionsAccess : true);
    if (nextPortalFilesAccessGranted !== true && !nextAutosyncMasterGranted) {
      nextPortalFilesClientId = null;
      nextPortalFilesJobId = null;
    }

    const passwordHash = password ? await bcrypt.hash(password, 10) : null;

    /**
     * GET /users always reads Postgres (permissions UI). When WASABI_WRITES_PRIMARY_ENABLED, the snapshot
     * is updated separately — without mirroring here, the next refresh would show stale toggles.
     */
    async function persistUserUpdateToPostgres() {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const updatedCoreResult = await client.query(
          `UPDATE users
           SET display_name = $1,
               is_admin = $2,
               account_type = $3,
               employee_role = $4,
               roles = $5::jsonb,
               portal_files_client_id = $6,
               portal_files_job_id = $7,
               portal_files_access_granted = $8,
               self_signup = $9,
               portal_permissions_access = $10,
               autosync_master_granted = $11,
               updated_at = NOW()
           WHERE id = $12
           RETURNING id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, autosync_master_granted, portal_permissions_access, self_signup`,
          [
            nextDisplayName,
            nextIsAdmin,
            nextAccountType,
            nextEmployeeRole,
            JSON.stringify(nextRoles),
            nextPortalFilesClientId,
            nextPortalFilesJobId,
            nextPortalFilesAccessGranted,
            nextSelfSignup,
            nextPortalPermissionsAccess,
            nextAutosyncMasterGranted,
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

        let updatedRow = updatedCoreResult.rows[0];
        if (passwordHash) {
          const pwResult = await client.query(
            `UPDATE users
             SET password = $1,
                 must_change_password = false,
                 updated_at = NOW()
             WHERE id = $2
             RETURNING id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, autosync_master_granted, portal_permissions_access, self_signup`,
            [passwordHash, id]
          );
          updatedRow = pwResult.rows[0];
        }

        /**
         * Keep the currently signed-in admin session alive while they edit their own permissions.
         * Revoking immediately here causes follow-up save/hydration calls to 401 and bounce to login.
         * For password changes (or editing another account), revoke sessions so new auth state applies.
         */
        const editingSelf = String(req.user?.id || '') === String(id || '');
        const shouldRevokeSessions = passwordHash != null || !editingSelf;
        if (shouldRevokeSessions) {
          await client.query('DELETE FROM auth_sessions WHERE user_id = $1', [String(id)]);
        }

        await client.query('COMMIT');
        return updatedRow;
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
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
          account_type: nextAccountType,
          employee_role: nextEmployeeRole,
          roles: normalizeRoles(nextRoles),
          portal_files_client_id: nextPortalFilesClientId || null,
          portal_files_job_id: nextPortalFilesJobId || null,
          portal_files_access_granted: nextPortalFilesAccessGranted === true,
          autosync_master_granted: nextAutosyncMasterGranted === true,
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

        const sessions = ensureSnapshotTable(data, 'auth_sessions');
        data.auth_sessions = sessions.filter((row) => String(row.user_id || '') !== String(id || ''));
      });
    }

    const pgRow = await persistUserUpdateToPostgres();
    const updatedResult = { rows: [pgRow] };

    if (hasCompanyPayload) {
      const companyId = cleanString(req.body?.companyId);
      let companyRoleKey = '';
      if (hasCompanyRolePayload) {
        companyRoleKey = cleanString(req.body?.companyRoleKey || req.body?.roleKey || 'employee').toLowerCase();
      } else {
        const membershipResult = await pool.query(
          `SELECT role_key
           FROM user_company_membership
           WHERE user_id = $1
           LIMIT 1`,
          [String(id)]
        );
        companyRoleKey = cleanString(membershipResult.rows[0]?.role_key || 'employee').toLowerCase();
      }
      if (!companyId) {
        await pool.query('DELETE FROM user_company_membership WHERE user_id = $1', [String(id)]);
      } else {
        await pool.query(
          `INSERT INTO user_company_membership (user_id, company_id, role_key, override_folder_grants)
           VALUES ($1, $2, $3, '[]'::jsonb)
           ON CONFLICT (user_id)
           DO UPDATE SET company_id = EXCLUDED.company_id, role_key = EXCLUDED.role_key, updated_at = NOW()`,
          [String(id), companyId, companyRoleKey || 'employee']
        );
      }
    }

    const user = await attachScopesToUser(normalizeUser(updatedResult.rows[0]));
    if (req.tenantScope?.mode === 'tenant') {
      await syncTenantUserMirrors(req.tenantScope, updatedResult.rows[0]);
    }
    res.json({
      success: true,
      user,
      ...(legacyScopeWarnings.length ? { deprecated: legacyScopeWarnings } : {})
    });
  } catch (error) {
    console.error('UPDATE USER ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/users/:id/elevate-horizon-admin', requireAuth, requireAdminPanelAccess, requireMike, async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'User id is required' });
  }
  try {
    const result = await pool.query(
      `UPDATE users
       SET is_admin = true,
           account_type = 'employee',
           employee_role = 'admin',
           self_signup = false,
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, autosync_master_granted, portal_permissions_access, self_signup`,
      [id]
    );
    if (!result.rowCount) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    await pool.query('DELETE FROM auth_sessions WHERE user_id = $1', [id]);
    return res.json({
      success: true,
      user: normalizeUser(result.rows[0])
    });
  } catch (error) {
    console.error('ELEVATE HORIZON ADMIN ERROR:', error);
    return res.status(500).json({ success: false, error: error.message || 'Elevation failed' });
  }
});

app.delete('/users/:id', requireAuth, requireAdminPanelOrTenantUserManagement, async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'User id is required' });
  }
  if (req.tenantScope?.mode === 'tenant') {
    const allowed = await assertUserIdInTenantScope(pool, id, req.tenantScope);
    if (!allowed) {
      return res.status(403).json({ success: false, error: 'User is outside your workspace' });
    }
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
    if (WASABI_WRITES_PRIMARY_ENABLED && req.tenantScope?.mode !== 'tenant') {
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
    if (req.tenantScope?.mode === 'tenant') {
      if (req.tenantScope.tenantSlug) {
        await removeTenantAuthUser(req.tenantScope.tenantSlug, id).catch(() => {});
      }
      if (req.tenantScope.postgresSchema) {
        await removeUserFromTenantLoginSchema(pool, req.tenantScope.postgresSchema, id).catch(() => {});
      }
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
        snapshotRecords = await readRecordsFromWasabiSnapshotForUser(req.user, req);
      } catch (error) {
        if (WASABI_RECORDS_PRIMARY_STRICT) throw error;
      }
      const out = sortPlannerRecordsForList(snapshotRecords);
return res.json({ success: true, records: out });
    }

    const pgRecords = await readPlannerRecordsFromPostgresForUser(req.user);

    if (!WASABI_RECORDS_PRIMARY_ENABLED) {
      const out = sortPlannerRecordsForList(pgRecords);
return res.json({ success: true, records: out });
    }

    let snapshotRecords = [];
    try {
      snapshotRecords = await readRecordsFromWasabiSnapshotForUser(req.user, req);
    } catch (error) {
      if (WASABI_RECORDS_PRIMARY_STRICT) throw error;
    }

    const merged = mergePlannerRecordsById(snapshotRecords, pgRecords);
    const out = sortPlannerRecordsForList(merged);
return res.json({ success: true, records: out });
  } catch (error) {
    console.error('GET RECORDS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

function normalizePlanWorkspaceBoardKey(raw) {
  const b = String(raw || '').trim();
  return PIPESYNC_PLAN_WORKSPACE_BOARDS.has(b) ? b : '';
}

function readPlanWorkspaceActiveMap(data) {
  const o = data?.pipesync_plan_workspace_active;
  if (!o || typeof o !== 'object' || Array.isArray(o)) {
    return { planView: null, pdfMapView: null };
  }
  return {
    planView: o.planView && typeof o.planView === 'object' ? o.planView : null,
    pdfMapView: o.pdfMapView && typeof o.pdfMapView === 'object' ? o.pdfMapView : null
  };
}

function planWorkspaceEntryIsNewer(candidate, incumbent) {
  if (!candidate?.saved_at) return false;
  if (!incumbent?.saved_at) return true;
  return String(candidate.saved_at) > String(incumbent.saved_at);
}

async function putPipesyncPlanWorkspaceSaveBlob(storageKey, bodyObj, planStorage) {
  const s3 = planStorage?.client || wasabiStateClient;
  const bucket = String(planStorage?.bucket || WASABI_STATE_BUCKET || '').trim();
  if (!s3 || !bucket) {
    throw new Error('Wasabi object storage is not configured.');
  }
  const json = JSON.stringify(bodyObj);
  if (json.length > PIPESYNC_PLAN_WORKSPACE_SAVE_MAX_BYTES) {
    throw new Error('Workspace save exceeds the maximum size.');
  }
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: storageKey,
      Body: Buffer.from(json, 'utf8'),
      ContentType: 'application/json'
    })
  );
}

async function readPipesyncPlanWorkspaceSaveBlob(storageKey, planStorage) {
  const s3 = planStorage?.client || wasabiStateClient;
  const bucket = String(planStorage?.bucket || WASABI_STATE_BUCKET || '').trim();
  if (!s3 || !bucket) {
    throw new Error('Wasabi object storage is not configured.');
  }
  if (!isValidPipesyncPlanWorkspaceSaveStorageKey(storageKey)) {
    throw new Error('Invalid workspace save storage key.');
  }
  const out = await s3.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: storageKey
    })
  );
  const raw = await bodyToBuffer(out.Body);
  const parsed = JSON.parse(raw.toString('utf8'));
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Workspace save blob is not valid JSON.');
  }
  return parsed;
}

async function loadHydratedWorkspaceBoardFromEntry(entry, planStorage) {
  if (!entry?.storage_key || !isValidPipesyncPlanWorkspaceSaveStorageKey(entry.storage_key)) return null;
  try {
    const snap = await readPipesyncPlanWorkspaceSaveBlob(entry.storage_key, planStorage);
    const board = snap?.board && typeof snap.board === 'object' ? snap.board : null;
    if (!board) return null;
    return hydratePlanBoardBranch(board, planStorage);
  } catch (err) {
    console.warn('Workspace save hydrate failed:', entry?.id, err?.message || err);
    return null;
  }
}

function prunePlanWorkspaceSaveIndex(rows, username, board) {
  const un = String(username || '').toLowerCase();
  const mine = rows
    .filter((r) => r && String(r.username || '').toLowerCase() === un && r.board === board)
    .sort((a, b) => String(b.saved_at || '').localeCompare(String(a.saved_at || '')));
  const dropIds = new Set(mine.slice(PIPESYNC_PLAN_WORKSPACE_SAVE_MAX_PER_USER_BOARD).map((r) => r.id));
  return rows.filter((r) => !dropIds.has(r.id));
}

function mergePlanViewPayloadBranch(existingPayload, boardKey, sanitizedBoard) {
  let payload =
    existingPayload && typeof existingPayload === 'object' && !Array.isArray(existingPayload)
      ? JSON.parse(JSON.stringify(existingPayload))
      : { v: 2, imagePlan: {}, pdfMapView: {} };
  if (payload.v !== 2 || !payload.imagePlan || !payload.pdfMap) {
    payload = { v: 2, imagePlan: {}, pdfMapView: {} };
  }
  if (boardKey === 'planView') payload.imagePlan = sanitizedBoard;
  else payload.pdfMap = sanitizedBoard;
  return sanitizePlanViewPayloadForPersist(payload);
}

app.get('/pipesync/plan-view', requireAuth, requirePsrViewerAccess, async (req, res) => {
  try {
    const un = pipesyncPlanViewUsernameKey(req.user);
    if (!un) {
      return res.json({ success: true, payload: null, updated_at: null });
    }
    if (!(await wasabiStateConfiguredForRequest(req))) {
      return res.json({ success: true, payload: null, updated_at: null, wasabi: false });
    }
    const tables = await loadSnapshotTablesForRequest(req, false);
    const rows = Array.isArray(tables[PIPESYNC_PLAN_VIEW_TABLE]) ? tables[PIPESYNC_PLAN_VIEW_TABLE] : [];
    const row = rows.find((r) => String(r?.username || '').toLowerCase() === un);
    let payload = row && row.payload && typeof row.payload === 'object' && !Array.isArray(row.payload) ? row.payload : null;
    if (payload) payload = await hydratePlanViewPayloadForResponse(payload, req);
    return res.json({
      success: true,
      payload,
      updated_at: row?.updated_at || null
    });
  } catch (error) {
    console.error('GET PIPESYNC PLAN VIEW:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/pipesync/plan-view', requireAuth, requirePsrViewerAccess, async (req, res) => {
  try {
    if (!WASABI_WRITES_PRIMARY_ENABLED) {
      return res.status(503).json({ success: false, error: 'Wasabi primary writes are disabled on this server.' });
    }
    if (!(await wasabiStateConfiguredForRequest(req))) {
      return res.status(503).json({ success: false, error: 'Wasabi state storage is not configured.' });
    }
    const un = pipesyncPlanViewUsernameKey(req.user);
    if (!un) {
      return res.status(400).json({ success: false, error: 'Account has no username for plan view storage.' });
    }
    const payload = req.body?.payload;
    if (payload == null || typeof payload !== 'object' || Array.isArray(payload)) {
      return res.status(400).json({ success: false, error: 'Body must be JSON { "payload": { ... } }.' });
    }
    const sanitized = sanitizePlanViewPayloadForPersist(payload);
    const json = JSON.stringify(sanitized);
    if (json.length > PIPESYNC_PLAN_VIEW_MAX_BYTES) {
      return res.status(413).json({ success: false, error: 'Plan view data exceeds the maximum save size.' });
    }
    const now = nowIso();
    await runWasabiStateWriteForRequest(req, `pipesync-plan-view:${un}`, async (data) => {
      const rows = ensureSnapshotTable(data, PIPESYNC_PLAN_VIEW_TABLE);
      const idx = rows.findIndex((r) => String(r?.username || '').toLowerCase() === un);
      const row = { username: un, payload: sanitized, updated_at: now };
      if (idx >= 0) rows[idx] = row;
      else rows.push(row);
    });
    return res.json({ success: true, updated_at: now });
  } catch (error) {
    console.error('PUT PIPESYNC PLAN VIEW:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post(
  '/pipesync/plan-view/upload-presign',
  requireAuth,
  requirePsrViewerAccess,
  express.json({ limit: '64kb' }),
  async (req, res) => {
    try {
      const planStorage = await planViewWasabiForRequest(req);
      if (!planStorage.configured) {
        return res.status(503).json({ success: false, error: 'Wasabi object storage is not configured' });
      }
      const { client: planS3, bucket: planBucket, rootPrefix } = planStorage;
      const fileName = cleanString(req.body?.fileName);
      let contentType = cleanString(req.body?.contentType || 'application/octet-stream');
      // Browsers often send application/octet-stream for PDFs — infer from filename.
      if (!contentType || contentType === 'application/octet-stream') {
        if (/\.pdf$/i.test(fileName)) contentType = 'application/pdf';
        else if (/\.png$/i.test(fileName)) contentType = 'image/png';
        else if (/\.jpe?g$/i.test(fileName)) contentType = 'image/jpeg';
        else if (/\.webp$/i.test(fileName)) contentType = 'image/webp';
      }
      const fileSize = Number(req.body?.fileSize);
      const reuseKey = cleanString(req.body?.storageKey);
      if (reuseKey && isValidPipesyncPlanPageStorageKey(reuseKey, rootPrefix)) {
        try {
          assertKeyWithinTenantRoot(reuseKey, rootPrefix);
        } catch {
          return res.status(403).json({ success: false, error: 'Forbidden' });
        }
        // Overwrite/update existing piece (e.g. bake PDF annotation into the file). fileName optional for naming.
      } else if (!fileName) {
        return res.status(400).json({ success: false, error: 'fileName is required (or provide storageKey to update existing)' });
      }
      if (!Number.isFinite(fileSize) || fileSize < 1 || fileSize > PIPESYNC_PLAN_VIEW_UPLOAD_MAX_BYTES) {
        return res.status(400).json({
          success: false,
          error: `fileSize must be between 1 and ${PIPESYNC_PLAN_VIEW_UPLOAD_MAX_BYTES} bytes`
        });
      }
      if (!isAllowedAdminAttachmentContentType(contentType, 'pipesync-plan-view')) {
        return res.status(400).json({ success: false, error: 'Only images and PDF files are allowed for plan view.' });
      }
      const storageKey =
        reuseKey && isValidPipesyncPlanPageStorageKey(reuseKey, rootPrefix)
          ? reuseKey
          : buildPipesyncPlanPageStorageKey(fileName, rootPrefix);
      const signed = await presignAdminAttachmentPut(
        planS3,
        planBucket,
        storageKey,
        contentType,
        ADMIN_ATTACHMENT_UPLOAD_TTL_SECONDS
      );
      let viewUrl = null;
      try {
        const getSigned = await presignAdminAttachmentGet(
          planS3,
          planBucket,
          storageKey,
          ADMIN_ATTACHMENT_VIEW_TTL_SECONDS
        );
        viewUrl = getSigned.url;
      } catch {
        /* client can reopen plan view to refresh */
      }
      return res.json({ success: true, ...signed, viewUrl });
    } catch (error) {
      console.error('PIPESYNC PLAN VIEW UPLOAD PRESIGN:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

app.post(
  '/pipesync/plan-view/delete-files',
  requireAuth,
  requirePsrViewerAccess,
  express.json({ limit: '256kb' }),
  async (req, res) => {
    try {
      const planStorage = await planViewWasabiForRequest(req);
      if (!planStorage.configured) {
        return res.status(503).json({ success: false, error: 'Wasabi object storage is not configured' });
      }
      const rawKeys = Array.isArray(req.body?.storageKeys) ? req.body.storageKeys : [];
      const storageKeys = [...new Set(rawKeys.map((k) => cleanString(k)).filter((k) => isValidPipesyncPlanPageStorageKey(k)))];
      if (!storageKeys.length) {
        return res.status(400).json({ success: false, error: 'storageKeys must include at least one valid plan page key.' });
      }
      await deletePipesyncPlanPageKeys(planStorage.client, planStorage.bucket, storageKeys);
      return res.json({ success: true, deleted: storageKeys.length });
    } catch (error) {
      console.error('PIPESYNC PLAN VIEW DELETE FILES:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

/** Presign GET for an existing plan-board PDF (or image) object when the client has storageKey but no view URL. */
app.post(
  '/pipesync/plan-view/read-url',
  requireAuth,
  requirePsrViewerAccess,
  express.json({ limit: '32kb' }),
  async (req, res) => {
    try {
      const planStorage = await planViewWasabiForRequest(req);
      if (!planStorage.configured) {
        return res.status(503).json({ success: false, error: 'Wasabi object storage is not configured' });
      }
      const { client: planS3, bucket: planBucket, rootPrefix } = planStorage;
      const storageKey = cleanString(req.body?.storageKey);
      if (!storageKey || !isPersistablePlanPdfStorageKey(storageKey, rootPrefix)) {
        return res.status(400).json({ success: false, error: 'A valid plan page storageKey is required.' });
      }
      try {
        assertKeyWithinTenantRoot(storageKey, rootPrefix);
      } catch {
        return res.status(403).json({ success: false, error: 'Forbidden' });
      }
      const { url } = await presignAdminAttachmentGet(
        planS3,
        planBucket,
        storageKey,
        ADMIN_ATTACHMENT_VIEW_TTL_SECONDS
      );
      return res.json({ success: true, url: typeof url === 'string' ? url : '' });
    } catch (error) {
      console.error('PIPESYNC PLAN VIEW READ URL:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

/** Newest workspace checkpoint per board across all users (for collaborative auto-load). */
app.get(
  '/pipesync/plan-view/workspace-saves/active',
  requireAuth,
  requirePsrViewerAccess,
  async (req, res) => {
    try {
      const un = pipesyncPlanViewUsernameKey(req.user);
      const planStorage = await planViewWasabiForRequest(req);
      if (!(await wasabiStateConfiguredForRequest(req))) {
        return res.json({ success: true, planView: null, pdfMapView: null, wasabi: false });
      }
      const tables = await loadSnapshotTablesForRequest(req, false);
      const rows = Array.isArray(tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE])
        ? tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE]
        : [];
      const pickLatestForBoard = (boardKey) =>
        rows
          .filter((r) => r && String(r.username || '').toLowerCase() === un && r.board === boardKey)
          .sort((a, b) => String(b.saved_at || '').localeCompare(String(a.saved_at || '')))[0] || null;

      // Per-user active workspace is the default for cross-device continuity.
      let planViewEntry = pickLatestForBoard('planView');
      let pdfMapViewEntry = pickLatestForBoard('pdfMapView');
      if (!planViewEntry || !pdfMapViewEntry) {
        const legacyActive = readPlanWorkspaceActiveMap(tables);
        if (!planViewEntry) planViewEntry = legacyActive.planView;
        if (!pdfMapViewEntry) pdfMapViewEntry = legacyActive.pdfMapView;
      }
      const [planViewBoard, pdfMapViewBoard] = await Promise.all([
        loadHydratedWorkspaceBoardFromEntry(planViewEntry, planStorage),
        loadHydratedWorkspaceBoardFromEntry(pdfMapViewEntry, planStorage)
      ]);
      return res.json({
        success: true,
        planView: planViewEntry
          ? {
              id: planViewEntry.id,
              username: planViewEntry.username,
              saved_at: planViewEntry.saved_at,
              board: planViewBoard
            }
          : null,
        pdfMapView: pdfMapViewEntry
          ? {
              id: pdfMapViewEntry.id,
              username: pdfMapViewEntry.username,
              saved_at: pdfMapViewEntry.saved_at,
              board: pdfMapViewBoard
            }
          : null
      });
    } catch (error) {
      console.error('GET PLAN WORKSPACE ACTIVE:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

/** Current user's workspace save history for one board. */
app.get(
  '/pipesync/plan-view/workspace-saves/mine',
  requireAuth,
  requirePsrViewerAccess,
  async (req, res) => {
    try {
      const un = pipesyncPlanViewUsernameKey(req.user);
      const board = normalizePlanWorkspaceBoardKey(req.query?.board);
      if (!un) return res.json({ success: true, saves: [] });
      if (!board) {
        return res.status(400).json({ success: false, error: 'Query board must be planView or pdfMapView.' });
      }
      if (!(await wasabiStateConfiguredForRequest(req))) {
        return res.json({ success: true, saves: [], wasabi: false });
      }
      const tables = await loadSnapshotTablesForRequest(req, false);
      const rows = Array.isArray(tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE])
        ? tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE]
        : [];
      const saves = rows
        .filter((r) => r && String(r.username || '').toLowerCase() === un && r.board === board)
        .sort((a, b) => String(b.saved_at || '').localeCompare(String(a.saved_at || '')))
        .map((r) => ({
          id: r.id,
          board: r.board,
          saved_at: r.saved_at,
          username: r.username,
          bytes: Number(r.bytes) || 0
        }));
      return res.json({ success: true, saves });
    } catch (error) {
      console.error('GET PLAN WORKSPACE MINE:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

/** Current user's most recent workspace save for one board (hydrated board body). */
app.get(
  '/pipesync/plan-view/workspace-saves/mine/latest',
  requireAuth,
  requirePsrViewerAccess,
  async (req, res) => {
    try {
      const un = pipesyncPlanViewUsernameKey(req.user);
      const board = normalizePlanWorkspaceBoardKey(req.query?.board);
      if (!un) return res.json({ success: true, save: null });
      if (!board) {
        return res.status(400).json({ success: false, error: 'Query board must be planView or pdfMapView.' });
      }
      const planStorage = await planViewWasabiForRequest(req);
      if (!(await wasabiStateConfiguredForRequest(req))) {
        return res.json({ success: true, save: null, wasabi: false });
      }
      const tables = await loadSnapshotTablesForRequest(req, false);
      const rows = Array.isArray(tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE])
        ? tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE]
        : [];
      const entry = rows
        .filter((r) => r && String(r.username || '').toLowerCase() === un && r.board === board)
        .sort((a, b) => String(b.saved_at || '').localeCompare(String(a.saved_at || '')))[0];
      if (!entry) return res.json({ success: true, save: null });
      const hydrated = await loadHydratedWorkspaceBoardFromEntry(entry, planStorage);
      return res.json({
        success: true,
        save: {
          id: entry.id,
          board: entry.board,
          saved_at: entry.saved_at,
          username: entry.username,
          boardData: hydrated
        }
      });
    } catch (error) {
      console.error('GET PLAN WORKSPACE MINE LATEST:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

/** Load one workspace save by id (owner only). */
app.get(
  '/pipesync/plan-view/workspace-saves/:saveId',
  requireAuth,
  requirePsrViewerAccess,
  async (req, res) => {
    try {
      const un = pipesyncPlanViewUsernameKey(req.user);
      const saveId = String(req.params?.saveId || '').trim();
      if (!un) return res.status(401).json({ success: false, error: 'Not signed in.' });
      if (!saveId) return res.status(400).json({ success: false, error: 'saveId is required.' });
      const planStorage = await planViewWasabiForRequest(req);
      if (!(await wasabiStateConfiguredForRequest(req))) {
        return res.status(503).json({ success: false, error: 'Wasabi object storage is not configured.' });
      }
      const tables = await loadSnapshotTablesForRequest(req, false);
      const rows = Array.isArray(tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE])
        ? tables[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE]
        : [];
      const entry = rows.find((r) => r && r.id === saveId);
      if (!entry || String(entry.username || '').toLowerCase() !== un) {
        return res.status(404).json({ success: false, error: 'Workspace save not found.' });
      }
      const hydrated = await loadHydratedWorkspaceBoardFromEntry(entry, planStorage);
      if (!hydrated) {
        return res.status(404).json({ success: false, error: 'Workspace save data is missing or invalid.' });
      }
      return res.json({
        success: true,
        save: {
          id: entry.id,
          board: entry.board,
          saved_at: entry.saved_at,
          username: entry.username,
          boardData: hydrated
        }
      });
    } catch (error) {
      console.error('GET PLAN WORKSPACE SAVE:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

/** Persist a workspace checkpoint to Wasabi (per-user history + global newest pointer). */
app.post(
  '/pipesync/plan-view/workspace-saves',
  requireAuth,
  requirePsrViewerAccess,
  express.json({ limit: '16mb' }),
  async (req, res) => {
    try {
      if (!WASABI_WRITES_PRIMARY_ENABLED) {
        return res.status(503).json({ success: false, error: 'Wasabi primary writes are disabled on this server.' });
      }
      if (!(await wasabiStateConfiguredForRequest(req))) {
        return res.status(503).json({ success: false, error: 'Wasabi object storage is not configured.' });
      }
      const planStorage = await planViewWasabiForRequest(req);
      if (!planStorage.configured) {
        return res.status(503).json({ success: false, error: 'Wasabi object storage is not configured.' });
      }
      const un = pipesyncPlanViewUsernameKey(req.user);
      if (!un) {
        return res.status(400).json({ success: false, error: 'Account has no username for plan view storage.' });
      }
      const boardKey = normalizePlanWorkspaceBoardKey(req.body?.boardKey || req.body?.board);
      const boardRaw = req.body?.board;
      if (!boardKey) {
        return res.status(400).json({ success: false, error: 'boardKey must be planView or pdfMapView.' });
      }
      if (!boardRaw || typeof boardRaw !== 'object' || Array.isArray(boardRaw)) {
        return res.status(400).json({ success: false, error: 'Body must include a board object snapshot.' });
      }
      const sanitizedBoard = sanitizePlanBoardBranch(boardRaw);
      const blobJson = JSON.stringify({ savedAt: nowIso(), boardKey, board: sanitizedBoard });
      if (blobJson.length > PIPESYNC_PLAN_WORKSPACE_SAVE_MAX_BYTES) {
        return res.status(413).json({ success: false, error: 'Workspace save exceeds the maximum size.' });
      }
      const rootPrefix = await tenantWasabiRootForRequest(req);
      const saveId = crypto.randomUUID();
      const storageKey = buildPipesyncPlanWorkspaceSaveStorageKey(saveId, rootPrefix);
      const savedAt = nowIso();
      await putPipesyncPlanWorkspaceSaveBlob(storageKey, {
        savedAt,
        boardKey,
        username: un,
        board: sanitizedBoard
      }, planStorage);
      const indexRow = {
        id: saveId,
        username: un,
        board: boardKey,
        saved_at: savedAt,
        storage_key: storageKey,
        bytes: blobJson.length
      };
      await runWasabiStateWriteForRequest(req, `pipesync-plan-workspace-save:${un}:${boardKey}`, async (data) => {
        const rows = ensureSnapshotTable(data, PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE);
        rows.push(indexRow);
        data[PIPESYNC_PLAN_WORKSPACE_SAVE_TABLE] = prunePlanWorkspaceSaveIndex(rows, un, boardKey);
        const active = readPlanWorkspaceActiveMap(data);
        const incumbent = active[boardKey];
        if (planWorkspaceEntryIsNewer(indexRow, incumbent)) {
          active[boardKey] = {
            id: saveId,
            username: un,
            board: boardKey,
            saved_at: savedAt,
            storage_key: storageKey
          };
          data.pipesync_plan_workspace_active = active;
        }
        const planRows = ensureSnapshotTable(data, PIPESYNC_PLAN_VIEW_TABLE);
        const pIdx = planRows.findIndex((r) => String(r?.username || '').toLowerCase() === un);
        const prevPayload = pIdx >= 0 && planRows[pIdx]?.payload ? planRows[pIdx].payload : null;
        const mergedPayload = mergePlanViewPayloadBranch(prevPayload, boardKey, sanitizedBoard);
        const planRow = { username: un, payload: mergedPayload, updated_at: savedAt };
        if (pIdx >= 0) planRows[pIdx] = planRow;
        else planRows.push(planRow);
      });
      return res.json({
        success: true,
        save: {
          id: saveId,
          board: boardKey,
          saved_at: savedAt,
          username: un
        }
      });
    } catch (error) {
      console.error('POST PLAN WORKSPACE SAVE:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  }
);

app.post('/records', requireAuth, requirePsrDataEntryAccess, async (req, res) => {
  try {
    const showStorm = req.body?.createStorm !== false;
    const showSanitary = !!req.body?.createSanitary;
    const record = {
      record_date: cleanString(req.body?.record_date || req.body?.date || new Date().toISOString().slice(0, 10)),
      client: upperCleanString(req.body?.client),
      city: upperCleanString(req.body?.city),
      street: upperCleanString(req.body?.street),
      jobsite: normalizeJobsiteName(req.body?.jobsite, req.body?.street),
      status: '',
      saved_by: req.user.displayName || req.user.username,
      systems: {
        storm: [],
        sanitary: []
      },
      systemBranches: { storm: showStorm, sanitary: showSanitary }
    };
    if (!userCanCreatePsrRecord(req.user, record)) return denyOutOfScope(res);

    const saved = await createPlannerRecord(record, req);
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
  const jobsiteWrite = persistedPlannerJobsiteForWrite(record);
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
        jobsite: jobsiteWrite,
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
        jobsite: jobsiteWrite,
        status: cleanString(record.status || ''),
        saved_by: cleanString(record.saved_by || ''),
        data: serializeRecordData(record),
        updated_at: nowIso()
      };
      rows[idx] = savedRow;
    }
  });
  if (PLANNER_STORE_WASABI_ONLY) {
    if (wasabiWrote && savedRow) return normalizeRecordRow(savedRow);
    throw new Error('Planner data is stored only in Wasabi; persist write failed. Check WASABI_WRITES_PRIMARY_ENABLED and bucket credentials.');
  }
  /**
   * Hybrid mode: GET /records uses Postgres whenever WASABI_RECORDS_PRIMARY_ENABLED is off (the default).
   * A successful Wasabi write used to return here without mirroring to Postgres, so edits existed only in
   * latest.json and disappeared on the next read. Always upsert Postgres when not Wasabi-only canonical.
   */
  const pgSource = wasabiWrote && savedRow ? normalizeRecordRow(savedRow) : record;
  const jobsiteForPg = persistedPlannerJobsiteForWrite(pgSource);
  const payload = [
    cleanString(pgSource.record_date),
    pgSource.client,
    pgSource.city,
    upperCleanString(pgSource.street),
    jobsiteForPg,
    cleanString(pgSource.status || ''),
    cleanString(pgSource.saved_by || ''),
    JSON.stringify(serializeRecordData(pgSource)),
    String(pgSource.id)
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
  if (!isPlannerRecordUuid(pgSource.id)) {
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

async function createPlannerRecord(record, req) {
  const id = crypto.randomUUID();
  let createdRow = null;
  const writeMutator = async (data) => {
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
    const uid = String(req?.user?.id || '').trim();
    if (uid && isTenantBoundUser(req?.user)) {
      const scopes = ensureSnapshotTable(data, 'user_psr_scopes');
      scopes.push({
        user_id: uid,
        client: createdRow.client,
        city: createdRow.city,
        jobsite: createdRow.jobsite,
        psr_record_id: id,
        created_at: now
      });
    }
  };
  const tenantScope = req ? await resolveTenantWasabiStateScope(pool, req) : null;
  if (tenantScope || (req && isTenantBoundUser(req?.user))) {
    await runWasabiStateWriteForRequest(req, 'create-planner-record', writeMutator);
  } else {
    const wasabiWrote = await tryWasabiStateWrite('create-planner-record', writeMutator);
    if (PLANNER_STORE_WASABI_ONLY && !wasabiWrote) {
      throw new Error(
        'Planner data is stored only in Wasabi; create failed. Enable WASABI_WRITES_PRIMARY_ENABLED=1 and configure Wasabi bucket keys.'
      );
    }
  }
  if (PLANNER_STORE_WASABI_ONLY) {
    if (!createdRow) {
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
  if (PLANNER_STORE_WASABI_ONLY) {
    return wasabiWrote ? deletedId : null;
  }
  /** Hybrid: mirror delete to Postgres; Wasabi-only returns above. */
  const result = await pool.query('DELETE FROM planner_records WHERE CAST(id AS text) = $1 RETURNING id', [String(id)]);
  if (result.rows.length) return result.rows[0].id;
  return deletedId;
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
  if (PLANNER_STORE_WASABI_ONLY) {
    return wasabiWrote ? deletedCount : 0;
  }
  /** Hybrid: always remove matching rows from Postgres as well. */
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

    if (req.body?.systemBranches && typeof req.body.systemBranches === 'object') {
      record.systemBranches = coerceSystemBranchesForStorage(req.body.systemBranches, record.systems);
    }

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
      systems: { storm: [], sanitary: [] },
      systemBranches: { storm: true, sanitary: false }
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
    if (segmentPatch.linkedPortalDb3FileId !== undefined) {
      found.linkedPortalDb3FileId = cleanString(segmentPatch.linkedPortalDb3FileId).slice(0, 128);
      found.linkedPortalDb3FolderPath = cleanString(segmentPatch.linkedPortalDb3FolderPath).slice(0, 800);
      found.linkedPortalDb3ClientId = cleanString(segmentPatch.linkedPortalDb3ClientId).slice(0, 128);
      found.linkedPortalDb3JobId = cleanString(segmentPatch.linkedPortalDb3JobId).slice(0, 128);
    }

    if (segmentPatch.db3ImportedPartial !== undefined && segmentPatch.db3ImportedPartial !== null) {
      const partial =
        typeof segmentPatch.db3ImportedPartial === 'object' && !Array.isArray(segmentPatch.db3ImportedPartial)
          ? segmentPatch.db3ImportedPartial
          : parseJsonObject(segmentPatch.db3ImportedPartial, {});
      const allowed = new Set(['HP_EDIT_INSPECTED_BY', 'HP_EDIT_CERTIFICATE_NO']);
      const cur = found.db3Imported && typeof found.db3Imported === 'object' ? { ...found.db3Imported } : {};
      for (const [k, v] of Object.entries(partial)) {
        const ku = String(k || '')
          .trim()
          .toUpperCase();
        if (!allowed.has(ku)) continue;
        const str =
          typeof v === 'number' && Number.isFinite(v)
            ? String(v)
            : String(v == null ? '' : v).trim();
        if (!str) delete cur[ku];
        else cur[ku] = str.slice(0, 4000);
      }
      found.db3Imported = sanitizeDb3ImportedObject(cur);
    }

    if (Object.keys(versionPatch).length) {
      if (isVacLineOperator(req.user) && versionPatch.status !== undefined) {
        const nextStatus = normalizeStatus(versionPatch.status);
        if (nextStatus !== 'jetted') {
          return res.status(403).json({
            success: false,
            error: 'Vac Operator and Simple Vac accounts can only mark status as Jetted.'
          });
        }
      }
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

app.get('/pipesync/pricing-state', requireAuth, requirePricingAccess, async (req, res) => {
  try {
    const un = pipesyncPlanViewUsernameKey(req.user);
    if (!un) {
      return res.json({ success: true, payload: null, updated_at: null });
    }
    if (!wasabiStateClient || !WASABI_STATE_BUCKET) {
      return res.json({ success: true, payload: null, updated_at: null, wasabi: false });
    }
    const snap = await loadWasabiLatestStateSnapshot(false);
    const tables = readWasabiSnapshotDataTables(snap || {}, { strict: false });
    const rows = Array.isArray(tables[PIPESYNC_PRICING_STATE_TABLE]) ? tables[PIPESYNC_PRICING_STATE_TABLE] : [];
    const row = rows.find((r) => String(r?.username || '').toLowerCase() === un);
    const payload = row?.payload ? sanitizePricingStatePayloadForPersist(row.payload) : null;
    return res.json({
      success: true,
      payload,
      updated_at: row?.updated_at || null
    });
  } catch (error) {
    console.error('GET PIPESYNC PRICING STATE:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/pipesync/pricing-state', requireAuth, requirePricingAccess, async (req, res) => {
  try {
    if (!WASABI_WRITES_PRIMARY_ENABLED) {
      return res.status(503).json({ success: false, error: 'Wasabi primary writes are disabled on this server.' });
    }
    if (!wasabiStateClient || !WASABI_STATE_BUCKET) {
      return res.status(503).json({ success: false, error: 'Wasabi state storage is not configured.' });
    }
    const un = pipesyncPlanViewUsernameKey(req.user);
    if (!un) {
      return res.status(400).json({ success: false, error: 'Account has no username for pricing storage.' });
    }
    const payload = req.body?.payload;
    if (payload == null || typeof payload !== 'object' || Array.isArray(payload)) {
      return res.status(400).json({ success: false, error: 'Body must be JSON { "payload": { ... } }.' });
    }
    const ifMissingOnly = req.body?.ifMissing === true;
    const sanitized = sanitizePricingStatePayloadForPersist(payload);
    const json = JSON.stringify(sanitized);
    if (json.length > PIPESYNC_PRICING_STATE_MAX_BYTES) {
      return res.status(413).json({ success: false, error: 'Pricing state exceeds the maximum save size.' });
    }

    const now = nowIso();
    let didWrite = false;
    let resolvedRow = null;
    await runWasabiStateWrite(`pipesync-pricing-state:${un}`, async (data) => {
      const rows = ensureSnapshotTable(data, PIPESYNC_PRICING_STATE_TABLE);
      const idx = rows.findIndex((r) => String(r?.username || '').toLowerCase() === un);
      const existing = idx >= 0 ? rows[idx] : null;
      if (ifMissingOnly && existing) {
        resolvedRow = existing;
        return;
      }
      const row = { username: un, payload: sanitized, updated_at: now };
      if (idx >= 0) rows[idx] = row;
      else rows.push(row);
      didWrite = true;
      resolvedRow = row;
    });

    if (!didWrite) {
      return res.json({
        success: true,
        seeded: false,
        payload: resolvedRow?.payload ? sanitizePricingStatePayloadForPersist(resolvedRow.payload) : null,
        updated_at: resolvedRow?.updated_at || null
      });
    }
    return res.json({ success: true, seeded: ifMissingOnly ? true : undefined, payload: sanitized, updated_at: now });
  } catch (error) {
    console.error('PUT PIPESYNC PRICING STATE:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/admin/attachments/upload-presign', requireAuth, requireAdmin, express.json({ limit: '64kb' }), async (req, res) => {
  try {
    if (!adminAttachmentsWasabiConfigured()) {
      return res.status(503).json({ success: false, error: 'Wasabi object storage is not configured' });
    }
    const rootPrefix = await tenantWasabiRootForRequest(req);
    const fileName = cleanString(req.body?.fileName);
    const contentType = cleanString(req.body?.contentType || 'application/octet-stream');
    const fileSize = Number(req.body?.fileSize);
    const fileKind =
      String(req.body?.fileKind || 'jobsite-asset').trim().toLowerCase() === 'daily-report' ? 'daily-report' : 'jobsite-asset';
    if (!fileName) return res.status(400).json({ success: false, error: 'fileName is required' });
    if (!Number.isFinite(fileSize) || fileSize < 1 || fileSize > ADMIN_ATTACHMENT_MAX_BYTES) {
      return res.status(400).json({
        success: false,
        error: `fileSize must be between 1 and ${ADMIN_ATTACHMENT_MAX_BYTES} bytes`
      });
    }
    if (!isAllowedAdminAttachmentContentType(contentType, fileKind)) {
      return res.status(400).json({ success: false, error: 'Unsupported content type for this upload kind' });
    }
    const storageKey = buildAdminAttachmentStorageKey(fileName, rootPrefix);
    const signed = await presignAdminAttachmentPut(
      wasabiStateClient,
      WASABI_STATE_BUCKET,
      storageKey,
      contentType,
      ADMIN_ATTACHMENT_UPLOAD_TTL_SECONDS
    );
    return res.json({ success: true, ...signed });
  } catch (error) {
    console.error('ADMIN ATTACHMENT PRESIGN ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/daily-reports', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (WASABI_APP_DATA_STORE_WASABI_ONLY) {
      const reports = (await readDailyReportsFromWasabiSnapshot()) || [];
      return res.json({ success: true, reports: await hydrateDailyReportsResponseRows(reports) });
    }
    if (WASABI_REPORTS_PRIMARY_ENABLED) {
      try {
        const snapshotReports = await readDailyReportsFromWasabiSnapshot();
        if (snapshotReports) {
          return res.json({ success: true, reports: await hydrateDailyReportsResponseRows(snapshotReports) });
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
    res.json({ success: true, reports: await hydrateDailyReportsResponseRows(reports) });
  } catch (error) {
    console.error('GET DAILY REPORTS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/daily-reports', requireAuth, requireAdmin, express.json({ limit: '20mb' }), async (req, res) => {
  try {
    const files = normalizeAdminFilesForPersist(req.body?.files);
    const created = await createDailyReport({
      title: cleanString(req.body?.title),
      report_date: cleanString(req.body?.report_date || new Date().toISOString().slice(0, 10)),
      notes: cleanString(req.body?.notes),
      files,
      created_by: req.user.displayName || req.user.username
    });
    const hydrated = (await hydrateDailyReportsResponseRows([created]))[0] || created;
    res.status(201).json({ success: true, report: hydrated });
  } catch (error) {
    console.error('CREATE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/daily-reports/:id', requireAuth, requireAdmin, express.json({ limit: '20mb' }), async (req, res) => {
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
    const addedFiles = Array.isArray(req.body?.files) ? req.body.files : [];
    const nextFiles = normalizeAdminFilesForPersist([...keptFiles, ...addedFiles]);
    const removedKeys = storageKeysRemovedBetweenFileLists(currentFiles, nextFiles);
    if (adminAttachmentsWasabiConfigured() && removedKeys.length) {
      await deleteAdminAttachmentKeys(wasabiStateClient, WASABI_STATE_BUCKET, removedKeys);
    }
    const updated = await updateDailyReportById(req.params.id, {
      title: cleanString(req.body?.title),
      report_date: cleanString(req.body?.report_date || current.report_date),
      notes: cleanString(req.body?.notes),
      files: nextFiles
    });
    const hydrated = (await hydrateDailyReportsResponseRows([updated]))[0] || updated;
    res.json({ success: true, report: hydrated });
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
      const assets = (await readJobsiteAssetsFromWasabiSnapshotForUser(req.user, req)) || [];
      return res.json({ success: true, assets: await hydrateJobsiteAssetsResponseRows(assets) });
    }
    if (WASABI_ASSETS_PRIMARY_ENABLED) {
      try {
        const snapshotAssets = await readJobsiteAssetsFromWasabiSnapshotForUser(req.user, req);
        if (snapshotAssets) {
          return res.json({ success: true, assets: await hydrateJobsiteAssetsResponseRows(snapshotAssets) });
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
    res.json({ success: true, assets: await hydrateJobsiteAssetsResponseRows(assets) });
  } catch (error) {
    console.error('GET JOBSITE ASSETS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/jobsite-assets', requireAuth, requireAdmin, express.json({ limit: '20mb' }), async (req, res) => {
  try {
    const files = normalizeAdminFilesForPersist(req.body?.files);
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
    const hydrated = (await hydrateJobsiteAssetsResponseRows([created]))[0] || created;
    res.status(201).json({ success: true, asset: hydrated });
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
    const scope = resolveWincanImportScope(req.body, rows);
    let { targetClient, targetCity, targetJobsite, targetSystem } = scope;
    let existingRecords = [];
    if (scope.targetRecordId) {
      const selectedRecord = await fetchRecordById(scope.targetRecordId);
      if (!selectedRecord) {
        return res.status(400).json({ success: false, error: 'Selected PSR job no longer exists. Re-pick a green job and preview again.' });
      }
      targetClient = selectedRecord.client;
      targetCity = selectedRecord.city;
      targetJobsite = normalizeJobsiteName(selectedRecord.jobsite, selectedRecord.street);
      existingRecords = [selectedRecord];
    } else {
      existingRecords = await findPlannerRecordsByScope(targetClient, targetCity, targetJobsite, { latestOnly: false });
    }
    const existingDedupeKeys = new Set();
    const existingDedupeHashes = new Set();
    const existingRefs = new Set();
    existingRecords.forEach((record) => {
      const scoped = collectRecordDb3IdentitySets(record, targetSystem);
      scoped.dedupeKeys.forEach((key) => existingDedupeKeys.add(key));
      scoped.dedupeHashes.forEach((hash) => existingDedupeHashes.add(hash));
      scoped.references.forEach((ref) => existingRefs.add(ref));
    });

    const refKeys = rows.map((row) => String(row?.reference || '').trim().toLowerCase()).filter(Boolean);
    const placedDupMap = await findPlacedDuplicatePayloadsByReferences(refKeys, {
      client: targetClient,
      city: targetCity,
      jobsite: targetJobsite
    });

    const previewRows = rows.map((row) => {
      const refKey = String(row?.reference || '').trim().toLowerCase();
      const identity = buildDb3DeterministicIdentity(row);
      const placedDup = refKey ? placedDupMap.get(refKey) : null;
      const duplicate =
        (identity.dedupeKey && existingDedupeKeys.has(identity.dedupeKey)) ||
        (identity.dedupeHash && existingDedupeHashes.has(identity.dedupeHash.toLowerCase())) ||
        existingRefs.has(refKey);
      return {
        ...row,
        db3DedupeKey: identity.dedupeKey,
        db3RowHash: identity.dedupeHash,
        duplicate,
        existingInDatabase: duplicate,
        placedDuplicate: !!placedDup,
        placedDuplicateOf: placedDup || null
      };
    });

    const updateMode = String(req.body?.updateMode || '').trim() === '1' || String(req.body?.updateMode || '').toLowerCase() === 'true';
    if (updateMode) {
      console.warn('[db3-preview][plan-sync-update]', {
        strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
        targetRecordId: scope.targetRecordId || '',
        targetClient,
        targetCity,
        targetJobsite,
        targetSystem,
        rowCount: previewRows.length,
        existingCount: previewRows.filter((row) => row.duplicate).length,
        newCount: previewRows.filter((row) => !row.duplicate).length
      });
    }

    res.json({ success: true, sourceKind: 'DB3', defaultJobsite: cleanString(previewRows[0]?.project || 'NOT SET'), rows: previewRows, updateMode });
  } catch (error) {
    console.error('IMPORT PREVIEW ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/imports/wincan/commit', requireAuth, requireMike, async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
    const scope = resolveWincanImportScope(req.body, rows);
    let { targetClient, targetCity, targetJobsite, targetSystem } = scope;
    let selectedRecord = null;
    if (scope.targetRecordId) {
      selectedRecord = await fetchRecordById(scope.targetRecordId);
      if (!selectedRecord) {
        return res.status(400).json({ success: false, error: 'Selected PSR job no longer exists. Re-pick a green job and commit again.' });
      }
      targetClient = selectedRecord.client;
      targetCity = selectedRecord.city;
      targetJobsite = normalizeJobsiteName(selectedRecord.jobsite, selectedRecord.street);
    }
    if (!targetJobsite || targetJobsite === 'NOT SET') {
      return res.status(400).json({
        success: false,
        error: 'Could not determine jobsite. Enter a jobsite name or ensure the WinCan DB3 project name is set.'
      });
    }

    let record;
    if (selectedRecord) {
      record = selectedRecord;
    } else {
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
    }
    ensureImportTargetSystemBranch(record, targetSystem);

    const existingIdentity = collectRecordDb3IdentitySets(record, targetSystem);
    const refSet = existingIdentity.references;
    const dedupeKeySet = existingIdentity.dedupeKeys;
    const dedupeHashSet = existingIdentity.dedupeHashes;
    const commitRefKeys = rows.map((r) => String(r?.reference || '').trim().toLowerCase()).filter(Boolean);
    const placedAtCommit = await findPlacedDuplicatePayloadsByReferences(commitRefKeys, {
      client: targetClient,
      city: targetCity,
      jobsite: targetJobsite
    });

    rows.forEach((row) => {
      if (!row) return;
      const jobsiteDup = rowHasJobsiteDuplicateFlag(row);
      if (jobsiteDup && isDb3DuplicateExcludeDecision(row)) return;
      const refLower = String(row.reference || '').trim().toLowerCase();
      const identity = buildDb3DeterministicIdentity(row);
      const dedupeKey = String(row.db3DedupeKey || identity.dedupeKey || '').trim();
      const dedupeHash = String(row.db3RowHash || identity.dedupeHash || '').trim().toLowerCase();
      if (!jobsiteDup || !isDb3DuplicateIncludeDecision(row)) {
        if (refSet.has(refLower)) return;
        if (dedupeKey && dedupeKeySet.has(dedupeKey)) return;
        if (dedupeHash && dedupeHashSet.has(dedupeHash)) return;
      }
      const refKey = String(row.reference || '').trim().toLowerCase();
      const placedDup = placedAtCommit.get(refKey) || row.placedDuplicateOf || null;
      let importReference = row.reference;
      if (jobsiteDup && isDb3DuplicateIncludeDecision(row)) {
        importReference = nextDb3DuplicateReference(row.reference, refSet);
      }
      const dupNotes = placedDup
        ? 'Imported from WinCan DB3. Flagged: possible double entry (same OBJ_Key in this jobsite).'
        : 'Imported from WinCan DB3.';
      const renamedNote =
        importReference && String(importReference) !== String(row.reference || '')
          ? ` Imported as ${importReference}.`
          : '';
      const segment = normalizeSegment({
        id: crypto.randomUUID(),
        reference: importReference,
        upstream: row.upstream,
        downstream: row.downstream,
        dia: row.dia,
        material: row.material,
        shape: row.shape,
        length: row.length,
        footage: row.length,
        street: row.street,
        system: targetSystem,
        db3Imported: row.db3Imported,
        db3DuplicateOf: placedDup || undefined,
        db3DedupeKey: dedupeKey,
        db3RowHash: dedupeHash,
        versions: [
          defaultVersion(req.user.displayName || req.user.username, {
            status: 'neutral',
            recordedDate: record.record_date,
            notes: `${dupNotes}${renamedNote}`
          })
        ]
      }, req.user.displayName || req.user.username);
      if (!Array.isArray(record.systems[targetSystem])) record.systems[targetSystem] = [];
      record.systems[targetSystem].push(segment);
      refSet.add(String(segment.reference || '').toLowerCase());
      if (dedupeKey) dedupeKeySet.add(dedupeKey);
      if (dedupeHash) dedupeHashSet.add(dedupeHash);
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
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot(true);
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
  if (sql.startsWith('select * from auto_import_logs order by created_at desc limit')) {
    const snapshot = await requireFreshSnapshot();
    const limit = Math.max(1, Number(params[0] || 200));
    const rows = [...snapshotRows(snapshot, 'auto_import_logs')]
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
  if (!WASABI_AUTO_IMPORT_PRIMARY_ENABLED || !WASABI_WRITES_PRIMARY_ENABLED) {
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
  if (sql.includes('from portal_share_links where token = $1')) return true;
  if (sql.startsWith('select 1 from portal_share_guest_sessions where guest_token = $1 and share_link_id = $2'))
    return true;
  if (
    sql.startsWith(
      'select a.id, a.email, a.first_name as "firstname", a.last_name as "lastname", a.role, a.company, a.accessed_at as "accessedat", l.kind, l.token, l.created_at as "linkcreatedat" from portal_share_access_log a join portal_share_links l on l.id = a.share_link_id where l.client_id = $1 and l.job_id = $2 order by a.accessed_at desc limit 500'
    )
  )
    return true;
  if (
    sql.startsWith('insert into portal_share_links (id, token, client_id, job_id, kind, created_by_username, payload')
  )
    return true;
  if (sql.startsWith('update portal_share_links set revoked_at = now(), revoked_by_username = $2 where token = $1 returning revoked_at'))
    return true;
  if (sql.startsWith('insert into portal_share_access_log')) return true;
  if (sql.startsWith('insert into portal_share_guest_sessions')) return true;
  return false;
}

/**
 * SaaS unified permissions (company membership, role folder grants, per-user folder grants, legacy scopes)
 * live only in Postgres — not in the Wasabi auth snapshot. PipeShare boot and `/api/files/tree` read these
 * on every request via `loadEffectivePathGrantsForUser`; routing them through portal-data-primary strict
 * mode throws "Portal Wasabi adapter does not support this query shape" for customer/client users.
 */
function portalPermissionsLivePostgresSql(text) {
  const sql = normalizeSqlForPortalData(text);
  if (!sql) return false;
  return (
    sql.includes('user_company_membership') ||
    sql.includes('company_folder_grants') ||
    sql.includes('user_folder_grants') ||
    sql.includes('user_portal_scopes') ||
    sql.includes('user_psr_scopes') ||
    sql.includes('saas_tenant_instances') ||
    sql.includes(' from companies ') ||
    sql.includes(' join companies ') ||
    sql.includes('trash_bin_entries')
  );
}

/**
 * When WASABI_PORTAL_DATA_PRIMARY is on, mutating portal SQL is applied inside latest.json only.
 * PipeShare reads `portal_path_grants` (and share-link rows used by guests) from **live Postgres** (`aclPool`),
 * so Wasabi-only writes would look successful yet vanish on refresh — same class of bug as planner Postgres mirror.
 * Upload session tables are excluded: `queryPortalDataWithWasabiFallback` always forwards them to Postgres first.
 */
function portalBusinessDataSqlMirrorPostgresAfterWasabi(text) {
  const sql = normalizeSqlForPortalData(text);
  if (!sql || sql === 'begin' || sql === 'commit' || sql === 'rollback') return false;
  if (!/^(insert|update|delete)\s/.test(sql)) return false;
  if (sql.includes('portal_upload_sessions') || sql.includes('portal_upload_session_parts')) return false;
  return (
    sql.includes('portal_path_grants') ||
    sql.includes('portal_share_links') ||
    sql.includes('portal_share_access_log') ||
    sql.includes('portal_share_guest_sessions')
  );
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
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot(true);
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
        'insert into portal_share_links (id, token, client_id, job_id, kind, created_by_username, payload'
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
        created_at: now,
        expires_at: params[7] ? new Date(String(params[7])).toISOString() : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        revoked_at: null,
        revoked_by_username: null
      });
      outRows = [];
      return;
    }
    if (sql.startsWith('update portal_share_links set revoked_at = now(), revoked_by_username = $2 where token = $1 returning revoked_at')) {
      const token = String(params[0] || '');
      const by = params[1] == null ? null : String(params[1]);
      const row = shareLinks.find((r) => String(r.token || '') === token);
      if (row) {
        row.revoked_at = now;
        row.revoked_by_username = by;
      }
      outRows = [{ revoked_at: row ? row.revoked_at : null }];
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
  if (portalPermissionsLivePostgresSql(text)) {
    return pool.query(text, params);
  }
  if (!WASABI_PORTAL_DATA_PRIMARY_ENABLED || !WASABI_WRITES_PRIMARY_ENABLED) {
    return pool.query(text, params);
  }
  const normalizedSql = normalizeSqlForPortalData(text);
  try {
    const result = await runPortalDataWasabiQuery(text, params);
    if (result) {
      wasabiPortalDataHandledByWasabi += 1;
      if (portalBusinessDataSqlMirrorPostgresAfterWasabi(text)) {
        try {
          await pool.query(text, params);
        } catch (mirrorErr) {
          console.warn('[wasabi-portal-data] postgres mirror after Wasabi write failed:', mirrorErr?.message || mirrorErr);
        }
      }
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
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot(true);
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
  if (!WASABI_OUTLOOK_PRIMARY_ENABLED || !WASABI_WRITES_PRIMARY_ENABLED) {
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
    if (!snapshotCache) snapshotCache = await loadWasabiLatestStateSnapshot(true);
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
        'insert into users ( username, display_name, password, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup, email, first_name, last_name, company, title, phone, email_verified ) values ($1, $2, $3, false, \'customer\', null, $4::jsonb, false, null, null, false, true, $5, $6, $7, $8, $9, $10, true) returning id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup, email, first_name, last_name, company, title, phone, email_verified'
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
        account_type: 'customer',
        employee_role: null,
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
  if (!WASABI_SIGNUP_PRIMARY_ENABLED || !WASABI_WRITES_PRIMARY_ENABLED) {
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

async function createSignupUserWithWasabi({ email, verificationRow, saasSignup }) {
  if (!WASABI_SIGNUP_PRIMARY_ENABLED || !verificationRow) return null;
  const row = verificationRow;
  let response = null;
  let createdUserRow = null;
  let createdCompany = '';
  const wrote = await tryWasabiStateWrite('signup-create-user', async (data) => {
    const users = ensureSnapshotTable(data, 'users');
    const emailNeedle = String(email || '').trim().toLowerCase();
    if (looksLikeMike({ email: emailNeedle, username: emailNeedle })) {
      response = {
        status: 403,
        body: { success: false, error: 'This email is reserved for the Horizon Pipe BASE operator account.' }
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
      account_type: 'customer',
      employee_role: null,
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
    createdUserRow = userRow;
    createdCompany = String(row.company || '').trim();
    if (!saasSignup) {
      response = {
        status: 200,
        body: {
          success: true,
          user: normalizeUser(userRow),
          requiresApproval: true,
          message: 'Account created. An administrator must grant access before you can sign in.'
        }
      };
    }
  });
  if (!wrote) return response;

  if (saasSignup && createdUserRow) {
    const companyName = createdCompany || createdUserRow.username.split('@')[0] || 'Workspace';
    try {
      await upsertTenantDraft(pool, createdUserRow.id, {
        businessName: companyName,
        branding: { businessName: companyName }
      });
      await mirrorSelfSignupUserToPostgres(createdUserRow);
      const ownerCtx = await getSaasOwnerSessionContext(pool, createdUserRow.id);
      const user = await attachScopesToUser(
        normalizeUser(createdUserRow, {
          tenantPurchaser: ownerCtx.tenantPurchaser,
          saasTenantOwner: false,
          subscriptionStatus: ownerCtx.subscriptionStatus
        })
      );
      const token = await issueSession(createdUserRow.id, { keepSession: false });
      return {
        status: 200,
        body: {
          success: true,
          user,
          token,
          capabilities: resolveCapabilities(user),
          message: 'Account created. Taking you to your control panel.'
        }
      };
    } catch (error) {
      console.error('[signup] Wasabi SaaS verify follow-up failed:', error);
      return {
        status: 500,
        body: {
          success: false,
          error: 'Account created but sign-in could not be completed. Please try signing in.'
        }
      };
    }
  }

  if (response) return response;
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
registerCompanyPermissionsRoutes(app, {
  pool,
  requireAuth,
  requireAdminPanelAccess,
  requireAdminPanelOrTenantUserManagement
});
registerUserGrantsRoutes(app, { pool, requireAuth, requireAdminPanelAccess });
registerSignupRoutes(app, {
  pool,
  query: querySignupDataWithWasabiFallback,
  createSignupUserWithWasabi,
  signupPrimaryStrict: WASABI_SIGNUP_PRIMARY_STRICT,
  cleanString,
  normalizeRoles,
  issueSession,
  attachScopesToUser,
  resolveCapabilities,
  normalizeUser
});
registerAccountRoutes(app, {
  pool,
  requireAuth,
  cleanString,
  readFreshUserFromPostgresById,
  tryWasabiStateWrite,
  ensureSnapshotTable,
  nowIso
});
registerSaasTenantRoutes(app, {
  pool,
  requireAuth,
  wasabiClient: wasabiStateClient,
  wasabiBucket: WASABI_STATE_BUCKET
});
registerSaasBillingRoutes(app, { pool, requireAuth });
const platformReleaseWasabiClient = createPlatformReleaseS3Client() || wasabiStateClient;
const platformReleaseWasabiBucket = resolvePlatformReleaseBucket() || WASABI_STATE_BUCKET;
registerPlatformReleaseRoutes(app, {
  pool,
  requireAuth,
  requireAdmin,
  wasabiClient: platformReleaseWasabiClient,
  wasabiBucket: platformReleaseWasabiBucket
});
registerOvhOpsRoutes(app, { requireAuth, requireAdmin });
registerCustomerSupportRoutes(app, {
  pool,
  requireAuth,
  readSession,
  currentToken
});
if (isOvhOpsEnabled()) {
  startMetricsCollector();
  console.log('[ovh-ops] metrics collector started');
}

const SAAS_CPANEL_STATIC_DIR = process.env.SAAS_CPANEL_STATIC_DIR
  ? path.resolve(process.env.SAAS_CPANEL_STATIC_DIR)
  : path.resolve(__dirname, '../horizon-frontend/horizonpipe-cpanel');

if (fs.existsSync(SAAS_CPANEL_STATIC_DIR)) {
  app.use(
    '/horizonpipe-cpanel',
    express.static(SAAS_CPANEL_STATIC_DIR, { index: ['index.html'], fallthrough: true })
  );
  app.get('/horizonpipe-cpanel', (_req, res) => {
    res.sendFile(path.join(SAAS_CPANEL_STATIC_DIR, 'index.html'));
  });
  console.log(`[saas-cpanel] GET /horizonpipe-cpanel/* from ${SAAS_CPANEL_STATIC_DIR}`);
} else {
  console.warn(
    `[saas-cpanel] static dir not found (${SAAS_CPANEL_STATIC_DIR}); set SAAS_CPANEL_STATIC_DIR or clone horizon-frontend beside horizon-backend`
  );
}

const autoImportPlugin = createAutoImportPlugin({
  pool,
  query: queryAutoImportWithWasabiFallback,
  requireMike: requireDataAutoSyncEmployeeAccess,
  requireDesktopHeartbeat: requireDataAutoSyncDesktopHeartbeatAccess,
  requireAuth,
  fetchPlannerRecord: fetchRecordById,
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
        `[wasabi-sql-mirror] enabled=${WASABI_SQL_MIRROR_ENABLED ? 'yes' : 'no'} prefix=${WASABI_SQL_MIRROR_PREFIX} flush=${WASABI_SQL_MIRROR_FLUSH_MS}ms buffer=${WASABI_SQL_MIRROR_MAX_BUFFER} skipTables=${Array.from(WASABI_SQL_MIRROR_SKIP_TABLE_SET).sort().join(',') || '(none)'}`
      );
      void loadWasabiLatestStateSnapshot(true).catch((error) => {
        console.warn('[wasabi-state] boot snapshot preload failed:', error?.message || error);
      });
    } else {
      console.warn('[wasabi-state] snapshots disabled: configure WASABI_* and WASABI_BUCKET');
    }

    const FRONTEND_STATIC_DIR = process.env.FRONTEND_STATIC_DIR
      ? path.resolve(process.env.FRONTEND_STATIC_DIR)
      : path.resolve(__dirname, '../horizon-frontend');
    if (fs.existsSync(FRONTEND_STATIC_DIR)) {
      app.use(
        express.static(FRONTEND_STATIC_DIR, { index: ['index.html'], fallthrough: true, extensions: ['html'] })
      );
      console.log(`[frontend] static files (PipeShare, PipeSync, login, cPanel) from ${FRONTEND_STATIC_DIR}`);
    } else {
      console.warn(
        `[frontend] static dir not found (${FRONTEND_STATIC_DIR}); PipeShare/PipeSync links will 404 until horizon-frontend is cloned beside horizon-backend`
      );
    }

    app.listen(PORT, () => {
      logDeploymentProfileAtStartup();
      console.log(`Horizon backend listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('BOOT ERROR:', error);
    process.exit(1);
  });
