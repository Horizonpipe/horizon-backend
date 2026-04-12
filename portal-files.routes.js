'use strict';

/**
 * Client portal Wasabi proxy — same auth as the rest of horizon-backend.
 * Env (Render): WASABI_ACCESS_KEY_ID, WASABI_SECRET_ACCESS_KEY, WASABI_BUCKET,
 * WASABI_REGION, WASABI_ENDPOINT (also accepts WASABI_ACCESS_KEY / WASABI_SECRET_KEY).
 *
 * Heavy GET traffic (video, large downloads) should use `/api/files/presign/:id`,
 * `/api/files/share-view/:token/presign/:id`, or `/api/guest/share/:token/presign/:id`
 * so browsers fetch object bytes directly from Wasabi (configure bucket CORS for your portal origins).
 * Multipart resumable chunks still POST through this service unless extended with presigned part URLs.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const archiver = require('archiver');
const express = require('express');
const {
  filterTreeForSharePayload,
  sharePayloadAllowsFile,
  isValidEmail
} = require('./share-helpers.js');
const multer = require('multer');
const {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  S3Client,
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  UploadPartCommand
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { Upload } = require('@aws-sdk/lib-storage');
const { NodeHttpHandler } = require('@smithy/node-http-handler');
const { canManagePortalExtras } = require('./capabilities');

const CATEGORIES = new Set(['videos', 'db3', 'pdf', 'photos']);
const FOLDER_MARKER = '.hp-folder';
const DATA_AUTO_SYNC_MODE = 'dataautosync';
/** Client / non-employee AUTOSYNC accounts are pinned to this job folder (default 2; override with DATA_AUTO_SYNC_CLIENT_JOB_ID). */
const DATA_AUTO_SYNC_JOB_ID = String(process.env.DATA_AUTO_SYNC_CLIENT_JOB_ID || '2').trim() || '2';
/** `roles.dataAutoSyncEmployee` users who are not portal admins are pinned to this folder (default 2). */
const DATA_AUTO_SYNC_EMPLOYEE_JOB_ID = String(process.env.DATA_AUTO_SYNC_EMPLOYEE_JOB_ID || '2').trim() || '2';
/** When no explicit jobId is provided, portal admins start on this folder. */
const DATA_AUTO_SYNC_ADMIN_DEFAULT_JOB_ID =
  String(process.env.DATA_AUTO_SYNC_ADMIN_DEFAULT_JOB_ID || '8').trim() || '8';
const PORTAL_FOLDER_COPY_CONCURRENCY = clampIntEnv('PORTAL_FOLDER_COPY_CONCURRENCY', 8, 1, 32);
const PORTAL_FOLDER_DELETE_CONCURRENCY = clampIntEnv('PORTAL_FOLDER_DELETE_CONCURRENCY', 8, 1, 32);
/** Max items per {@code POST /check-paths} (JSON body stays well under express 4mb). */
const PORTAL_CHECK_PATHS_MAX = clampIntEnv('PORTAL_CHECK_PATHS_MAX', 800, 50, 2000);
/** Parallel S3 HeadObject calls per check-paths request (Wasabi handles many concurrent small reads). */
const PORTAL_CHECK_PATHS_HEAD_CONCURRENCY = clampIntEnv('PORTAL_CHECK_PATHS_HEAD_CONCURRENCY', 32, 1, 64);

/**
 * When the job has path grants, users with **no** matching `portal_path_grants` rows see an empty tree (strict).
 * Set `PORTAL_LENIENT_PATH_GRANTS=1` to allow portal clients with zero personal grants to see the full job
 * (legacy escape hatch only).
 */
function portalLenientPathGrantsEnabled() {
  const raw = process.env.PORTAL_LENIENT_PATH_GRANTS;
  if (raw === undefined || String(raw).trim() === '') return false;
  const v = String(raw).trim().toLowerCase();
  if (v === '1' || v === 'true' || v === 'yes' || v === 'on') return true;
  return false;
}

/**
 * @param {import('express').Request['user'] | null | undefined} user
 * @param {Array<{ path_prefix: string, recursive: boolean, access_mode: string }>} userGrants
 */
function bypassPathGrantsForLenientPortalClient(user, userGrants) {
  if (!portalLenientPathGrantsEnabled()) return false;
  if (!user || user.portalFilesAccessGranted !== true) return false;
  if (userCanManagePortalExtras(user)) return false;
  return !userGrants.length;
}

function clampIntEnv(name, fallback, min, max) {
  const raw = Number(process.env[name]);
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
}

/**
 * @template T, R
 * @param {T[]} items
 * @param {number} concurrency
 * @param {(item: T) => Promise<R>} fn
 * @returns {Promise<R[]>}
 */
async function mapWithConcurrency(items, concurrency, fn) {
  if (!items.length) return [];
  const results = new Array(items.length);
  let next = 0;
  const n = items.length;
  const workers = Math.min(Math.max(1, Math.floor(concurrency)), n);
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= n) return;
      results[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: workers }, () => worker()));
  return results;
}

/**
 * Portal ACL / path grants (aligned with `capabilities.canManagePortalExtras`: global admin or env whitelist).
 * @param {import('express').Request['user']} user
 */
function userCanManagePortalExtras(user) {
  return canManagePortalExtras(user);
}

/** @param {import('express').Request['user']} user */
function userIsPortalAdmin(user) {
  return userCanManagePortalExtras(user);
}

/**
 * Fine-grained non-admin portal capabilities.
 * @param {import('express').Request['user']} user
 * @param {'upload'|'download'|'edit'|'delete'} capability
 */
function userCanPortalCapability(user, capability) {
  if (!user) return false;
  if (userIsPortalAdmin(user)) return true;
  const roles = user.roles && typeof user.roles === 'object' ? user.roles : {};
  if (capability === 'upload') return roles.portalUpload === true;
  if (capability === 'download') return roles.portalDownload === true;
  if (capability === 'edit') return roles.portalEdit === true;
  if (capability === 'delete') return roles.portalDelete === true;
  return false;
}

/**
 * @param {import('express').Request['user']} user
 */
function userCanDataAutoSync(user) {
  if (!user) return false;
  if (userIsPortalAdmin(user)) return true;
  const roles = user.roles && typeof user.roles === 'object' ? user.roles : {};
  return roles.dataAutoSyncEmployee === true;
}

/** AUTOSYNC line employee: `dataAutoSyncEmployee` role without portal-admin extras (folder 2 only). */
function isDataAutoSyncLineEmployee(user) {
  return userCanDataAutoSync(user) && !userIsPortalAdmin(user);
}

function pickUserDefaultClientId(user) {
  if (!user) return '';
  const scoped = Array.isArray(user.portalScopes) ? user.portalScopes : [];
  const firstScopedClient = String(scoped[0]?.clientId || '').trim();
  if (firstScopedClient) return firstScopedClient;
  return String(user.portalFilesClientId || '').trim();
}

function readPortalMode(req, source) {
  const bodyMode =
    source && typeof source === 'object'
      ? String(source.portalMode || source.mode || source.appMode || '').trim().toLowerCase()
      : '';
  const queryMode = String(req?.query?.portalMode || req?.query?.mode || '').trim().toLowerCase();
  const headerMode = String(req?.headers?.['x-hp-portal-mode'] || '').trim().toLowerCase();
  return bodyMode || queryMode || headerMode;
}

/**
 * Resolve effective client/job for regular portal or DataAutoSync mode.
 * DataAutoSync mode defaults non-admins to a fixed client folder (job id),
 * while admins may pick any folder via explicit jobId override.
 */
function resolvePortalScope(req, source, options = {}) {
  const mode = readPortalMode(req, source);
  const isDataAutoSync = mode === DATA_AUTO_SYNC_MODE;
  if (isDataAutoSync) {
    const u = req?.user;
    const dasOk =
      userCanDataAutoSync(u) ||
      userIsPortalAdmin(u) ||
      u?.portalFilesAccessGranted === true;
    if (!dasOk) {
      return { error: 'DataAutoSync access is not enabled for this account' };
    }
  }
  const rawClient =
    source && typeof source === 'object'
      ? String(source.clientId || source.client_id || '').trim()
      : '';
  const rawJob =
    source && typeof source === 'object' ? String(source.jobId || source.job_id || '').trim() : '';
  const clientId = rawClient || (isDataAutoSync ? pickUserDefaultClientId(req?.user) : '');
  const requireJob = options.requireJob !== false;
  const adminCanOverrideDataAutoSyncJob = isDataAutoSync && userIsPortalAdmin(req?.user);
  const jobId = isDataAutoSync
    ? adminCanOverrideDataAutoSyncJob && rawJob
      ? rawJob
      : adminCanOverrideDataAutoSyncJob
        ? DATA_AUTO_SYNC_ADMIN_DEFAULT_JOB_ID
        : isDataAutoSyncLineEmployee(req?.user)
          ? DATA_AUTO_SYNC_EMPLOYEE_JOB_ID
          : DATA_AUTO_SYNC_JOB_ID
    : rawJob;
  if (!clientId || (requireJob && !jobId)) {
    return { error: 'clientId and jobId are required' };
  }
  return { clientId, jobId, isDataAutoSync };
}

const portalUpload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 * 1024 }
});

const portalBatchUpload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 * 1024, files: 100 }
});

/**
 * Resumable chunk endpoint benefits from in-memory buffers:
 * avoids temp-disk write + re-read before hashing/uploading.
 */
const portalChunkUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 80 * 1024 * 1024 }
});

/**
 * Multipart upload to Wasabi (S3 API): parallel part uploads over multiple connections.
 * queueSize = concurrent UploadPart calls; partSize must be ≥5MB (S3 rules, except last part).
 */
const S3_UPLOAD_PARALLEL = { queueSize: 10, partSize: 16 * 1024 * 1024 };

/**
 * @param {import('@aws-sdk/client-s3').S3Client} s3Client
 * @param {string} bucketName
 * @param {string} Key
 * @param {string} tempPath
 * @param {string} contentType
 */
async function s3UploadFromTempPath(s3Client, bucketName, Key, tempPath, contentType) {
  const stream = fs.createReadStream(tempPath);
  const uploadTask = new Upload({
    client: s3Client,
    queueSize: S3_UPLOAD_PARALLEL.queueSize,
    partSize: S3_UPLOAD_PARALLEL.partSize,
    params: {
      Bucket: bucketName,
      Key,
      Body: stream,
      ContentType: contentType || 'application/octet-stream'
    }
  });
  try {
    await uploadTask.done();
  } finally {
    fs.unlink(tempPath, () => {});
  }
}

function portalUploadKey(clientId, jobId, folderPathRel, originalName, explicitCategory) {
  const fp = normalizeRelPath(folderPathRel || '');
  if (fp) {
    return `${jobPrefix(String(clientId), String(jobId))}${fp}/${sanitizeFilename(originalName)}`;
  }
  const cat = explicitCategory || inferCategoryFromFilename(originalName);
  return objectKey(String(clientId), String(jobId), String(cat), originalName);
}

/**
 * @template T
 * @param {T[]} array
 * @param {number} concurrency
 * @param {(item: T, index: number) => Promise<void>} fn
 */
async function runPool(array, concurrency, fn) {
  let i = 0;
  const n = Math.max(1, Math.min(concurrency, array.length || 1));
  const workers = Array.from({ length: n }, async () => {
    while (true) {
      const idx = i++;
      if (idx >= array.length) return;
      await fn(array[idx], idx);
    }
  });
  await Promise.all(workers);
}

/**
 * @template T
 * @param {T[]} array
 * @param {number} concurrency
 * @param {(item: T, index: number) => Promise<void>} fn
 * @returns {Promise<Array<{ index: number, error: unknown }>>}
 */
async function runPoolCollectErrors(array, concurrency, fn) {
  const errors = [];
  await runPool(array, concurrency, async (item, index) => {
    try {
      await fn(item, index);
    } catch (error) {
      errors.push({ index, error });
    }
  });
  return errors;
}

function summarizePoolErrors(phase, errors, mapping) {
  if (!errors || errors.length === 0) return null;
  const first = errors[0];
  const firstMsg =
    first && first.error instanceof Error
      ? first.error.message
      : String(first && first.error ? first.error : 'Unknown error');
  const firstFrom = mapping?.[first.index]?.from || '';
  const firstTo = mapping?.[first.index]?.to || '';
  return `${phase} failed (${errors.length} items). firstIndex=${first.index} firstFrom=${firstFrom} firstTo=${firstTo} firstError=${firstMsg}`;
}

let portalResumeSchemaReady = null;

/**
 * Server-side state for resumable multipart uploads.
 * Keeps progress across tab close / browser restart / transient network outages.
 */
async function ensurePortalResumeSchema(pool) {
  if (!portalResumeSchemaReady) {
    portalResumeSchemaReady = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS portal_upload_sessions (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id TEXT NOT NULL,
          client_id TEXT NOT NULL,
          job_id TEXT NOT NULL,
          folder_path TEXT NOT NULL DEFAULT '',
          file_name TEXT NOT NULL,
          file_size BIGINT NOT NULL,
          mime_type TEXT NOT NULL DEFAULT '',
          object_key TEXT NOT NULL,
          multipart_upload_id TEXT NOT NULL,
          chunk_size INTEGER NOT NULL,
          sha256 TEXT,
          status TEXT NOT NULL DEFAULT 'uploading',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          completed_at TIMESTAMPTZ
        )
      `);
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_portal_upload_sessions_user_status
         ON portal_upload_sessions (user_id, status, updated_at DESC)`
      );
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_portal_upload_sessions_scope
         ON portal_upload_sessions (client_id, job_id, status, updated_at DESC)`
      );
      await pool.query(`
        CREATE TABLE IF NOT EXISTS portal_upload_session_parts (
          session_id UUID NOT NULL REFERENCES portal_upload_sessions(id) ON DELETE CASCADE,
          part_number INTEGER NOT NULL,
          etag TEXT NOT NULL,
          sha256 TEXT,
          size BIGINT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (session_id, part_number)
        )
      `);
      await pool.query(
        `ALTER TABLE portal_upload_session_parts
         ADD COLUMN IF NOT EXISTS sha256 TEXT`
      );
    })().catch((e) => {
      portalResumeSchemaReady = null;
      throw e;
    });
  }
  return portalResumeSchemaReady;
}

let portalObjectSha256SchemaReady = null;

/** SHA-256 for presigned PUT / browser-agnostic multipart (no `portal_upload_sessions` row). */
async function ensurePortalObjectSha256Schema(pool) {
  if (!portalObjectSha256SchemaReady) {
    portalObjectSha256SchemaReady = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS portal_object_sha256 (
          object_key TEXT PRIMARY KEY,
          client_id TEXT NOT NULL,
          job_id TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_portal_object_sha256_scope ON portal_object_sha256 (client_id, job_id)`
      );
    })().catch((e) => {
      portalObjectSha256SchemaReady = null;
      throw e;
    });
  }
  return portalObjectSha256SchemaReady;
}

function resumableChunkSize(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return 8 * 1024 * 1024;
  return Math.max(5 * 1024 * 1024, Math.min(64 * 1024 * 1024, Math.floor(n)));
}

function isUploadSessionOpen(row) {
  return row && row.status === 'uploading' && row.multipart_upload_id;
}

function contiguousUploadedBytes(parts) {
  let expect = 1;
  let bytes = 0;
  for (const p of parts) {
    const pn = Number(p.part_number);
    if (!Number.isFinite(pn) || pn !== expect) break;
    bytes += Number(p.size || 0);
    expect += 1;
  }
  return bytes;
}

function normalizeSha256Hex(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-f0-9]/g, '');
}

/**
 * @param {string} filePath
 * @returns {Promise<string>}
 */
function sha256HexForBuffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * @param {NodeJS.ReadableStream} stream
 * @returns {Promise<string>}
 */
async function sha256HexForReadable(stream) {
  const h = crypto.createHash('sha256');
  return await new Promise((resolve, reject) => {
    stream.on('data', (chunk) => h.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(h.digest('hex')));
  });
}

function createWasabiClient() {
  const accessKeyId = process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY;
  const secretAccessKey = process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY;
  const region = process.env.WASABI_REGION || 'us-east-1';
  const endpoint = process.env.WASABI_ENDPOINT || 'https://s3.us-east-1.wasabisys.com';
  if (!accessKeyId || !secretAccessKey) return null;
  const maxSockets = Math.max(
    8,
    Math.min(128, Number(process.env.WASABI_MAX_SOCKETS || process.env.PORTAL_S3_MAX_SOCKETS || 32))
  );
  const socketTimeoutMs = Math.max(
    30000,
    Math.min(600000, Number(process.env.WASABI_SOCKET_TIMEOUT_MS || 120000))
  );
  return new S3Client({
    region,
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 30000,
      socketTimeout: socketTimeoutMs,
      maxSockets
    })
  });
}

function bucketName() {
  return process.env.WASABI_BUCKET || null;
}

function segment(s) {
  const t = String(s ?? '').trim();
  if (!t || t.includes('..') || t.includes('/') || t.includes('\\')) {
    throw new Error('Invalid clientId or jobId');
  }
  return t;
}

function sanitizeFilename(name) {
  const base = String(name ?? '').split(/[/\\]/).pop() || 'file';
  const cleaned = base.replace(/[^\w.\- ()\[\]]+/g, '_').slice(0, 240);
  if (!cleaned) throw new Error('Invalid filename');
  return cleaned;
}

function sanitizeFolderSegment(name) {
  const t = String(name ?? '').trim();
  if (!t || t === '.' || t === '..') throw new Error('Invalid folder name');
  /** Slashes only — do not reject `..` as substring (e.g. `A..J.J` job folder names). Traversal is blocked in {@link normalizeRelPath}. */
  if (t.includes('/') || t.includes('\\')) throw new Error('Invalid folder name');
  const cleaned = t.replace(/[^\w.\- ()\[\]]+/g, '_').slice(0, 120);
  if (!cleaned) throw new Error('Invalid folder name');
  if (cleaned === FOLDER_MARKER) throw new Error('Reserved folder name');
  return cleaned;
}

function assertCategory(cat) {
  if (!CATEGORIES.has(cat)) {
    throw new Error(`Invalid category. Use one of: ${[...CATEGORIES].join(', ')}`);
  }
}

/** When folderPath is empty and category omitted (portal root upload), pick a bucket folder from the filename. */
function inferCategoryFromFilename(name) {
  const n = String(name || '').toLowerCase();
  if (n.endsWith('.pdf')) return 'pdf';
  if (n.endsWith('.db3')) return 'db3';
  if (/\.(mp4|webm|ogg|mov|m4v|avi|mkv)$/i.test(n)) return 'videos';
  if (/\.(jpg|jpeg|png|gif|webp|bmp|tif|tiff)$/i.test(n)) return 'photos';
  return 'videos';
}

function objectKey(clientId, jobId, category, filename) {
  assertCategory(category);
  const safe = sanitizeFilename(filename);
  return `clients/${segment(clientId)}/jobs/${segment(jobId)}/${category}/${safe}`;
}

function jobPrefix(clientId, jobId) {
  return `clients/${segment(clientId)}/jobs/${segment(jobId)}/`;
}

function parseJobFromObjectKey(key) {
  const m = /^clients\/([^/]+)\/jobs\/([^/]+)\//.exec(String(key ?? ''));
  if (!m) return null;
  return { clientId: m[1], jobId: m[2] };
}

/** Guess Content-Type when S3 returns application/octet-stream so browsers decode video/PDF blobs correctly. */
function contentTypeFromFilename(name) {
  const n = String(name || '').toLowerCase();
  if (n.endsWith('.mp4')) return 'video/mp4';
  if (n.endsWith('.webm')) return 'video/webm';
  if (n.endsWith('.ogg') || n.endsWith('.ogv')) return 'video/ogg';
  if (n.endsWith('.mov') || n.endsWith('.m4v')) return 'video/quicktime';
  if (n.endsWith('.mkv')) return 'video/x-matroska';
  if (n.endsWith('.avi')) return 'video/x-msvideo';
  if (n.endsWith('.pdf')) return 'application/pdf';
  if (n.endsWith('.db3')) return 'application/octet-stream';
  if (/\.(jpg|jpeg)$/i.test(n)) return 'image/jpeg';
  if (n.endsWith('.png')) return 'image/png';
  if (n.endsWith('.gif')) return 'image/gif';
  if (n.endsWith('.webp')) return 'image/webp';
  return null;
}

/**
 * Parse Range: bytes=… for progressive video/audio (browser sends many ranged GETs).
 * @param {string | undefined} rangeHeader
 * @param {number} fileSize
 * @returns {{ start: number, end: number } | null}
 */
function parseBytesRange(rangeHeader, fileSize) {
  if (!rangeHeader || typeof rangeHeader !== 'string') return null;
  const m = /^bytes=(\d*)-(\d*)$/i.exec(String(rangeHeader).trim());
  if (!m) return null;
  const size = Number(fileSize);
  if (!Number.isFinite(size) || size <= 0) return null;
  let start;
  let end;
  if (m[1] === '' && m[2] !== '') {
    const suffixLen = parseInt(m[2], 10);
    if (!Number.isFinite(suffixLen) || suffixLen <= 0) return null;
    start = Math.max(0, size - suffixLen);
    end = size - 1;
  } else if (m[1] !== '' && m[2] === '') {
    start = parseInt(m[1], 10);
    if (!Number.isFinite(start)) return null;
    end = size - 1;
  } else if (m[1] !== '' && m[2] !== '') {
    start = parseInt(m[1], 10);
    end = parseInt(m[2], 10);
    if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  } else {
    return null;
  }
  if (start < 0 || start >= size) return null;
  end = Math.min(end, size - 1);
  if (start > end) return null;
  return { start, end };
}

/**
 * Cap how many bytes one Range GET may serve (browsers reopen ranges while scrubbing; without a cap,
 * `bytes=0-` can pull an entire large MP4 in one connection).
 * @param {{ start: number, end: number }} pr
 * @param {number} fileSize
 * @param {number} maxChunk
 */
function clampBytesRangeToMaxChunk(pr, fileSize, maxChunk) {
  if (!pr || !Number.isFinite(maxChunk) || maxChunk <= 0) return pr;
  const chunk = pr.end - pr.start + 1;
  if (chunk <= maxChunk) return pr;
  const end = Math.min(pr.start + maxChunk - 1, fileSize - 1);
  if (pr.start > end) return pr;
  return { start: pr.start, end };
}

/**
 * When the browser aborts a video range (scrub), destroy the S3 stream so sockets do not pile up.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('stream').Readable} body
 */
function pipeS3BodyWithAbortSupport(req, res, body) {
  if (!body || typeof body.pipe !== 'function') return false;
  const stream = body;
  const detach = () => {
    req.removeListener('close', onClientGone);
    req.removeListener('aborted', onClientGone);
  };
  const onClientGone = () => {
    detach();
    if (!res.writableEnded) {
      try {
        res.destroy();
      } catch {
        /* ignore */
      }
      try {
        stream.destroy();
      } catch {
        /* ignore */
      }
    }
  };
  req.on('close', onClientGone);
  req.on('aborted', onClientGone);
  res.once('finish', detach);
  res.once('close', detach);
  stream.on('error', (err) => {
    detach();
    if (!res.headersSent) res.status(500).end();
    else res.destroy(err);
  });
  stream.pipe(res);
  return true;
}

function keyToId(key) {
  return Buffer.from(key, 'utf8').toString('base64url');
}

function idToKey(id) {
  return Buffer.from(String(id), 'base64url').toString('utf8');
}

/**
 * Normalize relative path under job root (no leading/trailing slash).
 */
function normalizeRelPath(p) {
  const raw = String(p ?? '').trim().replace(/\\/g, '/');
  if (!raw) return '';
  const segments = raw.split('/').filter(Boolean);
  if (segments.some((x) => x === '.' || x === '..')) throw new Error('Invalid path');
  for (const seg of segments) {
    sanitizeFolderSegment(seg);
  }
  return segments.join('/');
}

function joinRel(parentPath, name) {
  const p = normalizeRelPath(parentPath);
  const n = sanitizeFolderSegment(name);
  return p ? `${p}/${n}` : n;
}

function parentRelPath(rel) {
  const n = normalizeRelPath(rel);
  if (!n) return '';
  const i = n.lastIndexOf('/');
  return i === -1 ? '' : n.slice(0, i);
}

function basenameRel(rel) {
  const n = normalizeRelPath(rel);
  if (!n) return '';
  const i = n.lastIndexOf('/');
  return i === -1 ? n : n.slice(i + 1);
}

function safeZipSegment(seg) {
  return String(seg || '')
    .replace(/\\/g, '/')
    .replace(/[<>:"|?*\u0000-\u001F]/g, '_')
    .trim();
}

function safeZipEntryPath(relPath) {
  const bits = String(relPath || '')
    .replace(/\\/g, '/')
    .split('/')
    .filter(Boolean)
    .map((seg) => safeZipSegment(seg).replace(/^\.+$/, '_'))
    .filter(Boolean);
  return bits.join('/');
}

function copySourceHeader(bucket, key) {
  return `${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
}

async function listAllKeys(s3, bucket, prefix) {
  const keys = [];
  let pageToken;
  do {
    const resp = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: pageToken
      })
    );
    for (const obj of resp.Contents || []) {
      if (!obj.Key) continue;
      const rawEtag = obj.ETag != null ? String(obj.ETag).replace(/^"+|"+$/g, '') : '';
      keys.push({
        Key: obj.Key,
        Size: obj.Size ?? 0,
        LastModified: obj.LastModified,
        ...(rawEtag ? { ETag: rawEtag } : {})
      });
    }
    pageToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (pageToken);
  return keys;
}

/**
 * Distinct job ids that have at least one object under {@code clients/{clientId}/jobs/{jobId}/}.
 * Uses {@code Delimiter: '/'} so Wasabi returns one common prefix per job folder (fast), not every object key.
 * @param {import('@aws-sdk/client-s3').S3Client} s3
 * @param {string} bucket
 * @param {string} jobsPrefix e.g. {@code clients/acme/jobs/}
 * @returns {Promise<Set<string>>}
 */
async function listJobIdsUnderClientJobsPrefix(s3, bucket, jobsPrefix) {
  const p = String(jobsPrefix || '').replace(/\\/g, '/');
  const base = p.endsWith('/') ? p : `${p}/`;
  const jobIds = new Set();
  let pageToken;
  do {
    const resp = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: base,
        Delimiter: '/',
        ContinuationToken: pageToken
      })
    );
    for (const cp of resp.CommonPrefixes || []) {
      const full = String(cp.Prefix || '');
      if (!full.startsWith(base)) continue;
      let rest = full.slice(base.length).replace(/\/+$/, '');
      const slash = rest.indexOf('/');
      if (slash >= 0) rest = rest.slice(0, slash);
      const jobId = rest.trim();
      if (jobId) jobIds.add(jobId);
    }
    pageToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (pageToken);
  return jobIds;
}

function isFolderMarkerKey(relKey) {
  return relKey.endsWith(`/${FOLDER_MARKER}`) || relKey === FOLDER_MARKER;
}

function markerRelToFolderRel(markerRel) {
  if (markerRel === FOLDER_MARKER) return '';
  if (markerRel.endsWith(`/${FOLDER_MARKER}`)) {
    return markerRel.slice(0, -(FOLDER_MARKER.length + 1));
  }
  return null;
}

/**
 * Build nested catalog from flat keys under job prefix.
 */
function buildTreeFromKeys(jobPref, entries) {
  const rel = (key) => key.slice(jobPref.length);
  const folderSet = new Set();
  const folderMeta = new Map();

  const files = [];

  for (const { Key: key, Size: size, LastModified: lm, ETag: etag } of entries) {
    if (!key.startsWith(jobPref)) continue;
    const r = rel(key);
    if (!r) continue;

    if (isFolderMarkerKey(r)) {
      const folderRel = markerRelToFolderRel(r);
      if (folderRel !== null && folderRel !== '') {
        folderSet.add(folderRel);
        const iso = lm ? lm.toISOString() : null;
        const prev = folderMeta.get(folderRel);
        if (!prev || (iso && (!prev.lastModified || iso > prev.lastModified))) {
          folderMeta.set(folderRel, { lastModified: iso });
        }
      }
      continue;
    }

    const slash = r.lastIndexOf('/');
    const parentPath = slash === -1 ? '' : r.slice(0, slash);
    const name = slash === -1 ? r : r.slice(slash + 1);
    let p = parentPath;
    while (p !== '') {
      folderSet.add(p);
      const ix = p.lastIndexOf('/');
      p = ix === -1 ? '' : p.slice(0, ix);
    }

    files.push({
      id: keyToId(key),
      key,
      path: r,
      parentPath,
      name,
      size,
      lastModified: lm ? lm.toISOString() : null,
      ...(etag ? { etag: String(etag) } : {})
    });
  }

  const folders = [...folderSet].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
  const folderRows = folders.map((fp) => ({
    path: fp,
    parentPath: parentRelPath(fp),
    name: basenameRel(fp),
    lastModified: folderMeta.get(fp)?.lastModified ?? null
  }));

  return { folders: folderRows, files };
}

function portalForceJobScope() {
  const fc = (process.env.PORTAL_FORCE_CLIENT_ID || '').trim();
  const fj = (process.env.PORTAL_FORCE_JOB_ID || '').trim();
  return fc && fj ? { clientId: fc, jobId: fj } : null;
}

function portalSharedDefaultScope() {
  const fc = (process.env.PORTAL_SHARED_DEFAULT_CLIENT_ID || 'portal-users').trim();
  const fj = (process.env.PORTAL_SHARED_DEFAULT_JOB_ID || '8').trim();
  return fc && fj ? { clientId: fc, jobId: fj } : null;
}

/** Set `PORTAL_PORTAL_USERS_PEER_READ=1` so any signed-in user may list/read `portal-users/{userId}` when that user id exists (optional; prefer PORTAL_FORCE_* for one shared folder). */
function portalUsersPeerReadEnabled() {
  const v = String(process.env.PORTAL_PORTAL_USERS_PEER_READ || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/** Aligns with `normalizePsrScopeEntry` in server.js (portal-files cannot import server — avoid circular require). */
function portalPsrClean(s) {
  return String(s || '').trim();
}
function portalPsrUpper(s) {
  return portalPsrClean(s).toUpperCase();
}
function portalNormalizeJobsiteLabel(jobsite, street) {
  const j = portalPsrUpper(jobsite);
  const st = portalPsrUpper(street);
  if (!j) return '';
  if (st && j.toLowerCase() === st.toLowerCase()) return '';
  return j;
}
function portalNormalizePsrScopeEntry(value) {
  if (!value || typeof value !== 'object') return null;
  const recordId = portalPsrClean(value.recordId || value.record_id || value.jobsiteId || value.record || '');
  const client = portalPsrUpper(value.client);
  const city = portalPsrUpper(value.city);
  const jobsite = portalNormalizeJobsiteLabel(value.jobsite, value.street);
  if (!client || !city || !jobsite) return null;
  return { recordId: recordId || null, client, city, jobsite };
}
/**
 * Portal `(clientId, jobId)` pairs are keyed like planner rows: `job_id` is often the planner UUID or the jobsite label.
 * PSR-only accounts may lack `user.portalScopes[]` rows even when `user.psrScopes[]` grants the same job folder.
 */
function portalJobAllowedByPsrScopes(user, clientId, jobId) {
  if (!user || user.portalFilesAccessGranted !== true) return false;
  const c = portalPsrClean(clientId);
  const j = portalPsrClean(jobId);
  if (!c || !j) return false;
  const list = Array.isArray(user.psrScopes) ? user.psrScopes : [];
  for (const raw of list) {
    const entry = portalNormalizePsrScopeEntry(raw);
    if (!entry) continue;
    if (entry.client !== portalPsrUpper(c)) continue;
    if (entry.recordId && entry.recordId === j) return true;
    if (entry.jobsite && entry.jobsite.toLowerCase() === j.toLowerCase()) return true;
  }
  return false;
}

function portalPsrScopesTouchClient(user, clientId) {
  const want = portalPsrUpper(clientId);
  if (!want) return false;
  const list = Array.isArray(user?.psrScopes) ? user.psrScopes : [];
  for (const raw of list) {
    const entry = portalNormalizePsrScopeEntry(raw);
    if (entry && entry.client === want) return true;
  }
  return false;
}

async function assertPortalJobAccess(pool, user, clientId, jobId, options = {}) {
  if (userIsPortalAdmin(user)) return true;
  if (!user || user.portalFilesAccessGranted !== true) return false;
  const c = String(clientId || '').trim();
  const j = String(jobId || '').trim();
  if (!c || !j) return false;

  if (portalJobAllowedByPsrScopes(user, c, j)) return true;

  const optWide = options.allowClientWideDataAutoSync;
  let allowClientWideDataAutoSync = false;
  if (optWide === true) {
    if (isDataAutoSyncLineEmployee(user)) {
      allowClientWideDataAutoSync = j === DATA_AUTO_SYNC_EMPLOYEE_JOB_ID;
    } else if (userCanDataAutoSync(user)) {
      allowClientWideDataAutoSync = false;
    } else {
      allowClientWideDataAutoSync = j === DATA_AUTO_SYNC_JOB_ID;
    }
  } else if (optWide !== false) {
    allowClientWideDataAutoSync =
      userCanDataAutoSync(user) && j === DATA_AUTO_SYNC_JOB_ID && !isDataAutoSyncLineEmployee(user);
  }

  const scopeList = Array.isArray(user.portalScopes) ? user.portalScopes : [];
  if (scopeList.length) {
    if (
      scopeList.some((scope) => {
        const uc = String(scope?.clientId || '').trim();
        const uj = String(scope?.jobId || '').trim();
        return uc === c && uj === j;
      })
    ) {
      return true;
    }
    if (allowClientWideDataAutoSync) {
      return scopeList.some((scope) => String(scope?.clientId || '').trim() === c);
    }
    return false;
  }
  // Backward-compatible fallback while legacy fields are still present.
  const legacyClient = String(user.portalFilesClientId || '').trim();
  const legacyJob = String(user.portalFilesJobId || '').trim();
  if (!legacyClient || !legacyJob) return false;
  if (c === legacyClient && j === legacyJob) return true;
  if (allowClientWideDataAutoSync && c === legacyClient) return true;
  return false;
}

async function assertPortalJobAccessForRequest(pool, req, clientId, jobId) {
  const isDataAutoSync = readPortalMode(req) === DATA_AUTO_SYNC_MODE;
  return assertPortalJobAccess(pool, req.user, clientId, jobId, {
    allowClientWideDataAutoSync: isDataAutoSync
  });
}

async function portalJobHasPathGrants(grantPool, clientId, jobId) {
  const r = await grantPool.query(
    `SELECT 1 FROM portal_path_grants WHERE client_id = $1 AND job_id = $2 LIMIT 1`,
    [String(clientId), String(jobId)]
  );
  return r.rows.length > 0;
}

/**
 * Grants for the signed-in user. Match DB `username` column to session username or email (some admins store email in grants).
 * @param {import('express').Request['user'] | null | undefined} user
 */
async function loadUserPathGrants(grantPool, clientId, jobId, user) {
  const u = String(user?.username || '').trim();
  const em = String(user?.email || '').trim();
  const r = await grantPool.query(
    `SELECT path_prefix, COALESCE(recursive, true) AS recursive, COALESCE(access_mode, 'full') AS access_mode
     FROM portal_path_grants
     WHERE client_id = $1 AND job_id = $2
       AND (
         LOWER(TRIM(username)) = LOWER(TRIM($3))
         OR ($4 <> '' AND LOWER(TRIM(username)) = LOWER(TRIM($4)))
       )`,
    [String(clientId), String(jobId), u, em]
  );
  return r.rows;
}

/** When true, `GET /api/files` and `/tree` skip path-grant filtering so permission editors see the full job tree. */
function readPermissionsEditorQuery(req) {
  const v = String(req.query?.permissionsEditor || req.query?.permEditor || '')
    .trim()
    .toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

async function remapPortalPathGrantPrefixes(grantPool, clientId, jobId, fromRelPath, toRelPath) {
  const from = normalizeRelPath(fromRelPath || '');
  const to = normalizeRelPath(toRelPath || '');
  if (!from || !to || from === to) return;
  const rows = await grantPool.query(
    `SELECT id, path_prefix
     FROM portal_path_grants
     WHERE client_id = $1 AND job_id = $2`,
    [String(clientId), String(jobId)]
  );
  for (const row of rows.rows) {
    const current = normalizeRelPath(row.path_prefix || '');
    if (current === from) {
      await grantPool.query(`UPDATE portal_path_grants SET path_prefix = $1 WHERE id = $2`, [to, row.id]);
      continue;
    }
    if (current.startsWith(`${from}/`)) {
      const suffix = current.slice(from.length);
      await grantPool.query(`UPDATE portal_path_grants SET path_prefix = $1 WHERE id = $2`, [`${to}${suffix}`, row.id]);
    }
  }
}

async function removePortalPathGrantPrefixes(grantPool, clientId, jobId, rootRelPath) {
  const root = normalizeRelPath(rootRelPath || '');
  if (!root) return;
  await grantPool.query(
    `DELETE FROM portal_path_grants
     WHERE client_id = $1 AND job_id = $2
       AND (path_prefix = $3 OR path_prefix LIKE $4)`,
    [String(clientId), String(jobId), root, `${root}/%`]
  );
}

function relPathMatchesGrant(relPath, pathPrefix, recursive) {
  const rp = normalizeRelPath(relPath);
  const p = normalizeRelPath(pathPrefix ?? '');
  if (p === '') return true;
  const rec = recursive !== false;
  if (rec) return rp === p || rp.startsWith(`${p}/`);
  if (rp === p) return true;
  if (rp.startsWith(`${p}/`)) {
    const rest = rp.slice(p.length + 1);
    return !rest.includes('/');
  }
  return false;
}

function normalizeGrantAccessMode(mode) {
  const m = String(mode || '')
    .trim()
    .toLowerCase();
  if (m === 'view') return 'view';
  if (m === 'view_download') return 'view_download';
  return 'full';
}

function isValidGrantAccessMode(mode) {
  const m = String(mode || '')
    .trim()
    .toLowerCase();
  return m === 'full' || m === 'view' || m === 'view_download';
}

function grantModeAllows(mode, required) {
  const m = normalizeGrantAccessMode(mode);
  if (required === 'view') return true;
  if (required === 'download') return m === 'full' || m === 'view_download';
  return m === 'full';
}

async function assertPortalPathRel(grantPool, user, clientId, jobId, relPath, required = 'view') {
  if (!user) return false;
  if (userIsPortalAdmin(user)) return true;
  const jobOk = await assertPortalJobAccess(grantPool, user, String(clientId), String(jobId));
  if (!jobOk) return false;
  const anyGrants = await portalJobHasPathGrants(grantPool, clientId, jobId);
  if (!anyGrants) return true;
  const grants = await loadUserPathGrants(grantPool, clientId, jobId, user);
  if (!grants.length) {
    if (portalJobAllowedByPsrScopes(user, String(clientId), String(jobId))) {
      return true;
    }
    return bypassPathGrantsForLenientPortalClient(user, grants);
  }
  const rp = normalizeRelPath(relPath);
  return grants.some(
    (g) => relPathMatchesGrant(rp, g.path_prefix, g.recursive) && grantModeAllows(g.access_mode, required)
  );
}

/**
 * Whether {@code relPath} would appear in {@code GET /api/files/tree} for this user (path grants, DAS user folder, PSR).
 * Used by lightweight POST helpers so they cannot probe keys outside the visible tree.
 */
async function assertRelPathMatchesPortalTreeVisibility(grantPool, req, clientId, jobId, treePortalMode, relPath) {
  if (userIsPortalAdmin(req.user)) return true;
  const rp = normalizeRelPath(relPath || '');
  if (!rp) return false;
  const isDas = treePortalMode === DATA_AUTO_SYNC_MODE;
  const jobHasPathGrants = await portalJobHasPathGrants(grantPool, clientId, jobId);
  const permEditorTree = readPermissionsEditorQuery(req) && userCanManagePortalExtras(req.user);
  if (!jobHasPathGrants || permEditorTree) {
    if (isDas) {
      const ur = normalizeRelPath(dataAutosyncPortalUserFolderPrefix(req.user));
      if (ur && rp !== ur && !rp.startsWith(`${ur}/`)) return false;
    }
    return true;
  }
  const treeUserGrants = await loadUserPathGrants(grantPool, clientId, jobId, req.user);
  if (bypassPathGrantsForLenientPortalClient(req.user, treeUserGrants)) return true;
  if (treeUserGrants.length) {
    return treeUserGrants.some((g) => relPathMatchesGrant(rp, g.path_prefix, g.recursive));
  }
  if (portalJobAllowedByPsrScopes(req.user, String(clientId), String(jobId))) return true;
  if (isDas) {
    const ur = normalizeRelPath(dataAutosyncPortalUserFolderPrefix(req.user));
    if (ur) return rp === ur || rp.startsWith(`${ur}/`);
    return false;
  }
  return false;
}

/**
 * Same rules as {@link assertRelPathMatchesPortalTreeVisibility} but loads grants once per request.
 * Used by {@code POST /check-paths} so large batches do not re-hit the DB for every path.
 */
async function createPortalPathVisibilityChecker(grantPool, req, clientId, jobId, treePortalMode) {
  if (userIsPortalAdmin(req.user)) {
    return { check: () => true };
  }
  const isDas = treePortalMode === DATA_AUTO_SYNC_MODE;
  const jobHasPathGrants = await portalJobHasPathGrants(grantPool, clientId, jobId);
  const permEditorTree = readPermissionsEditorQuery(req) && userCanManagePortalExtras(req.user);
  if (!jobHasPathGrants || permEditorTree) {
    const ur = isDas ? normalizeRelPath(dataAutosyncPortalUserFolderPrefix(req.user)) : '';
    return {
      check(relPath) {
        const rp = normalizeRelPath(relPath || '');
        if (!rp) return false;
        if (isDas && ur && rp !== ur && !rp.startsWith(`${ur}/`)) return false;
        return true;
      }
    };
  }
  const treeUserGrants = await loadUserPathGrants(grantPool, clientId, jobId, req.user);
  if (bypassPathGrantsForLenientPortalClient(req.user, treeUserGrants)) {
    return { check: () => true };
  }
  if (treeUserGrants.length) {
    return {
      check(relPath) {
        const rp = normalizeRelPath(relPath || '');
        if (!rp) return false;
        return treeUserGrants.some((g) => relPathMatchesGrant(rp, g.path_prefix, g.recursive));
      }
    };
  }
  if (portalJobAllowedByPsrScopes(req.user, String(clientId), String(jobId))) {
    return { check: () => true };
  }
  if (isDas) {
    const ur = normalizeRelPath(dataAutosyncPortalUserFolderPrefix(req.user));
    return {
      check(relPath) {
        const rp = normalizeRelPath(relPath || '');
        if (!rp) return false;
        if (ur) return rp === ur || rp.startsWith(`${ur}/`);
        return false;
      }
    };
  }
  return { check: () => false };
}

/** Keep only files (and ancestor folders) under a relative path prefix — used for Data Auto Sync tree when job has grants but the user has no explicit grant rows yet. */
function filterTreeToDescendantPrefix(tree, prefixRel) {
  const p = normalizeRelPath(prefixRel || '');
  if (!p) return { folders: tree.folders || [], files: tree.files || [] };
  const files = (tree.files || []).filter((f) => {
    const rp = normalizeRelPath(f.path || '');
    return rp === p || rp.startsWith(`${p}/`);
  });
  const keepFolders = new Set();
  for (const f of files) {
    let cur = f.parentPath || '';
    while (cur) {
      keepFolders.add(normalizeRelPath(cur));
      cur = parentRelPath(cur);
    }
    keepFolders.add(p);
    let up = p;
    while (up) {
      keepFolders.add(up);
      up = parentRelPath(up);
    }
  }
  const folders = (tree.folders || []).filter((fol) => keepFolders.has(normalizeRelPath(fol.path || '')));
  return { folders, files };
}

/** Match Java {@code FileRelativizer.sanitizeUserFolder} for per-user portal folders. */
function dataAutosyncPortalUserFolderPrefix(user) {
  const raw = String(user?.displayName || user?.username || '').trim();
  if (!raw) return '';
  const safe = raw.replace(/[^A-Za-z0-9 _-]/g, '').trim();
  if (!safe) return '';
  return safe.length > 72 ? safe.slice(0, 72) : safe;
}

function filterTreeByPathGrants(tree, grants, jobHasAnyGrant) {
  if (!jobHasAnyGrant) return tree;
  if (!grants.length) return { folders: [], files: [] };
  const allows = (rp) =>
    grants.some((g) => relPathMatchesGrant(normalizeRelPath(rp), g.path_prefix, g.recursive));
  const files = (tree.files || []).filter((f) => allows(f.path));
  const keepFolders = new Set();
  for (const f of files) {
    let p = f.parentPath || '';
    while (p !== '') {
      keepFolders.add(p);
      p = parentRelPath(p);
    }
  }
  for (const g of grants) {
    const p = normalizeRelPath(g.path_prefix || '');
    if (!p) {
      return tree;
    }
    keepFolders.add(p);
    let cur = p;
    while (cur) {
      keepFolders.add(cur);
      cur = parentRelPath(cur);
    }
  }
  const folders = (tree.folders || []).filter((fol) => keepFolders.has(fol.path));
  return { folders, files };
}

/**
 * DB-only share link creation + access log. Mounted before Wasabi check so POST /api/files/shares
 * works whenever Postgres is configured (even if object storage env is missing).
 */
function registerPortalShareLinkRoutes(app, { pool: poolOption, query, requireAuth, requireAdmin }) {
  const dbQuery =
    typeof query === 'function'
      ? query
      : (poolOption && typeof poolOption.query === 'function' ? poolOption.query.bind(poolOption) : null);
  if (typeof dbQuery !== 'function') {
    throw new Error('registerPortalShareLinkRoutes requires either pool.query or options.query.');
  }
  const pool = { query: dbQuery };
  const r = express.Router();
  r.use(requireAuth);
  r.use((req, res, next) => {
    if (readPortalMode(req) === DATA_AUTO_SYNC_MODE && !userCanDataAutoSync(req.user)) {
      return res.status(403).json({ error: 'DataAutoSync employee access is not enabled for this account' });
    }
    return next();
  });

  r.post('/shares', express.json({ limit: '512kb' }), async (req, res) => {
    try {
      const { clientId, jobId, kind: kindRaw, folderPaths, fileIds } = req.body || {};
      if (!clientId || !jobId) {
        return res.status(400).json({ error: 'clientId and jobId are required' });
      }
      const kind = String(kindRaw ?? '')
        .trim()
        .toLowerCase();
      if (kind !== 'public' && kind !== 'interactive' && kind !== 'signin') {
        return res.status(400).json({ error: 'kind must be public, interactive, or signin' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const fp = Array.isArray(folderPaths) ? folderPaths : [];
      const fi = Array.isArray(fileIds) ? fileIds : [];
      if (fp.length === 0 && fi.length === 0) {
        return res.status(400).json({ error: 'Select at least one folder or file' });
      }
      const token = crypto.randomBytes(24).toString('base64url');
      const createdBy = String(req.user?.username || '');
      const payload = { folderPaths: fp.map(String), fileIds: fi.map(String) };
      const id = crypto.randomUUID();
      await pool.query(
        `INSERT INTO portal_share_links (id, token, client_id, job_id, kind, created_by_username, payload)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
        [id, token, String(clientId), String(jobId), kind, createdBy, JSON.stringify(payload)]
      );
      return res.status(201).json({ token, id, kind, clientId: String(clientId), jobId: String(jobId) });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.get('/share-access', async (req, res) => {
    try {
      if (!userCanManagePortalExtras(req.user)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const { clientId, jobId } = req.query;
      if (!clientId || !jobId) {
        return res.status(400).json({ error: 'clientId and jobId query params are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const r2 = await pool.query(
        `SELECT a.id, a.email, a.first_name AS "firstName", a.last_name AS "lastName", a.role, a.company,
                a.accessed_at AS "accessedAt", l.kind, l.token, l.created_at AS "linkCreatedAt"
         FROM portal_share_access_log a
         JOIN portal_share_links l ON l.id = a.share_link_id
         WHERE l.client_id = $1 AND l.job_id = $2
         ORDER BY a.accessed_at DESC
         LIMIT 500`,
        [String(clientId), String(jobId)]
      );
      return res.json({ rows: r2.rows });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  app.use('/api/files', r);
}

function registerPortalFilesRoutes(app, { pool: poolOption, query, requireAuth, requireAdmin }) {
  const dbQuery =
    typeof query === 'function'
      ? query
      : (poolOption && typeof poolOption.query === 'function' ? poolOption.query.bind(poolOption) : null);
  if (typeof dbQuery !== 'function') {
    throw new Error('registerPortalFilesRoutes requires either pool.query or options.query.');
  }
  const pool = { query: dbQuery };
  /** Path grants must match `GET /permissions/tree` portal path rows (live Postgres in all modes). Wasabi portal-data-primary must not shadow them. */
  const aclPool =
    poolOption && typeof poolOption.query === 'function'
      ? { query: (text, params) => poolOption.query(text, params) }
      : pool;
  /** Resumable upload metadata must always use live Postgres (never `queryPortalDataWithWasabiFallback`). */
  const uploadMetaPool =
    poolOption && typeof poolOption.query === 'function'
      ? { query: (text, params) => poolOption.query(text, params) }
      : pool;
  registerPortalShareLinkRoutes(app, { pool, query: dbQuery, requireAuth, requireAdmin });

  const s3 = createWasabiClient();
  const bucket = bucketName();

  if (!s3 || !bucket) {
    console.warn(
      '[portal-files] Wasabi not configured — set WASABI_ACCESS_KEY_ID, WASABI_SECRET_ACCESS_KEY, WASABI_BUCKET (and optional WASABI_REGION / WASABI_ENDPOINT)'
    );
    app.use('/api/files', (req, res) => {
      res.status(503).json({ error: 'File storage not configured on server' });
    });
    return;
  }

  /** Browser → Wasabi direct GET (video/blob). Match portal-api / horizon-frontend `PORTAL_PRESIGN_TTL_SECONDS`. */
  const PORTAL_PRESIGN_TTL_SECONDS = Math.max(60, Math.min(604800, Number(process.env.PORTAL_PRESIGN_TTL_SECONDS || 3600)));
  const PORTAL_PRESIGN_DISABLED = String(process.env.PORTAL_PRESIGN_DISABLED || '0').trim() === '1';

  /**
   * Optional: resumable `/upload/resumable/complete` re-downloads the full object from Wasabi to verify SHA-256.
   * **Off by default** (no full-object read through Render). Enabling is deliberate: you must set **both**
   * `PORTAL_RESUMABLE_COMPLETE_STREAM_VERIFY=1` and `PORTAL_RESUMABLE_COMPLETE_STREAM_VERIFY_CONFIRM=1`.
   * A lone `PORTAL_RESUMABLE_COMPLETE_STREAM_VERIFY=1` does nothing — avoids accidental dashboard toggles.
   * When off: trust the client-provided digest (already required) and only `HeadObject` for size.
   */
  const PORTAL_RESUMABLE_COMPLETE_STREAM_VERIFY =
    String(process.env.PORTAL_RESUMABLE_COMPLETE_STREAM_VERIFY || '0').trim() === '1' &&
    String(process.env.PORTAL_RESUMABLE_COMPLETE_STREAM_VERIFY_CONFIRM || '0').trim() === '1';

  /** Browser → Wasabi direct PUT / multipart parts. Set `PORTAL_UPLOAD_PRESIGN=0` to disable (client uses proxy upload). */
  const PORTAL_UPLOAD_PRESIGN_ENABLED = String(process.env.PORTAL_UPLOAD_PRESIGN || '1').trim().toLowerCase() !== '0';
  const PORTAL_UPLOAD_PRESIGN_MAX_BYTES = Math.max(
    1024 * 1024,
    Math.min(5368709120, Number(process.env.PORTAL_UPLOAD_PRESIGN_MAX_BYTES || 5368709120))
  );
  const S3_MAX_PARTS_HORIZON = 10000;
  const S3_MIN_PART_BYTES_HORIZON = 5 * 1024 * 1024;
  const MULTIPART_TARGET_PART_BYTES_HORIZON = Math.max(
    S3_MIN_PART_BYTES_HORIZON,
    Math.min(128 * 1024 * 1024, Number(process.env.PORTAL_MULTIPART_PART_BYTES || 8 * 1024 * 1024))
  );

  /**
   * @param {number} fileSize
   * @returns {{ partSize: number, partCount: number }}
   */
  function multipartUploadLayoutHorizon(fileSize) {
    const n = Number(fileSize);
    if (!Number.isFinite(n) || n < 0) throw new Error('Invalid fileSize');
    if (n === 0) return { partSize: 0, partCount: 0 };
    let partSize = MULTIPART_TARGET_PART_BYTES_HORIZON;
    let partCount = Math.ceil(n / partSize);
    if (partCount > S3_MAX_PARTS_HORIZON) {
      partSize = Math.ceil(n / S3_MAX_PARTS_HORIZON);
      const align = 64 * 1024;
      partSize = Math.max(S3_MIN_PART_BYTES_HORIZON, Math.ceil(partSize / align) * align);
      partCount = Math.ceil(n / partSize);
      if (partCount > S3_MAX_PARTS_HORIZON) {
        throw new Error('File too large for multipart upload part limit');
      }
    }
    return { partSize, partCount };
  }

  const r = express.Router();
  r.use(requireAuth);

  /**
   * Persist client-reported full-object SHA-256 (presigned uploads; trusted like resumable flow).
   */
  async function upsertPortalObjectSha256FromClient(key, clientId, jobId, rawSha256) {
    const bodySha256 = normalizeSha256Hex(rawSha256);
    if (bodySha256.length !== 64) return;
    await ensurePortalObjectSha256Schema(uploadMetaPool);
    await uploadMetaPool.query(
      `INSERT INTO portal_object_sha256 (object_key, client_id, job_id, sha256, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (object_key) DO UPDATE SET
         sha256 = EXCLUDED.sha256,
         client_id = EXCLUDED.client_id,
         job_id = EXCLUDED.job_id,
         updated_at = NOW()`,
      [String(key), String(clientId), String(jobId), bodySha256]
    );
  }

  /**
   * Attach SHA-256 from `portal_upload_sessions` (resumable) and `portal_object_sha256` (presigned)
   * onto tree file nodes for client-side hash dedupe.
   */
  async function mergeCompletedUploadSha256IntoTree(clientId, jobId, tree) {
    const files = tree && Array.isArray(tree.files) ? tree.files : [];
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      await ensurePortalObjectSha256Schema(uploadMetaPool);
      const r = await uploadMetaPool.query(
        `SELECT DISTINCT ON (object_key) object_key, sha256
         FROM portal_upload_sessions
         WHERE client_id = $1 AND job_id = $2 AND status = 'completed'
           AND sha256 IS NOT NULL AND btrim(sha256) <> ''
         ORDER BY object_key, completed_at DESC NULLS LAST, updated_at DESC`,
        [String(clientId), String(jobId)]
      );
      const rows = r.rows || [];
      const rObj = await uploadMetaPool.query(
        `SELECT object_key, sha256 FROM portal_object_sha256 WHERE client_id = $1 AND job_id = $2`,
        [String(clientId), String(jobId)]
      );
      const objRows = rObj.rows || [];
      const byKey = new Map();
      for (const row of rows) {
        const k = String(row.object_key || '');
        const h = normalizeSha256Hex(row.sha256);
        if (k && h.length === 64) byKey.set(k, h);
      }
      for (const row of objRows) {
        const k = String(row.object_key || '');
        const h = normalizeSha256Hex(row.sha256);
        if (k && h.length === 64) byKey.set(k, h);
      }
      for (const f of files) {
        const key = String(f.key || '');
        const h = byKey.get(key);
        if (h) {
          f.sha256 = h;
        }
      }
    } catch (e) {
      console.warn('[portal-files] mergeCompletedUploadSha256IntoTree:', e?.message || e);
    }
  }

  r.get('/storage-health', async (req, res) => {
    try {
      if (!userIsPortalAdmin(req.user)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const endpoint = String(process.env.WASABI_ENDPOINT || '').trim() || null;
      const region = String(process.env.WASABI_REGION || '').trim() || 'us-east-1';
      const startedAt = Date.now();
      const probe = await s3.send(
        new ListObjectsV2Command({
          Bucket: bucket,
          MaxKeys: 1
        })
      );
      return res.json({
        provider: 'wasabi-s3-compatible',
        bucket,
        endpoint,
        region,
        objectCountSample: Number(probe.KeyCount || 0),
        listProbeMs: Date.now() - startedAt,
        message: 'Wasabi bucket probe succeeded'
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg, provider: 'wasabi-s3-compatible', bucket });
    }
  });

  r.get('/', async (req, res) => {
    try {
      const scope = resolvePortalScope(req, req.query);
      if (scope.error) {
        return res.status(400).json({ error: 'clientId and jobId query params are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const prefix = jobPrefix(String(clientId), String(jobId));
      const jobHasPathGrants = await portalJobHasPathGrants(aclPool, clientId, jobId);
      const permEditorList =
        readPermissionsEditorQuery(req) && userCanManagePortalExtras(req.user);
      let userGrants = null;
      if (jobHasPathGrants && !permEditorList) {
        const loaded = await loadUserPathGrants(aclPool, clientId, jobId, req.user);
        if (!bypassPathGrantsForLenientPortalClient(req.user, loaded)) {
          if (loaded.length) {
            userGrants = loaded;
          } else if (!portalJobAllowedByPsrScopes(req.user, String(clientId), String(jobId))) {
            userGrants = loaded;
          }
        }
      }
      const out = [];
      const keys = await listAllKeys(s3, bucket, prefix);
      for (const obj of keys) {
        const rel = obj.Key.slice(prefix.length);
        if (!rel || isFolderMarkerKey(rel)) continue;
        if (userGrants && !userGrants.some((g) => relPathMatchesGrant(rel, g.path_prefix, g.recursive))) {
          continue;
        }
        out.push({
          id: keyToId(obj.Key),
          key: obj.Key,
          name: path.basename(obj.Key),
          size: obj.Size ?? 0,
          lastModified: obj.LastModified ? obj.LastModified.toISOString() : null
        });
      }
      return res.json({ files: out });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.get('/tree', async (req, res) => {
    try {
      const scope = resolvePortalScope(req, req.query);
      if (scope.error) {
        return res.status(400).json({ error: 'clientId and jobId query params are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const prefix = jobPrefix(String(clientId), String(jobId));
      const keys = await listAllKeys(s3, bucket, prefix);
      let tree = buildTreeFromKeys(prefix, keys);
      const treePortalMode = readPortalMode(req, req.query);
      const isDataAutoSyncTreeList = treePortalMode === DATA_AUTO_SYNC_MODE;
      const jobHasPathGrantsTree = await portalJobHasPathGrants(aclPool, clientId, jobId);
      const permEditorTree =
        readPermissionsEditorQuery(req) && userCanManagePortalExtras(req.user);
      /** @type {Array<{ path_prefix: string, recursive: boolean, access_mode: string }>} */
      let treeUserGrants = [];
      let appliedPathGrantFilter = false;
      if (jobHasPathGrantsTree && !permEditorTree) {
        treeUserGrants = await loadUserPathGrants(aclPool, clientId, jobId, req.user);
        if (!bypassPathGrantsForLenientPortalClient(req.user, treeUserGrants)) {
          if (treeUserGrants.length) {
            tree = filterTreeByPathGrants(tree, treeUserGrants, true);
            appliedPathGrantFilter = true;
          } else if (!portalJobAllowedByPsrScopes(req.user, String(clientId), String(jobId))) {
            if (isDataAutoSyncTreeList) {
              const userRoot = dataAutosyncPortalUserFolderPrefix(req.user);
              if (userRoot) {
                tree = filterTreeToDescendantPrefix(tree, userRoot);
                appliedPathGrantFilter = true;
              } else {
                tree = filterTreeByPathGrants(tree, treeUserGrants, true);
                appliedPathGrantFilter = true;
              }
            } else {
              tree = filterTreeByPathGrants(tree, treeUserGrants, true);
              appliedPathGrantFilter = true;
            }
          }
        }
      }
      await mergeCompletedUploadSha256IntoTree(clientId, jobId, tree);
      return res.json(tree);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  /**
   * Lightweight existence + size check for Data Auto Sync / desktop (avoids downloading the full `/tree` JSON).
   * Body: `{ clientId, jobId, portalMode?: "dataautosync", items: [{ path, size }] }` — path is portal-relative
   * (same as tree `path`). Uses S3 HeadObject per item; batch size capped by PORTAL_CHECK_PATHS_MAX (default 800),
   * parallel heads by PORTAL_CHECK_PATHS_HEAD_CONCURRENCY (default 16). Tune via env on Render if needed.
   */
  r.post('/check-paths', express.json({ limit: '4mb' }), async (req, res) => {
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      if (scope.error) return res.status(400).json({ error: scope.error });
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const treePortalMode = readPortalMode(req, body);
      const rawItems = Array.isArray(body.items) ? body.items : [];
      const max = PORTAL_CHECK_PATHS_MAX;
      if (rawItems.length > max) {
        return res.status(400).json({ error: `At most ${max} paths per request.` });
      }
      const pref = jobPrefix(String(clientId), String(jobId));
      const pathGate = await createPortalPathVisibilityChecker(aclPool, req, clientId, jobId, treePortalMode);
      /** @type {{ pathRel: string, key: string, expected: number }[]} */
      const work = [];
      for (const raw of rawItems) {
        let pathRel;
        try {
          pathRel = normalizeRelPath(raw?.path ?? raw?.remotePath ?? '');
        } catch (err) {
          const m = err instanceof Error ? err.message : String(err);
          return res.status(400).json({ error: m });
        }
        if (!pathRel) continue;
        if (!pathGate.check(pathRel)) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        const key = pref + pathRel;
        const expected = raw?.size != null ? Number(raw.size) : NaN;
        work.push({ pathRel, key, expected });
      }

      const headOne = async (w) => {
        try {
          const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: w.key }));
          const cl = Number(head.ContentLength ?? 0);
          if (Number.isFinite(w.expected) && w.expected >= 0 && cl !== w.expected) {
            return { kind: 'mismatch', pathRel: w.pathRel, expectedSize: w.expected, actualSize: cl };
          }
          return { kind: 'present', pathRel: w.pathRel, size: cl };
        } catch (e) {
          const code = e?.$metadata?.httpStatusCode;
          const name = String(e?.name || '');
          if (code === 404 || name === 'NotFound' || String(e?.Code || '') === '404') {
            return {
              kind: 'missing',
              pathRel: w.pathRel,
              expectedSize: Number.isFinite(w.expected) ? w.expected : null
            };
          }
          throw e;
        }
      };

      const rowResults = await mapWithConcurrency(work, PORTAL_CHECK_PATHS_HEAD_CONCURRENCY, headOne);
      const present = [];
      const missing = [];
      const sizeMismatch = [];
      for (const r of rowResults) {
        if (r.kind === 'present') present.push({ path: r.pathRel, size: r.size });
        else if (r.kind === 'missing') {
          missing.push({ path: r.pathRel, expectedSize: r.expectedSize });
        } else {
          sizeMismatch.push({
            path: r.pathRel,
            expectedSize: r.expectedSize,
            actualSize: r.actualSize
          });
        }
      }
      return res.json({ success: true, present, missing, sizeMismatch });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  /**
   * DB-only: list portal-relative paths registered with the given SHA-256 (global dedupe without loading `/tree`).
   * Body: `{ clientId, jobId, portalMode?: "dataautosync", sha256 }`.
   */
  r.post('/find-hash-paths', express.json({ limit: '32kb' }), async (req, res) => {
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      if (scope.error) return res.status(400).json({ error: scope.error });
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const hash = normalizeSha256Hex(String(body.sha256 ?? body.hash ?? ''));
      if (hash.length !== 64) {
        return res.status(400).json({ error: 'sha256 must be 64 hex characters.' });
      }
      const treePortalMode = readPortalMode(req, body);
      const pref = jobPrefix(String(clientId), String(jobId));
      await ensurePortalObjectSha256Schema(uploadMetaPool);
      await ensurePortalResumeSchema(uploadMetaPool);
      const keys = new Set();
      const q1 = await uploadMetaPool.query(
        `SELECT object_key FROM portal_object_sha256
         WHERE client_id = $1 AND job_id = $2 AND lower(sha256) = lower($3)
         LIMIT 80`,
        [String(clientId), String(jobId), hash]
      );
      for (const row of q1.rows || []) {
        const k = String(row.object_key || '');
        if (k.startsWith(pref)) keys.add(k.slice(pref.length));
      }
      const q2 = await uploadMetaPool.query(
        `SELECT object_key FROM portal_upload_sessions
         WHERE client_id = $1 AND job_id = $2 AND status = 'completed'
           AND sha256 IS NOT NULL AND lower(btrim(sha256)) = lower($3)
         ORDER BY completed_at DESC NULLS LAST
         LIMIT 80`,
        [String(clientId), String(jobId), hash]
      );
      for (const row of q2.rows || []) {
        const k = String(row.object_key || '');
        if (k.startsWith(pref)) keys.add(k.slice(pref.length));
      }
      const allowed = [];
      for (const rel of keys) {
        if (await assertRelPathMatchesPortalTreeVisibility(aclPool, req, clientId, jobId, treePortalMode, rel)) {
          allowed.push(rel);
        }
      }
      return res.json({ success: true, paths: allowed });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.get('/jobs', async (req, res) => {
    try {
      const scope = resolvePortalScope(req, req.query, { requireJob: false });
      if (scope.error) {
        return res.status(400).json({ error: 'clientId query param is required' });
      }
      const clientId = String(scope.clientId || '').trim();
      if (!clientId) {
        return res.status(400).json({ error: 'clientId query param is required' });
      }
      const admin = userIsPortalAdmin(req.user);
      const portalClientOk =
        req.user?.portalFilesAccessGranted === true &&
        Array.isArray(req.user.portalScopes) &&
        req.user.portalScopes.some((s) => String(s?.clientId || '').trim() === clientId);
      const psrClientOk =
        req.user?.portalFilesAccessGranted === true && portalPsrScopesTouchClient(req.user, clientId);
      const legacyClientOk =
        req.user?.portalFilesAccessGranted === true &&
        String(req.user?.portalFilesClientId || '').trim() === clientId;
      if (!admin && !portalClientOk && !psrClientOk && !legacyClientOk) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const probePrefix = jobPrefix(clientId, '__hp_jobs_probe__');
      const prefix = probePrefix.replace(/__hp_jobs_probe__\/$/, '');
      const set = await listJobIdsUnderClientJobsPrefix(s3, bucket, prefix);
      const scoped = Array.isArray(req.user?.portalScopes) ? req.user.portalScopes : [];
      for (const s of scoped) {
        if (String(s?.clientId || '').trim() !== clientId) continue;
        const jid = String(s?.jobId || '').trim();
        if (jid) set.add(jid);
      }
      const legacyJob = String(req.user?.portalFilesJobId || '').trim();
      const legacyClient = String(req.user?.portalFilesClientId || '').trim();
      if (legacyJob && legacyClient === clientId) set.add(legacyJob);
      const psrList = Array.isArray(req.user?.psrScopes) ? req.user.psrScopes : [];
      for (const raw of psrList) {
        const e = portalNormalizePsrScopeEntry(raw);
        if (!e || e.client !== portalPsrUpper(clientId)) continue;
        if (e.recordId) set.add(e.recordId);
        if (e.jobsite) set.add(e.jobsite);
      }
      const jobs = [...set].sort((a, b) => {
        const an = Number(a);
        const bn = Number(b);
        if (Number.isFinite(an) && Number.isFinite(bn)) return an - bn;
        return a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true });
      });
      return res.json({ clientId, jobs });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.get('/permissions', async (req, res) => {
    try {
      const scope = resolvePortalScope(req, req.query);
      if (scope.error) {
        return res.status(400).json({ error: 'clientId and jobId query params are required' });
      }
      const { clientId, jobId } = scope;
      if (!userCanManagePortalExtras(req.user)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const r2 = await aclPool.query(
        `SELECT id, username, path_prefix AS "pathPrefix", recursive, COALESCE(access_mode, 'full') AS "accessMode", created_at AS "createdAt"
         FROM portal_path_grants
         WHERE client_id = $1 AND job_id = $2
         ORDER BY LOWER(username), path_prefix`,
        [String(clientId), String(jobId)]
      );
      return res.json({ grants: r2.rows });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.put('/permissions', express.json({ limit: '512kb' }), async (req, res) => {
    try {
      if (!userCanManagePortalExtras(req.user)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      const grants = body.grants;
      if (scope.error || !Array.isArray(grants)) {
        return res.status(400).json({ error: 'clientId, jobId, and grants array are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      await aclPool.query(`DELETE FROM portal_path_grants WHERE client_id = $1 AND job_id = $2`, [
        String(clientId),
        String(jobId)
      ]);
      for (const g of grants) {
        const u = String(g.username || '').trim();
        if (!u) continue;
        let pp = '';
        try {
          pp = normalizeRelPath(g.pathPrefix != null ? String(g.pathPrefix) : '');
        } catch (err) {
          const m = err instanceof Error ? err.message : String(err);
          return res.status(400).json({ error: `Invalid pathPrefix: ${m}` });
        }
        const rec = g.recursive !== false;
        if (g.accessMode != null && !isValidGrantAccessMode(g.accessMode)) {
          return res.status(400).json({ error: 'Invalid accessMode. Allowed: full, view, view_download' });
        }
        const accessMode = normalizeGrantAccessMode(g.accessMode || g.access_mode || 'full');
        await aclPool.query(
          `INSERT INTO portal_path_grants (client_id, job_id, username, path_prefix, recursive, access_mode) VALUES ($1,$2,$3,$4,$5,$6)`,
          [String(clientId), String(jobId), u, pp, rec, accessMode]
        );
      }
      return res.json({ success: true });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  async function loadShareLinkRowForToken(tkn) {
    const q = await aclPool.query(`SELECT * FROM portal_share_links WHERE token = $1`, [String(tkn)]);
    return q.rows[0] || null;
  }

  /** @param {{ kind?: unknown, Kind?: unknown } | null | undefined} row */
  function portalShareLinkKind(row) {
    if (!row) return '';
    const raw = row.kind != null ? row.kind : row.Kind;
    return String(raw ?? '')
      .trim()
      .toLowerCase();
  }

  /**
   * @returns {Promise<{ ok: true, Key: string } | { ok: false, status: number, body: Record<string, unknown> }>}
   */
  async function shareViewAuthObjectKey(req, token, idParam) {
    const row = await loadShareLinkRowForToken(token);
    if (!row || portalShareLinkKind(row) !== 'signin') return { ok: false, status: 404, body: { error: 'Not found' } };
    if (!(await assertPortalJobAccess(pool, req.user, String(row.client_id), String(row.job_id)))) {
      return { ok: false, status: 403, body: { error: 'Forbidden' } };
    }
    const payload = row.payload || {};
    const Key = idToKey(idParam);
    if (!Key.startsWith('clients/')) {
      return { ok: false, status: 400, body: { error: 'Invalid id' } };
    }
    const parsed = parseJobFromObjectKey(Key);
    if (!parsed || parsed.clientId !== String(row.client_id) || parsed.jobId !== String(row.job_id)) {
      return { ok: false, status: 403, body: { error: 'Forbidden' } };
    }
    const pref = jobPrefix(String(row.client_id), String(row.job_id));
    const rel = Key.slice(pref.length);
    if (!sharePayloadAllowsFile(rel, keyToId(Key), payload)) {
      return { ok: false, status: 403, body: { error: 'Not included in this share' } };
    }
    return { ok: true, Key };
  }

  /** Sign-in share: tree for authenticated users with job access. */
  r.get('/share-view/:token/tree', async (req, res) => {
    try {
      const row = await loadShareLinkRowForToken(req.params.token);
      if (!row || portalShareLinkKind(row) !== 'signin') return res.status(404).json({ error: 'Not found' });
      if (!(await assertPortalJobAccess(pool, req.user, String(row.client_id), String(row.job_id)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const payload = row.payload || {};
      const prefix = jobPrefix(String(row.client_id), String(row.job_id));
      const keys = await listAllKeys(s3, bucket, prefix);
      const full = buildTreeFromKeys(prefix, keys);
      const filtered = filterTreeForSharePayload(full, payload);
      await mergeCompletedUploadSha256IntoTree(String(row.client_id), String(row.job_id), filtered);
      return res.json(filtered);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  /** Sign-in share: download one file (Bearer or ?access_token= for video tags). */
  r.get('/share-view/:token/download/:id', async (req, res) => {
    try {
      const auth = await shareViewAuthObjectKey(req, req.params.token, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      return await sendPortalS3ObjectWithRanges(req, res, auth.Key, 'share');
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.head('/share-view/:token/download/:id', async (req, res) => {
    try {
      const auth = await shareViewAuthObjectKey(req, req.params.token, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      return await sendPortalS3ObjectWithRanges(req, res, auth.Key, 'share');
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  /** Sign-in share: presigned Wasabi GET so bytes do not proxy through Render. */
  r.get('/share-view/:token/presign/:id', async (req, res) => {
    try {
      if (PORTAL_PRESIGN_DISABLED) {
        return res.status(404).json({ error: 'Presigned playback disabled' });
      }
      const auth = await shareViewAuthObjectKey(req, req.params.token, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      try {
        await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: auth.Key }));
      } catch (he) {
        const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
        if (hn === 'NotFound' || hn === 'NoSuchKey' || he?.$metadata?.httpStatusCode === 404) {
          return res.status(404).json({ error: 'Not found' });
        }
        throw he;
      }
      const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: bucket, Key: auth.Key }), {
        expiresIn: PORTAL_PRESIGN_TTL_SECONDS
      });
      return res.json({ url, expiresIn: PORTAL_PRESIGN_TTL_SECONDS });
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/folders', express.json(), async (req, res) => {
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      const { parentPath, name } = body;
      if (scope.error || !name) {
        return res.status(400).json({ error: 'clientId, jobId, and name are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const rel = joinRel(parentPath || '', name);
      if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, rel, 'view'))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }
      const pref = jobPrefix(String(clientId), String(jobId));
      const markerKey = rel ? `${pref}${rel}/${FOLDER_MARKER}` : `${pref}${FOLDER_MARKER}`;

      const probeP = `${pref}${rel}`;
      const under = await listAllKeys(s3, bucket, `${probeP}/`);
      if (under.length > 0) {
        return res.status(409).json({ error: 'A file or folder already exists at this path' });
      }
      try {
        await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: probeP }));
        return res.status(409).json({ error: 'A file or folder already exists at this path' });
      } catch (he) {
        const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
        if (hn !== 'NotFound' && he?.$metadata?.httpStatusCode !== 404) throw he;
      }

      await s3.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: markerKey,
          Body: Buffer.from('', 'utf8'),
          ContentType: 'application/octet-stream'
        })
      );
      return res.status(201).json({
        path: rel,
        parentPath: parentRelPath(rel),
        name: basenameRel(rel) || name,
        markerKey
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.patch('/rename', express.json(), async (req, res) => {
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      const { newName } = body;
      if (scope.error || !newName) {
        return res.status(400).json({ error: 'clientId, jobId, and newName are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'edit')) {
        return res.status(403).json({ error: 'Portal edit is not enabled for this account' });
      }
      const pref = jobPrefix(String(clientId), String(jobId));

      if (body.fileId) {
        const oldKey = idToKey(String(body.fileId));
        if (!oldKey.startsWith(pref) || isFolderMarkerKey(oldKey.slice(pref.length))) {
          return res.status(400).json({ error: 'Invalid file id' });
        }
        const oldRel = oldKey.slice(pref.length);
        const par = parentRelPath(oldRel);
        const sanitized = sanitizeFilename(newName);
        const newRel = par ? `${par}/${sanitized}` : sanitized;
        const newKey = `${pref}${newRel}`;
        if (oldKey === newKey) {
          return res.json({ id: keyToId(newKey), key: newKey, path: newRel });
        }
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, oldRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, newRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        try {
          await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: newKey }));
          return res.status(409).json({ error: 'Destination already exists' });
        } catch (he) {
          const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
          if (hn !== 'NotFound' && he?.$metadata?.httpStatusCode !== 404) {
            throw he;
          }
        }
        await s3.send(
          new CopyObjectCommand({
            Bucket: bucket,
            Key: newKey,
            CopySource: copySourceHeader(bucket, oldKey),
            MetadataDirective: 'COPY'
          })
        );
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: oldKey }));
        await remapPortalPathGrantPrefixes(aclPool, clientId, jobId, oldRel, newRel);
        return res.json({ id: keyToId(newKey), key: newKey, path: newRel, name: sanitized });
      }

      if (body.path !== undefined) {
        const transferStartedAt = Date.now();
        const oldFolderRel = normalizeRelPath(body.path);
        if (!oldFolderRel) {
          return res.status(400).json({ error: 'Cannot rename the job root folder' });
        }
        const parent = parentRelPath(oldFolderRel);
        const seg = sanitizeFolderSegment(newName);
        const newRel = parent ? `${parent}/${seg}` : seg;
        if (oldFolderRel === newRel) {
          return res.json({ path: newRel });
        }
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, oldFolderRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, newRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }

        const oldPrefix = `${pref}${oldFolderRel}/`;
        const listStartedAt = Date.now();
        const keys = await listAllKeys(s3, bucket, oldPrefix);
        if (keys.length === 0) {
          return res.status(404).json({ error: 'Folder not found' });
        }

        const destProbe = await listAllKeys(s3, bucket, `${pref}${newRel}`);
        const destTaken = destProbe.some(
          (o) => o.Key === `${pref}${newRel}` || o.Key.startsWith(`${pref}${newRel}/`)
        );
        if (destTaken) {
          return res.status(409).json({ error: 'Destination path is occupied' });
        }

        const newPrefix = `${pref}${newRel}/`;
        const mapping = keys.map((o) => ({
          from: o.Key,
          to: `${newPrefix}${o.Key.slice(oldPrefix.length)}`
        }));
        const copyStartedAt = Date.now();
        const copyErrors = await runPoolCollectErrors(mapping, PORTAL_FOLDER_COPY_CONCURRENCY, async ({ from, to }) => {
          await s3.send(
            new CopyObjectCommand({
              Bucket: bucket,
              Key: to,
              CopySource: copySourceHeader(bucket, from),
              MetadataDirective: 'COPY'
            })
          );
        });
        if (copyErrors.length > 0) {
          const summary = summarizePoolErrors('copy', copyErrors, mapping);
          console.warn('[portal-files] folder rename copy error', {
            clientId: String(clientId),
            jobId: String(jobId),
            oldFolderRel,
            newRel,
            itemCount: mapping.length,
            summary
          });
          return res.status(502).json({ error: summary || 'Folder copy failed' });
        }
        const deleteStartedAt = Date.now();
        const deleteErrors = await runPoolCollectErrors(
          mapping,
          PORTAL_FOLDER_DELETE_CONCURRENCY,
          async ({ from }) => {
            await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: from }));
          }
        );
        if (deleteErrors.length > 0) {
          const summary = summarizePoolErrors('delete', deleteErrors, mapping);
          console.warn('[portal-files] folder rename delete error', {
            clientId: String(clientId),
            jobId: String(jobId),
            oldFolderRel,
            newRel,
            itemCount: mapping.length,
            summary
          });
          return res.status(502).json({ error: summary || 'Folder delete failed after copy' });
        }
        const grantsStartedAt = Date.now();
        await remapPortalPathGrantPrefixes(aclPool, clientId, jobId, oldFolderRel, newRel);
        console.info('[portal-files] folder-rename stats', {
          clientId: String(clientId),
          jobId: String(jobId),
          oldFolderRel,
          newRel,
          itemCount: mapping.length,
          listMs: copyStartedAt - listStartedAt,
          copyMs: deleteStartedAt - copyStartedAt,
          deleteMs: grantsStartedAt - deleteStartedAt,
          grantsMs: Date.now() - grantsStartedAt,
          totalMs: Date.now() - transferStartedAt,
          copyConcurrency: PORTAL_FOLDER_COPY_CONCURRENCY,
          deleteConcurrency: PORTAL_FOLDER_DELETE_CONCURRENCY
        });
        return res.json({ path: newRel, parentPath: parentRelPath(newRel), name: seg });
      }

      return res.status(400).json({ error: 'Provide fileId or path for folder rename' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.patch('/move', express.json(), async (req, res) => {
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      const { fileId, folderPath, toParentPath, toClientId: toClientIdRaw, toJobId: toJobIdRaw } = body;
      if (scope.error || toParentPath === undefined) {
        return res.status(400).json({ error: 'clientId, jobId, and toParentPath are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'edit')) {
        return res.status(403).json({ error: 'Portal edit is not enabled for this account' });
      }
      const targetClientId = String(toClientIdRaw || clientId || '').trim();
      const targetJobId = String(toJobIdRaw || jobId || '').trim();
      if (!targetClientId || !targetJobId) {
        return res.status(400).json({ error: 'Destination client/job is required' });
      }
      const crossScope = String(targetClientId) !== String(clientId) || String(targetJobId) !== String(jobId);
      if (crossScope && !userIsPortalAdmin(req.user)) {
        return res.status(403).json({ error: 'Only admins can move across folder roots/jobs' });
      }
      const mode = readPortalMode(req, body);
      const allowClientWideDataAutoSync = mode === DATA_AUTO_SYNC_MODE;
      if (
        !(await assertPortalJobAccess(pool, req.user, String(targetClientId), String(targetJobId), {
          allowClientWideDataAutoSync
        }))
      ) {
        return res.status(403).json({ error: 'Forbidden destination scope' });
      }
      const pref = jobPrefix(String(clientId), String(jobId));
      const targetPref = jobPrefix(String(targetClientId), String(targetJobId));
      const destParent = normalizeRelPath(toParentPath);

      if (fileId) {
        const oldKey = idToKey(String(fileId));
        if (!oldKey.startsWith(pref) || isFolderMarkerKey(oldKey.slice(pref.length))) {
          return res.status(400).json({ error: 'Invalid file id' });
        }
        const oldRel = oldKey.slice(pref.length);
        const name = basenameRel(oldRel);
        const newRel = destParent ? `${destParent}/${name}` : name;
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, oldRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        if (!(await assertPortalPathRel(aclPool, req.user, targetClientId, targetJobId, newRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        const newKey = `${targetPref}${newRel}`;
        if (oldKey === newKey) {
          return res.json({ id: keyToId(newKey), key: newKey, path: newRel });
        }
        try {
          await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: newKey }));
          return res.status(409).json({ error: 'Destination already exists' });
        } catch (he) {
          const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
          if (hn !== 'NotFound' && he?.$metadata?.httpStatusCode !== 404) throw he;
        }
        await s3.send(
          new CopyObjectCommand({
            Bucket: bucket,
            Key: newKey,
            CopySource: copySourceHeader(bucket, oldKey),
            MetadataDirective: 'COPY'
          })
        );
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: oldKey }));
        if (crossScope) {
          await removePortalPathGrantPrefixes(aclPool, clientId, jobId, oldRel);
        } else {
          await remapPortalPathGrantPrefixes(aclPool, clientId, jobId, oldRel, newRel);
        }
        return res.json({
          id: keyToId(newKey),
          key: newKey,
          path: newRel,
          name,
          clientId: targetClientId,
          jobId: targetJobId
        });
      }

      if (folderPath !== undefined && String(folderPath).trim() !== '') {
        const transferStartedAt = Date.now();
        const oldFolderRel = normalizeRelPath(folderPath);
        if (!oldFolderRel) {
          return res.status(400).json({ error: 'Invalid folder path' });
        }
        const seg = sanitizeFolderSegment(basenameRel(oldFolderRel));
        const newRel = destParent ? `${destParent}/${seg}` : seg;
        if (oldFolderRel === newRel) {
          return res.json({ path: newRel });
        }
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, oldFolderRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        if (!(await assertPortalPathRel(aclPool, req.user, targetClientId, targetJobId, newRel, 'full'))) {
          return res.status(403).json({ error: 'Forbidden' });
        }
        const oldPrefix = `${pref}${oldFolderRel}/`;
        const listStartedAt = Date.now();
        const keys = await listAllKeys(s3, bucket, oldPrefix);
        if (keys.length === 0) {
          return res.status(404).json({ error: 'Folder not found' });
        }
        const destProbe = await listAllKeys(s3, bucket, `${targetPref}${newRel}`);
        const destTaken = destProbe.some(
          (o) => o.Key === `${targetPref}${newRel}` || o.Key.startsWith(`${targetPref}${newRel}/`)
        );
        if (destTaken) {
          return res.status(409).json({ error: 'Destination path is occupied' });
        }
        const newPrefix = `${targetPref}${newRel}/`;
        const mapping = keys.map((o) => ({
          from: o.Key,
          to: `${newPrefix}${o.Key.slice(oldPrefix.length)}`
        }));
        const copyStartedAt = Date.now();
        const copyErrors = await runPoolCollectErrors(mapping, PORTAL_FOLDER_COPY_CONCURRENCY, async ({ from, to }) => {
          await s3.send(
            new CopyObjectCommand({
              Bucket: bucket,
              Key: to,
              CopySource: copySourceHeader(bucket, from),
              MetadataDirective: 'COPY'
            })
          );
        });
        if (copyErrors.length > 0) {
          const summary = summarizePoolErrors('copy', copyErrors, mapping);
          console.warn('[portal-files] folder move copy error', {
            clientId: String(clientId),
            jobId: String(jobId),
            targetClientId: String(targetClientId),
            targetJobId: String(targetJobId),
            oldFolderRel,
            newRel,
            itemCount: mapping.length,
            summary
          });
          return res.status(502).json({ error: summary || 'Folder copy failed' });
        }
        const deleteStartedAt = Date.now();
        const deleteErrors = await runPoolCollectErrors(
          mapping,
          PORTAL_FOLDER_DELETE_CONCURRENCY,
          async ({ from }) => {
            await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: from }));
          }
        );
        if (deleteErrors.length > 0) {
          const summary = summarizePoolErrors('delete', deleteErrors, mapping);
          console.warn('[portal-files] folder move delete error', {
            clientId: String(clientId),
            jobId: String(jobId),
            targetClientId: String(targetClientId),
            targetJobId: String(targetJobId),
            oldFolderRel,
            newRel,
            itemCount: mapping.length,
            summary
          });
          return res.status(502).json({ error: summary || 'Folder delete failed after copy' });
        }
        const grantsStartedAt = Date.now();
        if (crossScope) {
          await removePortalPathGrantPrefixes(aclPool, clientId, jobId, oldFolderRel);
        } else {
          await remapPortalPathGrantPrefixes(aclPool, clientId, jobId, oldFolderRel, newRel);
        }
        console.info('[portal-files] folder-move stats', {
          clientId: String(clientId),
          jobId: String(jobId),
          targetClientId: String(targetClientId),
          targetJobId: String(targetJobId),
          oldFolderRel,
          newRel,
          crossScope,
          itemCount: mapping.length,
          listMs: copyStartedAt - listStartedAt,
          copyMs: deleteStartedAt - copyStartedAt,
          deleteMs: grantsStartedAt - deleteStartedAt,
          grantsMs: Date.now() - grantsStartedAt,
          totalMs: Date.now() - transferStartedAt,
          copyConcurrency: PORTAL_FOLDER_COPY_CONCURRENCY,
          deleteConcurrency: PORTAL_FOLDER_DELETE_CONCURRENCY
        });
        return res.json({
          path: newRel,
          parentPath: parentRelPath(newRel),
          name: seg,
          clientId: targetClientId,
          jobId: targetJobId
        });
      }

      return res.status(400).json({ error: 'Provide fileId or folderPath' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.delete('/folders', async (req, res) => {
    try {
      const scope = resolvePortalScope(req, req.query);
      const pathParam = req.query?.path;
      if (scope.error || pathParam === undefined || pathParam === '') {
        return res.status(400).json({ error: 'clientId, jobId, and non-empty path query params are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'delete')) {
        return res.status(403).json({ error: 'Portal delete is not enabled for this account' });
      }
      const folderRel = normalizeRelPath(pathParam);
      if (!folderRel) {
        return res.status(400).json({ error: 'path must name a folder under the job (not the job root)' });
      }
      if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, folderRel, 'full'))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const pref = jobPrefix(String(clientId), String(jobId));
      const prefix = `${pref}${folderRel}/`;
      const keys = await listAllKeys(s3, bucket, prefix);
      const markerKey = `${pref}${folderRel}/${FOLDER_MARKER}`;
      const toDelete = new Set(keys.map((k) => k.Key));
      toDelete.add(markerKey);
      for (const Key of toDelete) {
        try {
          await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key }));
        } catch (err) {
          if (err && err.name !== 'NoSuchKey') throw err;
        }
      }
      await removePortalPathGrantPrefixes(aclPool, clientId, jobId, folderRel);
      return res.status(204).send();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  async function assertWritablePresignPath(req, clientId, jobId, objectKey) {
    if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) return false;
    if (!userCanPortalCapability(req.user, 'upload')) return false;
    const pref = jobPrefix(String(clientId), String(jobId));
    const k = String(objectKey || '');
    if (!k.startsWith(pref)) return false;
    const rel = k.slice(pref.length);
    return assertPortalPathRel(aclPool, req.user, clientId, jobId, rel, 'full');
  }

  function buildPresignedUploadObjectKey(clientId, jobId, body) {
    const fileName = String(body?.fileName || '').trim();
    if (!fileName) return { error: { status: 400, body: { error: 'fileName is required' } } };
    const folderPath = normalizeRelPath(body?.folderPath || '');
    const categoryRaw = String(body?.category || '').trim().toLowerCase();
    if (folderPath) {
      const key = portalUploadKey(clientId, jobId, folderPath, fileName, null);
      return { key };
    }
    if (!categoryRaw || !CATEGORIES.has(categoryRaw)) {
      return {
        error: {
          status: 400,
          body: { error: 'category must be one of videos|db3|pdf|photos when folderPath is empty' }
        }
      };
    }
    const key = portalUploadKey(clientId, jobId, '', fileName, categoryRaw);
    return { key };
  }

  function expectedResumablePartBytes(sessionRow, partNumber) {
    const fileSize = Math.floor(Number(sessionRow.file_size || 0));
    const cs = Number(sessionRow.chunk_size || 0);
    if (!fileSize || !cs || partNumber < 1) return 0;
    const start = (partNumber - 1) * cs;
    if (start >= fileSize) return 0;
    return Math.min(cs, fileSize - start);
  }

  /** JSON: { clientId, jobId, folderPath?, category?, fileName, contentType?, fileSize? } → presigned PUT to Wasabi. */
  r.post('/upload/presign', express.json({ limit: '64kb' }), async (req, res) => {
    if (!PORTAL_UPLOAD_PRESIGN_ENABLED) {
      return res.status(404).json({ error: 'Direct upload presign is disabled' });
    }
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      if (scope.error) return res.status(400).json({ error: 'clientId and jobId are required' });
      const { clientId, jobId } = scope;
      const built = buildPresignedUploadObjectKey(clientId, jobId, body);
      if (built.error) return res.status(built.error.status).json(built.error.body);
      if (!(await assertWritablePresignPath(req, clientId, jobId, built.key))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }
      const rawSize = body.fileSize != null ? Number(body.fileSize) : NaN;
      if (Number.isFinite(rawSize) && rawSize > PORTAL_UPLOAD_PRESIGN_MAX_BYTES) {
        return res.status(400).json({
          error: `File exceeds direct upload limit (${PORTAL_UPLOAD_PRESIGN_MAX_BYTES} bytes); use multipart upload`
        });
      }
      const ct =
        body.contentType != null && String(body.contentType).trim() !== ''
          ? String(body.contentType).trim().slice(0, 256)
          : 'application/octet-stream';
      const url = await getSignedUrl(
        s3,
        new PutObjectCommand({
          Bucket: bucket,
          Key: built.key,
          ContentType: ct
        }),
        { expiresIn: PORTAL_PRESIGN_TTL_SECONDS }
      );
      const pref = jobPrefix(String(clientId), String(jobId));
      const rel = built.key.slice(pref.length);
      return res.json({
        url,
        expiresIn: PORTAL_PRESIGN_TTL_SECONDS,
        headers: { 'Content-Type': ct },
        id: keyToId(built.key),
        key: built.key,
        name: path.basename(built.key),
        path: rel,
        parentPath: parentRelPath(rel)
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  /** JSON: { clientId, jobId, folderPath?, category?, fileName, contentType?, fileSize } — start S3 multipart (no DB). */
  r.post('/upload/multipart/init', express.json({ limit: '64kb' }), async (req, res) => {
    if (!PORTAL_UPLOAD_PRESIGN_ENABLED) {
      return res.status(404).json({ error: 'Direct upload presign is disabled' });
    }
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      if (scope.error) return res.status(400).json({ error: 'clientId and jobId are required' });
      const { clientId, jobId } = scope;
      const fileSize = Number(body.fileSize);
      if (!Number.isFinite(fileSize) || fileSize <= 0) {
        return res.status(400).json({ error: 'fileSize must be a positive number' });
      }
      const built = buildPresignedUploadObjectKey(clientId, jobId, body);
      if (built.error) return res.status(built.error.status).json(built.error.body);
      if (!(await assertWritablePresignPath(req, clientId, jobId, built.key))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }
      const ct =
        body.contentType != null && String(body.contentType).trim() !== ''
          ? String(body.contentType).trim().slice(0, 256)
          : 'application/octet-stream';
      const { partSize, partCount } = multipartUploadLayoutHorizon(fileSize);
      const created = await s3.send(
        new CreateMultipartUploadCommand({
          Bucket: bucket,
          Key: built.key,
          ContentType: ct
        })
      );
      const uploadId = created.UploadId;
      if (!uploadId) return res.status(500).json({ error: 'Failed to start multipart upload' });
      const pref = jobPrefix(String(clientId), String(jobId));
      const rel = built.key.slice(pref.length);
      return res.json({
        uploadId,
        key: built.key,
        partSize,
        partCount,
        fileSize,
        contentType: ct,
        expiresIn: PORTAL_PRESIGN_TTL_SECONDS,
        id: keyToId(built.key),
        name: path.basename(built.key),
        path: rel,
        parentPath: parentRelPath(rel)
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  /** JSON: { key, uploadId, partNumbers: number[] } */
  r.post('/upload/multipart/sign-parts', express.json({ limit: '512kb' }), async (req, res) => {
    if (!PORTAL_UPLOAD_PRESIGN_ENABLED) {
      return res.status(404).json({ error: 'Direct upload presign is disabled' });
    }
    try {
      const { key: rawKey, uploadId, partNumbers } = req.body || {};
      const key = String(rawKey || '');
      const uid = String(uploadId || '');
      if (!key || !uid || !Array.isArray(partNumbers) || partNumbers.length === 0) {
        return res.status(400).json({ error: 'key, uploadId, and partNumbers are required' });
      }
      if (partNumbers.length > 2000) {
        return res.status(400).json({ error: 'Too many part numbers in one request (max 2000)' });
      }
      if (!key.startsWith('clients/')) return res.status(400).json({ error: 'Invalid key' });
      const parsed = parseJobFromObjectKey(key);
      if (!parsed || !(await assertWritablePresignPath(req, parsed.clientId, parsed.jobId, key))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const seen = new Set();
      const nums = [];
      for (const p of partNumbers) {
        const n = Number(p);
        if (!Number.isInteger(n) || n < 1 || n > 10000 || seen.has(n)) continue;
        seen.add(n);
        nums.push(n);
      }
      nums.sort((a, b) => a - b);
      if (nums.length === 0) return res.status(400).json({ error: 'No valid part numbers' });
      const parts = [];
      for (const pn of nums) {
        const url = await getSignedUrl(
          s3,
          new UploadPartCommand({
            Bucket: bucket,
            Key: key,
            UploadId: uid,
            PartNumber: pn
          }),
          { expiresIn: PORTAL_PRESIGN_TTL_SECONDS }
        );
        parts.push({ partNumber: pn, url });
      }
      return res.json({ parts, expiresIn: PORTAL_PRESIGN_TTL_SECONDS });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  /** JSON: { key, uploadId, parts: [{ partNumber, etag }] } */
  r.post('/upload/multipart/complete', express.json({ limit: '8mb' }), async (req, res) => {
    if (!PORTAL_UPLOAD_PRESIGN_ENABLED) {
      return res.status(404).json({ error: 'Direct upload presign is disabled' });
    }
    try {
      const { key: rawKey, uploadId, parts: rawParts } = req.body || {};
      const key = String(rawKey || '');
      const uid = String(uploadId || '');
      if (!key || !uid || !Array.isArray(rawParts) || rawParts.length === 0) {
        return res.status(400).json({ error: 'key, uploadId, and parts are required' });
      }
      if (!key.startsWith('clients/')) return res.status(400).json({ error: 'Invalid key' });
      const parsed = parseJobFromObjectKey(key);
      if (!parsed || !(await assertWritablePresignPath(req, parsed.clientId, parsed.jobId, key))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const s3Parts = rawParts
        .map((p) => {
          const pn = Number(p?.partNumber ?? p?.PartNumber);
          const etagRaw = p?.etag ?? p?.ETag ?? '';
          const etag = String(etagRaw).trim();
          return { PartNumber: pn, ETag: etag };
        })
        .filter((p) => Number.isInteger(p.PartNumber) && p.PartNumber >= 1 && p.ETag.length > 0)
        .sort((a, b) => a.PartNumber - b.PartNumber);
      if (s3Parts.length === 0 || s3Parts.length !== rawParts.length) {
        return res.status(400).json({ error: 'Each part must include partNumber and etag' });
      }
      await s3.send(
        new CompleteMultipartUploadCommand({
          Bucket: bucket,
          Key: key,
          UploadId: uid,
          MultipartUpload: { Parts: s3Parts }
        })
      );
      try {
        await upsertPortalObjectSha256FromClient(key, parsed.clientId, parsed.jobId, req.body?.sha256);
      } catch (e) {
        console.warn('[portal-files] upsertPortalObjectSha256FromClient (multipart complete):', e?.message || e);
      }
      let size = 0;
      try {
        const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        size = Number(head.ContentLength || 0);
      } catch {
        /* ignore */
      }
      const pref = jobPrefix(parsed.clientId, parsed.jobId);
      const rel = key.slice(pref.length);
      return res.status(201).json({
        id: keyToId(key),
        key,
        name: path.basename(key),
        size,
        path: rel,
        parentPath: parentRelPath(rel)
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  /** JSON: { key, sha256 } — after presigned PUT so tree merge can expose `sha256` (multipart sends digest on complete). */
  r.post('/upload/register-sha256', express.json({ limit: '64kb' }), async (req, res) => {
    try {
      const body = req.body || {};
      const key = String(body.key || '').trim();
      const h = normalizeSha256Hex(body.sha256 || '');
      if (!key.startsWith('clients/')) {
        return res.status(400).json({ error: 'key is required' });
      }
      if (h.length !== 64) {
        return res.status(400).json({ error: 'sha256 must be a 64-char hex digest' });
      }
      const parsed = parseJobFromObjectKey(key);
      if (!parsed) return res.status(400).json({ error: 'Invalid key' });
      if (!(await assertPortalJobAccessForRequest(pool, req, parsed.clientId, parsed.jobId))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!(await assertWritablePresignPath(req, parsed.clientId, parsed.jobId, key))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }
      await upsertPortalObjectSha256FromClient(key, parsed.clientId, parsed.jobId, h);
      return res.status(204).end();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  /** JSON: { key, uploadId } */
  r.post('/upload/multipart/abort', express.json({ limit: '64kb' }), async (req, res) => {
    if (!PORTAL_UPLOAD_PRESIGN_ENABLED) {
      return res.status(404).end();
    }
    try {
      const { key: rawKey, uploadId } = req.body || {};
      const key = String(rawKey || '');
      const uid = String(uploadId || '');
      if (!key || !uid || !key.startsWith('clients/')) {
        return res.status(400).json({ error: 'key and uploadId are required' });
      }
      const parsed = parseJobFromObjectKey(key);
      if (!parsed || !(await assertWritablePresignPath(req, parsed.clientId, parsed.jobId, key))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      await s3.send(new AbortMultipartUploadCommand({ Bucket: bucket, Key: key, UploadId: uid }));
      return res.status(204).end();
    } catch {
      return res.status(204).end();
    }
  });

  /** JSON: { sessionId, partNumber } — presigned UploadPart URL (bytes go browser → Wasabi). */
  r.post('/upload/resumable/sign-part', express.json({ limit: '64kb' }), async (req, res) => {
    if (!PORTAL_UPLOAD_PRESIGN_ENABLED) {
      return res.status(404).json({ error: 'Direct upload presign is disabled' });
    }
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      const sessionId = String(req.body?.sessionId || '').trim();
      const partNumber = Number(req.body?.partNumber);
      if (!sessionId || !Number.isInteger(partNumber) || partNumber < 1) {
        return res.status(400).json({ error: 'sessionId and integer partNumber are required' });
      }
      const sRes = await uploadMetaPool.query(
        `SELECT * FROM portal_upload_sessions WHERE id = $1 AND user_id = $2 LIMIT 1`,
        [sessionId, String(req.user?.id ?? req.user?.username ?? '')]
      );
      const sessionRow = sRes.rows[0];
      if (!isUploadSessionOpen(sessionRow)) {
        return res.status(404).json({ error: 'Upload session not found or closed' });
      }
      if (!(await assertPortalJobAccessForRequest(pool, req, sessionRow.client_id, sessionRow.job_id))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'upload')) {
        return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
      }
      const pref = jobPrefix(String(sessionRow.client_id), String(sessionRow.job_id));
      const relForAcl = String(sessionRow.object_key || '').slice(pref.length);
      if (!(await assertPortalPathRel(aclPool, req.user, sessionRow.client_id, sessionRow.job_id, relForAcl, 'full'))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }
      const expBytes = expectedResumablePartBytes(sessionRow, partNumber);
      if (expBytes <= 0) {
        return res.status(400).json({ error: 'Invalid part number for this session' });
      }
      const url = await getSignedUrl(
        s3,
        new UploadPartCommand({
          Bucket: bucket,
          Key: sessionRow.object_key,
          UploadId: sessionRow.multipart_upload_id,
          PartNumber: partNumber
        }),
        { expiresIn: PORTAL_PRESIGN_TTL_SECONDS }
      );
      return res.json({ url, expiresIn: PORTAL_PRESIGN_TTL_SECONDS, expectedBytes: expBytes });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  /** JSON: { sessionId, partNumber, etag, size, chunkSha256? } — record part after direct PUT to presigned URL. */
  r.post('/upload/resumable/part-complete', express.json({ limit: '64kb' }), async (req, res) => {
    if (!PORTAL_UPLOAD_PRESIGN_ENABLED) {
      return res.status(404).json({ error: 'Direct upload presign is disabled' });
    }
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      const sessionId = String(req.body?.sessionId || '').trim();
      const partNumber = Number(req.body?.partNumber);
      const etagIn = String(req.body?.etag || '').replace(/^"+|"+$/g, '');
      const sizeIn = Math.floor(Number(req.body?.size));
      const chunkSha256 = normalizeSha256Hex(req.body?.chunkSha256 || '');
      if (!sessionId || !Number.isInteger(partNumber) || partNumber < 1) {
        return res.status(400).json({ error: 'sessionId and integer partNumber are required' });
      }
      if (!etagIn) return res.status(400).json({ error: 'etag is required' });
      if (!Number.isFinite(sizeIn) || sizeIn <= 0) {
        return res.status(400).json({ error: 'size must be a positive integer' });
      }
      if (chunkSha256 && chunkSha256.length !== 64) {
        return res.status(400).json({ error: 'chunkSha256 must be a 64-char hex digest when provided' });
      }
      const sRes = await uploadMetaPool.query(
        `SELECT * FROM portal_upload_sessions WHERE id = $1 AND user_id = $2 LIMIT 1`,
        [sessionId, String(req.user?.id ?? req.user?.username ?? '')]
      );
      const sessionRow = sRes.rows[0];
      if (!isUploadSessionOpen(sessionRow)) {
        return res.status(404).json({ error: 'Upload session not found or closed' });
      }
      if (!(await assertPortalJobAccessForRequest(pool, req, sessionRow.client_id, sessionRow.job_id))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'upload')) {
        return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
      }
      const pref = jobPrefix(String(sessionRow.client_id), String(sessionRow.job_id));
      const relForAcl = String(sessionRow.object_key || '').slice(pref.length);
      if (!(await assertPortalPathRel(aclPool, req.user, sessionRow.client_id, sessionRow.job_id, relForAcl, 'full'))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }
      const expected = expectedResumablePartBytes(sessionRow, partNumber);
      if (expected !== sizeIn) {
        return res.status(409).json({ error: `Part size mismatch (expected ${expected}, got ${sizeIn})` });
      }
      const shaStored = chunkSha256 && chunkSha256.length === 64 ? chunkSha256 : null;
      await uploadMetaPool.query(
        `INSERT INTO portal_upload_session_parts (session_id, part_number, etag, sha256, size)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (session_id, part_number)
         DO UPDATE SET etag = EXCLUDED.etag, sha256 = EXCLUDED.sha256, size = EXCLUDED.size, created_at = NOW()`,
        [sessionId, partNumber, etagIn, shaStored, sizeIn]
      );
      await uploadMetaPool.query(`UPDATE portal_upload_sessions SET updated_at = NOW() WHERE id = $1`, [sessionId]);
      const parts = await uploadMetaPool.query(
        `SELECT part_number, size FROM portal_upload_session_parts WHERE session_id = $1 ORDER BY part_number`,
        [sessionId]
      );
      const uploadedBytes = contiguousUploadedBytes(parts.rows);
      return res.json({
        sessionId,
        partNumber,
        uploadedBytes,
        nextPartNumber: parts.rows.length + 1
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/upload', portalUpload.single('file'), async (req, res) => {
    const f = req.file;
    if (!f) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }
    try {
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      const { folderPath } = body;
      if (scope.error) {
        fs.unlink(f.path, () => {});
        return res.status(400).json({ error: 'clientId and jobId are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        fs.unlink(f.path, () => {});
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'upload')) {
        fs.unlink(f.path, () => {});
        return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
      }
      const original = req.body.filename || f.originalname || 'upload';
      const fp = normalizeRelPath(folderPath || '');
      const catExplicit = fp ? null : body.category || null;
      const Key = portalUploadKey(clientId, jobId, fp || '', original, catExplicit);
      const pref = jobPrefix(String(clientId), String(jobId));
      const relForAcl = Key.slice(pref.length);
      if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, relForAcl, 'full'))) {
        fs.unlink(f.path, () => {});
        return res.status(403).json({ error: 'Forbidden for this path' });
      }
      await s3UploadFromTempPath(s3, bucket, Key, f.path, f.mimetype || 'application/octet-stream');
      return res.status(201).json({
        id: keyToId(Key),
        key: Key,
        name: path.basename(Key),
        size: f.size,
        path: Key.slice(pref.length),
        parentPath: parentRelPath(Key.slice(pref.length))
      });
    } catch (e) {
      try {
        fs.unlink(f.path, () => {});
      } catch (_) {
        /* ignore */
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/upload/batch', portalBatchUpload.array('file', 100), async (req, res) => {
    const files = req.files;
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ error: 'Missing file field(s) "file"' });
    }
    const body = req.body || {};
    const scope = resolvePortalScope(req, body);
    const { folderPath, folderPaths: folderPathsRaw } = body;
    if (scope.error) {
      for (const f of files) fs.unlink(f.path, () => {});
      return res.status(400).json({ error: 'clientId and jobId are required' });
    }
    const { clientId, jobId } = scope;
    if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
      for (const f of files) fs.unlink(f.path, () => {});
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!userCanPortalCapability(req.user, 'upload')) {
      for (const f of files) {
        try {
          fs.unlink(f.path, () => {});
        } catch {
          /* ignore */
        }
      }
      return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
    }

    /** @type {string[]} */
    let pathsList;
    if (folderPathsRaw != null && String(folderPathsRaw).trim()) {
      try {
        const parsed = JSON.parse(String(folderPathsRaw));
        if (!Array.isArray(parsed) || parsed.length !== files.length) {
          for (const f of files) fs.unlink(f.path, () => {});
          return res.status(400).json({
            error: 'folderPaths must be a JSON array with the same length as the number of files'
          });
        }
        pathsList = parsed.map((p) => {
          try {
            return normalizeRelPath(p ?? '');
          } catch (err) {
            throw err;
          }
        });
      } catch (e) {
        for (const f of files) fs.unlink(f.path, () => {});
        const msg = e instanceof Error ? e.message : String(e);
        return res.status(400).json({ error: `Invalid folderPaths: ${msg}` });
      }
    } else {
      const fp = normalizeRelPath(folderPath || '');
      pathsList = files.map(() => fp);
    }

    const pref = jobPrefix(String(clientId), String(jobId));
    /** @type {Array<{ id: string, key: string, name: string, size: number, path: string, parentPath: string } | null>} */
    const okSlot = new Array(files.length).fill(null);
    /** @type {Array<{ index: number, name: string, error: string } | null>} */
    const errSlot = new Array(files.length).fill(null);
    const concurrency = Math.min(8, Math.max(1, files.length));

    await runPool(files, concurrency, async (f, idx) => {
      const original = f.originalname || 'upload';
      try {
        const Key = portalUploadKey(clientId, jobId, pathsList[idx], original, null);
        const relForAcl = Key.slice(pref.length);
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, relForAcl, 'full'))) {
          try {
            fs.unlink(f.path, () => {});
          } catch (_) {
            /* ignore */
          }
          errSlot[idx] = {
            index: idx,
            name: original,
            error: 'Forbidden for this path'
          };
          return;
        }
        await s3UploadFromTempPath(s3, bucket, Key, f.path, f.mimetype || 'application/octet-stream');
        okSlot[idx] = {
          id: keyToId(Key),
          key: Key,
          name: path.basename(Key),
          size: f.size,
          path: Key.slice(pref.length),
          parentPath: parentRelPath(Key.slice(pref.length))
        };
      } catch (e) {
        try {
          fs.unlink(f.path, () => {});
        } catch (_) {
          /* ignore */
        }
        errSlot[idx] = {
          index: idx,
          name: original,
          error: e instanceof Error ? e.message : String(e)
        };
      }
    });

    const items = okSlot.filter(Boolean);
    const errors = errSlot.filter(Boolean);
    const status = errors.length === 0 ? 201 : items.length > 0 ? 207 : 500;
    return res.status(status).json({
      items,
      ...(errors.length ? { errors } : {})
    });
  });

  r.get('/upload/resumable/active', async (req, res) => {
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      const scope = resolvePortalScope(req, req.query, { requireJob: false });
      const clientId = scope.error ? '' : scope.clientId;
      const jobId = scope.error ? '' : scope.jobId;
      const where = ['user_id = $1', "status = 'uploading'"];
      const vals = [String(req.user?.id ?? req.user?.username ?? '')];
      if (clientId) {
        vals.push(String(clientId));
        where.push(`client_id = $${vals.length}`);
      }
      if (jobId) {
        vals.push(String(jobId));
        where.push(`job_id = $${vals.length}`);
      }
      const out = await uploadMetaPool.query(
        `SELECT id, client_id, job_id, folder_path, file_name, file_size, mime_type, object_key, chunk_size, updated_at
         FROM portal_upload_sessions
         WHERE ${where.join(' AND ')}
         ORDER BY updated_at DESC
         LIMIT 500`,
        vals
      );
      const rows = [];
      for (const s of out.rows) {
        const p = await uploadMetaPool.query(
          `SELECT part_number, size FROM portal_upload_session_parts WHERE session_id = $1 ORDER BY part_number`,
          [s.id]
        );
        const uploadedBytes = contiguousUploadedBytes(p.rows);
        const nextPartNumber = p.rows.length + 1;
        rows.push({
          sessionId: s.id,
          clientId: s.client_id,
          jobId: s.job_id,
          folderPath: s.folder_path || '',
          fileName: s.file_name,
          fileSize: Number(s.file_size || 0),
          mimeType: s.mime_type || '',
          objectKey: s.object_key,
          chunkSize: Number(s.chunk_size || 0),
          uploadedBytes,
          nextPartNumber,
          updatedAt: s.updated_at
        });
      }
      return res.json({ sessions: rows });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/upload/resumable/init', express.json({ limit: '256kb' }), async (req, res) => {
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      const body = req.body || {};
      const scope = resolvePortalScope(req, body);
      const { folderPath, fileName, fileSize, mimeType, chunkSize, sha256 } = body;
      if (scope.error) {
        return res.status(400).json({ error: 'clientId and jobId are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'upload')) {
        return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
      }
      const original = String(fileName || '').trim();
      if (!original) return res.status(400).json({ error: 'fileName is required' });
      const expectedFileSha256 = normalizeSha256Hex(sha256);
      if (expectedFileSha256 && expectedFileSha256.length !== 64) {
        return res.status(400).json({ error: 'sha256 must be a 64-char hex digest' });
      }
      const sizeNum = Number(fileSize);
      if (!Number.isFinite(sizeNum) || sizeNum <= 0) {
        return res.status(400).json({ error: 'fileSize must be a positive number' });
      }
      const fp = normalizeRelPath(folderPath || '');
      const key = portalUploadKey(String(clientId), String(jobId), fp, original, fp ? null : null);
      const pref = jobPrefix(String(clientId), String(jobId));
      const relForAcl = key.slice(pref.length);
      if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, relForAcl, 'full'))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }

      const userId = String(req.user?.id ?? req.user?.username ?? '');
      const existing = await uploadMetaPool.query(
        `SELECT id, multipart_upload_id, chunk_size, object_key, file_size, file_name, mime_type, sha256
         FROM portal_upload_sessions
         WHERE user_id = $1 AND client_id = $2 AND job_id = $3
           AND folder_path = $4 AND file_name = $5 AND file_size = $6
           AND status = 'uploading'
         ORDER BY updated_at DESC
         LIMIT 1`,
        [userId, String(clientId), String(jobId), fp, original, Math.floor(sizeNum)]
      );
      if (existing.rows.length) {
        const s = existing.rows[0];
        const sessionSha256 = normalizeSha256Hex(s.sha256 || '');
        if (sessionSha256 && expectedFileSha256 && sessionSha256 !== expectedFileSha256) {
          return res.status(409).json({ error: 'Existing resumable session hash mismatch for this file' });
        }
        const p = await uploadMetaPool.query(
          `SELECT part_number, size FROM portal_upload_session_parts WHERE session_id = $1 ORDER BY part_number`,
          [s.id]
        );
        return res.status(200).json({
          sessionId: s.id,
          objectKey: s.object_key,
          chunkSize: Number(s.chunk_size || 0),
          uploadedBytes: contiguousUploadedBytes(p.rows),
          nextPartNumber: p.rows.length + 1,
          resumed: true
        });
      }

      const effectiveChunkSize = resumableChunkSize(chunkSize);
      const start = await s3.send(
        new CreateMultipartUploadCommand({
          Bucket: bucket,
          Key: key,
          ContentType: String(mimeType || '').trim() || 'application/octet-stream'
        })
      );
      const uploadId = start.UploadId;
      if (!uploadId) {
        throw new Error('Failed to start multipart upload');
      }
      const created = await uploadMetaPool.query(
        `INSERT INTO portal_upload_sessions
         (user_id, client_id, job_id, folder_path, file_name, file_size, mime_type, object_key, multipart_upload_id, chunk_size, sha256, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'uploading')
         RETURNING id`,
        [
          userId,
          String(clientId),
          String(jobId),
          fp,
          original,
          Math.floor(sizeNum),
          String(mimeType || '').trim() || '',
          key,
          uploadId,
          effectiveChunkSize,
          expectedFileSha256 || null
        ]
      );
      return res.status(201).json({
        sessionId: created.rows[0].id,
        objectKey: key,
        chunkSize: effectiveChunkSize,
        uploadedBytes: 0,
        nextPartNumber: 1,
        resumed: false
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/upload/resumable/chunk', portalChunkUpload.single('chunk'), async (req, res) => {
    const f = req.file;
    if (!f) return res.status(400).json({ error: 'Missing file field "chunk"' });
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      const sessionId = String(req.body?.sessionId || '').trim();
      const partNumber = Number(req.body?.partNumber);
      const chunkSha256 = normalizeSha256Hex(req.body?.chunkSha256 || '');
      if (!sessionId || !Number.isFinite(partNumber) || partNumber < 1 || !Number.isInteger(partNumber)) {
        return res.status(400).json({ error: 'sessionId and integer partNumber are required' });
      }
      if (chunkSha256.length !== 64) {
        return res.status(400).json({ error: 'chunkSha256 is required and must be a 64-char hex digest' });
      }
      if (!f.buffer || !Number.isFinite(Number(f.size || 0)) || Number(f.size || 0) <= 0) {
        return res.status(400).json({ error: 'Uploaded chunk body is empty' });
      }
      const sRes = await uploadMetaPool.query(
        `SELECT * FROM portal_upload_sessions WHERE id = $1 AND user_id = $2 LIMIT 1`,
        [sessionId, String(req.user?.id ?? req.user?.username ?? '')]
      );
      const sessionRow = sRes.rows[0];
      if (!isUploadSessionOpen(sessionRow)) {
        return res.status(404).json({ error: 'Upload session not found or closed' });
      }
      if (!(await assertPortalJobAccessForRequest(pool, req, sessionRow.client_id, sessionRow.job_id))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'upload')) {
        return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
      }
      const pref = jobPrefix(String(sessionRow.client_id), String(sessionRow.job_id));
      const relForAcl = String(sessionRow.object_key || '').slice(pref.length);
      if (!(await assertPortalPathRel(aclPool, req.user, sessionRow.client_id, sessionRow.job_id, relForAcl, 'full'))) {
        return res.status(403).json({ error: 'Forbidden for this path' });
      }

      const actualChunkSha256 = normalizeSha256Hex(sha256HexForBuffer(f.buffer));
      if (actualChunkSha256 !== chunkSha256) {
        return res.status(409).json({ error: 'Chunk hash mismatch', expected: chunkSha256, actual: actualChunkSha256 });
      }

      const partResp = await s3.send(
        new UploadPartCommand({
          Bucket: bucket,
          Key: sessionRow.object_key,
          UploadId: sessionRow.multipart_upload_id,
          PartNumber: partNumber,
          Body: f.buffer,
          ContentLength: f.size
        })
      );
      const etag = String(partResp.ETag || '').replace(/^"+|"+$/g, '');
      if (!etag) throw new Error('Missing ETag for uploaded part');
      await uploadMetaPool.query(
        `INSERT INTO portal_upload_session_parts (session_id, part_number, etag, sha256, size)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (session_id, part_number)
         DO UPDATE SET etag = EXCLUDED.etag, sha256 = EXCLUDED.sha256, size = EXCLUDED.size, created_at = NOW()`,
        [sessionId, partNumber, etag, actualChunkSha256, Math.floor(Number(f.size || 0))]
      );
      await uploadMetaPool.query(`UPDATE portal_upload_sessions SET updated_at = NOW() WHERE id = $1`, [sessionId]);
      const parts = await uploadMetaPool.query(
        `SELECT part_number, size FROM portal_upload_session_parts WHERE session_id = $1 ORDER BY part_number`,
        [sessionId]
      );
      const uploadedBytes = contiguousUploadedBytes(parts.rows);
      return res.json({
        sessionId,
        partNumber,
        uploadedBytes,
        nextPartNumber: parts.rows.length + 1
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/upload/resumable/complete', express.json({ limit: '128kb' }), async (req, res) => {
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      const sessionId = String(req.body?.sessionId || '').trim();
      const totalParts = Number(req.body?.totalParts);
      const bodySha256 = normalizeSha256Hex(req.body?.sha256 || '');
      if (!sessionId || !Number.isFinite(totalParts) || totalParts < 1 || !Number.isInteger(totalParts)) {
        return res.status(400).json({ error: 'sessionId and integer totalParts are required' });
      }
      if (bodySha256 && bodySha256.length !== 64) {
        return res.status(400).json({ error: 'sha256 must be a 64-char hex digest' });
      }
      const sRes = await uploadMetaPool.query(
        `SELECT * FROM portal_upload_sessions WHERE id = $1 AND user_id = $2 LIMIT 1`,
        [sessionId, String(req.user?.id ?? req.user?.username ?? '')]
      );
      const sessionRow = sRes.rows[0];
      if (!isUploadSessionOpen(sessionRow)) {
        return res.status(404).json({ error: 'Upload session not found or closed' });
      }
      if (!(await assertPortalJobAccessForRequest(pool, req, sessionRow.client_id, sessionRow.job_id))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      if (!userCanPortalCapability(req.user, 'upload')) {
        return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
      }
      const sessionSha256 = normalizeSha256Hex(sessionRow.sha256 || '');
      if (sessionSha256 && bodySha256 && sessionSha256 !== bodySha256) {
        return res.status(409).json({ error: 'Provided file hash does not match session hash' });
      }
      const expectedFileSha256 = bodySha256 || sessionSha256;
      if (expectedFileSha256.length !== 64) {
        return res.status(400).json({ error: 'sha256 is required to finalize resumable uploads' });
      }
      const parts = await uploadMetaPool.query(
        `SELECT part_number, etag, size FROM portal_upload_session_parts WHERE session_id = $1 ORDER BY part_number`,
        [sessionId]
      );
      if (parts.rows.length < totalParts) {
        return res.status(409).json({
          error: `Missing parts: have ${parts.rows.length}, need ${totalParts}`
        });
      }
      const use = [];
      for (let i = 1; i <= totalParts; i++) {
        const p = parts.rows[i - 1];
        if (!p || Number(p.part_number) !== i || !p.etag) {
          return res.status(409).json({ error: `Missing part ${i}` });
        }
        use.push({ ETag: String(p.etag), PartNumber: i });
      }
      await s3.send(
        new CompleteMultipartUploadCommand({
          Bucket: bucket,
          Key: sessionRow.object_key,
          UploadId: sessionRow.multipart_upload_id,
          MultipartUpload: { Parts: use }
        })
      );
      let actualFileSha256 = expectedFileSha256;
      if (PORTAL_RESUMABLE_COMPLETE_STREAM_VERIFY) {
        const finalObj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: sessionRow.object_key }));
        if (!finalObj.Body || typeof finalObj.Body.pipe !== 'function') {
          throw new Error('Missing completed object body for hash verification');
        }
        actualFileSha256 = normalizeSha256Hex(await sha256HexForReadable(finalObj.Body));
        if (actualFileSha256 !== expectedFileSha256) {
          try {
            await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: sessionRow.object_key }));
          } catch (_) {
            /* ignore delete failure after hash mismatch */
          }
          await uploadMetaPool.query(
            `UPDATE portal_upload_sessions
             SET status = 'failed', sha256 = $2, updated_at = NOW()
             WHERE id = $1`,
            [sessionId, actualFileSha256]
          );
          return res.status(409).json({
            error: 'Final file hash mismatch',
            expected: expectedFileSha256,
            actual: actualFileSha256
          });
        }
      } else {
        const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: sessionRow.object_key }));
        const expectedSize = Math.floor(Number(sessionRow.file_size || 0));
        const contentLen = Number(head.ContentLength);
        if (!Number.isFinite(expectedSize) || expectedSize <= 0) {
          throw new Error('Invalid session file_size for finalize');
        }
        if (!Number.isFinite(contentLen) || contentLen !== expectedSize) {
          try {
            await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: sessionRow.object_key }));
          } catch (_) {
            /* ignore */
          }
          await uploadMetaPool.query(
            `UPDATE portal_upload_sessions SET status = 'failed', updated_at = NOW() WHERE id = $1`,
            [sessionId]
          );
          return res.status(409).json({
            error: 'Completed object size mismatch',
            expectedBytes: expectedSize,
            actualBytes: Number.isFinite(contentLen) ? contentLen : null
          });
        }
      }
      await uploadMetaPool.query(
        `UPDATE portal_upload_sessions
         SET status = 'completed', sha256 = $2, completed_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
        [sessionId, actualFileSha256]
      );
      const pref = jobPrefix(String(sessionRow.client_id), String(sessionRow.job_id));
      return res.status(201).json({
        id: keyToId(sessionRow.object_key),
        key: sessionRow.object_key,
        name: path.basename(sessionRow.object_key),
        size: Number(sessionRow.file_size || 0),
        path: String(sessionRow.object_key).slice(pref.length),
        parentPath: parentRelPath(String(sessionRow.object_key).slice(pref.length))
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/upload/resumable/abort', express.json({ limit: '64kb' }), async (req, res) => {
    try {
      await ensurePortalResumeSchema(uploadMetaPool);
      const sessionId = String(req.body?.sessionId || '').trim();
      if (!sessionId) return res.status(400).json({ error: 'sessionId is required' });
      const sRes = await uploadMetaPool.query(
        `SELECT * FROM portal_upload_sessions WHERE id = $1 AND user_id = $2 LIMIT 1`,
        [sessionId, String(req.user?.id ?? req.user?.username ?? '')]
      );
      const sessionRow = sRes.rows[0];
      if (!sessionRow) return res.status(404).json({ error: 'Upload session not found' });
      if (!userCanPortalCapability(req.user, 'upload')) {
        return res.status(403).json({ error: 'Portal upload is not enabled for this account' });
      }
      if (isUploadSessionOpen(sessionRow)) {
        try {
          await s3.send(
            new AbortMultipartUploadCommand({
              Bucket: bucket,
              Key: sessionRow.object_key,
              UploadId: sessionRow.multipart_upload_id
            })
          );
        } catch (_) {
          /* ignore provider-side missing upload */
        }
      }
      await uploadMetaPool.query(`UPDATE portal_upload_sessions SET status = 'aborted', updated_at = NOW() WHERE id = $1`, [
        sessionId
      ]);
      return res.status(204).send();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  /**
   * Browsers send a burst of Range GETs while scrubbing video. Each request used to run several SQL
   * checks plus HeadObject — enough to starve the pg pool (default max 10) and look like a backend crash.
   */
  const PORTAL_DL_AUTH_TTL_MS = 60 * 1000;
  const PORTAL_DL_AUTH_DENY_TTL_MS = 12 * 1000;
  const PORTAL_DL_META_TTL_MS = 5 * 60 * 1000;
  const portalDlAuthCache = new Map();
  const portalDlObjectMetaCache = new Map();

  /** One Range GET cannot exceed this many bytes (limits work per scrub seek). */
  const PORTAL_DL_MAX_RANGE_BYTES = Math.max(
    256 * 1024,
    Math.min(64 * 1024 * 1024, Number(process.env.PORTAL_DL_MAX_RANGE_BYTES || 8 * 1024 * 1024))
  );
  /** Per-IP concurrent GET streams to S3 (scrubbing opens many; cap avoids Render OOM / socket exhaustion). */
  const PORTAL_DL_MAX_CONCURRENT_PER_IP = Math.max(
    4,
    Math.min(120, Number(process.env.PORTAL_DL_MAX_CONCURRENT_PER_IP || 24))
  );
  const portalDlActiveByIp = new Map();

  function portalDlClientIp(req) {
    const raw = String(req.ip || req.socket?.remoteAddress || 'unknown')
      .split(',')[0]
      .trim();
    return raw || 'unknown';
  }

  /**
   * @returns {boolean} false if this IP already has too many open download streams
   */
  function portalDlTryAcquireStreamSlot(req, res) {
    if (req.method !== 'GET') return true;
    const ip = portalDlClientIp(req);
    const n = (portalDlActiveByIp.get(ip) || 0) + 1;
    if (n > PORTAL_DL_MAX_CONCURRENT_PER_IP) {
      return false;
    }
    portalDlActiveByIp.set(ip, n);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      const c = (portalDlActiveByIp.get(ip) || 1) - 1;
      if (c <= 0) portalDlActiveByIp.delete(ip);
      else portalDlActiveByIp.set(ip, c);
    };
    res.once('finish', release);
    res.once('close', release);
    return true;
  }

  function portalDlAuthCacheKey(user, fileId) {
    if (userIsPortalAdmin(user)) return `admin::${fileId}`;
    const uid = user && user.id != null ? `id:${user.id}` : '';
    const un = user && user.username ? `u:${user.username}` : '';
    return `${uid || un || 'anon'}::${fileId}`;
  }

  function trimPortalDlMap(map, maxEntries = 3000) {
    if (map.size <= maxEntries) return;
    const n = Math.floor(map.size / 2);
    let k = 0;
    for (const key of map.keys()) {
      map.delete(key);
      if (++k >= n) break;
    }
  }

  function invalidatePortalDlCachesForFile(fileId, objectKey) {
    portalDlObjectMetaCache.delete(`${bucket}::${objectKey}`);
    const suffix = `::${fileId}`;
    for (const key of portalDlAuthCache.keys()) {
      if (key.endsWith(suffix)) portalDlAuthCache.delete(key);
    }
  }

  async function resolvePortalDownloadObjectMeta(objectKey) {
    const mk = `${bucket}::${objectKey}`;
    const now = Date.now();
    const hit = portalDlObjectMetaCache.get(mk);
    if (hit && hit.exp > now) return hit;
    const meta = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: objectKey }));
    const total = Number(meta.ContentLength);
    if (!Number.isFinite(total) || total < 0) {
      throw new Error('Missing object size');
    }
    const s3Type = (meta.ContentType || '').split(';')[0].trim().toLowerCase();
    const entry = {
      total,
      s3Type,
      rawContentType: meta.ContentType || '',
      exp: now + PORTAL_DL_META_TTL_MS
    };
    portalDlObjectMetaCache.set(mk, entry);
    trimPortalDlMap(portalDlObjectMetaCache);
    return entry;
  }

  /**
   * Stream one object from Wasabi with Range + HEAD metadata (video scrubbing). Caller enforces ACL.
   * @param {'portal'|'share'} dispositionMode share/guest links always inline; portal uses video/PDF rules.
   */
  async function sendPortalS3ObjectWithRanges(req, res, Key, dispositionMode) {
    const filename = path.basename(Key);
    const fromKey = contentTypeFromFilename(filename);
    let om;
    try {
      om = await resolvePortalDownloadObjectMeta(Key);
    } catch (headErr) {
      const hn = headErr && typeof headErr === 'object' && 'name' in headErr ? headErr.name : '';
      if (
        hn === 'NoSuchKey' ||
        (headErr instanceof Error && headErr.message && headErr.message.includes('NoSuchKey'))
      ) {
        return res.status(404).json({ error: 'Not found' });
      }
      throw headErr;
    }
    const total = om.total;

    const s3Type = om.s3Type;
    const useGuess =
      fromKey && (!s3Type || s3Type === 'application/octet-stream' || s3Type === 'binary/octet-stream');
    const contentType = useGuess ? fromKey : om.rawContentType || 'application/octet-stream';
    const inline =
      dispositionMode === 'share'
        ? true
        : /^video\//i.test(contentType) ||
          contentType === 'application/pdf' ||
          String(req.query?.inline || '') === '1';
    res.setHeader(
      'Content-Disposition',
      inline
        ? `inline; filename="${encodeURIComponent(filename)}"`
        : `attachment; filename="${encodeURIComponent(filename)}"`
    );
    res.setHeader('Content-Type', contentType);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'private, max-age=300');

    const rangeHdr = req.headers.range;
    const isHead = req.method === 'HEAD';

    if (isHead) {
      if (rangeHdr) {
        let pr = parseBytesRange(rangeHdr, total);
        if (!pr) {
          res.setHeader('Content-Range', `bytes */${total}`);
          return res.status(416).end();
        }
        pr = clampBytesRangeToMaxChunk(pr, total, PORTAL_DL_MAX_RANGE_BYTES);
        const chunk = pr.end - pr.start + 1;
        res.status(206);
        res.setHeader('Content-Range', `bytes ${pr.start}-${pr.end}/${total}`);
        res.setHeader('Content-Length', String(chunk));
        return res.end();
      }
      res.setHeader('Content-Length', String(total));
      return res.status(200).end();
    }

    if (rangeHdr) {
      let pr = parseBytesRange(rangeHdr, total);
      if (!pr) {
        res.setHeader('Content-Range', `bytes */${total}`);
        return res.status(416).end();
      }
      pr = clampBytesRangeToMaxChunk(pr, total, PORTAL_DL_MAX_RANGE_BYTES);
      if (!portalDlTryAcquireStreamSlot(req, res)) {
        return res
          .status(429)
          .setHeader('Retry-After', '2')
          .json({
            error:
              'Too many simultaneous video/download requests from this connection. Wait a second or avoid rapid scrubbing.'
          });
      }
      const obj = await s3.send(
        new GetObjectCommand({
          Bucket: bucket,
          Key,
          Range: `bytes=${pr.start}-${pr.end}`
        })
      );
      const chunk = pr.end - pr.start + 1;
      res.status(206);
      res.setHeader('Content-Range', `bytes ${pr.start}-${pr.end}/${total}`);
      res.setHeader('Content-Length', String(chunk));
      if (!obj.Body || typeof obj.Body.pipe !== 'function') {
        return res.status(500).json({ error: 'Empty body' });
      }
      if (!pipeS3BodyWithAbortSupport(req, res, /** @type {import('stream').Readable} */ (obj.Body))) {
        return res.status(500).json({ error: 'Empty body' });
      }
      return;
    }

    if (!portalDlTryAcquireStreamSlot(req, res)) {
      return res
        .status(429)
        .setHeader('Retry-After', '2')
        .json({
          error:
            'Too many simultaneous video/download requests from this connection. Wait a second or avoid rapid scrubbing.'
        });
    }

    const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key }));
    if (obj.ContentLength != null) {
      res.setHeader('Content-Length', String(obj.ContentLength));
    }
    if (!obj.Body || typeof obj.Body.pipe !== 'function') {
      return res.status(500).json({ error: 'Empty body' });
    }
    res.status(200);
    if (!pipeS3BodyWithAbortSupport(req, res, /** @type {import('stream').Readable} */ (obj.Body))) {
      return res.status(500).json({ error: 'Empty body' });
    }
  }

  /**
   * @returns {Promise<{ ok: true, Key: string } | { ok: false, status: number, body: Record<string, unknown> }>}
   */
  async function portalAuthDownloadKey(req, fileId) {
    if (!userCanPortalCapability(req.user, 'download')) {
      return { ok: false, status: 403, body: { error: 'Portal download is not enabled for this account' } };
    }
    const Key = idToKey(fileId);
    if (!Key.startsWith('clients/')) {
      return { ok: false, status: 400, body: { error: 'Invalid id' } };
    }
    if (Key.endsWith(`/${FOLDER_MARKER}`) || path.basename(Key) === FOLDER_MARKER) {
      return { ok: false, status: 400, body: { error: 'Not a downloadable file' } };
    }
    const parsed = parseJobFromObjectKey(Key);
    if (!parsed) {
      return { ok: false, status: 403, body: { error: 'Forbidden' } };
    }
    const prefDl = jobPrefix(parsed.clientId, parsed.jobId);
    const relPathDl = Key.slice(prefDl.length);
    let pathOk = false;
    if (userIsPortalAdmin(req.user)) {
      const now = Date.now();
      const authK = portalDlAuthCacheKey(req.user, fileId);
      const authHit = portalDlAuthCache.get(authK);
      if (authHit && authHit.exp > now) {
        pathOk = authHit.allowed;
      } else {
        pathOk = await assertPortalPathRel(aclPool, req.user, parsed.clientId, parsed.jobId, relPathDl, 'download');
        portalDlAuthCache.set(authK, {
          allowed: pathOk,
          exp: now + (pathOk ? PORTAL_DL_AUTH_TTL_MS : PORTAL_DL_AUTH_DENY_TTL_MS)
        });
        trimPortalDlMap(portalDlAuthCache);
      }
    } else {
      pathOk = await assertPortalPathRel(aclPool, req.user, parsed.clientId, parsed.jobId, relPathDl, 'download');
    }
    if (!pathOk) {
      return { ok: false, status: 403, body: { error: 'Forbidden' } };
    }
    return { ok: true, Key };
  }

  async function handlePortalFileDownload(req, res) {
    try {
      const auth = await portalAuthDownloadKey(req, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      return await sendPortalS3ObjectWithRanges(req, res, auth.Key, 'portal');
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  }

  /** HeadObject metadata for parallel ranged downloads (small JSON; no object body through Render). */
  r.get('/meta/:id', async (req, res) => {
    try {
      const auth = await portalAuthDownloadKey(req, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: auth.Key }));
      return res.json({
        size: Number(head.ContentLength || 0),
        contentType: head.ContentType || 'application/octet-stream',
        ...(head.LastModified ? { lastModified: head.LastModified.toISOString() } : {})
      });
    } catch (e) {
      const hn = e && typeof e === 'object' && 'name' in e ? /** @type {{ name?: string }} */ (e).name : '';
      if (hn === 'NotFound' || hn === 'NoSuchKey' || (e instanceof Error && e.message?.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  /** Presigned Wasabi GET — browser fetches bytes directly (video + large blobs). */
  r.get('/presign/:id', async (req, res) => {
    try {
      if (PORTAL_PRESIGN_DISABLED) {
        return res.status(404).json({ error: 'Presigned playback disabled' });
      }
      const auth = await portalAuthDownloadKey(req, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      try {
        await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: auth.Key }));
      } catch (he) {
        const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
        if (hn === 'NotFound' || hn === 'NoSuchKey' || he?.$metadata?.httpStatusCode === 404) {
          return res.status(404).json({ error: 'Not found' });
        }
        throw he;
      }
      const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: bucket, Key: auth.Key }), {
        expiresIn: PORTAL_PRESIGN_TTL_SECONDS
      });
      return res.json({ url, expiresIn: PORTAL_PRESIGN_TTL_SECONDS });
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.get('/folders/download', async (req, res) => {
    try {
      if (!userCanPortalCapability(req.user, 'download')) {
        return res.status(403).json({ error: 'Portal download is not enabled for this account' });
      }
      const scope = resolvePortalScope(req, req.query || {});
      const pathParam = req.query?.path;
      if (scope.error || pathParam == null || String(pathParam).trim() === '') {
        return res.status(400).json({ error: 'clientId, jobId, and folder path are required' });
      }
      const { clientId, jobId } = scope;
      if (!(await assertPortalJobAccessForRequest(pool, req, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const folderRel = normalizeRelPath(pathParam);
      if (!folderRel) {
        return res.status(400).json({ error: 'Folder path must be non-empty' });
      }
      if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, folderRel, 'download'))) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const pref = jobPrefix(String(clientId), String(jobId));
      const prefix = `${pref}${folderRel}/`;
      const keys = await listAllKeys(s3, bucket, prefix);
      if (!keys.length) {
        return res.status(404).json({ error: 'Folder not found' });
      }

      /** @type {Array<{ key: string, rel: string }>} */
      const files = [];
      for (const entry of keys) {
        const rel = entry.Key.slice(pref.length);
        if (!rel || isFolderMarkerKey(rel)) continue;
        if (!(await assertPortalPathRel(aclPool, req.user, clientId, jobId, rel, 'download'))) continue;
        const subRel = rel.slice(folderRel.length + 1);
        const zipRel = safeZipEntryPath(subRel);
        if (!zipRel) continue;
        files.push({ key: entry.Key, rel: zipRel });
      }

      const rootName = safeZipSegment(basenameRel(folderRel) || 'folder') || 'folder';
      const downloadName = `${rootName}.zip`;
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(downloadName)}"`);
      res.setHeader('Cache-Control', 'private, max-age=60');

      const zip = archiver('zip', { zlib: { level: 9 } });
      zip.on('warning', (warn) => {
        console.warn('[portal-files] zip warning', warn);
      });
      zip.on('error', (err) => {
        if (!res.headersSent) res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
        else res.destroy(err);
      });
      zip.pipe(res);

      if (!files.length) {
        zip.append('', { name: `${rootName}/` });
        await zip.finalize();
        return;
      }

      for (const file of files) {
        const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: file.key }));
        if (!obj.Body || typeof obj.Body.pipe !== 'function') continue;
        zip.append(obj.Body, { name: `${rootName}/${file.rel}` });
      }
      await zip.finalize();
      return;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.get('/download/:id', handlePortalFileDownload);
  r.head('/download/:id', handlePortalFileDownload);

  r.delete('/:id', async (req, res) => {
    try {
      if (!userCanPortalCapability(req.user, 'delete')) {
        return res.status(403).json({ error: 'Portal delete is not enabled for this account' });
      }
      const Key = idToKey(req.params.id);
      if (!Key.startsWith('clients/')) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      if (Key.endsWith(`/${FOLDER_MARKER}`)) {
        return res.status(400).json({ error: 'Use DELETE /api/files/folders to remove folders' });
      }
      const parsed = parseJobFromObjectKey(Key);
      if (!parsed || !(await assertPortalJobAccessForRequest(pool, req, parsed.clientId, parsed.jobId))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const prefDel = jobPrefix(parsed.clientId, parsed.jobId);
      const relPathDel = Key.slice(prefDel.length);
      if (!(await assertPortalPathRel(aclPool, req.user, parsed.clientId, parsed.jobId, relPathDel, 'full'))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key }));
      invalidatePortalDlCachesForFile(req.params.id, Key);
      return res.status(204).send();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  app.use('/api/files', r);

  const guest = express.Router();

  async function loadGuestShareRow(tkn) {
    const q = await aclPool.query(`SELECT * FROM portal_share_links WHERE token = $1`, [String(tkn)]);
    return q.rows[0] || null;
  }

  async function validateGuestSession(guestToken, shareLinkId) {
    const q = await aclPool.query(
      `SELECT 1 FROM portal_share_guest_sessions WHERE guest_token = $1 AND share_link_id = $2`,
      [String(guestToken), String(shareLinkId)]
    );
    return q.rows.length > 0;
  }

  function readGuestTokenFromReq(req) {
    const q = req.query.s || req.query.session;
    return typeof q === 'string' ? q.trim() : '';
  }

  guest.get('/share/:token/meta', async (req, res) => {
    try {
      const row = await loadGuestShareRow(req.params.token);
      if (!row) return res.status(404).json({ error: 'Link not found' });
      const linkKind = portalShareLinkKind(row);
      if (linkKind === 'signin') {
        return res.json({
          kind: 'signin',
          requiresSignIn: true,
          clientId: row.client_id,
          jobId: row.job_id
        });
      }
      const interactive = linkKind === 'interactive';
      const gt = readGuestTokenFromReq(req);
      const unlocked = !interactive || (gt && (await validateGuestSession(gt, row.id)));
      return res.json({
        kind: linkKind || 'public',
        needsRegistration: interactive && !unlocked,
        clientId: row.client_id,
        jobId: row.job_id
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  guest.post('/share/:token/register', express.json({ limit: '64kb' }), async (req, res) => {
    try {
      const row = await loadGuestShareRow(req.params.token);
      if (!row) return res.status(404).json({ error: 'Link not found' });
      if (portalShareLinkKind(row) !== 'interactive') {
        return res.status(400).json({ error: 'This link does not require registration' });
      }
      const { email, firstName, lastName, role, company } = req.body || {};
      const em = String(email ?? '').trim();
      const fn = String(firstName ?? '').trim();
      const ln = String(lastName ?? '').trim();
      const roleStr = String(role ?? '')
        .trim()
        .slice(0, 160);
      const companyStr = String(company ?? '')
        .trim()
        .slice(0, 160);
      if (!isValidEmail(em)) return res.status(400).json({ error: 'Valid email is required' });
      if (fn.length < 1 || fn.length > 120) return res.status(400).json({ error: 'First name is required' });
      if (ln.length < 1 || ln.length > 120) return res.status(400).json({ error: 'Last name is required' });

      const guestToken = crypto.randomBytes(32).toString('base64url');
      const ip =
        String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
          .split(',')[0]
          .trim() || null;
      const ua = String(req.headers['user-agent'] || '').slice(0, 512) || null;

      await pool.query('BEGIN');
      try {
        await pool.query(
          `INSERT INTO portal_share_access_log (share_link_id, email, first_name, last_name, role, company, ip_inet, user_agent)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [row.id, em, fn, ln, roleStr, companyStr, ip, ua]
        );
        await pool.query(
          `INSERT INTO portal_share_guest_sessions (guest_token, share_link_id, email, first_name, last_name, role, company)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [guestToken, row.id, em, fn, ln, roleStr, companyStr]
        );
        await pool.query('COMMIT');
      } catch (e) {
        await pool.query('ROLLBACK');
        throw e;
      }

      return res.json({ guestToken, ok: true });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  async function ensureGuestTreeAccess(req, shareRow) {
    if (portalShareLinkKind(shareRow) !== 'interactive') return true;
    const gt = readGuestTokenFromReq(req);
    if (!gt) return false;
    return validateGuestSession(gt, shareRow.id);
  }

  /**
   * @returns {Promise<{ ok: true, Key: string } | { ok: false, status: number, body: Record<string, unknown> }>}
   */
  async function guestShareAuthObjectKey(req, token, idParam) {
    const row = await loadGuestShareRow(token);
    if (!row) return { ok: false, status: 404, body: { error: 'Link not found' } };
    if (portalShareLinkKind(row) === 'signin') {
      return { ok: false, status: 401, body: { error: 'Sign in required', requiresSignIn: true, kind: 'signin' } };
    }
    if (!(await ensureGuestTreeAccess(req, row))) {
      return { ok: false, status: 401, body: { error: 'Registration required', needsRegistration: true } };
    }
    const payload = row.payload || {};
    const Key = idToKey(idParam);
    if (!Key.startsWith('clients/')) {
      return { ok: false, status: 400, body: { error: 'Invalid id' } };
    }
    const parsed = parseJobFromObjectKey(Key);
    if (!parsed || parsed.clientId !== String(row.client_id) || parsed.jobId !== String(row.job_id)) {
      return { ok: false, status: 403, body: { error: 'Forbidden' } };
    }
    const pref = jobPrefix(String(row.client_id), String(row.job_id));
    const rel = Key.slice(pref.length);
    if (!sharePayloadAllowsFile(rel, keyToId(Key), payload)) {
      return { ok: false, status: 403, body: { error: 'Not included in this share' } };
    }
    return { ok: true, Key };
  }

  /** Guest/public share: presigned Wasabi GET (bytes bypass Render). */
  guest.get('/share/:token/presign/:id', async (req, res) => {
    try {
      if (PORTAL_PRESIGN_DISABLED) {
        return res.status(404).json({ error: 'Presigned playback disabled' });
      }
      const auth = await guestShareAuthObjectKey(req, req.params.token, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      try {
        await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: auth.Key }));
      } catch (he) {
        const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
        if (hn === 'NotFound' || hn === 'NoSuchKey' || he?.$metadata?.httpStatusCode === 404) {
          return res.status(404).json({ error: 'Not found' });
        }
        throw he;
      }
      const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: bucket, Key: auth.Key }), {
        expiresIn: PORTAL_PRESIGN_TTL_SECONDS
      });
      return res.json({ url, expiresIn: PORTAL_PRESIGN_TTL_SECONDS });
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  guest.get('/share/:token/tree', async (req, res) => {
    try {
      const row = await loadGuestShareRow(req.params.token);
      if (!row) return res.status(404).json({ error: 'Link not found' });
      if (portalShareLinkKind(row) === 'signin') {
        return res.status(401).json({ error: 'Sign in required', requiresSignIn: true, kind: 'signin' });
      }
      if (!(await ensureGuestTreeAccess(req, row))) {
        return res.status(401).json({ error: 'Registration required', needsRegistration: true });
      }
      const payload = row.payload || {};
      const prefix = jobPrefix(String(row.client_id), String(row.job_id));
      const keys = await listAllKeys(s3, bucket, prefix);
      const full = buildTreeFromKeys(prefix, keys);
      const filtered = filterTreeForSharePayload(full, payload);
      await mergeCompletedUploadSha256IntoTree(String(row.client_id), String(row.job_id), filtered);
      return res.json(filtered);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  guest.get('/share/:token/download/:id', async (req, res) => {
    try {
      const auth = await guestShareAuthObjectKey(req, req.params.token, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      return await sendPortalS3ObjectWithRanges(req, res, auth.Key, 'share');
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  guest.head('/share/:token/download/:id', async (req, res) => {
    try {
      const auth = await guestShareAuthObjectKey(req, req.params.token, req.params.id);
      if (!auth.ok) return res.status(auth.status).json(auth.body);
      return await sendPortalS3ObjectWithRanges(req, res, auth.Key, 'share');
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  app.use('/api/guest', guest);
  console.log('[portal-files] /api/files + /api/guest mounted (Wasabi bucket:', bucket + ')');
}

module.exports = { registerPortalFilesRoutes };
