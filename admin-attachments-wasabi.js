'use strict';

const crypto = require('crypto');
const { PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const ADMIN_ATTACHMENT_STORAGE_PREFIX = 'app-data/horizon-admin/attachments/';
/** PipeSync Plan view pages (images or PDF) — same Wasabi bucket, distinct prefix for ACL hygiene. */
const PIPESYNC_PLAN_PAGE_STORAGE_PREFIX = 'app-data/horizon-pipesync/plan-pages/';
/** Versioned workspace checkpoints (board layout, masks, crops) — JSON blobs keyed by save id. */
const PIPESYNC_PLAN_WORKSPACE_SAVE_PREFIX = 'app-data/horizon-pipesync/plan-workspace-saves/';
/** Pre-baked plan PDFs for PipeShare (highlights embedded at share time). One object per doc page; overwritten when content changes. */
const PIPESYNC_PLAN_SHARE_BAKE_PREFIX = 'app-data/horizon-pipesync/plan-share-bakes/';

function sanitizeAdminAttachmentFilename(name) {
  const base = String(name || '').split(/[/\\]/).pop() || 'upload.bin';
  const cleaned = base.replace(/[^\w.\-+()\[\] ]/g, '_').trim();
  return (cleaned || 'upload.bin').slice(0, 200);
}

function buildAdminAttachmentStorageKey(fileName) {
  const id = crypto.randomUUID();
  return `${ADMIN_ATTACHMENT_STORAGE_PREFIX}${id}/${sanitizeAdminAttachmentFilename(fileName)}`;
}

function buildPipesyncPlanPageStorageKey(fileName) {
  const id = crypto.randomUUID();
  return `${PIPESYNC_PLAN_PAGE_STORAGE_PREFIX}${id}/${sanitizeAdminAttachmentFilename(fileName)}`;
}

function isValidPipesyncPlanPageStorageKey(key) {
  if (typeof key !== 'string') return false;
  if (!key.startsWith(PIPESYNC_PLAN_PAGE_STORAGE_PREFIX)) return false;
  if (key.length >= 4096 || key.includes('..')) return false;
  return true;
}

function sanitizePlanShareBakeIdSegment(value) {
  const id = String(value || '').trim().toLowerCase();
  if (!id || !/^[0-9a-f-]{36}$/.test(id)) return '';
  return id;
}

function planShareBakeSegmentFromSourceStorageKey(sourceStorageKey) {
  const sk = String(sourceStorageKey || '').trim();
  if (!sk) throw new Error('sourceStorageKey is required');
  return crypto.createHash('sha256').update(sk, 'utf8').digest('hex').slice(0, 32);
}

/** Stable bake object per doc + source PDF piece (survives page moves / folder reorganize in Plan View). */
function buildPipesyncPlanShareBakeStorageKey(docId, sourceStorageKey) {
  const doc = sanitizePlanShareBakeIdSegment(docId);
  if (!doc) throw new Error('docId must be a valid UUID');
  const seg = planShareBakeSegmentFromSourceStorageKey(sourceStorageKey);
  return `${PIPESYNC_PLAN_SHARE_BAKE_PREFIX}${doc}/${seg}.pdf`;
}

/** @deprecated Legacy page-id bakes — kept for HEAD fallback only. */
function buildPipesyncPlanShareBakeStorageKeyLegacy(docId, pageId) {
  const doc = sanitizePlanShareBakeIdSegment(docId);
  const page = sanitizePlanShareBakeIdSegment(pageId);
  if (!doc || !page) throw new Error('docId and pageId must be valid UUIDs');
  return `${PIPESYNC_PLAN_SHARE_BAKE_PREFIX}${doc}/${page}.pdf`;
}

function isValidPipesyncPlanShareBakeStorageKey(key) {
  if (typeof key !== 'string') return false;
  if (!key.startsWith(PIPESYNC_PLAN_SHARE_BAKE_PREFIX)) return false;
  if (!key.endsWith('.pdf')) return false;
  if (key.length >= 4096 || key.includes('..')) return false;
  const rest = key.slice(PIPESYNC_PLAN_SHARE_BAKE_PREFIX.length);
  const parts = rest.split('/');
  if (parts.length !== 2) return false;
  const pagePart = parts[1];
  if (!pagePart.endsWith('.pdf')) return false;
  const seg = pagePart.slice(0, -4);
  if (sanitizePlanShareBakeIdSegment(parts[0]) !== parts[0]) return false;
  return /^[0-9a-f]{32}$/.test(seg) || sanitizePlanShareBakeIdSegment(seg) === seg;
}

function isValidPlanShareDownloadStorageKey(key) {
  return isValidPipesyncPlanPageStorageKey(key) || isValidPipesyncPlanShareBakeStorageKey(key);
}

function buildPipesyncPlanWorkspaceSaveStorageKey(saveId) {
  const id = String(saveId || '').trim();
  if (!id || !/^[0-9a-f-]{36}$/i.test(id)) {
    throw new Error('Invalid workspace save id');
  }
  return `${PIPESYNC_PLAN_WORKSPACE_SAVE_PREFIX}${id}.json`;
}

function isValidPipesyncPlanWorkspaceSaveStorageKey(key) {
  if (typeof key !== 'string') return false;
  if (!key.startsWith(PIPESYNC_PLAN_WORKSPACE_SAVE_PREFIX)) return false;
  if (!key.endsWith('.json')) return false;
  if (key.length >= 4096 || key.includes('..')) return false;
  return true;
}

function isValidAdminAttachmentStorageKey(key) {
  if (typeof key !== 'string') return false;
  if (!key.startsWith(ADMIN_ATTACHMENT_STORAGE_PREFIX)) return false;
  if (key.length >= 4096 || key.includes('..')) return false;
  return true;
}

/** @param {'daily-report'|'jobsite-asset'|'pipesync-plan-view'} fileKind */
function isAllowedAdminAttachmentContentType(mime, fileKind) {
  const m = (String(mime || '').trim().toLowerCase() || 'application/octet-stream').split(';')[0].trim();
  if (fileKind === 'daily-report') return m.startsWith('image/') || m === 'application/pdf';
  if (fileKind === 'pipesync-plan-view') return m.startsWith('image/') || m === 'application/pdf';
  return m.startsWith('image/') || m === 'application/pdf';
}

async function presignAdminAttachmentPut(client, bucket, key, contentType, expiresIn, metadata = null) {
  const ct = String(contentType || 'application/octet-stream').trim() || 'application/octet-stream';
  const cmd = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    ContentType: ct,
    ...(metadata && typeof metadata === 'object' ? { Metadata: metadata } : {})
  });
  const url = await getSignedUrl(client, cmd, { expiresIn });
  return { url, method: 'PUT', headers: { 'Content-Type': ct }, storageKey: key, expiresIn };
}

async function headPipesyncPlanShareBake(client, bucket, key) {
  if (!isValidPipesyncPlanShareBakeStorageKey(key)) {
    return { exists: false, bakeFingerprint: '' };
  }
  try {
    const out = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    const meta = out.Metadata && typeof out.Metadata === 'object' ? out.Metadata : {};
    const bakeFingerprint =
      String(meta['bake-fingerprint'] || meta.bakefingerprint || meta['bakeFingerprint'] || '').trim();
    return {
      exists: true,
      bakeFingerprint,
      contentLength: Math.max(0, Number(out.ContentLength) || 0)
    };
  } catch (error) {
    const status = Number(error?.$metadata?.httpStatusCode) || 0;
    if (status === 404 || String(error?.name || '') === 'NotFound') {
      return { exists: false, bakeFingerprint: '' };
    }
    throw error;
  }
}

async function presignPipesyncPlanShareBakePut(client, bucket, key, contentType, bakeFingerprint, expiresIn) {
  if (!isValidPipesyncPlanShareBakeStorageKey(key)) throw new Error('Invalid plan share bake storage key');
  const fp = String(bakeFingerprint || '').trim().slice(0, 128);
  return presignAdminAttachmentPut(client, bucket, key, contentType, expiresIn, fp ? { 'bake-fingerprint': fp } : null);
}

async function presignAdminAttachmentGet(client, bucket, key, expiresIn) {
  const cmd = new GetObjectCommand({ Bucket: bucket, Key: key });
  const url = await getSignedUrl(client, cmd, { expiresIn });
  return { url, expiresIn };
}

async function deleteAdminAttachmentKeys(client, bucket, keys) {
  if (!client || !bucket || !Array.isArray(keys)) return;
  const seen = new Set();
  for (const raw of keys) {
    const key = String(raw || '').trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    if (!isValidAdminAttachmentStorageKey(key)) continue;
    try {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    } catch {
      /* best-effort */
    }
  }
}

async function deletePipesyncPlanPageKeys(client, bucket, keys) {
  if (!client || !bucket || !Array.isArray(keys)) return;
  const seen = new Set();
  for (const raw of keys) {
    const key = String(raw || '').trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    if (!isValidPipesyncPlanPageStorageKey(key)) continue;
    try {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    } catch {
      /* best-effort */
    }
  }
}

function collectAdminAttachmentStorageKeysFromFiles(files) {
  const out = [];
  const list = Array.isArray(files) ? files : [];
  for (const f of list) {
    const k = f && typeof f.storageKey === 'string' ? f.storageKey.trim() : '';
    if (k && isValidAdminAttachmentStorageKey(k)) out.push(k);
  }
  return out;
}

/** Keys present in oldFiles but not in newFiles (by storageKey string). */
function storageKeysRemovedBetweenFileLists(oldFiles, newFiles) {
  const oldKeys = new Set(collectAdminAttachmentStorageKeysFromFiles(oldFiles));
  const kept = new Set(collectAdminAttachmentStorageKeysFromFiles(newFiles));
  return [...oldKeys].filter((k) => !kept.has(k));
}

function normalizeAdminFilesForPersist(rawFiles) {
  const list = Array.isArray(rawFiles) ? rawFiles : [];
  const out = [];
  for (const raw of list) {
    if (!raw || typeof raw !== 'object') continue;
    const f = { ...raw };
    delete f.viewUrl;
    delete f.url;
    const id = String(f.id || '').trim();
    const name = String(f.name || f.originalname || '').trim() || 'file';
    const mime = String(f.mime || f.mimetype || 'application/octet-stream').trim();
    const size = Math.floor(Number(f.size));
    const storageKey = String(f.storageKey || '').trim();
    const dataUrl = typeof f.dataUrl === 'string' && f.dataUrl.startsWith('data:') ? f.dataUrl : '';

    const next = { id: id || crypto.randomUUID(), name, mime, size: Number.isFinite(size) && size >= 0 ? size : 0 };
    if (storageKey && isValidAdminAttachmentStorageKey(storageKey)) {
      next.storageKey = storageKey;
      out.push(next);
    } else if (dataUrl) {
      next.dataUrl = dataUrl;
      out.push(next);
    }
  }
  return out;
}

async function hydrateAdminFilesWithViewUrls(client, bucket, files, viewExpiresIn) {
  if (!client || !bucket || !Array.isArray(files)) return files || [];
  const ttl = Number(viewExpiresIn);
  const expiresIn = Number.isFinite(ttl) && ttl >= 60 ? ttl : 3600;
  const out = [];
  for (const f of files) {
    if (!f || typeof f !== 'object') continue;
    const copy = { ...f };
    delete copy.viewUrl;
    const sk = String(copy.storageKey || '').trim();
    if (sk && isValidAdminAttachmentStorageKey(sk) && !copy.dataUrl) {
      try {
        const { url } = await presignAdminAttachmentGet(client, bucket, sk, expiresIn);
        copy.viewUrl = url;
      } catch {
        /* leave without viewUrl */
      }
    }
    out.push(copy);
  }
  return out;
}

async function hydrateAdminReportOrAssetRows(client, bucket, rows, filesField, viewExpiresIn) {
  if (!Array.isArray(rows) || !rows.length) return rows;
  const mapped = [];
  for (const row of rows) {
    const next = { ...row };
    next[filesField] = await hydrateAdminFilesWithViewUrls(client, bucket, row[filesField], viewExpiresIn);
    mapped.push(next);
  }
  return mapped;
}

module.exports = {
  ADMIN_ATTACHMENT_STORAGE_PREFIX,
  PIPESYNC_PLAN_PAGE_STORAGE_PREFIX,
  PIPESYNC_PLAN_SHARE_BAKE_PREFIX,
  PIPESYNC_PLAN_WORKSPACE_SAVE_PREFIX,
  sanitizeAdminAttachmentFilename,
  buildAdminAttachmentStorageKey,
  buildPipesyncPlanPageStorageKey,
  buildPipesyncPlanShareBakeStorageKey,
  buildPipesyncPlanShareBakeStorageKeyLegacy,
  planShareBakeSegmentFromSourceStorageKey,
  buildPipesyncPlanWorkspaceSaveStorageKey,
  isValidPipesyncPlanPageStorageKey,
  isValidPipesyncPlanShareBakeStorageKey,
  isValidPlanShareDownloadStorageKey,
  isValidPipesyncPlanWorkspaceSaveStorageKey,
  isValidAdminAttachmentStorageKey,
  isAllowedAdminAttachmentContentType,
  presignAdminAttachmentPut,
  presignPipesyncPlanShareBakePut,
  presignAdminAttachmentGet,
  headPipesyncPlanShareBake,
  deleteAdminAttachmentKeys,
  deletePipesyncPlanPageKeys,
  collectAdminAttachmentStorageKeysFromFiles,
  storageKeysRemovedBetweenFileLists,
  normalizeAdminFilesForPersist,
  hydrateAdminFilesWithViewUrls,
  hydrateAdminReportOrAssetRows
};
