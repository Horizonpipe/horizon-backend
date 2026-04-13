'use strict';

const crypto = require('crypto');
const { PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const ADMIN_ATTACHMENT_STORAGE_PREFIX = 'app-data/horizon-admin/attachments/';

function sanitizeAdminAttachmentFilename(name) {
  const base = String(name || '').split(/[/\\]/).pop() || 'upload.bin';
  const cleaned = base.replace(/[^\w.\-+()\[\] ]/g, '_').trim();
  return (cleaned || 'upload.bin').slice(0, 200);
}

function buildAdminAttachmentStorageKey(fileName) {
  const id = crypto.randomUUID();
  return `${ADMIN_ATTACHMENT_STORAGE_PREFIX}${id}/${sanitizeAdminAttachmentFilename(fileName)}`;
}

function isValidAdminAttachmentStorageKey(key) {
  if (typeof key !== 'string') return false;
  if (!key.startsWith(ADMIN_ATTACHMENT_STORAGE_PREFIX)) return false;
  if (key.length >= 4096 || key.includes('..')) return false;
  return true;
}

/** @param {'daily-report'|'jobsite-asset'} fileKind */
function isAllowedAdminAttachmentContentType(mime, fileKind) {
  const m = (String(mime || '').trim().toLowerCase() || 'application/octet-stream').split(';')[0].trim();
  if (fileKind === 'daily-report') return m.startsWith('image/');
  return m.startsWith('image/') || m === 'application/pdf';
}

async function presignAdminAttachmentPut(client, bucket, key, contentType, expiresIn) {
  const ct = String(contentType || 'application/octet-stream').trim() || 'application/octet-stream';
  const cmd = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    ContentType: ct
  });
  const url = await getSignedUrl(client, cmd, { expiresIn });
  return { url, method: 'PUT', headers: { 'Content-Type': ct }, storageKey: key, expiresIn };
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
  sanitizeAdminAttachmentFilename,
  buildAdminAttachmentStorageKey,
  isValidAdminAttachmentStorageKey,
  isAllowedAdminAttachmentContentType,
  presignAdminAttachmentPut,
  presignAdminAttachmentGet,
  deleteAdminAttachmentKeys,
  collectAdminAttachmentStorageKeysFromFiles,
  storageKeysRemovedBetweenFileLists,
  normalizeAdminFilesForPersist,
  hydrateAdminFilesWithViewUrls,
  hydrateAdminReportOrAssetRows
};
