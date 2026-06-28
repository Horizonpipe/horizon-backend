'use strict';

const crypto = require('crypto');
const { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

/** Support chat file blobs — distinct from portal job files and admin attachments. */
const CHAT_UPLOAD_STORAGE_PREFIX = 'chat-uploads/';
/**
 * Retention window; attachment JSON stores matching expiresAt.
 * Optional cleanup: list `chat-uploads/` and delete keys where HeadObject metadata
 * `expires-at` (or message DB) is past TTL, or configure Wasabi lifecycle on prefix.
 */
const CHAT_UPLOAD_TTL_MS = 10 * 24 * 60 * 60 * 1000;
const CHAT_UPLOAD_PRESIGN_TTL_SECONDS = 3600;
const MAX_CHAT_UPLOAD_BYTES = 100 * 1024 * 1024;

function cleanSegment(v) {
  const t = String(v ?? '').trim();
  if (!t || t.includes('..') || t.includes('/') || t.includes('\\')) {
    throw new Error('Invalid chat upload scope');
  }
  return t;
}

function sanitizeChatUploadFilename(name) {
  const base = String(name || '').split(/[/\\]/).pop() || 'file.bin';
  const cleaned = base.replace(/[^\w.\-+ ()\[\]]+/g, '_').trim();
  return (cleaned || 'file.bin').slice(0, 200);
}

function buildChatUploadStorageKey(tenantId, sessionId, fileName) {
  const fileId = crypto.randomUUID();
  const safeName = sanitizeChatUploadFilename(fileName);
  const tenant = cleanSegment(tenantId);
  const session = cleanSegment(sessionId);
  const expiresAt = new Date(Date.now() + CHAT_UPLOAD_TTL_MS).toISOString();
  return {
    fileId,
    wasabiKey: `${CHAT_UPLOAD_STORAGE_PREFIX}${tenant}/${session}/${fileId}-${safeName}`,
    expiresAt
  };
}

function chatUploadKeyPrefix(tenantId, sessionId) {
  return `${CHAT_UPLOAD_STORAGE_PREFIX}${cleanSegment(tenantId)}/${cleanSegment(sessionId)}/`;
}

function isValidChatUploadStorageKey(key, tenantId, sessionId) {
  if (typeof key !== 'string') return false;
  const prefix = chatUploadKeyPrefix(tenantId, sessionId);
  if (!key.startsWith(prefix)) return false;
  if (key.includes('..') || key.length >= 1024) return false;
  return true;
}

function isChatUploadExpired(expiresAt) {
  const t = Date.parse(String(expiresAt || ''));
  if (!Number.isFinite(t)) return true;
  return Date.now() >= t;
}

function createChatUploadWasabiClient() {
  const accessKeyId = process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY;
  const secretAccessKey = process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY;
  const region = process.env.WASABI_REGION || 'us-east-1';
  const endpoint = process.env.WASABI_ENDPOINT || 'https://s3.us-east-1.wasabisys.com';
  if (!accessKeyId || !secretAccessKey) return null;
  return new S3Client({
    region,
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true
  });
}

function chatUploadBucketName() {
  return process.env.WASABI_BUCKET || null;
}

async function presignChatUploadPut(client, bucket, key, contentType, expiresAt, expiresIn = CHAT_UPLOAD_PRESIGN_TTL_SECONDS) {
  const ct = String(contentType || 'application/octet-stream').trim() || 'application/octet-stream';
  const cmd = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    ContentType: ct,
    Metadata: {
      'expires-at': String(expiresAt || ''),
      'horizon-kind': 'support-chat-upload'
    }
  });
  const url = await getSignedUrl(client, cmd, { expiresIn });
  return {
    url,
    method: 'PUT',
    headers: { 'Content-Type': ct },
    expiresIn
  };
}

async function presignChatUploadGet(client, bucket, key, expiresIn = CHAT_UPLOAD_PRESIGN_TTL_SECONDS) {
  const cmd = new GetObjectCommand({ Bucket: bucket, Key: key });
  const url = await getSignedUrl(client, cmd, { expiresIn });
  return { url, expiresIn };
}

async function headChatUploadObject(client, bucket, key) {
  return client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
}

module.exports = {
  CHAT_UPLOAD_STORAGE_PREFIX,
  CHAT_UPLOAD_TTL_MS,
  CHAT_UPLOAD_PRESIGN_TTL_SECONDS,
  MAX_CHAT_UPLOAD_BYTES,
  buildChatUploadStorageKey,
  isValidChatUploadStorageKey,
  isChatUploadExpired,
  createChatUploadWasabiClient,
  chatUploadBucketName,
  presignChatUploadPut,
  presignChatUploadGet,
  headChatUploadObject,
  sanitizeChatUploadFilename
};
