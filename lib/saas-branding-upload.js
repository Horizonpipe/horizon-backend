'use strict';

const crypto = require('crypto');
const { PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const BRANDING_PRESIGN_TTL_SECONDS = 900;
const LOGO_MAX_BYTES = 5 * 1024 * 1024;
const SAMPLE_MAX_BYTES = 8 * 1024 * 1024;
const MAX_SAMPLE_COUNT = 8;

function sanitizeBrandingFileName(name) {
  const base = String(name || '').split(/[/\\]/).pop() || 'upload.bin';
  const cleaned = base.replace(/[^\w.\-+()\[\] ]/g, '_').trim();
  return (cleaned || 'upload.bin').slice(0, 200);
}

function normalizeTenantRoot(rootPrefix) {
  const root = String(rootPrefix || '').trim();
  if (!root) return '';
  return root.endsWith('/') ? root : `${root}/`;
}

function buildTenantBrandingStorageKey(rootPrefix, kind, fileName) {
  const root = normalizeTenantRoot(rootPrefix);
  if (!/^Tenants\/[^/]+\//i.test(root) && !/^tenants\/[^/]+\//.test(root)) {
    throw new Error('Tenant storage root is not configured');
  }
  const folder = kind === 'logo' ? 'logo' : 'samples';
  const id = crypto.randomUUID();
  return `${root}branding/${folder}/${id}/${sanitizeBrandingFileName(fileName)}`;
}

function isValidTenantBrandingStorageKey(key, rootPrefix) {
  const root = normalizeTenantRoot(rootPrefix);
  if (!root || typeof key !== 'string') return false;
  if (key.length >= 4096 || key.includes('..')) return false;
  return key.startsWith(`${root}branding/`);
}

function isAllowedBrandingContentType(mime) {
  const m = String(mime || '')
    .trim()
    .toLowerCase()
    .split(';')[0]
    .trim();
  return m.startsWith('image/');
}

function maxBytesForKind(kind) {
  return kind === 'logo' ? LOGO_MAX_BYTES : SAMPLE_MAX_BYTES;
}

async function presignTenantBrandingPut(client, bucket, key, contentType, expiresIn) {
  const ct = String(contentType || 'application/octet-stream').trim() || 'application/octet-stream';
  const cmd = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    ContentType: ct
  });
  const ttl = Number(expiresIn);
  const seconds = Number.isFinite(ttl) && ttl >= 60 ? ttl : BRANDING_PRESIGN_TTL_SECONDS;
  const url = await getSignedUrl(client, cmd, { expiresIn: seconds });
  return {
    url,
    method: 'PUT',
    headers: { 'Content-Type': ct },
    storageKey: key,
    expiresIn: seconds
  };
}

module.exports = {
  BRANDING_PRESIGN_TTL_SECONDS,
  LOGO_MAX_BYTES,
  SAMPLE_MAX_BYTES,
  MAX_SAMPLE_COUNT,
  buildTenantBrandingStorageKey,
  isValidTenantBrandingStorageKey,
  isAllowedBrandingContentType,
  maxBytesForKind,
  presignTenantBrandingPut
};
