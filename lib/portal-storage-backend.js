'use strict';

const { S3Client } = require('@aws-sdk/client-s3');
const { NodeHttpHandler } = require('@smithy/node-http-handler');
const { resolveDeploymentProfile } = require('./deployment-profile');

/** @type {{ base: import('@aws-sdk/client-s3').S3Client | null, saas: import('@aws-sdk/client-s3').S3Client | null }} */
const cachedClients = { base: null, saas: null };

function cleanString(v) {
  return String(v ?? '').trim();
}

/**
 * @param {boolean} useSaasBucket
 * @returns {import('@aws-sdk/client-s3').S3Client | null}
 */
function createPortalWasabiClient(useSaasBucket) {
  const accessKeyId = process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY;
  const secretAccessKey = process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY;
  const region =
    (useSaasBucket && process.env.SAAS_WASABI_REGION) ||
    process.env.WASABI_REGION ||
    'us-east-1';
  const endpoint =
    (useSaasBucket && process.env.SAAS_WASABI_ENDPOINT) ||
    process.env.WASABI_ENDPOINT ||
    `https://s3.${region}.wasabisys.com`;
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

/**
 * @param {{ features?: { tenantVirtualboxStorage?: boolean } }} profile
 */
function resolvePortalBucket(profile) {
  if (profile?.features?.tenantVirtualboxStorage && process.env.SAAS_WASABI_BUCKET) {
    return process.env.SAAS_WASABI_BUCKET;
  }
  return process.env.WASABI_BUCKET || null;
}

function useSaasPortalBucket(profile) {
  return profile.features.tenantVirtualboxStorage === true && !!process.env.SAAS_WASABI_BUCKET;
}

function getCachedPortalClient(useSaasBucket) {
  const key = useSaasBucket ? 'saas' : 'base';
  if (!cachedClients[key]) {
    cachedClients[key] = createPortalWasabiClient(useSaasBucket);
  }
  return cachedClients[key];
}

/**
 * Resolve Wasabi client, bucket, and tenant root prefix for a portal-files request.
 * @param {import('express').Request | { headers?: Record<string, string | string[] | undefined>, tenantStorage?: { wasabiRootPrefix?: string } } | null | undefined} req
 */
function resolveStorageBackend(req) {
  const requestHost = cleanString(req?.headers?.['x-forwarded-host'] || req?.headers?.host);
  const profile = resolveDeploymentProfile({ requestHost });
  const saasBucket = useSaasPortalBucket(profile);
  return Object.freeze({
    profile,
    s3: getCachedPortalClient(saasBucket),
    bucket: resolvePortalBucket(profile),
    rootPrefix: cleanString(req?.tenantStorage?.wasabiRootPrefix),
    useSaasBucket: saasBucket
  });
}

/** Process-level defaults (this PM2 app runs one deployment mode). */
function resolveStorageBackendForProcess() {
  return resolveStorageBackend({ headers: {}, tenantStorage: {} });
}

module.exports = {
  createPortalWasabiClient,
  resolvePortalBucket,
  resolveStorageBackend,
  resolveStorageBackendForProcess
};
