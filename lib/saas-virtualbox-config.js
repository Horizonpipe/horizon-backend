'use strict';

const { S3Client } = require('@aws-sdk/client-s3');

function cleanString(v) {
  return String(v ?? '').trim();
}

/** Wasabi bucket dedicated to SaaS leased virtualboxes (e.g. saaspipeshare). */
function saasWasabiBucket() {
  return cleanString(process.env.SAAS_WASABI_BUCKET || process.env.WASABI_BUCKET);
}

function saasWasabiRegion() {
  return cleanString(process.env.SAAS_WASABI_REGION || process.env.WASABI_REGION || 'us-east-2');
}

function saasWasabiEndpoint() {
  const explicit = cleanString(process.env.SAAS_WASABI_ENDPOINT || process.env.WASABI_ENDPOINT);
  if (explicit) return explicit.replace(/\/$/, '');
  const region = saasWasabiRegion();
  return `https://s3.${region}.wasabisys.com`;
}

/** Top-level folder inside the SaaS bucket — default `Tenants/`. */
function saasTenantFolderPrefix() {
  const raw = cleanString(process.env.SAAS_TENANT_FOLDER_PREFIX || 'Tenants');
  const normalized = raw.replace(/\/+$/, '');
  return normalized ? `${normalized}/` : 'Tenants/';
}

let saasWasabiClient = null;

function createSaasWasabiClient() {
  const accessKeyId = cleanString(process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY);
  const secretAccessKey = cleanString(
    process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY
  );
  if (!accessKeyId || !secretAccessKey) return null;
  const endpoint = saasWasabiEndpoint();
  return new S3Client({
    region: saasWasabiRegion(),
    endpoint,
    forcePathStyle: !!endpoint,
    credentials: { accessKeyId, secretAccessKey }
  });
}

function getSaasWasabiClient() {
  if (!saasWasabiClient) {
    saasWasabiClient = createSaasWasabiClient();
  }
  return saasWasabiClient;
}

function saasVirtualboxConfigured() {
  return !!(getSaasWasabiClient() && saasWasabiBucket());
}

module.exports = {
  saasWasabiBucket,
  saasWasabiRegion,
  saasWasabiEndpoint,
  saasTenantFolderPrefix,
  createSaasWasabiClient,
  getSaasWasabiClient,
  saasVirtualboxConfigured
};
