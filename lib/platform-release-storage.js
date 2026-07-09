'use strict';

const { S3Client } = require('@aws-sdk/client-s3');

function cleanString(v) {
  return String(v ?? '').trim();
}

/**
 * Wasabi bucket for platform release manifest + artifacts.
 * Hybrid OVH: legacy portal files use WASABI_BUCKET; release catalog uses SAAS_WASABI_BUCKET.
 */
function resolvePlatformReleaseBucket(env = process.env) {
  return (
    cleanString(env.HP_PLATFORM_RELEASE_BUCKET) ||
    cleanString(env.SAAS_WASABI_BUCKET) ||
    cleanString(env.WASABI_BUCKET)
  );
}

/** Buckets to probe for release manifest + artifacts (publish script may target a different bucket than Node default). */
function listPlatformReleaseBucketCandidates(env = process.env) {
  const out = [];
  for (const b of [
    cleanString(env.HP_PLATFORM_RELEASE_BUCKET),
    cleanString(env.WASABI_BUCKET),
    cleanString(env.SAAS_WASABI_BUCKET)
  ]) {
    if (b && !out.includes(b)) out.push(b);
  }
  return out;
}

function resolvePlatformReleaseS3Config(env = process.env) {
  const bucket = resolvePlatformReleaseBucket(env);
  const saasBucket = cleanString(env.SAAS_WASABI_BUCKET);
  const useSaas = Boolean(saasBucket && bucket === saasBucket);
  const region =
    (useSaas && cleanString(env.SAAS_WASABI_REGION)) ||
    cleanString(env.WASABI_REGION) ||
    'us-east-1';
  const endpoint =
    (useSaas && cleanString(env.SAAS_WASABI_ENDPOINT)) ||
    cleanString(env.WASABI_ENDPOINT) ||
    `https://s3.${region}.wasabisys.com`;
  return { bucket, region, endpoint };
}

function resolveS3ConfigForBucket(bucket, env = process.env) {
  const b = cleanString(bucket);
  const saasBucket = cleanString(env.SAAS_WASABI_BUCKET);
  if (b && saasBucket && b === saasBucket) {
    const region = cleanString(env.SAAS_WASABI_REGION) || 'us-east-2';
    return {
      bucket: b,
      region,
      endpoint:
        cleanString(env.SAAS_WASABI_ENDPOINT) || `https://s3.${region}.wasabisys.com`
    };
  }
  const region = cleanString(env.WASABI_REGION) || 'us-east-1';
  return {
    bucket: b,
    region,
    endpoint: cleanString(env.WASABI_ENDPOINT) || `https://s3.${region}.wasabisys.com`
  };
}

function createS3ClientForBucket(bucket, env = process.env) {
  const { region, endpoint } = resolveS3ConfigForBucket(bucket, env);
  const accessKeyId = cleanString(env.WASABI_ACCESS_KEY_ID || env.WASABI_ACCESS_KEY);
  const secretAccessKey = cleanString(env.WASABI_SECRET_ACCESS_KEY || env.WASABI_SECRET_KEY);
  if (!accessKeyId || !secretAccessKey || !cleanString(bucket)) return null;
  return new S3Client({
    region,
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true
  });
}

function createPlatformReleaseS3Client(env = process.env) {
  const { region, endpoint } = resolvePlatformReleaseS3Config(env);
  const accessKeyId = cleanString(env.WASABI_ACCESS_KEY_ID || env.WASABI_ACCESS_KEY);
  const secretAccessKey = cleanString(env.WASABI_SECRET_ACCESS_KEY || env.WASABI_SECRET_KEY);
  if (!accessKeyId || !secretAccessKey) return null;
  return new S3Client({
    region,
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true
  });
}

module.exports = {
  resolvePlatformReleaseBucket,
  listPlatformReleaseBucketCandidates,
  resolvePlatformReleaseS3Config,
  resolveS3ConfigForBucket,
  createS3ClientForBucket,
  createPlatformReleaseS3Client
};
