'use strict';
/**
 * Ensure both portal buckets allow browser Range GET/HEAD and presigned PUT.
 * Safe to re-run. Does not print credentials.
 *
 *   cd /opt/horizon/horizon-backend && node deploy/ovh/ensure-wasabi-cors.cjs
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '..', '.env') });
const { S3Client, PutBucketCorsCommand, GetBucketCorsCommand } = require('@aws-sdk/client-s3');
const { NodeHttpHandler } = require('@smithy/node-http-handler');

const CORS = {
  CORSRules: [
    {
      AllowedOrigins: ['*'],
      AllowedMethods: ['GET', 'HEAD', 'PUT', 'POST'],
      AllowedHeaders: ['*'],
      ExposeHeaders: [
        'ETag',
        'Content-Length',
        'Content-Range',
        'Accept-Ranges',
        'Content-Type',
        'Content-Disposition'
      ],
      MaxAgeSeconds: 3600
    }
  ]
};

function clientFor(region, endpoint) {
  const accessKeyId = process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY;
  const secretAccessKey = process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY;
  if (!accessKeyId || !secretAccessKey) throw new Error('Wasabi credentials missing');
  return new S3Client({
    region,
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true,
    requestHandler: new NodeHttpHandler({ connectionTimeout: 15000, socketTimeout: 30000 })
  });
}

async function ensure(s3, bucket) {
  if (!bucket) {
    console.log(JSON.stringify({ bucket: null, skipped: true }));
    return;
  }
  await s3.send(new PutBucketCorsCommand({ Bucket: bucket, CORSConfiguration: CORS }));
  const got = await s3.send(new GetBucketCorsCommand({ Bucket: bucket }));
  const rule = (got.CORSRules || [])[0] || {};
  console.log(
    JSON.stringify({
      bucket,
      origins: rule.AllowedOrigins || [],
      methods: rule.AllowedMethods || [],
      expose: rule.ExposeHeaders || []
    })
  );
}

async function main() {
  const base = clientFor(process.env.WASABI_REGION || 'us-east-1', process.env.WASABI_ENDPOINT);
  const saas = clientFor(
    process.env.SAAS_WASABI_REGION || process.env.WASABI_REGION || 'us-east-1',
    process.env.SAAS_WASABI_ENDPOINT || process.env.WASABI_ENDPOINT
  );
  await ensure(base, process.env.WASABI_BUCKET);
  await ensure(saas, process.env.SAAS_WASABI_BUCKET);
}

main().catch((e) => {
  console.error('FAIL', e && (e.name || e.Code), e && e.message);
  process.exit(1);
});
