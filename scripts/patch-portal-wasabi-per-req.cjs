'use strict';

const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../portal-files.routes.js');
let src = fs.readFileSync(file, 'utf8');
const start = src.indexOf('  const baseHost = process.env.HP_PRIVATE_BASE_DOMAIN');
const end = src.lastIndexOf('module.exports = { registerPortalFilesRoutes }');
if (start < 0 || end < 0) {
  console.error('markers not found');
  process.exit(1);
}

const head = src.slice(0, start);
let body = src.slice(start, end);
const tail = src.slice(end);

const replacements = [
  [/await s3\.send/g, 'await portalS3().send'],
  [/getSignedUrl\(\s*s3,/g, 'getSignedUrl(portalS3(),'],
  [/listAllKeysCapped\(s3, bucket,/g, 'listAllKeysCapped(portalS3(), portalBucket(),'],
  [/listAllKeys\(s3, bucket,/g, 'listAllKeys(portalS3(), portalBucket(),'],
  [/listJobIdsUnderClientJobsPrefix\(s3, bucket,/g, 'listJobIdsUnderClientJobsPrefix(portalS3(), portalBucket(),'],
  [/s3UploadFromTempPath\(s3, bucket,/g, 's3UploadFromTempPath(portalS3(), portalBucket(),'],
  [/Bucket: bucket\b/g, 'Bucket: portalBucket()'],
  [/copySourceHeader\(bucket,/g, 'copySourceHeader(portalBucket(),'],
  [/\$\{bucket\}::/g, '${portalBucket()}::'],
  [/,\s*bucket,\s*$/gm, ', portalBucket(),'],
  [/provider: 'wasabi-s3-compatible',\s*\n\s*bucket,/g, "provider: 'wasabi-s3-compatible',\n        bucket: portalBucket(),"],
  [/error: msg, provider: 'wasabi-s3-compatible', bucket \}/g, "error: msg, provider: 'wasabi-s3-compatible', bucket: portalBucket() }"],
  [
    /const url = await getSignedUrl\(\s*\n\s*s3,/g,
    'const url = await getSignedUrl(\n        portalS3(),'
  ],
  [
    /await getSignedUrl\(\s*\n\s*s3,/g,
    'await getSignedUrl(\n        portalS3(),'
  ]
];

for (const [re, rep] of replacements) {
  body = body.replace(re, rep);
}

// Fix accidental double portalBucket() from nested replaces
body = body.replace(/portalBucket\(\)\(\)/g, 'portalBucket()');

fs.writeFileSync(file, head + body + tail);
console.log('patched portal-files.routes.js for per-request Wasabi');
