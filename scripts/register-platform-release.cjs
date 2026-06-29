'use strict';

require('dotenv').config();
const fs = require('fs');
const {
  createPlatformReleaseS3Client,
  resolvePlatformReleaseBucket,
  resolvePlatformReleaseS3Config
} = require('../lib/platform-release-storage');
const { publishPlatformRelease } = require('../platform-release.service');

const version = process.argv[2] || '0.0.1';
const gitSha = process.argv[3] || '';

if (process.env.HP_DEPLOYMENT_MODE !== 'non-saas') {
  console.error('Set HP_DEPLOYMENT_MODE=non-saas for registration');
  process.exit(1);
}

const draft = JSON.parse(fs.readFileSync('platform-release-draft.json', 'utf8'));
const client = createPlatformReleaseS3Client();
const bucket = resolvePlatformReleaseBucket();
const { region, endpoint } = resolvePlatformReleaseS3Config();
if (!client || !bucket) {
  console.error('Platform release Wasabi client/bucket not configured');
  process.exit(1);
}
console.error(`[register] bucket=${bucket} region=${region} endpoint=${endpoint}`);

publishPlatformRelease(client, bucket, {
  version,
  title: draft.title,
  description: draft.description,
  changeLog: draft.changeLog,
  gitSha,
  gitBranch: 'main',
  artifactKeys: {
    frontend: `platform/releases/${version}/artifacts/frontend.tar.gz`,
    backend: `platform/releases/${version}/artifacts/backend.tar.gz`
  }
})
  .then((result) => {
    console.log(JSON.stringify(result, null, 2));
  })
  .catch((error) => {
    console.error(error.message || error);
    process.exit(1);
  });
