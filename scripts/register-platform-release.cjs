'use strict';

require('dotenv').config();
const fs = require('fs');
const { S3Client } = require('@aws-sdk/client-s3');
const { publishPlatformRelease } = require('../platform-release.service');

const version = process.argv[2] || '0.0.1';
const gitSha = process.argv[3] || '';

if (process.env.HP_DEPLOYMENT_MODE !== 'non-saas') {
  console.error('Set HP_DEPLOYMENT_MODE=non-saas for registration');
  process.exit(1);
}

const draft = JSON.parse(fs.readFileSync('platform-release-draft.json', 'utf8'));
const client = new S3Client({
  region: process.env.WASABI_REGION,
  endpoint: process.env.WASABI_ENDPOINT,
  credentials: {
    accessKeyId: process.env.WASABI_ACCESS_KEY_ID,
    secretAccessKey: process.env.WASABI_SECRET_ACCESS_KEY
  },
  forcePathStyle: true
});
const bucket = process.env.WASABI_BUCKET;

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
