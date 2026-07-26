#!/usr/bin/env node
/**
 * Register an already-uploaded platform release without HTTP auth.
 * Use when HP_RELEASE_ADMIN_TOKEN is not a valid admin JWT (publish curl 401).
 *
 * Usage:
 *   HP_DEPLOYMENT_MODE=non-saas node scripts/register-platform-release-local.cjs [version]
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { S3Client } = require('@aws-sdk/client-s3');
const { publishPlatformRelease } = require('../platform-release.service');

function loadEnv(filePath) {
  const out = {};
  if (!fs.existsSync(filePath)) return out;
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    if (!line || line.trim().startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 0) continue;
    const key = line.slice(0, i).trim();
    let val = line.slice(i + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

function pick(env, keys) {
  for (const k of keys) {
    if (env[k]) return env[k];
  }
  return '';
}

async function main() {
  const root = path.join(__dirname, '..');
  const env = { ...loadEnv(path.join(root, '.env')), ...process.env };
  Object.assign(process.env, env);

  if (String(process.env.HP_DEPLOYMENT_MODE || '') !== 'non-saas') {
    console.error('[register-local] Set HP_DEPLOYMENT_MODE=non-saas for this command');
    process.exit(1);
  }

  const version = String(process.argv[2] || '').trim();
  const draftPath = path.join(root, 'platform-release-draft.json');
  let title = '';
  let description = '';
  let changeLog = [];
  try {
    if (fs.existsSync(draftPath)) {
      const draft = JSON.parse(fs.readFileSync(draftPath, 'utf8'));
      title = draft.title || '';
      description = draft.description || '';
      changeLog = Array.isArray(draft.changeLog) ? draft.changeLog.filter(Boolean) : [];
    }
  } catch {
    /* ignore */
  }

  const bucket =
    pick(env, ['HP_PLATFORM_RELEASE_BUCKET', 'SAAS_WASABI_BUCKET', 'WASABI_BUCKET']) || '';
  const endpoint =
    bucket && bucket === env.SAAS_WASABI_BUCKET
      ? pick(env, ['SAAS_WASABI_ENDPOINT']) || 'https://s3.us-east-2.wasabisys.com'
      : pick(env, ['WASABI_ENDPOINT']) || 'https://s3.us-east-1.wasabisys.com';
  const region =
    bucket && bucket === env.SAAS_WASABI_BUCKET
      ? pick(env, ['SAAS_WASABI_REGION']) || 'us-east-2'
      : pick(env, ['WASABI_REGION']) || 'us-east-1';
  const accessKey = pick(env, ['WASABI_ACCESS_KEY_ID']);
  const secretKey = pick(env, ['WASABI_SECRET_ACCESS_KEY']);
  if (!bucket || !accessKey || !secretKey) {
    console.error('[register-local] missing Wasabi bucket/credentials');
    process.exit(1);
  }

  const client = new S3Client({
    region,
    endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId: accessKey, secretAccessKey: secretKey }
  });

  const gitSha = require('child_process')
    .execSync('git rev-parse --short HEAD', { cwd: root })
    .toString()
    .trim();
  const gitBranch = require('child_process')
    .execSync('git rev-parse --abbrev-ref HEAD', { cwd: root })
    .toString()
    .trim();

  const entry = await publishPlatformRelease(client, bucket, {
    version: version || undefined,
    title,
    description,
    changeLog,
    publishedBy: 'local-register',
    gitSha,
    gitBranch,
    artifactKeys: version
      ? {
          frontend: `platform/releases/${version}/artifacts/frontend.tar.gz`,
          backend: `platform/releases/${version}/artifacts/backend.tar.gz`
        }
      : undefined
  });

  console.log(`[register-local] registered v${entry.version}`);
  console.log(JSON.stringify({ version: entry.version, title: entry.title }, null, 2));
}

main().catch((err) => {
  console.error('[register-local]', err && err.message ? err.message : err);
  process.exit(1);
});
