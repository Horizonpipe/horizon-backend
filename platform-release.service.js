'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync } = require('child_process');
const { GetObjectCommand, PutObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const {
  buildManifestKey,
  buildReleaseMetaKey,
  buildReleaseArtifactKey,
  buildNonSaasRuntimeKey,
  buildSaasRuntimeKey,
  PLATFORM_RELEASES_ROOT
} = require('./lib/platform-release-paths');
const {
  loadPlatformReleaseDraft,
  clearPlatformReleaseDraft
} = require('./lib/platform-release-draft');

const MANIFEST_SCHEMA_VERSION = 1;

function cleanString(v) {
  return String(v ?? '').trim();
}

const {
  deploymentMode,
  isSaasDeployment,
  isPrivateBaseDeployment
} = require('./lib/deployment-profile');

function isNonSaasDeployment() {
  return isPrivateBaseDeployment();
}

async function bodyToBuffer(body) {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (body instanceof Uint8Array) return Buffer.from(body);
  const chunks = [];
  for await (const chunk of body) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function getJsonObject(client, bucket, key) {
  if (!client || !bucket) return null;
  try {
    const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    const raw = await bodyToBuffer(out.Body);
    const enc = String(out.ContentEncoding || '').toLowerCase();
    const text =
      enc.includes('gzip') || (raw.length >= 2 && raw[0] === 0x1f && raw[1] === 0x8b)
        ? zlib.gunzipSync(raw).toString('utf8')
        : raw.toString('utf8');
    return JSON.parse(text);
  } catch (err) {
    if (err && (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404)) return null;
    throw err;
  }
}

async function putJsonObject(client, bucket, key, value, { gzip = true } = {}) {
  if (!client || !bucket) throw new Error('Wasabi is not configured');
  const raw = Buffer.from(JSON.stringify(value, null, 2), 'utf8');
  const putBase = {
    Bucket: bucket,
    Key: key,
    Body: gzip ? zlib.gzipSync(raw) : raw,
    ContentType: 'application/json'
  };
  if (gzip) putBase.ContentEncoding = 'gzip';
  await client.send(new PutObjectCommand(putBase));
}

function emptyManifest() {
  return {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    latestPublished: '',
    recommendedVersion: '',
    nonSaasCurrentVersion: '',
    saasDeployedVersion: '',
    versions: []
  };
}

function parseSemver(version) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(cleanString(version));
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3] };
}

function bumpPatchVersion(current) {
  const parsed = parseSemver(current);
  if (!parsed) return '0.0.1';
  return `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`;
}

function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  return pa.patch - pb.patch;
}

function sortVersionsDesc(versions) {
  return [...versions].sort((a, b) => compareSemver(b.version, a.version));
}

function simplifyCommitMessage(raw) {
  let msg = cleanString(raw);
  if (!msg) return '';
  msg = msg.replace(/^(fix|feat|chore|docs|refactor|perf|style|test|build|ci)(\([^)]+\))?:?\s*/i, '');
  msg = msg.replace(/^Merge (branch|pull request).*$/i, '');
  if (!msg) return '';
  msg = msg.charAt(0).toUpperCase() + msg.slice(1);
  if (!/[.!?]$/.test(msg)) msg += '.';
  return msg;
}

function repoRootFromEnv() {
  const fromEnv = cleanString(process.env.HP_REPO_ROOT);
  if (fromEnv && fs.existsSync(fromEnv)) return fromEnv;
  const backendRoot = path.resolve(__dirname);
  const siblingFrontend = path.resolve(backendRoot, '../horizon-frontend');
  if (fs.existsSync(siblingFrontend)) return path.resolve(backendRoot, '..');
  return backendRoot;
}

function generateChangeLogFromGit({ sinceVersion = '', limit = 20 } = {}) {
  const root = repoRootFromEnv();
  const bullets = [];
  try {
    const range = sinceVersion ? `platform-v${sinceVersion}..HEAD` : `-n ${limit}`;
    const log = execSync(`git log ${range} --pretty=format:%s`, {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    });
    for (const line of log.split('\n')) {
      const simplified = simplifyCommitMessage(line);
      if (simplified && !bullets.includes(simplified)) bullets.push(simplified);
    }
  } catch {
    /* git unavailable on this host */
  }
  return bullets.slice(0, limit);
}

function buildLaymanDescription({ title = '', changeLog = [], extra = '' } = {}) {
  const parts = [];
  const heading = cleanString(title);
  if (heading) parts.push(heading);
  if (changeLog.length) {
    if (!extra) parts.push('');
    parts.push('What changed:');
    for (const item of changeLog.slice(0, 12)) {
      parts.push(`• ${item}`);
    }
  }
  const extraText = cleanString(extra);
  if (extraText) {
    if (parts.length) parts.push('');
    parts.push(extraText);
  }
  if (!parts.length) {
    return 'Small improvements and fixes to PipeShare and PipeSync.';
  }
  return parts.join('\n');
}

function resolveReleaseNotes({ title = '', description = '', changeLog = [], sinceVersion = '', nextVersion = '0.0.1' } = {}) {
  const draft = loadPlatformReleaseDraft();
  const draftLog = draft?.changeLog?.length ? draft.changeLog : [];
  const gitLog = generateChangeLogFromGit({ sinceVersion });
  const mergedLog = [...new Set([...draftLog, ...gitLog])].filter(Boolean);

  const releaseTitle =
    cleanString(title) ||
    cleanString(draft?.title) ||
    (mergedLog[0] ? mergedLog[0].replace(/\.$/, '') : '') ||
    `Platform update ${nextVersion}`;

  const releaseDescription =
    cleanString(description) ||
    cleanString(draft?.description) ||
    buildLaymanDescription({ title: releaseTitle, changeLog: mergedLog });

  return {
    title: releaseTitle,
    description: releaseDescription,
    changeLog: mergedLog.length ? mergedLog : [releaseTitle]
  };
}

function gitShaShort() {
  try {
    return execSync('git rev-parse --short HEAD', {
      cwd: repoRootFromEnv(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    return '';
  }
}

function gitBranchName() {
  try {
    return execSync('git rev-parse --abbrev-ref HEAD', {
      cwd: repoRootFromEnv(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    return '';
  }
}

async function loadManifest(client, bucket) {
  const manifest = (await getJsonObject(client, bucket, buildManifestKey())) || emptyManifest();
  manifest.versions = Array.isArray(manifest.versions) ? manifest.versions : [];
  return manifest;
}

async function saveManifest(client, bucket, manifest) {
  await putJsonObject(client, bucket, buildManifestKey(), manifest);
}

async function loadRuntime(client, bucket, mode) {
  const key = mode === 'saas' ? buildSaasRuntimeKey() : buildNonSaasRuntimeKey();
  return (await getJsonObject(client, bucket, key)) || {};
}

async function saveRuntime(client, bucket, mode, payload) {
  const key = mode === 'saas' ? buildSaasRuntimeKey() : buildNonSaasRuntimeKey();
  await putJsonObject(client, bucket, key, payload);
}

function briefReleaseSummary(entry) {
  if (!entry || typeof entry !== 'object') return 'Platform update';
  const title = cleanString(entry.title);
  if (title) return title.length > 96 ? `${title.slice(0, 93)}…` : title;
  const first = Array.isArray(entry.changeLog) ? cleanString(entry.changeLog[0]) : '';
  if (first) return first.length > 96 ? `${first.slice(0, 93)}…` : first;
  return `Platform update ${cleanString(entry.version) || ''}`.trim();
}

function normalizeReleaseEntry(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const version = cleanString(entry.version);
  if (!parseSemver(version)) return null;
  const normalized = {
    version,
    publishedAt: cleanString(entry.publishedAt) || new Date().toISOString(),
    publishedBy: cleanString(entry.publishedBy),
    gitSha: cleanString(entry.gitSha),
    gitBranch: cleanString(entry.gitBranch),
    title: cleanString(entry.title),
    description: cleanString(entry.description),
    changeLog: Array.isArray(entry.changeLog) ? entry.changeLog.map(cleanString).filter(Boolean) : [],
    artifactKeys: entry.artifactKeys && typeof entry.artifactKeys === 'object' ? entry.artifactKeys : {},
    recommended: entry.recommended === true
  };
  normalized.briefSummary = briefReleaseSummary(normalized);
  return normalized;
}

async function getPlatformReleaseStatus(client, bucket) {
  const manifest = await loadManifest(client, bucket);
  const nonSaasRuntime = await loadRuntime(client, bucket, 'non-saas');
  const saasRuntime = await loadRuntime(client, bucket, 'saas');
  const versions = sortVersionsDesc(manifest.versions.map(normalizeReleaseEntry).filter(Boolean));
  const recommendedVersion =
    cleanString(manifest.recommendedVersion) ||
    cleanString(nonSaasRuntime.version) ||
    cleanString(manifest.latestPublished) ||
    '';
  return {
    deploymentMode: deploymentMode(),
    manifest: {
      latestPublished: cleanString(manifest.latestPublished),
      recommendedVersion,
      nonSaasCurrentVersion:
        cleanString(manifest.nonSaasCurrentVersion) || cleanString(nonSaasRuntime.version) || '',
      saasDeployedVersion: cleanString(manifest.saasDeployedVersion) || cleanString(saasRuntime.version) || ''
    },
    nonSaasRuntime,
    saasRuntime,
    versions,
    nextSuggestedVersion: bumpPatchVersion(cleanString(manifest.latestPublished) || '0.0.0')
  };
}

async function registerNonSaasHeartbeat(client, bucket, { version, actor = '', gitSha = '', notes = '' } = {}) {
  if (!isNonSaasDeployment()) {
    throw new Error('Non-SaaS heartbeat can only run on HP_DEPLOYMENT_MODE=non-saas hosts');
  }
  const v = cleanString(version);
  if (!parseSemver(v)) throw new Error('Invalid version (use semver like 0.0.1)');

  const manifest = await loadManifest(client, bucket);
  manifest.nonSaasCurrentVersion = v;
  manifest.recommendedVersion = v;
  await saveManifest(client, bucket, manifest);

  await saveRuntime(client, bucket, 'non-saas', {
    version: v,
    gitSha: gitSha || gitShaShort(),
    gitBranch: gitBranchName(),
    updatedAt: new Date().toISOString(),
    updatedBy: cleanString(actor),
    notes: cleanString(notes),
    host: cleanString(process.env.PUBLIC_ORIGIN || process.env.SAAS_CPANEL_BASE_URL || '')
  });

  return { version: v, recommendedVersion: v };
}

async function publishPlatformRelease(
  client,
  bucket,
  {
    version,
    title = '',
    description = '',
    changeLog = [],
    publishedBy = '',
    gitSha = '',
    gitBranch = '',
    artifactKeys = {}
  } = {}
) {
  if (!isNonSaasDeployment()) {
    throw new Error('Publishing is only allowed from non-SaaS (your private PipeShare/PipeSync) servers');
  }

  const manifest = await loadManifest(client, bucket);
  const nextVersion = cleanString(version) || bumpPatchVersion(manifest.latestPublished || '0.0.0');
  if (!parseSemver(nextVersion)) throw new Error('Invalid version (use semver like 0.0.1)');
  if (manifest.versions.some((v) => cleanString(v.version) === nextVersion)) {
    throw new Error(`Version ${nextVersion} already exists`);
  }

  const autoLog =
    Array.isArray(changeLog) && changeLog.length
      ? changeLog.map(cleanString).filter(Boolean)
      : resolveReleaseNotes({ sinceVersion: manifest.latestPublished, nextVersion }).changeLog;

  const resolved = resolveReleaseNotes({
    title,
    description,
    changeLog: autoLog,
    sinceVersion: manifest.latestPublished,
    nextVersion
  });

  const releaseTitle = resolved.title;
  const releaseDescription = resolved.description;

  const entry = normalizeReleaseEntry({
    version: nextVersion,
    publishedAt: new Date().toISOString(),
    publishedBy: cleanString(publishedBy),
    gitSha: gitSha || gitShaShort(),
    gitBranch: gitBranch || gitBranchName(),
    title: releaseTitle,
    description: releaseDescription,
    changeLog: resolved.changeLog,
    artifactKeys: {
      frontend: artifactKeys.frontend || buildReleaseArtifactKey(nextVersion, 'frontend.tar.gz'),
      backend: artifactKeys.backend || buildReleaseArtifactKey(nextVersion, 'backend.tar.gz'),
      releaseMeta: buildReleaseMetaKey(nextVersion)
    },
    recommended: true
  });

  await putJsonObject(client, bucket, buildReleaseMetaKey(nextVersion), entry);

  manifest.versions = sortVersionsDesc([
    ...manifest.versions.filter((v) => cleanString(v.version) !== nextVersion),
    entry
  ]);
  for (const v of manifest.versions) {
    v.recommended = cleanString(v.version) === nextVersion;
  }
  manifest.latestPublished = nextVersion;
  manifest.recommendedVersion = nextVersion;
  manifest.nonSaasCurrentVersion = nextVersion;
  await saveManifest(client, bucket, manifest);

  await saveRuntime(client, bucket, 'non-saas', {
    version: nextVersion,
    gitSha: entry.gitSha,
    gitBranch: entry.gitBranch,
    updatedAt: entry.publishedAt,
    updatedBy: entry.publishedBy,
    notes: entry.title
  });

  clearPlatformReleaseDraft();

  return entry;
}

async function artifactExists(client, bucket, key) {
  if (!client || !bucket || !key) return false;
  try {
    await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    return true;
  } catch {
    return false;
  }
}

async function applyPlatformRelease(client, bucket, { version, actor = '' } = {}, { pool } = {}) {
  if (!isSaasDeployment()) {
    throw new Error('Apply is only allowed on HP_DEPLOYMENT_MODE=saas hosts');
  }
  const v = cleanString(version);
  if (!parseSemver(v)) throw new Error('Invalid version');

  const manifest = await loadManifest(client, bucket);
  const entry = manifest.versions.find((item) => cleanString(item.version) === v);
  if (!entry) throw new Error(`Version ${v} was not found in the release catalog`);

  const frontendKey = cleanString(entry.artifactKeys?.frontend) || buildReleaseArtifactKey(v, 'frontend.tar.gz');
  const backendKey = cleanString(entry.artifactKeys?.backend) || buildReleaseArtifactKey(v, 'backend.tar.gz');

  const hasFrontend = await artifactExists(client, bucket, frontendKey);
  const hasBackend = await artifactExists(client, bucket, backendKey);
  if (!hasFrontend && !hasBackend) {
    throw new Error(`Version ${v} has no uploaded artifacts yet. Publish from non-SaaS first.`);
  }

  const applyScript = cleanString(process.env.HP_PLATFORM_APPLY_SCRIPT);
  if (!applyScript || !fs.existsSync(applyScript)) {
    throw new Error('HP_PLATFORM_APPLY_SCRIPT is not configured on this SaaS host');
  }

  const childProcess = require('child_process');
  await new Promise((resolve, reject) => {
    const proc = childProcess.spawn('bash', [applyScript, v], {
      env: {
        ...process.env,
        HP_RELEASE_VERSION: v,
        HP_RELEASE_FRONTEND_KEY: frontendKey,
        HP_RELEASE_BACKEND_KEY: backendKey
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stderr = '';
    proc.stderr.on('data', (chunk) => {
      stderr += String(chunk || '');
    });
    proc.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || `Apply script exited with code ${code}`));
    });
  });

  manifest.saasDeployedVersion = v;
  await saveManifest(client, bucket, manifest);

  await saveRuntime(client, bucket, 'saas', {
    version: v,
    appliedAt: new Date().toISOString(),
    appliedBy: cleanString(actor),
    gitSha: cleanString(entry.gitSha),
    title: cleanString(entry.title)
  });

  if (pool) {
    await pool.query(
      `INSERT INTO platform_release_events (version, event_type, actor_user_id, deployment_mode, notes)
       VALUES ($1, 'applied', $2, 'saas', $3)`,
      [v, cleanString(actor), cleanString(entry.title)]
    );
  }

  return { version: v, appliedAt: new Date().toISOString() };
}

async function previewNextRelease(client, bucket, { title = '', description = '', forceDraft = false } = {}) {
  const status = await getPlatformReleaseStatus(client, bucket);
  const draft = loadPlatformReleaseDraft();
  const useServerDraft = forceDraft || (!cleanString(title) && !cleanString(description));
  const resolved = resolveReleaseNotes({
    title: useServerDraft ? '' : title,
    description: useServerDraft ? '' : description,
    sinceVersion: status.manifest.latestPublished,
    nextVersion: status.nextSuggestedVersion
  });
  return {
    nextVersion: status.nextSuggestedVersion,
    title: resolved.title,
    description: resolved.description,
    changeLog: resolved.changeLog,
    recommendedFromNonSaas: status.manifest.nonSaasCurrentVersion,
    fromDraft: !!draft,
    draftUpdatedAt: draft?.updatedAt || ''
  };
}

async function listPlatformReleases(client, bucket) {
  const status = await getPlatformReleaseStatus(client, bucket);
  return {
    releases: status.versions,
    latestPublished: status.manifest.latestPublished,
    recommendedVersion: status.manifest.recommendedVersion,
    saasDeployedVersion: status.manifest.saasDeployedVersion,
    nonSaasCurrentVersion: status.manifest.nonSaasCurrentVersion
  };
}

module.exports = {
  PLATFORM_RELEASES_ROOT,
  deploymentMode,
  isSaasDeployment,
  isNonSaasDeployment,
  bumpPatchVersion,
  briefReleaseSummary,
  buildLaymanDescription,
  generateChangeLogFromGit,
  getPlatformReleaseStatus,
  listPlatformReleases,
  registerNonSaasHeartbeat,
  publishPlatformRelease,
  applyPlatformRelease,
  previewNextRelease,
  buildReleaseArtifactKey
};
