require('dotenv').config({ path: '/opt/horizon/horizon-backend/.env' });
const pg = require('pg');
const { S3Client, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { canManagePortalExtras } = require('../capabilities');
const { loadEffectivePathGrantsForUser } = require('../company-permissions.service');

function fullJobPrefix(clientId, jobId) {
  return `clients/${clientId}/jobs/${jobId}/`;
}

function parentRelPath(p) {
  const ix = String(p || '').lastIndexOf('/');
  return ix === -1 ? '' : p.slice(0, ix);
}

function buildTreeFromKeys(jobPref, entries) {
  const rel = (key) => key.slice(jobPref.length);
  const folderSet = new Set();
  const files = [];
  for (const { Key: key, Size: size } of entries) {
    if (!key.startsWith(jobPref)) continue;
    const r = rel(key);
    if (!r || r.endsWith('/.hp-folder') || r === '.hp-folder') continue;
    const slash = r.lastIndexOf('/');
    const parentPath = slash === -1 ? '' : r.slice(0, slash);
    const name = slash === -1 ? r : r.slice(slash + 1);
    let p = parentPath;
    while (p !== '') {
      folderSet.add(p);
      p = parentRelPath(p);
    }
    files.push({ path: r, parentPath, name, size });
  }
  const folders = [...folderSet].sort().map((fp) => ({ path: fp, parentPath: parentRelPath(fp) }));
  return { folders, files };
}

(async () => {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const u = await pool.query(`SELECT * FROM users WHERE username = 'Mike Strickland' LIMIT 1`);
  const row = u.rows[0];
  const user = {
    id: row.id,
    username: row.username,
    email: row.email,
    isAdmin: row.is_admin,
    portalFilesAccessGranted: row.portal_files_access_granted,
    portalFilesClientId: row.portal_files_client_id,
    portalFilesJobId: row.portal_files_job_id,
    roles: row.roles || {}
  };
  console.log('mikePortalScope', {
    portalFilesClientId: row.portal_files_client_id,
    portalFilesJobId: row.portal_files_job_id,
    portalFilesAccessGranted: row.portal_files_access_granted,
    isAdmin: row.is_admin
  });
  console.log('canManagePortalExtras', canManagePortalExtras(user));

  const prefix = fullJobPrefix('portal-users', '8');
  const s3 = new S3Client({
    region: process.env.WASABI_REGION || 'eu-central-1',
    endpoint: process.env.WASABI_ENDPOINT || 'https://s3.eu-central-1.wasabisys.com',
    credentials: {
      accessKeyId: process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY,
      secretAccessKey: process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY
    },
    forcePathStyle: true
  });
  const keys = [];
  let token;
  do {
    const r = await s3.send(new ListObjectsV2Command({
      Bucket: process.env.WASABI_BUCKET,
      Prefix: prefix,
      MaxKeys: 1000,
      ContinuationToken: token
    }));
    for (const o of r.Contents || []) keys.push({ Key: o.Key, Size: o.Size });
    token = r.IsTruncated ? r.NextContinuationToken : undefined;
  } while (token);
  const tree = buildTreeFromKeys(prefix, keys);
  console.log('rawTree', { s3Keys: keys.length, folders: tree.folders.length, files: tree.files.length, topFolders: tree.folders.filter((f) => !f.parentPath).slice(0, 5).map((f) => f.path) });

  const grants = await loadEffectivePathGrantsForUser(pool, user, 'portal-users', '8');
  console.log('mikeGrants', grants);

  const grantCheck = await pool.query(`SELECT 1 FROM portal_path_grants WHERE client_id='portal-users' AND job_id='8' LIMIT 1`);
  console.log('jobHasPathGrants', grantCheck.rows.length > 0);

  await pool.end();
})().catch((e) => { console.error(e); process.exit(1); });
