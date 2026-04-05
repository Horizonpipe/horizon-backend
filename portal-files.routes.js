'use strict';

/**
 * Client portal Wasabi proxy — same auth as the rest of horizon-backend.
 * Env (Render): WASABI_ACCESS_KEY_ID, WASABI_SECRET_ACCESS_KEY, WASABI_BUCKET,
 * WASABI_REGION, WASABI_ENDPOINT (also accepts WASABI_ACCESS_KEY / WASABI_SECRET_KEY).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const multer = require('multer');
const {
  S3Client,
  CopyObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand
} = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');

const CATEGORIES = new Set(['videos', 'db3', 'pdf', 'photos']);
const FOLDER_MARKER = '.hp-folder';
const MAX_DELETE_BATCH = 1000;

const portalUpload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 * 1024 }
});

function createWasabiClient() {
  const accessKeyId = process.env.WASABI_ACCESS_KEY_ID || process.env.WASABI_ACCESS_KEY;
  const secretAccessKey = process.env.WASABI_SECRET_ACCESS_KEY || process.env.WASABI_SECRET_KEY;
  const region = process.env.WASABI_REGION || 'us-east-1';
  const endpoint = process.env.WASABI_ENDPOINT || 'https://s3.us-east-1.wasabisys.com';
  if (!accessKeyId || !secretAccessKey) return null;
  return new S3Client({
    region,
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true
  });
}

function bucketName() {
  return process.env.WASABI_BUCKET || null;
}

function segment(s) {
  const t = String(s ?? '').trim();
  if (!t || t.includes('..') || t.includes('/') || t.includes('\\')) {
    throw new Error('Invalid clientId or jobId');
  }
  return t;
}

function sanitizeFilename(name) {
  const base = String(name ?? '').split(/[/\\]/).pop() || 'file';
  const cleaned = base.replace(/[^\w.\- ()\[\]]+/g, '_').slice(0, 240);
  if (!cleaned || cleaned === '.' || cleaned === '..') throw new Error('Invalid filename');
  return cleaned;
}

function sanitizeFolderSegment(name) {
  const raw = String(name ?? '').trim();
  const cleaned = raw.replace(/[^\w.\- ()\[\]]+/g, '_').slice(0, 120);
  if (!cleaned || cleaned === '.' || cleaned === '..') throw new Error('Invalid folder name');
  return cleaned;
}

function normalizeRelativePath(input) {
  const raw = String(input ?? '').trim().replace(/^\/+|\/+$/g, '');
  if (!raw) return '';
  return raw
    .split('/')
    .map((part) => sanitizeFolderSegment(part))
    .join('/');
}

function assertCategory(cat) {
  if (!CATEGORIES.has(cat)) {
    throw new Error(`Invalid category. Use one of: ${[...CATEGORIES].join(', ')}`);
  }
}

function jobPrefix(clientId, jobId) {
  return `clients/${segment(clientId)}/jobs/${segment(jobId)}/`;
}

function relativeFilePath(folderPath, filename) {
  const dir = normalizeRelativePath(folderPath);
  const safe = sanitizeFilename(filename);
  return dir ? `${dir}/${safe}` : safe;
}

function fileObjectKey(clientId, jobId, folderPath, filename) {
  return `${jobPrefix(clientId, jobId)}${relativeFilePath(folderPath, filename)}`;
}

function objectKeyForCategory(clientId, jobId, category, filename) {
  assertCategory(category);
  return fileObjectKey(clientId, jobId, category, filename);
}

function folderMarkerKey(clientId, jobId, folderPath) {
  const rel = normalizeRelativePath(folderPath);
  if (!rel) throw new Error('Cannot create the root folder');
  return `${jobPrefix(clientId, jobId)}${rel}/${FOLDER_MARKER}`;
}

function folderPrefix(clientId, jobId, folderPath) {
  const rel = normalizeRelativePath(folderPath);
  if (!rel) throw new Error('Folder path is required');
  return `${jobPrefix(clientId, jobId)}${rel}/`;
}

function parseJobFromObjectKey(key) {
  const m = /^clients\/([^/]+)\/jobs\/([^/]+)\//.exec(String(key ?? ''));
  if (!m) return null;
  return { clientId: m[1], jobId: m[2] };
}

function keyToId(key) {
  return Buffer.from(key, 'utf8').toString('base64url');
}

function idToKey(id) {
  return Buffer.from(String(id), 'base64url').toString('utf8');
}

function relativePathFromKey(prefix, key) {
  if (!String(key).startsWith(prefix)) return '';
  return String(key).slice(prefix.length);
}

function parentRelativePath(relPath) {
  const rel = normalizeRelativePath(relPath);
  if (!rel) return '';
  const parts = rel.split('/');
  parts.pop();
  return parts.join('/');
}

function basenameRelativePath(relPath) {
  const rel = normalizeRelativePath(relPath);
  if (!rel) return '';
  const parts = rel.split('/');
  return parts[parts.length - 1] || '';
}

function copySource(bucket, key) {
  return `${bucket}/${String(key).split('/').map(encodeURIComponent).join('/')}`;
}

async function listAllObjects(s3, bucket, prefix) {
  const out = [];
  let pageToken;
  do {
    const resp = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: pageToken
      })
    );
    out.push(...(resp.Contents || []));
    pageToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (pageToken);
  return out;
}

async function objectExists(s3, bucket, key) {
  const resp = await s3.send(
    new ListObjectsV2Command({
      Bucket: bucket,
      Prefix: key,
      MaxKeys: 1
    })
  );
  return (resp.Contents || []).some((obj) => obj.Key === key);
}

async function prefixHasObjects(s3, bucket, prefix) {
  const resp = await s3.send(
    new ListObjectsV2Command({
      Bucket: bucket,
      Prefix: prefix,
      MaxKeys: 1
    })
  );
  return !!(resp.Contents || []).length;
}

async function deleteKeys(s3, bucket, keys) {
  if (!keys.length) return;
  for (let i = 0; i < keys.length; i += MAX_DELETE_BATCH) {
    const batch = keys.slice(i, i + MAX_DELETE_BATCH);
    await s3.send(
      new DeleteObjectsCommand({
        Bucket: bucket,
        Delete: { Objects: batch.map((Key) => ({ Key })) }
      })
    );
  }
}

function buildCatalog(prefix, objects) {
  const folders = new Map();
  const files = [];

  function rememberFolder(folderPath, modifiedAt = null) {
    const rel = normalizeRelativePath(folderPath);
    if (!rel) return;
    const existing = folders.get(rel);
    const nextIso = modifiedAt instanceof Date ? modifiedAt.toISOString() : null;
    if (!existing) {
      folders.set(rel, {
        path: rel,
        name: basenameRelativePath(rel),
        parentPath: parentRelativePath(rel),
        lastModified: nextIso
      });
      return;
    }
    if (nextIso && (!existing.lastModified || nextIso > existing.lastModified)) {
      existing.lastModified = nextIso;
    }
  }

  for (const obj of objects) {
    const rel = relativePathFromKey(prefix, obj.Key);
    if (!rel || rel.endsWith('/')) continue;
    const parts = rel.split('/').filter(Boolean);
    if (!parts.length) continue;

    if (parts[parts.length - 1] === FOLDER_MARKER) {
      rememberFolder(parts.slice(0, -1).join('/'), obj.LastModified || null);
      continue;
    }

    for (let i = 1; i < parts.length; i += 1) {
      rememberFolder(parts.slice(0, i).join('/'), obj.LastModified || null);
    }

    const parentPath = parts.slice(0, -1).join('/');
    const pathRel = parts.join('/');
    files.push({
      id: keyToId(obj.Key),
      key: obj.Key,
      path: pathRel,
      parentPath,
      name: parts[parts.length - 1],
      size: obj.Size ?? 0,
      lastModified: obj.LastModified ? obj.LastModified.toISOString() : null
    });
  }

  const sortedFolders = [...folders.values()].sort((a, b) => {
    const depthA = a.path.split('/').length;
    const depthB = b.path.split('/').length;
    if (depthA !== depthB) return depthA - depthB;
    return a.path.localeCompare(b.path, undefined, { sensitivity: 'base' });
  });

  files.sort((a, b) => a.path.localeCompare(b.path, undefined, { sensitivity: 'base' }));

  return { folders: sortedFolders, files };
}

/**
 * Admin: all prefixes. Others: must match a planner row for this client + zob (record id or jobsite label).
 */
async function assertPortalJobAccess(pool, user, clientId, jobId) {
  if (user && user.isAdmin) return true;
  const c = String(clientId || '').trim();
  const j = String(jobId || '').trim();
  if (!c || !j) return false;
  try {
    const r = await pool.query(
      `SELECT 1 FROM planner_records
       WHERE LOWER(TRIM(client)) = LOWER(TRIM($1))
         AND (
           CAST(id AS TEXT) = $2
           OR LOWER(TRIM(jobsite)) = LOWER(TRIM($2))
         )
       LIMIT 1`,
      [c, j]
    );
    return r.rows.length > 0;
  } catch (e) {
    console.error('[portal-files] assertPortalJobAccess', e);
    return false;
  }
}

function registerPortalFilesRoutes(app, { pool, requireAuth }) {
  const s3 = createWasabiClient();
  const bucket = bucketName();

  if (!s3 || !bucket) {
    console.warn(
      '[portal-files] Wasabi not configured — set WASABI_ACCESS_KEY_ID, WASABI_SECRET_ACCESS_KEY, WASABI_BUCKET (and optional WASABI_REGION / WASABI_ENDPOINT)'
    );
    app.use('/api/files', (req, res) => {
      res.status(503).json({ error: 'File storage not configured on server' });
    });
    return;
  }

  const r = express.Router();
  r.use(requireAuth);

  r.get('/', async (req, res) => {
    try {
      const { clientId, jobId } = req.query;
      if (!clientId || !jobId) {
        return res.status(400).json({ error: 'clientId and jobId query params are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const prefix = jobPrefix(String(clientId), String(jobId));
      const objects = await listAllObjects(s3, bucket, prefix);
      const files = buildCatalog(prefix, objects).files;
      return res.json({ files });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.get('/tree', async (req, res) => {
    try {
      const { clientId, jobId } = req.query;
      if (!clientId || !jobId) {
        return res.status(400).json({ error: 'clientId and jobId query params are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const prefix = jobPrefix(String(clientId), String(jobId));
      const objects = await listAllObjects(s3, bucket, prefix);
      return res.json(buildCatalog(prefix, objects));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.post('/folders', async (req, res) => {
    try {
      const { clientId, jobId, parentPath = '', name = '', path: rawPath = '' } = req.body || {};
      if (!clientId || !jobId) {
        return res.status(400).json({ error: 'clientId and jobId are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const folderPath = rawPath
        ? normalizeRelativePath(rawPath)
        : (() => {
            const parent = normalizeRelativePath(parentPath);
            const child = sanitizeFolderSegment(name);
            return parent ? `${parent}/${child}` : child;
          })();

      if (!folderPath) {
        return res.status(400).json({ error: 'Folder path is required' });
      }

      if (await prefixHasObjects(s3, bucket, folderPrefix(String(clientId), String(jobId), folderPath))) {
        return res.status(409).json({ error: 'Folder already exists' });
      }

      const Key = folderMarkerKey(String(clientId), String(jobId), folderPath);
      await s3.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key,
          Body: '',
          ContentType: 'application/x-directory'
        })
      );

      return res.status(201).json({
        path: folderPath,
        parentPath: parentRelativePath(folderPath),
        name: basenameRelativePath(folderPath)
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.patch('/rename', async (req, res) => {
    try {
      const {
        clientId,
        jobId,
        type,
        path: oldPathRaw,
        newName
      } = req.body || {};

      if (!clientId || !jobId || !type || !oldPathRaw || !newName) {
        return res.status(400).json({ error: 'clientId, jobId, type, path, and newName are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const oldPath = normalizeRelativePath(oldPathRaw);
      if (!oldPath) {
        return res.status(400).json({ error: 'Cannot rename the root folder' });
      }

      const parentPath = parentRelativePath(oldPath);
      const safeName = type === 'folder' ? sanitizeFolderSegment(newName) : sanitizeFilename(newName);
      const nextPath = parentPath ? `${parentPath}/${safeName}` : safeName;

      if (oldPath === nextPath) {
        return res.json({ path: oldPath, newPath: nextPath, name: safeName });
      }

      if (type === 'folder') {
        const oldPrefix = folderPrefix(String(clientId), String(jobId), oldPath);
        const newPrefix = folderPrefix(String(clientId), String(jobId), nextPath);

        if (await prefixHasObjects(s3, bucket, newPrefix)) {
          return res.status(409).json({ error: 'A folder with that name already exists' });
        }

        const objects = await listAllObjects(s3, bucket, oldPrefix);
        if (!objects.length) {
          return res.status(404).json({ error: 'Folder not found' });
        }

        for (const obj of objects) {
          const suffix = obj.Key.slice(oldPrefix.length);
          const newKey = `${newPrefix}${suffix}`;
          await s3.send(
            new CopyObjectCommand({
              Bucket: bucket,
              CopySource: copySource(bucket, obj.Key),
              Key: newKey
            })
          );
        }

        await deleteKeys(s3, bucket, objects.map((obj) => obj.Key));

        return res.json({
          path: oldPath,
          newPath: nextPath,
          parentPath,
          name: safeName
        });
      }

      if (type !== 'file') {
        return res.status(400).json({ error: 'type must be "folder" or "file"' });
      }

      const oldKey = `${jobPrefix(String(clientId), String(jobId))}${oldPath}`;
      const newKey = `${jobPrefix(String(clientId), String(jobId))}${nextPath}`;

      if (!(await objectExists(s3, bucket, oldKey))) {
        return res.status(404).json({ error: 'File not found' });
      }
      if (await objectExists(s3, bucket, newKey)) {
        return res.status(409).json({ error: 'A file with that name already exists' });
      }

      await s3.send(
        new CopyObjectCommand({
          Bucket: bucket,
          CopySource: copySource(bucket, oldKey),
          Key: newKey
        })
      );
      await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: oldKey }));

      return res.json({
        id: keyToId(newKey),
        path: nextPath,
        parentPath,
        name: safeName
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.post('/upload', portalUpload.single('file'), async (req, res) => {
    const f = req.file;
    if (!f) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }

    try {
      const { clientId, jobId, category, folderPath = '', filename = '' } = req.body || {};
      if (!clientId || !jobId) {
        fs.unlink(f.path, () => {});
        return res.status(400).json({ error: 'clientId and jobId are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        fs.unlink(f.path, () => {});
        return res.status(403).json({ error: 'Forbidden' });
      }

      let Key;
      let relPath;
      if (folderPath) {
        relPath = relativeFilePath(String(folderPath), filename || f.originalname || 'upload');
        Key = `${jobPrefix(String(clientId), String(jobId))}${relPath}`;
      } else {
        const finalCategory = String(category || '').trim();
        if (!finalCategory) {
          fs.unlink(f.path, () => {});
          return res.status(400).json({ error: 'folderPath or category is required' });
        }
        Key = objectKeyForCategory(String(clientId), String(jobId), finalCategory, filename || f.originalname || 'upload');
        relPath = relativePathFromKey(jobPrefix(String(clientId), String(jobId)), Key);
      }

      const stream = fs.createReadStream(f.path);
      const uploadTask = new Upload({
        client: s3,
        params: {
          Bucket: bucket,
          Key,
          Body: stream,
          ContentType: f.mimetype || 'application/octet-stream'
        }
      });
      await uploadTask.done();
      fs.unlink(f.path, () => {});

      return res.status(201).json({
        id: keyToId(Key),
        key: Key,
        path: relPath,
        parentPath: parentRelativePath(relPath),
        name: path.basename(Key),
        size: f.size
      });
    } catch (e) {
      try {
        fs.unlink(f.path, () => {});
      } catch (_) {
        /* ignore */
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.get('/download/:id', async (req, res) => {
    try {
      const Key = idToKey(req.params.id);
      if (!Key.startsWith('clients/')) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const parsed = parseJobFromObjectKey(Key);
      if (!parsed || !(await assertPortalJobAccess(pool, req.user, parsed.clientId, parsed.jobId))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const head = await s3.send(new GetObjectCommand({ Bucket: bucket, Key }));
      const filename = path.basename(Key);
      res.setHeader('Content-Type', head.ContentType || 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
      if (head.ContentLength != null) {
        res.setHeader('Content-Length', String(head.ContentLength));
      }
      if (head.Body && typeof head.Body.pipe === 'function') {
        head.Body.pipe(res);
        return;
      }
      return res.status(500).json({ error: 'Empty body' });
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.delete('/folders', async (req, res) => {
    try {
      const { clientId, jobId, path: folderPathRaw } = req.query;
      if (!clientId || !jobId || !folderPathRaw) {
        return res.status(400).json({ error: 'clientId, jobId, and path are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const prefix = folderPrefix(String(clientId), String(jobId), String(folderPathRaw));
      const objects = await listAllObjects(s3, bucket, prefix);
      if (objects.length) {
        await deleteKeys(s3, bucket, objects.map((obj) => obj.Key));
      }
      return res.status(204).send();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.delete('/:id', async (req, res) => {
    try {
      const Key = idToKey(req.params.id);
      if (!Key.startsWith('clients/')) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      const parsed = parseJobFromObjectKey(Key);
      if (!parsed || !(await assertPortalJobAccess(pool, req.user, parsed.clientId, parsed.jobId))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key }));
      return res.status(204).send();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  app.use('/api/files', r);
  console.log('[portal-files] /api/files mounted (Wasabi bucket:', bucket + ')');
}

module.exports = { registerPortalFilesRoutes };
