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
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand
} = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');

const CATEGORIES = new Set(['videos', 'db3', 'pdf', 'photos']);
const FOLDER_MARKER = '.hp-folder';

const portalUpload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 * 1024 }
});

const portalBatchUpload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 * 1024, files: 100 }
});

/** Faster multipart uploads to S3-compatible storage (Wasabi). */
const S3_UPLOAD_PARALLEL = { queueSize: 8, partSize: 8 * 1024 * 1024 };

/**
 * @param {import('@aws-sdk/client-s3').S3Client} s3Client
 * @param {string} bucketName
 * @param {string} Key
 * @param {string} tempPath
 * @param {string} contentType
 */
async function s3UploadFromTempPath(s3Client, bucketName, Key, tempPath, contentType) {
  const stream = fs.createReadStream(tempPath);
  const uploadTask = new Upload({
    client: s3Client,
    queueSize: S3_UPLOAD_PARALLEL.queueSize,
    partSize: S3_UPLOAD_PARALLEL.partSize,
    params: {
      Bucket: bucketName,
      Key,
      Body: stream,
      ContentType: contentType || 'application/octet-stream'
    }
  });
  try {
    await uploadTask.done();
  } finally {
    fs.unlink(tempPath, () => {});
  }
}

function portalUploadKey(clientId, jobId, folderPathRel, originalName, explicitCategory) {
  const fp = normalizeRelPath(folderPathRel || '');
  if (fp) {
    return `${jobPrefix(String(clientId), String(jobId))}${fp}/${sanitizeFilename(originalName)}`;
  }
  const cat = explicitCategory || inferCategoryFromFilename(originalName);
  return objectKey(String(clientId), String(jobId), String(cat), originalName);
}

/**
 * @template T
 * @param {T[]} array
 * @param {number} concurrency
 * @param {(item: T, index: number) => Promise<void>} fn
 */
async function runPool(array, concurrency, fn) {
  let i = 0;
  const n = Math.max(1, Math.min(concurrency, array.length || 1));
  const workers = Array.from({ length: n }, async () => {
    while (true) {
      const idx = i++;
      if (idx >= array.length) return;
      await fn(array[idx], idx);
    }
  });
  await Promise.all(workers);
}

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
  if (!cleaned) throw new Error('Invalid filename');
  return cleaned;
}

function sanitizeFolderSegment(name) {
  const t = String(name ?? '').trim();
  if (!t || t === '.' || t === '..') throw new Error('Invalid folder name');
  if (t.includes('/') || t.includes('\\') || t.includes('..')) throw new Error('Invalid folder name');
  const cleaned = t.replace(/[^\w.\- ()\[\]]+/g, '_').slice(0, 120);
  if (!cleaned) throw new Error('Invalid folder name');
  if (cleaned === FOLDER_MARKER) throw new Error('Reserved folder name');
  return cleaned;
}

function assertCategory(cat) {
  if (!CATEGORIES.has(cat)) {
    throw new Error(`Invalid category. Use one of: ${[...CATEGORIES].join(', ')}`);
  }
}

/** When folderPath is empty and category omitted (portal root upload), pick a bucket folder from the filename. */
function inferCategoryFromFilename(name) {
  const n = String(name || '').toLowerCase();
  if (n.endsWith('.pdf')) return 'pdf';
  if (n.endsWith('.db3')) return 'db3';
  if (/\.(mp4|webm|ogg|mov|m4v|avi|mkv)$/i.test(n)) return 'videos';
  if (/\.(jpg|jpeg|png|gif|webp|bmp|tif|tiff)$/i.test(n)) return 'photos';
  return 'videos';
}

function objectKey(clientId, jobId, category, filename) {
  assertCategory(category);
  const safe = sanitizeFilename(filename);
  return `clients/${segment(clientId)}/jobs/${segment(jobId)}/${category}/${safe}`;
}

function jobPrefix(clientId, jobId) {
  return `clients/${segment(clientId)}/jobs/${segment(jobId)}/`;
}

function parseJobFromObjectKey(key) {
  const m = /^clients\/([^/]+)\/jobs\/([^/]+)\//.exec(String(key ?? ''));
  if (!m) return null;
  return { clientId: m[1], jobId: m[2] };
}

/** Guess Content-Type when S3 returns application/octet-stream so browsers decode video/PDF blobs correctly. */
function contentTypeFromFilename(name) {
  const n = String(name || '').toLowerCase();
  if (n.endsWith('.mp4')) return 'video/mp4';
  if (n.endsWith('.webm')) return 'video/webm';
  if (n.endsWith('.ogg') || n.endsWith('.ogv')) return 'video/ogg';
  if (n.endsWith('.mov') || n.endsWith('.m4v')) return 'video/quicktime';
  if (n.endsWith('.mkv')) return 'video/x-matroska';
  if (n.endsWith('.avi')) return 'video/x-msvideo';
  if (n.endsWith('.pdf')) return 'application/pdf';
  if (n.endsWith('.db3')) return 'application/octet-stream';
  if (/\.(jpg|jpeg)$/i.test(n)) return 'image/jpeg';
  if (n.endsWith('.png')) return 'image/png';
  if (n.endsWith('.gif')) return 'image/gif';
  if (n.endsWith('.webp')) return 'image/webp';
  return null;
}

/**
 * Parse Range: bytes=… for progressive video/audio (browser sends many ranged GETs).
 * @param {string | undefined} rangeHeader
 * @param {number} fileSize
 * @returns {{ start: number, end: number } | null}
 */
function parseBytesRange(rangeHeader, fileSize) {
  if (!rangeHeader || typeof rangeHeader !== 'string') return null;
  const m = /^bytes=(\d*)-(\d*)$/i.exec(String(rangeHeader).trim());
  if (!m) return null;
  const size = Number(fileSize);
  if (!Number.isFinite(size) || size <= 0) return null;
  let start;
  let end;
  if (m[1] === '' && m[2] !== '') {
    const suffixLen = parseInt(m[2], 10);
    if (!Number.isFinite(suffixLen) || suffixLen <= 0) return null;
    start = Math.max(0, size - suffixLen);
    end = size - 1;
  } else if (m[1] !== '' && m[2] === '') {
    start = parseInt(m[1], 10);
    if (!Number.isFinite(start)) return null;
    end = size - 1;
  } else if (m[1] !== '' && m[2] !== '') {
    start = parseInt(m[1], 10);
    end = parseInt(m[2], 10);
    if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  } else {
    return null;
  }
  if (start < 0 || start >= size) return null;
  end = Math.min(end, size - 1);
  if (start > end) return null;
  return { start, end };
}

function keyToId(key) {
  return Buffer.from(key, 'utf8').toString('base64url');
}

function idToKey(id) {
  return Buffer.from(String(id), 'base64url').toString('utf8');
}

/**
 * Normalize relative path under job root (no leading/trailing slash).
 */
function normalizeRelPath(p) {
  const raw = String(p ?? '').trim().replace(/\\/g, '/');
  if (!raw) return '';
  const segments = raw.split('/').filter(Boolean);
  if (segments.some((x) => x === '.' || x === '..')) throw new Error('Invalid path');
  for (const seg of segments) {
    sanitizeFolderSegment(seg);
  }
  return segments.join('/');
}

function joinRel(parentPath, name) {
  const p = normalizeRelPath(parentPath);
  const n = sanitizeFolderSegment(name);
  return p ? `${p}/${n}` : n;
}

function parentRelPath(rel) {
  const n = normalizeRelPath(rel);
  if (!n) return '';
  const i = n.lastIndexOf('/');
  return i === -1 ? '' : n.slice(0, i);
}

function basenameRel(rel) {
  const n = normalizeRelPath(rel);
  if (!n) return '';
  const i = n.lastIndexOf('/');
  return i === -1 ? n : n.slice(i + 1);
}

function copySourceHeader(bucket, key) {
  return `${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
}

async function listAllKeys(s3, bucket, prefix) {
  const keys = [];
  let pageToken;
  do {
    const resp = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: pageToken
      })
    );
    for (const obj of resp.Contents || []) {
      if (obj.Key) keys.push({ Key: obj.Key, Size: obj.Size ?? 0, LastModified: obj.LastModified });
    }
    pageToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (pageToken);
  return keys;
}

function isFolderMarkerKey(relKey) {
  return relKey.endsWith(`/${FOLDER_MARKER}`) || relKey === FOLDER_MARKER;
}

function markerRelToFolderRel(markerRel) {
  if (markerRel === FOLDER_MARKER) return '';
  if (markerRel.endsWith(`/${FOLDER_MARKER}`)) {
    return markerRel.slice(0, -(FOLDER_MARKER.length + 1));
  }
  return null;
}

/**
 * Build nested catalog from flat keys under job prefix.
 */
function buildTreeFromKeys(jobPref, entries) {
  const rel = (key) => key.slice(jobPref.length);
  const folderSet = new Set();
  const folderMeta = new Map();

  const files = [];

  for (const { Key: key, Size: size, LastModified: lm } of entries) {
    if (!key.startsWith(jobPref)) continue;
    const r = rel(key);
    if (!r) continue;

    if (isFolderMarkerKey(r)) {
      const folderRel = markerRelToFolderRel(r);
      if (folderRel !== null && folderRel !== '') {
        folderSet.add(folderRel);
        const iso = lm ? lm.toISOString() : null;
        const prev = folderMeta.get(folderRel);
        if (!prev || (iso && (!prev.lastModified || iso > prev.lastModified))) {
          folderMeta.set(folderRel, { lastModified: iso });
        }
      }
      continue;
    }

    const slash = r.lastIndexOf('/');
    const parentPath = slash === -1 ? '' : r.slice(0, slash);
    const name = slash === -1 ? r : r.slice(slash + 1);
    let p = parentPath;
    while (p !== '') {
      folderSet.add(p);
      const ix = p.lastIndexOf('/');
      p = ix === -1 ? '' : p.slice(0, ix);
    }

    files.push({
      id: keyToId(key),
      key,
      path: r,
      parentPath,
      name,
      size,
      lastModified: lm ? lm.toISOString() : null
    });
  }

  const folders = [...folderSet].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
  const folderRows = folders.map((fp) => ({
    path: fp,
    parentPath: parentRelPath(fp),
    name: basenameRel(fp),
    lastModified: folderMeta.get(fp)?.lastModified ?? null
  }));

  return { folders: folderRows, files };
}

async function assertPortalJobAccess(pool, user, clientId, jobId) {
  if (user && user.isAdmin) return true;
  const c = String(clientId || '').trim();
  const j = String(jobId || '').trim();
  if (!c || !j) return false;
  if (c === 'portal-users' && user && j === String(user.id)) return true;
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
      const out = [];
      const keys = await listAllKeys(s3, bucket, prefix);
      for (const obj of keys) {
        const rel = obj.Key.slice(prefix.length);
        if (!rel || isFolderMarkerKey(rel)) continue;
        out.push({
          id: keyToId(obj.Key),
          key: obj.Key,
          name: path.basename(obj.Key),
          size: obj.Size ?? 0,
          lastModified: obj.LastModified ? obj.LastModified.toISOString() : null
        });
      }
      return res.json({ files: out });
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
      const keys = await listAllKeys(s3, bucket, prefix);
      const tree = buildTreeFromKeys(prefix, keys);
      return res.json(tree);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.post('/folders', express.json(), async (req, res) => {
    try {
      const { clientId, jobId, parentPath, name } = req.body || {};
      if (!clientId || !jobId || !name) {
        return res.status(400).json({ error: 'clientId, jobId, and name are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const rel = joinRel(parentPath || '', name);
      const pref = jobPrefix(String(clientId), String(jobId));
      const markerKey = rel ? `${pref}${rel}/${FOLDER_MARKER}` : `${pref}${FOLDER_MARKER}`;

      const probeP = `${pref}${rel}`;
      const under = await listAllKeys(s3, bucket, `${probeP}/`);
      if (under.length > 0) {
        return res.status(409).json({ error: 'A file or folder already exists at this path' });
      }
      try {
        await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: probeP }));
        return res.status(409).json({ error: 'A file or folder already exists at this path' });
      } catch (he) {
        const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
        if (hn !== 'NotFound' && he?.$metadata?.httpStatusCode !== 404) throw he;
      }

      await s3.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: markerKey,
          Body: Buffer.from('', 'utf8'),
          ContentType: 'application/octet-stream'
        })
      );
      return res.status(201).json({
        path: rel,
        parentPath: parentRelPath(rel),
        name: basenameRel(rel) || name,
        markerKey
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(400).json({ error: msg });
    }
  });

  r.patch('/rename', express.json(), async (req, res) => {
    try {
      const body = req.body || {};
      const { clientId, jobId, newName } = body;
      if (!clientId || !jobId || !newName) {
        return res.status(400).json({ error: 'clientId, jobId, and newName are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const pref = jobPrefix(String(clientId), String(jobId));

      if (body.fileId) {
        const oldKey = idToKey(String(body.fileId));
        if (!oldKey.startsWith(pref) || isFolderMarkerKey(oldKey.slice(pref.length))) {
          return res.status(400).json({ error: 'Invalid file id' });
        }
        const oldRel = oldKey.slice(pref.length);
        const par = parentRelPath(oldRel);
        const sanitized = sanitizeFilename(newName);
        const newRel = par ? `${par}/${sanitized}` : sanitized;
        const newKey = `${pref}${newRel}`;
        if (oldKey === newKey) {
          return res.json({ id: keyToId(newKey), key: newKey, path: newRel });
        }
        try {
          await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: newKey }));
          return res.status(409).json({ error: 'Destination already exists' });
        } catch (he) {
          const hn = he && typeof he === 'object' && 'name' in he ? he.name : '';
          if (hn !== 'NotFound' && he?.$metadata?.httpStatusCode !== 404) {
            throw he;
          }
        }
        await s3.send(
          new CopyObjectCommand({
            Bucket: bucket,
            Key: newKey,
            CopySource: copySourceHeader(bucket, oldKey),
            MetadataDirective: 'COPY'
          })
        );
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: oldKey }));
        return res.json({ id: keyToId(newKey), key: newKey, path: newRel, name: sanitized });
      }

      if (body.path !== undefined) {
        const oldFolderRel = normalizeRelPath(body.path);
        if (!oldFolderRel) {
          return res.status(400).json({ error: 'Cannot rename the job root folder' });
        }
        const parent = parentRelPath(oldFolderRel);
        const seg = sanitizeFolderSegment(newName);
        const newRel = parent ? `${parent}/${seg}` : seg;
        if (oldFolderRel === newRel) {
          return res.json({ path: newRel });
        }

        const oldPrefix = `${pref}${oldFolderRel}/`;
        const keys = await listAllKeys(s3, bucket, oldPrefix);
        if (keys.length === 0) {
          return res.status(404).json({ error: 'Folder not found' });
        }

        const destProbe = await listAllKeys(s3, bucket, `${pref}${newRel}`);
        const destTaken = destProbe.some(
          (o) => o.Key === `${pref}${newRel}` || o.Key.startsWith(`${pref}${newRel}/`)
        );
        if (destTaken) {
          return res.status(409).json({ error: 'Destination path is occupied' });
        }

        const newPrefix = `${pref}${newRel}/`;
        const mapping = keys.map((o) => ({
          from: o.Key,
          to: `${newPrefix}${o.Key.slice(oldPrefix.length)}`
        }));

        for (const { from, to } of mapping) {
          await s3.send(
            new CopyObjectCommand({
              Bucket: bucket,
              Key: to,
              CopySource: copySourceHeader(bucket, from),
              MetadataDirective: 'COPY'
            })
          );
        }
        for (const { from } of mapping) {
          await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: from }));
        }
        return res.json({ path: newRel, parentPath: parentRelPath(newRel), name: seg });
      }

      return res.status(400).json({ error: 'Provide fileId or path for folder rename' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.delete('/folders', async (req, res) => {
    try {
      const { clientId, jobId, path: pathParam } = req.query;
      if (!clientId || !jobId || pathParam === undefined || pathParam === '') {
        return res.status(400).json({ error: 'clientId, jobId, and non-empty path query params are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const folderRel = normalizeRelPath(pathParam);
      if (!folderRel) {
        return res.status(400).json({ error: 'path must name a folder under the job (not the job root)' });
      }
      const pref = jobPrefix(String(clientId), String(jobId));
      const prefix = `${pref}${folderRel}/`;
      const keys = await listAllKeys(s3, bucket, prefix);
      const markerKey = `${pref}${folderRel}/${FOLDER_MARKER}`;
      const toDelete = new Set(keys.map((k) => k.Key));
      toDelete.add(markerKey);
      for (const Key of toDelete) {
        try {
          await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key }));
        } catch (err) {
          if (err && err.name !== 'NoSuchKey') throw err;
        }
      }
      return res.status(204).send();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  });

  r.post('/upload', portalUpload.single('file'), async (req, res) => {
    const f = req.file;
    if (!f) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }
    try {
      const { clientId, jobId, category, folderPath } = req.body;
      if (!clientId || !jobId) {
        fs.unlink(f.path, () => {});
        return res.status(400).json({ error: 'clientId and jobId are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        fs.unlink(f.path, () => {});
        return res.status(403).json({ error: 'Forbidden' });
      }
      const original = req.body.filename || f.originalname || 'upload';
      const fp = normalizeRelPath(folderPath || '');
      const catExplicit = fp ? null : req.body.category || null;
      const Key = portalUploadKey(clientId, jobId, fp || '', original, catExplicit);
      await s3UploadFromTempPath(s3, bucket, Key, f.path, f.mimetype || 'application/octet-stream');
      const pref = jobPrefix(String(clientId), String(jobId));
      return res.status(201).json({
        id: keyToId(Key),
        key: Key,
        name: path.basename(Key),
        size: f.size,
        path: Key.slice(pref.length),
        parentPath: parentRelPath(Key.slice(pref.length))
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

  r.post('/upload/batch', portalBatchUpload.array('file', 100), async (req, res) => {
    const files = req.files;
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ error: 'Missing file field(s) "file"' });
    }
    const { clientId, jobId, folderPath, folderPaths: folderPathsRaw } = req.body || {};
    if (!clientId || !jobId) {
      for (const f of files) fs.unlink(f.path, () => {});
      return res.status(400).json({ error: 'clientId and jobId are required' });
    }
    if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
      for (const f of files) fs.unlink(f.path, () => {});
      return res.status(403).json({ error: 'Forbidden' });
    }

    /** @type {string[]} */
    let pathsList;
    if (folderPathsRaw != null && String(folderPathsRaw).trim()) {
      try {
        const parsed = JSON.parse(String(folderPathsRaw));
        if (!Array.isArray(parsed) || parsed.length !== files.length) {
          for (const f of files) fs.unlink(f.path, () => {});
          return res.status(400).json({
            error: 'folderPaths must be a JSON array with the same length as the number of files'
          });
        }
        pathsList = parsed.map((p) => {
          try {
            return normalizeRelPath(p ?? '');
          } catch (err) {
            throw err;
          }
        });
      } catch (e) {
        for (const f of files) fs.unlink(f.path, () => {});
        const msg = e instanceof Error ? e.message : String(e);
        return res.status(400).json({ error: `Invalid folderPaths: ${msg}` });
      }
    } else {
      const fp = normalizeRelPath(folderPath || '');
      pathsList = files.map(() => fp);
    }

    const pref = jobPrefix(String(clientId), String(jobId));
    /** @type {Array<{ id: string, key: string, name: string, size: number, path: string, parentPath: string } | null>} */
    const okSlot = new Array(files.length).fill(null);
    /** @type {Array<{ index: number, name: string, error: string } | null>} */
    const errSlot = new Array(files.length).fill(null);
    const concurrency = Math.min(8, Math.max(1, files.length));

    await runPool(files, concurrency, async (f, idx) => {
      const original = f.originalname || 'upload';
      try {
        const Key = portalUploadKey(clientId, jobId, pathsList[idx], original, null);
        await s3UploadFromTempPath(s3, bucket, Key, f.path, f.mimetype || 'application/octet-stream');
        okSlot[idx] = {
          id: keyToId(Key),
          key: Key,
          name: path.basename(Key),
          size: f.size,
          path: Key.slice(pref.length),
          parentPath: parentRelPath(Key.slice(pref.length))
        };
      } catch (e) {
        try {
          fs.unlink(f.path, () => {});
        } catch (_) {
          /* ignore */
        }
        errSlot[idx] = {
          index: idx,
          name: original,
          error: e instanceof Error ? e.message : String(e)
        };
      }
    });

    const items = okSlot.filter(Boolean);
    const errors = errSlot.filter(Boolean);
    const status = errors.length === 0 ? 201 : items.length > 0 ? 207 : 500;
    return res.status(status).json({
      items,
      ...(errors.length ? { errors } : {})
    });
  });

  async function handlePortalFileDownload(req, res) {
    try {
      const Key = idToKey(req.params.id);
      if (!Key.startsWith('clients/')) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      if (Key.endsWith(`/${FOLDER_MARKER}`) || path.basename(Key) === FOLDER_MARKER) {
        return res.status(400).json({ error: 'Not a downloadable file' });
      }
      const parsed = parseJobFromObjectKey(Key);
      if (!parsed || !(await assertPortalJobAccess(pool, req.user, parsed.clientId, parsed.jobId))) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const filename = path.basename(Key);
      const fromKey = contentTypeFromFilename(filename);
      const meta = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key }));
      const total = Number(meta.ContentLength);
      if (!Number.isFinite(total) || total < 0) {
        return res.status(500).json({ error: 'Missing object size' });
      }

      const s3Type = (meta.ContentType || '').split(';')[0].trim().toLowerCase();
      const useGuess =
        fromKey &&
        (!s3Type || s3Type === 'application/octet-stream' || s3Type === 'binary/octet-stream');
      const contentType = useGuess ? fromKey : meta.ContentType || 'application/octet-stream';
      const inline =
        /^video\//i.test(contentType) ||
        contentType === 'application/pdf' ||
        String(req.query?.inline || '') === '1';
      res.setHeader(
        'Content-Disposition',
        inline
          ? `inline; filename="${encodeURIComponent(filename)}"`
          : `attachment; filename="${encodeURIComponent(filename)}"`
      );
      res.setHeader('Content-Type', contentType);
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Cache-Control', 'private, max-age=300');

      const rangeHdr = req.headers.range;
      const isHead = req.method === 'HEAD';

      if (isHead) {
        if (rangeHdr) {
          const pr = parseBytesRange(rangeHdr, total);
          if (!pr) {
            res.setHeader('Content-Range', `bytes */${total}`);
            return res.status(416).end();
          }
          const chunk = pr.end - pr.start + 1;
          res.status(206);
          res.setHeader('Content-Range', `bytes ${pr.start}-${pr.end}/${total}`);
          res.setHeader('Content-Length', String(chunk));
          return res.end();
        }
        res.setHeader('Content-Length', String(total));
        return res.status(200).end();
      }

      if (rangeHdr) {
        const pr = parseBytesRange(rangeHdr, total);
        if (!pr) {
          res.setHeader('Content-Range', `bytes */${total}`);
          return res.status(416).end();
        }
        const obj = await s3.send(
          new GetObjectCommand({
            Bucket: bucket,
            Key,
            Range: `bytes=${pr.start}-${pr.end}`
          })
        );
        const chunk = pr.end - pr.start + 1;
        res.status(206);
        res.setHeader('Content-Range', `bytes ${pr.start}-${pr.end}/${total}`);
        res.setHeader('Content-Length', String(chunk));
        if (!obj.Body || typeof obj.Body.pipe !== 'function') {
          return res.status(500).json({ error: 'Empty body' });
        }
        obj.Body.on('error', (err) => {
          if (!res.headersSent) res.status(500).end();
          else res.destroy(err);
        });
        obj.Body.pipe(res);
        return;
      }

      const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key }));
      if (obj.ContentLength != null) {
        res.setHeader('Content-Length', String(obj.ContentLength));
      }
      if (!obj.Body || typeof obj.Body.pipe !== 'function') {
        return res.status(500).json({ error: 'Empty body' });
      }
      obj.Body.on('error', (err) => {
        if (!res.headersSent) res.status(500).end();
        else res.destroy(err);
      });
      res.status(200);
      obj.Body.pipe(res);
    } catch (e) {
      const name = e && typeof e === 'object' && 'name' in e ? e.name : '';
      if (name === 'NoSuchKey' || (e instanceof Error && e.message && e.message.includes('NoSuchKey'))) {
        return res.status(404).json({ error: 'Not found' });
      }
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(500).json({ error: msg });
    }
  }

  r.get('/download/:id', handlePortalFileDownload);
  r.head('/download/:id', handlePortalFileDownload);

  r.delete('/:id', async (req, res) => {
    try {
      const Key = idToKey(req.params.id);
      if (!Key.startsWith('clients/')) {
        return res.status(400).json({ error: 'Invalid id' });
      }
      if (Key.endsWith(`/${FOLDER_MARKER}`)) {
        return res.status(400).json({ error: 'Use DELETE /api/files/folders to remove folders' });
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
