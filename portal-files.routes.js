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
const { S3Client, DeleteObjectCommand, GetObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');

const CATEGORIES = new Set(['videos', 'db3', 'pdf', 'photos']);

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
  if (!cleaned) throw new Error('Invalid filename');
  return cleaned;
}

function assertCategory(cat) {
  if (!CATEGORIES.has(cat)) {
    throw new Error(`Invalid category. Use one of: ${[...CATEGORIES].join(', ')}`);
  }
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

function keyToId(key) {
  return Buffer.from(key, 'utf8').toString('base64url');
}

function idToKey(id) {
  return Buffer.from(String(id), 'base64url').toString('utf8');
}

/**
 * Admin: all prefixes. Others: must match a planner row for this client + job (record id or jobsite label).
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
        for (const obj of resp.Contents || []) {
          if (!obj.Key.endsWith('/')) {
            out.push({
              id: keyToId(obj.Key),
              key: obj.Key,
              name: path.basename(obj.Key),
              size: obj.Size ?? 0,
              lastModified: obj.LastModified ? obj.LastModified.toISOString() : null
            });
          }
        }
        pageToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
      } while (pageToken);
      return res.json({ files: out });
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
      const { clientId, jobId, category } = req.body;
      if (!clientId || !jobId || !category) {
        fs.unlink(f.path, () => {});
        return res.status(400).json({ error: 'clientId, jobId, and category are required' });
      }
      if (!(await assertPortalJobAccess(pool, req.user, String(clientId), String(jobId)))) {
        fs.unlink(f.path, () => {});
        return res.status(403).json({ error: 'Forbidden' });
      }
      const original = req.body.filename || f.originalname || 'upload';
      const Key = objectKey(String(clientId), String(jobId), String(category), original);
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
