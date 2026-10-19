'use strict';

/**
 * Netflix-style preview ladder for PipeShare videos.
 *
 * The original object stays put. Beside it, in a hidden folder the explorer skips:
 *   {dir}/.hp-hls/{filename}/master.m3u8
 *   {dir}/.hp-hls/{filename}/preview.m3u8 + preview_*.ts   (light 360p)
 *   {dir}/.hp-hls/{filename}/full.m3u8 + full_*.ts         (original video, stream-copied)
 *   {dir}/.hp-hls/{filename}/ready.json
 *
 * One `.hp-hls` folder per directory keeps folder listings from growing by one
 * prefix per video. Playlists are rewritten by the API so segment bytes are
 * presigned Wasabi GETs. One ffmpeg job runs on the host at a time.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { Pool } = require('pg');
const {
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { resolveStorageBackend } = require('./portal-storage-backend');

const VIDEO_EXT = new Set(['.mp4', '.m4v', '.mov', '.webm', '.mkv', '.avi', '.ogv']);
const PLAYLIST_NAMES = new Set(['master.m3u8', 'preview.m3u8', 'full.m3u8']);
const SEGMENT_NAME = /^[A-Za-z0-9._-]+$/;
const LOCK_PATH = process.env.PORTAL_HLS_LOCK_PATH || '/tmp/horizon-portal-video-hls.lock';
const STALE_MS = Math.max(60 * 1000, Number(process.env.PORTAL_HLS_STALE_MS || 2 * 60 * 1000));
const FAIL_RETRY_MS = Math.max(60 * 1000, Number(process.env.PORTAL_HLS_RETRY_MS || 30 * 60 * 1000));
const MAX_SOURCE_BYTES = Math.max(
  32 * 1024 * 1024,
  Number(process.env.PORTAL_HLS_MAX_SOURCE_BYTES || 4 * 1024 * 1024 * 1024)
);
const PRESIGN_TTL = Math.max(60, Math.min(604800, Number(process.env.PORTAL_PRESIGN_TTL_SECONDS || 3600)));

/** @type {import('pg').Pool | null | false} */
let hlsPool = null;
let schemaReady = null;
/** @type {import('child_process').ChildProcess | null} */
let activeChild = null;

function hlsEnabled() {
  const v = String(process.env.PORTAL_VIDEO_HLS ?? '1').trim().toLowerCase();
  return v !== '0' && v !== 'false' && v !== 'off' && v !== 'no';
}

function ffmpegBin() {
  return process.env.FFMPEG_PATH || 'ffmpeg';
}

function ffprobeBin() {
  return process.env.FFPROBE_PATH || 'ffprobe';
}

function isPortalHlsSidecarObjectKey(key) {
  return String(key || '')
    .split('/')
    .some((seg) => seg === '.hp-hls');
}

function isPortalHlsSidecarRelPath(rel) {
  return isPortalHlsSidecarObjectKey(rel);
}

function isPortalVideoObjectKey(key) {
  const base = path.posix.basename(String(key || '')).toLowerCase();
  const dot = base.lastIndexOf('.');
  if (dot < 0) return false;
  if (isPortalHlsSidecarObjectKey(key)) return false;
  return VIDEO_EXT.has(base.slice(dot));
}

function hlsPrefixForObjectKey(key) {
  const norm = String(key || '').replace(/\/+$/, '');
  const slash = norm.lastIndexOf('/');
  const dir = slash >= 0 ? norm.slice(0, slash + 1) : '';
  const base = slash >= 0 ? norm.slice(slash + 1) : norm;
  return `${dir}.hp-hls/${base}/`;
}

function isHlsPlaylistName(name) {
  return PLAYLIST_NAMES.has(String(name || ''));
}

function logName(key) {
  const parts = String(key || '').split('/').filter(Boolean);
  return parts.slice(-2).join('/') || 'video';
}

function evenDim(n) {
  const x = Math.max(2, Math.round(Number(n) || 2));
  return x % 2 === 0 ? x : x - 1;
}

function contentTypeForHlsName(name) {
  const n = String(name || '').toLowerCase();
  if (n.endsWith('.m3u8')) return 'application/vnd.apple.mpegurl';
  if (n.endsWith('.ts')) return 'video/mp2t';
  if (n.endsWith('.m4s') || n.endsWith('.mp4')) return 'video/mp4';
  if (n.endsWith('.json')) return 'application/json';
  return 'application/octet-stream';
}

function stripEtag(value) {
  return String(value || '').replace(/^"+|"+$/g, '').trim();
}

/**
 * Rewrite playlist URIs. Tag lines keep their text; URI="..." and bare segment
 * lines are passed through mapUri unless they are already absolute.
 * @param {string} text
 * @param {(uri: string) => string} mapUri
 */
function rewriteHlsPlaylist(text, mapUri) {
  const lines = String(text || '').split(/\r?\n/);
  return lines
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      if (trimmed.startsWith('#')) {
        return line.replace(/URI="([^"]+)"/g, (all, uri) => {
          if (/^https?:\/\//i.test(uri)) return all;
          return `URI="${mapUri(uri)}"`;
        });
      }
      if (/^https?:\/\//i.test(trimmed)) return line;
      return mapUri(trimmed);
    })
    .join('\n');
}

function assertSafeSegmentName(uri) {
  const name = String(uri || '').trim();
  if (!SEGMENT_NAME.test(name) || name.includes('..')) {
    throw new Error('Invalid playlist entry');
  }
  return name;
}

function databaseSsl() {
  const url = String(process.env.DATABASE_URL || '');
  const local = /(^|@)(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(url) || /sslmode=disable/i.test(url);
  const off = process.env.DATABASE_SSL === '0' || /^false$/i.test(String(process.env.DATABASE_SSL || ''));
  if (off || local) return false;
  return { rejectUnauthorized: false };
}

function getHlsPool() {
  if (hlsPool === false) return null;
  if (hlsPool) return hlsPool;
  const connectionString = String(process.env.DATABASE_URL || '').trim();
  if (!connectionString) {
    hlsPool = false;
    console.warn('[portal-hls] DATABASE_URL missing; video preview ladder stays off');
    return null;
  }
  hlsPool = new Pool({
    connectionString,
    max: 2,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 15000,
    ssl: databaseSsl()
  });
  hlsPool.on('error', (err) => {
    console.warn('[portal-hls] postgres pool error:', err?.message || err);
  });
  return hlsPool;
}

async function ensureSchema() {
  const pool = getHlsPool();
  if (!pool) return null;
  if (!schemaReady) {
    schemaReady = pool
      .query(
        `CREATE TABLE IF NOT EXISTS portal_video_hls_jobs (
           object_key TEXT PRIMARY KEY,
           bucket TEXT NOT NULL,
           status TEXT NOT NULL,
           detail TEXT NOT NULL DEFAULT '',
           needs_rerun BOOLEAN NOT NULL DEFAULT FALSE,
           updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
         )`
      )
      .catch((e) => {
        schemaReady = null;
        throw e;
      });
  }
  await schemaReady;
  return pool;
}

function pidAlive(pid) {
  const n = Number(pid);
  if (!Number.isInteger(n) || n <= 0) return false;
  try {
    process.kill(n, 0);
    return true;
  } catch (e) {
    return e && e.code === 'EPERM';
  }
}

function readLock() {
  try {
    return JSON.parse(fs.readFileSync(LOCK_PATH, 'utf8'));
  } catch {
    return null;
  }
}

function writeLock(fd, extra) {
  const body = JSON.stringify({
    pid: process.pid,
    touchedAt: Date.now(),
    ffmpegPid: activeChild && activeChild.pid ? activeChild.pid : 0,
    ...(extra || {})
  });
  try {
    fs.ftruncateSync(fd, 0);
    fs.writeSync(fd, body, 0);
  } catch {
    /* lock file is best-effort */
  }
}

function tryAcquireLock() {
  const cur = readLock();
  if (cur && pidAlive(cur.pid) && Date.now() - Number(cur.touchedAt || 0) < STALE_MS) {
    return null;
  }
  if (cur?.ffmpegPid) {
    try {
      process.kill(Number(cur.ffmpegPid), 'SIGKILL');
    } catch {
      /* already gone */
    }
  }
  try {
    fs.unlinkSync(LOCK_PATH);
  } catch {
    /* absent */
  }
  try {
    const fd = fs.openSync(LOCK_PATH, 'wx');
    writeLock(fd);
    return fd;
  } catch {
    return null;
  }
}

function releaseLock(fd) {
  try {
    fs.closeSync(fd);
  } catch {
    /* ignore */
  }
  try {
    const cur = readLock();
    if (!cur || cur.pid === process.pid) fs.unlinkSync(LOCK_PATH);
  } catch {
    /* ignore */
  }
}

function clientForBucket(bucket) {
  const want = String(bucket || '');
  const base = resolveStorageBackend({ headers: { host: process.env.HP_PRIVATE_BASE_DOMAIN || 'pipeshare.live' } });
  if (base?.s3 && base.bucket === want) return base.s3;
  const saas = resolveStorageBackend({ headers: { host: process.env.SAAS_PIPESHARE_DOMAIN || 'pipeshare.net' } });
  if (saas?.s3 && saas.bucket === want) return saas.s3;
  return null;
}

function runCapture(bin, args) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      reject(e);
      return;
    }
    activeChild = child;
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => {
      out += d.toString();
      if (out.length > 2_000_000) out = out.slice(-1_000_000);
    });
    child.stderr.on('data', (d) => {
      err = (err + d.toString()).slice(-4000);
    });
    child.on('error', (e) => {
      if (activeChild === child) activeChild = null;
      reject(e);
    });
    child.on('close', (code) => {
      if (activeChild === child) activeChild = null;
      if (code === 0) resolve(out);
      else reject(new Error(`${path.basename(bin)} exit ${code}: ${err.slice(-600)}`));
    });
  });
}

function runFfmpeg(args, cwd) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(ffmpegBin(), args, { cwd, stdio: ['ignore', 'ignore', 'pipe'] });
    } catch (e) {
      reject(e);
      return;
    }
    activeChild = child;
    let err = '';
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    }, Math.max(60 * 1000, Number(process.env.PORTAL_HLS_TIMEOUT_MS || 3 * 60 * 60 * 1000)));
    child.stderr.on('data', (d) => {
      err = (err + d.toString()).slice(-4000);
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      if (activeChild === child) activeChild = null;
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (activeChild === child) activeChild = null;
      if (code === 0) resolve();
      else reject(new Error(`ffmpeg exit ${code}: ${err.slice(-600)}`));
    });
  });
}

async function headObject(s3, bucket, key) {
  try {
    return await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
  } catch (e) {
    const name = e && e.name ? e.name : '';
    const status = e?.$metadata?.httpStatusCode;
    if (name === 'NotFound' || name === 'NoSuchKey' || status === 404) return null;
    throw e;
  }
}

async function readObjectText(s3, bucket, key) {
  const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  const chunks = [];
  for await (const chunk of obj.Body) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

async function deletePrefix(s3, bucket, prefix) {
  let token;
  do {
    const resp = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: token
      })
    );
    const objects = (resp.Contents || []).map((o) => ({ Key: String(o.Key || '') })).filter((o) => o.Key);
    for (let i = 0; i < objects.length; i += 1000) {
      const batch = objects.slice(i, i + 1000);
      if (!batch.length) continue;
      await s3.send(
        new DeleteObjectsCommand({
          Bucket: bucket,
          Delete: { Objects: batch, Quiet: true }
        })
      );
    }
    token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (token);
}

async function getJobRow(pool, key) {
  const r = await pool.query(
    `SELECT object_key, bucket, status, detail, needs_rerun, updated_at
     FROM portal_video_hls_jobs WHERE object_key = $1`,
    [key]
  );
  return r.rows[0] || null;
}

async function enqueueJob(pool, bucket, key) {
  await pool.query(
    `INSERT INTO portal_video_hls_jobs (object_key, bucket, status, detail, needs_rerun, updated_at)
     VALUES ($1, $2, 'queued', '', FALSE, NOW())
     ON CONFLICT (object_key) DO UPDATE SET
       bucket = EXCLUDED.bucket,
       needs_rerun = CASE
         WHEN portal_video_hls_jobs.status = 'preparing'
          AND portal_video_hls_jobs.updated_at > NOW() - ($3::bigint * INTERVAL '1 millisecond')
         THEN TRUE
         ELSE FALSE
       END,
       status = CASE
         WHEN portal_video_hls_jobs.status = 'preparing'
          AND portal_video_hls_jobs.updated_at > NOW() - ($3::bigint * INTERVAL '1 millisecond')
         THEN portal_video_hls_jobs.status
         ELSE 'queued'
       END,
       detail = CASE
         WHEN portal_video_hls_jobs.status = 'preparing'
          AND portal_video_hls_jobs.updated_at > NOW() - ($3::bigint * INTERVAL '1 millisecond')
         THEN portal_video_hls_jobs.detail
         ELSE ''
       END,
       updated_at = CASE
         WHEN portal_video_hls_jobs.status = 'preparing'
          AND portal_video_hls_jobs.updated_at > NOW() - ($3::bigint * INTERVAL '1 millisecond')
         THEN portal_video_hls_jobs.updated_at
         ELSE NOW()
       END`,
    [key, bucket, STALE_MS]
  );
}

async function claimNext(pool) {
  const r = await pool.query(
    `WITH next AS (
       SELECT object_key
       FROM portal_video_hls_jobs
       WHERE status = 'queued'
          OR (status = 'preparing' AND updated_at < NOW() - ($1::bigint * INTERVAL '1 millisecond'))
       ORDER BY updated_at ASC
       LIMIT 1
       FOR UPDATE SKIP LOCKED
     )
     UPDATE portal_video_hls_jobs j
     SET status = 'preparing', detail = '', updated_at = NOW()
     FROM next
     WHERE j.object_key = next.object_key
     RETURNING j.object_key, j.bucket`,
    [STALE_MS]
  );
  return r.rows[0] || null;
}

async function markJob(pool, key, status, detail) {
  await pool.query(
    `UPDATE portal_video_hls_jobs
     SET status = $2, detail = $3, needs_rerun = FALSE, updated_at = NOW()
     WHERE object_key = $1`,
    [key, status, String(detail || '').slice(0, 400)]
  );
}

async function finishOrRerun(pool, key) {
  const r = await pool.query(
    `UPDATE portal_video_hls_jobs
     SET status = CASE WHEN needs_rerun THEN 'queued' ELSE 'ready' END,
         needs_rerun = FALSE,
         detail = '',
         updated_at = NOW()
     WHERE object_key = $1
     RETURNING status`,
    [key]
  );
  return r.rows[0]?.status || 'ready';
}

async function heartbeat(pool, key, fd) {
  writeLock(fd);
  try {
    await pool.query(
      `UPDATE portal_video_hls_jobs SET updated_at = NOW() WHERE object_key = $1 AND status = 'preparing'`,
      [key]
    );
  } catch (e) {
    console.warn('[portal-hls] heartbeat failed:', e?.message || e);
  }
}

function buildMaster({ preview, full, version }) {
  return [
    '#EXTM3U',
    `#EXT-X-VERSION:${version || 3}`,
    `#EXT-X-STREAM-INF:BANDWIDTH=${preview.bandwidth},RESOLUTION=${preview.width}x${preview.height},NAME="Preview"`,
    'preview.m3u8',
    `#EXT-X-STREAM-INF:BANDWIDTH=${full.bandwidth},RESOLUTION=${full.width}x${full.height},NAME="Full"`,
    'full.m3u8',
    ''
  ].join('\n');
}

async function uploadTree(s3, bucket, prefix, dir) {
  const names = fs
    .readdirSync(dir)
    .filter((name) => {
      try {
        return fs.statSync(path.join(dir, name)).isFile() && name !== 'ready.json';
      } catch {
        return false;
      }
    });
  let cursor = 0;
  async function worker() {
    while (cursor < names.length) {
      const name = names[cursor];
      cursor += 1;
      const body = fs.readFileSync(path.join(dir, name));
      await s3.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: prefix + name,
          Body: body,
          ContentType: contentTypeForHlsName(name),
          CacheControl: 'private, max-age=86400'
        })
      );
    }
  }
  const workers = Math.min(4, Math.max(1, names.length));
  await Promise.all(Array.from({ length: workers }, () => worker()));
}

async function transcodeOne(s3, bucket, key, pool, fd) {
  const head = await headObject(s3, bucket, key);
  if (!head) {
    const err = new Error('Video object is missing');
    err.code = 'UNSUPPORTED';
    throw err;
  }
  const size = Number(head.ContentLength || 0);
  if (!Number.isFinite(size) || size <= 0) {
    const err = new Error('Video object is empty');
    err.code = 'UNSUPPORTED';
    throw err;
  }
  if (size > MAX_SOURCE_BYTES) {
    const err = new Error(`Video is over the preview size cap (${Math.round(MAX_SOURCE_BYTES / (1024 * 1024))} MB)`);
    err.code = 'UNSUPPORTED';
    throw err;
  }
  const free = (() => {
    try {
      const st = fs.statfsSync(os.tmpdir());
      return Number(st.bavail) * Number(st.bsize);
    } catch {
      return null;
    }
  })();
  if (free != null && free < size * 2.4 + 512 * 1024 * 1024) {
    throw new Error('Not enough free disk to build the preview ladder');
  }

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-hls-'));
  const input = path.join(work, 'source.bin');
  const outDir = path.join(work, 'out');
  fs.mkdirSync(outDir);
  const beat = setInterval(() => {
    void heartbeat(pool, key, fd);
  }, 20000);
  try {
    const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    await pipeline(obj.Body, fs.createWriteStream(input));
    await heartbeat(pool, key, fd);

    let probeRaw = '';
    try {
      probeRaw = await runCapture(ffprobeBin(), [
        '-v',
        'error',
        '-print_format',
        'json',
        '-show_format',
        '-show_streams',
        input
      ]);
    } catch (e) {
      if (e && e.code === 'ENOENT') {
        const err = new Error('ffmpeg is not installed on the server');
        err.code = 'FFMPEG_MISSING';
        throw err;
      }
      throw e;
    }
    const probe = JSON.parse(probeRaw || '{}');
    const streams = Array.isArray(probe.streams) ? probe.streams : [];
    const video = streams.find((s) => s && s.codec_type === 'video');
    const audio = streams.find((s) => s && s.codec_type === 'audio');
    if (!video) {
      const err = new Error('File has no video stream');
      err.code = 'UNSUPPORTED';
      throw err;
    }
    const srcW = evenDim(video.width || 640);
    const srcH = evenDim(video.height || 360);
    const prevH = srcH > 360 ? 360 : srcH;
    const prevW = evenDim((srcW * prevH) / srcH);
    const srcBr = Number(video.bit_rate || probe.format?.bit_rate || 0);
    const previewVideoRate = srcBr > 0 && srcBr < 1_200_000 ? 350_000 : 700_000;
    const previewBandwidth = previewVideoRate + (audio ? 96_000 : 0);
    const fullBandwidth = Math.max(previewBandwidth + 400_000, srcBr || srcW * srcH * 3);
    const vCodec = String(video.codec_name || '').toLowerCase();
    const aCodec = String(audio?.codec_name || '').toLowerCase();
    const fullIsTs = vCodec === 'h264';

    const previewArgs = ['-y', '-i', input, '-map', '0:v:0'];
    if (audio) previewArgs.push('-map', '0:a:0');
    previewArgs.push(
      '-vf',
      `scale=-2:${prevH}`,
      '-c:v',
      'libx264',
      '-preset',
      'veryfast',
      '-profile:v',
      'main',
      '-pix_fmt',
      'yuv420p',
      '-threads',
      '2',
      '-b:v',
      String(previewVideoRate),
      '-maxrate',
      String(Math.round(previewVideoRate * 1.25)),
      '-bufsize',
      String(previewVideoRate * 2)
    );
    if (audio) previewArgs.push('-c:a', 'aac', '-b:a', '96k', '-ac', '2');
    previewArgs.push(
      '-hls_time',
      '4',
      '-hls_playlist_type',
      'vod',
      '-hls_list_size',
      '0',
      '-hls_flags',
      'independent_segments',
      '-hls_segment_filename',
      'preview_%03d.ts',
      'preview.m3u8'
    );
    await runFfmpeg(previewArgs, outDir);
    await heartbeat(pool, key, fd);

    const fullArgs = ['-y', '-i', input, '-map', '0:v:0'];
    if (audio) fullArgs.push('-map', '0:a:0');
    if (fullIsTs) {
      fullArgs.push('-c:v', 'copy', '-bsf:v', 'h264_mp4toannexb');
      if (audio) {
        if (aCodec === 'aac') fullArgs.push('-c:a', 'copy');
        else fullArgs.push('-c:a', 'aac', '-b:a', '128k', '-ac', '2');
      }
      fullArgs.push(
        '-hls_time',
        '6',
        '-hls_playlist_type',
        'vod',
        '-hls_list_size',
        '0',
        '-hls_flags',
        'independent_segments',
        '-hls_segment_filename',
        'full_%03d.ts',
        'full.m3u8'
      );
    } else {
      fullArgs.push('-c:v', 'copy');
      if (audio) {
        if (aCodec === 'aac') fullArgs.push('-c:a', 'copy');
        else fullArgs.push('-c:a', 'aac', '-b:a', '128k', '-ac', '2');
      }
      fullArgs.push(
        '-hls_time',
        '6',
        '-hls_playlist_type',
        'vod',
        '-hls_list_size',
        '0',
        '-hls_segment_type',
        'fmp4',
        '-hls_fmp4_init_filename',
        'full_init.mp4',
        '-hls_segment_filename',
        'full_%03d.m4s',
        'full.m3u8'
      );
    }
    await runFfmpeg(fullArgs, outDir);

    if (!fs.existsSync(path.join(outDir, 'preview.m3u8')) || !fs.existsSync(path.join(outDir, 'full.m3u8'))) {
      throw new Error('ffmpeg did not write both playlists');
    }
    fs.writeFileSync(
      path.join(outDir, 'master.m3u8'),
      buildMaster({
        preview: { bandwidth: previewBandwidth, width: prevW, height: prevH },
        full: { bandwidth: Math.round(fullBandwidth), width: srcW, height: srcH },
        version: fullIsTs ? 3 : 6
      })
    );

    const prefix = hlsPrefixForObjectKey(key);
    await deletePrefix(s3, bucket, prefix);
    await uploadTree(s3, bucket, prefix, outDir);
    const ready = {
      v: 1,
      etag: stripEtag(head.ETag),
      bytes: size,
      preview: { bandwidth: previewBandwidth, width: prevW, height: prevH },
      full: { bandwidth: Math.round(fullBandwidth), width: srcW, height: srcH, copied: vCodec === 'h264' },
      preparedAt: new Date().toISOString()
    };
    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: prefix + 'ready.json',
        Body: Buffer.from(JSON.stringify(ready)),
        ContentType: 'application/json',
        CacheControl: 'private, max-age=60'
      })
    );
    console.info('[portal-hls] ready', logName(key), `${Math.round(size / (1024 * 1024))}MB`);
  } finally {
    clearInterval(beat);
    try {
      fs.rmSync(work, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

async function drain(pool, fd) {
  try {
    while (true) {
      const next = await claimNext(pool);
      if (!next) return;
      const s3 = clientForBucket(next.bucket);
      if (!s3) {
        await markJob(pool, next.object_key, 'failed', 'No storage client for that bucket');
        continue;
      }
      try {
        await transcodeOne(s3, next.bucket, next.object_key, pool, fd);
        await finishOrRerun(pool, next.object_key);
      } catch (e) {
        const code = e && e.code ? e.code : '';
        const msg = String(e?.message || e).slice(0, 400);
        const status = code === 'UNSUPPORTED' ? 'unsupported' : 'failed';
        console.warn('[portal-hls]', status, logName(next.object_key), msg);
        try {
          await markJob(pool, next.object_key, status, msg);
        } catch (markErr) {
          console.warn('[portal-hls] could not record failure:', markErr?.message || markErr);
        }
      }
    }
  } finally {
    releaseLock(fd);
  }
}

function kickRunner(pool) {
  const fd = tryAcquireLock();
  if (fd == null) return;
  setImmediate(() => {
    drain(pool, fd).catch((e) => {
      console.warn('[portal-hls] queue failed:', e?.message || e);
      releaseLock(fd);
    });
  });
}

/**
 * Queue a ladder build after upload. Safe to call more than once.
 * @param {{ s3?: import('@aws-sdk/client-s3').S3Client, bucket?: string, key?: string }} payload
 */
async function schedulePortalVideoHls(payload) {
  if (!hlsEnabled()) return { status: 'none' };
  const key = String(payload?.key || '');
  const bucket = String(payload?.bucket || '');
  const s3 = payload?.s3;
  if (!s3 || !bucket || !isPortalVideoObjectKey(key)) return { status: 'unsupported' };
  const pool = await ensureSchema();
  if (!pool) return { status: 'none' };
  try {
    const readyHead = await headObject(s3, bucket, hlsPrefixForObjectKey(key) + 'ready.json');
    if (readyHead) {
      const source = await headObject(s3, bucket, key);
      let readyEtag = '';
      try {
        const text = await readObjectText(s3, bucket, hlsPrefixForObjectKey(key) + 'ready.json');
        readyEtag = stripEtag(JSON.parse(text || '{}').etag);
      } catch {
        readyEtag = '';
      }
      const sourceEtag = stripEtag(source?.ETag);
      if (readyEtag && sourceEtag && readyEtag === sourceEtag) return { status: 'ready' };
    }
  } catch (e) {
    console.warn('[portal-hls] ready check failed:', e?.message || e);
  }
  await enqueueJob(pool, bucket, key);
  kickRunner(pool);
  return { status: 'preparing' };
}

/**
 * @param {{ s3: import('@aws-sdk/client-s3').S3Client, bucket: string, key: string, fileId: string }} opts
 */
async function getPortalVideoHlsStatus(opts) {
  const key = String(opts?.key || '');
  const fileId = encodeURIComponent(String(opts?.fileId || ''));
  const masterUrl = fileId ? `/api/files/hls/${fileId}/master.m3u8` : '';
  if (!hlsEnabled()) return { status: 'none', masterUrl: '' };
  if (!isPortalVideoObjectKey(key)) return { status: 'unsupported', masterUrl: '' };
  const s3 = opts.s3;
  const bucket = String(opts.bucket || '');
  if (!s3 || !bucket) return { status: 'none', masterUrl: '' };
  const ready = await headObject(s3, bucket, hlsPrefixForObjectKey(key) + 'ready.json');
  if (ready) return { status: 'ready', masterUrl };
  const pool = await ensureSchema();
  if (!pool) return { status: 'none', masterUrl: '' };
  const row = await getJobRow(pool, key);
  if (row?.status === 'unsupported') return { status: 'unsupported', masterUrl: '', detail: row.detail || '' };
  if (row?.status === 'failed') {
    const age = Date.now() - new Date(row.updated_at).getTime();
    if (Number.isFinite(age) && age < FAIL_RETRY_MS) {
      return { status: 'failed', masterUrl: '', detail: row.detail || '' };
    }
  }
  if (row?.status === 'preparing') {
    const age = Date.now() - new Date(row.updated_at).getTime();
    if (Number.isFinite(age) && age < STALE_MS) return { status: 'preparing', masterUrl: '' };
  }
  if (row?.status === 'queued') {
    kickRunner(pool);
    return { status: 'preparing', masterUrl: '' };
  }
  await enqueueJob(pool, bucket, key);
  kickRunner(pool);
  return { status: 'preparing', masterUrl: '' };
}

async function presignHlsGet(s3, bucket, key, expiresIn) {
  const filename = path.posix.basename(key);
  const input = {
    Bucket: bucket,
    Key: key,
    ResponseContentType: contentTypeForHlsName(filename),
    ResponseCacheControl: 'private, max-age=3600'
  };
  return getSignedUrl(s3, new GetObjectCommand(input), { expiresIn });
}

/**
 * @param {{ s3: import('@aws-sdk/client-s3').S3Client, bucket: string, sourceKey: string, name: string, variantBaseUrl: string, accessToken?: string, expiresIn?: number }} opts
 */
async function loadRewrittenHlsPlaylist(opts) {
  const name = String(opts.name || '');
  if (!isHlsPlaylistName(name)) {
    const err = new Error('Not found');
    err.status = 404;
    throw err;
  }
  const prefix = hlsPrefixForObjectKey(opts.sourceKey);
  const text = await readObjectText(opts.s3, opts.bucket, prefix + name);
  const expiresIn = opts.expiresIn || PRESIGN_TTL;
  const token = String(opts.accessToken || '').trim();
  const base = String(opts.variantBaseUrl || '').replace(/\/$/, '');
  const uris = collectPlaylistUris(text);
  /** @type {Map<string, string>} */
  const mapped = new Map();
  if (name === 'master.m3u8') {
    for (const uri of uris) {
      const safe = assertSafeSegmentName(uri);
      const abs = `${base}/${safe}`;
      mapped.set(uri, token ? `${abs}?access_token=${encodeURIComponent(token)}` : abs);
    }
  } else {
    await Promise.all(
      uris.map(async (uri) => {
        const safe = assertSafeSegmentName(uri);
        mapped.set(uri, await presignHlsGet(opts.s3, opts.bucket, prefix + safe, expiresIn));
      })
    );
  }
  return rewriteHlsPlaylist(text, (uri) => mapped.get(uri) || uri);
}

function collectPlaylistUris(text) {
  /** @type {string[]} */
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) {
      const re = /URI="([^"]+)"/g;
      let match;
      while ((match = re.exec(line))) {
        if (!/^https?:\/\//i.test(match[1])) out.push(match[1]);
      }
      continue;
    }
    if (!/^https?:\/\//i.test(trimmed)) out.push(trimmed);
  }
  return out;
}

function scheduleDeletePortalVideoHls(s3, bucket, key) {
  if (!s3 || !bucket || !key || isPortalHlsSidecarObjectKey(key)) return;
  const prefix = hlsPrefixForObjectKey(key);
  setImmediate(() => {
    deletePrefix(s3, bucket, prefix).catch((e) => {
      console.warn('[portal-hls] sidecar delete failed:', e?.message || e);
    });
    ensureSchema()
      .then((pool) => (pool ? pool.query('DELETE FROM portal_video_hls_jobs WHERE object_key = $1', [key]) : null))
      .catch(() => {});
  });
}

module.exports = {
  isPortalVideoObjectKey,
  isPortalHlsSidecarRelPath,
  isPortalHlsSidecarObjectKey,
  hlsPrefixForObjectKey,
  isHlsPlaylistName,
  rewriteHlsPlaylist,
  schedulePortalVideoHls,
  getPortalVideoHlsStatus,
  loadRewrittenHlsPlaylist,
  scheduleDeletePortalVideoHls
};
