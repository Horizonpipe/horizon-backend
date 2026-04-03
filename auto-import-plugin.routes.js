const express = require('express');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const initSqlJs = require('sql.js');

function createAutoImportPlugin(options = {}) {
  const {
    pool,
    requireMike,
    requireAuth,
    writeSegment,
    buildVersion,
    uid = () => crypto.randomUUID(),
    nowIso = () => new Date().toISOString(),
    uploadDir = path.join(process.cwd(), 'uploads', 'auto-import-plugin'),
    logger = console
  } = options;

  if (!pool) throw new Error('createAutoImportPlugin requires a pg pool.');
  if (typeof requireMike !== 'function') throw new Error('createAutoImportPlugin requires requireMike middleware.');
  if (typeof requireAuth !== 'function') throw new Error('createAutoImportPlugin requires requireAuth middleware.');
  if (typeof writeSegment !== 'function') throw new Error('createAutoImportPlugin requires writeSegment(jobsiteId, payload, savedBy).');
  if (typeof buildVersion !== 'function') throw new Error('createAutoImportPlugin requires buildVersion(payload).');

  fs.mkdirSync(uploadDir, { recursive: true });

  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const safe = String(file.originalname || 'file').replace(/[^a-zA-Z0-9._-]/g, '_');
      cb(null, `${Date.now()}_${crypto.randomUUID()}_${safe}`);
    }
  });
  const upload = multer({ storage, limits: { fileSize: 60 * 1024 * 1024 } });

  const router = express.Router();

  async function initSchema() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS auto_import_projects (
        id TEXT PRIMARY KEY,
        source_key TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        db3_path TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'idle',
        detection_mode TEXT NOT NULL DEFAULT 'auto',
        detected_job_client TEXT DEFAULT '',
        detected_job_city TEXT DEFAULT '',
        detected_jobsite TEXT DEFAULT '',
        last_seen_at TIMESTAMPTZ,
        last_scan_at TIMESTAMPTZ,
        last_switch_at TIMESTAMPTZ,
        last_error TEXT DEFAULT '',
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS auto_import_runs (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        active_db3_path TEXT NOT NULL,
        switch_reason TEXT DEFAULT '',
        rows_found INTEGER NOT NULL DEFAULT 0,
        rows_changed INTEGER NOT NULL DEFAULT 0,
        rows_inserted INTEGER NOT NULL DEFAULT 0,
        rows_updated INTEGER NOT NULL DEFAULT 0,
        notes TEXT DEFAULT '',
        payload JSONB NOT NULL DEFAULT '{}'::jsonb
      );

      CREATE TABLE IF NOT EXISTS auto_import_row_cache (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
        row_key TEXT NOT NULL,
        row_hash TEXT NOT NULL,
        system_type TEXT NOT NULL DEFAULT 'storm',
        reference TEXT NOT NULL,
        upstream TEXT DEFAULT '',
        downstream TEXT DEFAULT '',
        dia TEXT DEFAULT '',
        material TEXT DEFAULT '',
        length NUMERIC(12,3) DEFAULT 0,
        footage NUMERIC(12,3) DEFAULT 0,
        source_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(project_id, row_key)
      );

      CREATE TABLE IF NOT EXISTS auto_import_bindings (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
        client TEXT NOT NULL,
        city TEXT NOT NULL,
        jobsite TEXT NOT NULL,
        system_type TEXT NOT NULL DEFAULT 'storm',
        pinned BOOLEAN NOT NULL DEFAULT FALSE,
        created_by TEXT DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(project_id)
      );

      CREATE INDEX IF NOT EXISTS idx_auto_import_projects_seen ON auto_import_projects(last_seen_at DESC);
      CREATE INDEX IF NOT EXISTS idx_auto_import_runs_project_started ON auto_import_runs(project_id, started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_auto_import_row_cache_project_seen ON auto_import_row_cache(project_id, last_seen_at DESC);
    `);
  }

  function clean(value) {
    return String(value || '').trim();
  }

  function normalizeMode(value) {
    const mode = clean(value).toLowerCase();
    if (mode === 'pinned') return 'pinned';
    if (mode === 'suggest') return 'suggest';
    return 'auto';
  }

  function diaFromShape(shape, size1, size2) {
    const s1 = clean(size1);
    const s2 = clean(size2);
    const shapeText = clean(shape).toLowerCase();
    if (s1 && s2 && s1 !== s2) return `${s1}x${s2}`;
    if (s1) return s1;
    if (shapeText.includes('ellipse') && s1 && s2) return `${s1}x${s2}`;
    return s1 || s2 || clean(shape);
  }

  function sha(value) {
    return crypto.createHash('sha1').update(value).digest('hex');
  }

  function rowKeyFor(row) {
    return `${clean(row.system || 'storm')}|${clean(row.reference).toLowerCase()}`;
  }

  function rowHashFor(row) {
    return sha(JSON.stringify({
      reference: clean(row.reference),
      upstream: clean(row.upstream),
      downstream: clean(row.downstream),
      dia: clean(row.dia),
      material: clean(row.material),
      length: Number(row.length || 0),
      footage: Number(row.footage || row.length || 0)
    }));
  }

  async function parseDb3(filePath) {
    const SQL = await initSqlJs({ locateFile: (file) => require.resolve(`sql.js/dist/${file}`) });
    const buffer = await fsp.readFile(filePath);
    const db = new SQL.Database(buffer);
    const tablesResult = db.exec("SELECT name FROM sqlite_master WHERE type='table'");
    const tables = new Set((tablesResult[0]?.values || []).map((row) => row[0]));
    if (!tables.has('SECTION')) throw new Error('SECTION table not found in DB3 file.');

    const result = db.exec(`
      SELECT
        COALESCE(s.OBJ_Key, '') AS reference,
        COALESCE(s.OBJ_FromNode_REF, '') AS upstream,
        COALESCE(s.OBJ_ToNode_REF, '') AS downstream,
        COALESCE(s.OBJ_Material, '') AS material,
        COALESCE(s.OBJ_Shape, '') AS shape,
        COALESCE(s.OBJ_Size1, '') AS size1,
        COALESCE(s.OBJ_Size2, '') AS size2,
        COALESCE(si.INS_InspectedLength, s.OBJ_Length, 0) AS length,
        COALESCE(s.OBJ_City, '') AS city,
        COALESCE(s.OBJ_Street, '') AS street,
        COALESCE(s.OBJ_Project, '') AS project_name
      FROM SECTION s
      LEFT JOIN SECINSP si ON si.OBJ_ID = s.OBJ_ID
    `);

    if (!result[0]) return [];
    const columns = result[0].columns;
    return result[0].values.map((values) => {
      const raw = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
      const dia = diaFromShape(raw.shape, raw.size1, raw.size2);
      const length = Number(raw.length || 0);
      return {
        system: 'storm',
        reference: clean(raw.reference),
        upstream: clean(raw.upstream),
        downstream: clean(raw.downstream),
        material: clean(raw.material),
        dia,
        length,
        footage: length,
        city: clean(raw.city),
        street: clean(raw.street),
        projectName: clean(raw.project_name)
      };
    }).filter((row) => row.reference);
  }

  async function ensureProject({ db3Path, displayName = '' }) {
    const sourceKey = sha(path.resolve(db3Path));
    const existing = await pool.query('SELECT * FROM auto_import_projects WHERE source_key = $1 LIMIT 1', [sourceKey]);
    if (existing.rows[0]) {
      const updated = await pool.query(`
        UPDATE auto_import_projects
        SET display_name = $2,
            db3_path = $3,
            last_seen_at = NOW(),
            updated_at = NOW()
        WHERE source_key = $1
        RETURNING *
      `, [sourceKey, displayName || path.basename(db3Path), path.resolve(db3Path)]);
      return updated.rows[0];
    }

    const inserted = await pool.query(`
      INSERT INTO auto_import_projects (
        id, source_key, display_name, db3_path, status, last_seen_at, metadata
      ) VALUES ($1,$2,$3,$4,'idle',NOW(),'{}'::jsonb)
      RETURNING *
    `, [uid(), sourceKey, displayName || path.basename(db3Path), path.resolve(db3Path)]);
    return inserted.rows[0];
  }

  async function upsertBinding(projectId, body, username) {
    const client = clean(body.client);
    const city = clean(body.city);
    const jobsite = clean(body.jobsite);
    const systemType = clean(body.systemType || 'storm') || 'storm';
    const pinned = !!body.pinned;
    if (!client || !city || !jobsite) throw new Error('Client, city, and jobsite are required.');

    const existing = await pool.query('SELECT id FROM auto_import_bindings WHERE project_id = $1 LIMIT 1', [projectId]);
    if (existing.rows[0]) {
      const updated = await pool.query(`
        UPDATE auto_import_bindings
        SET client = $2,
            city = $3,
            jobsite = $4,
            system_type = $5,
            pinned = $6,
            created_by = COALESCE(NULLIF(created_by,''), $7),
            updated_at = NOW()
        WHERE project_id = $1
        RETURNING *
      `, [projectId, client, city, jobsite, systemType, pinned, username || 'System']);
      return updated.rows[0];
    }

    const inserted = await pool.query(`
      INSERT INTO auto_import_bindings (id, project_id, client, city, jobsite, system_type, pinned, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *
    `, [uid(), projectId, client, city, jobsite, systemType, pinned, username || 'System']);
    return inserted.rows[0];
  }

  async function syncProjectRows(project, rows, username) {
    const bindingResult = await pool.query('SELECT * FROM auto_import_bindings WHERE project_id = $1 LIMIT 1', [project.id]);
    const binding = bindingResult.rows[0];
    if (!binding) throw new Error('Bind this DB3 project to a client/city/jobsite before syncing.');

    const targetJobsiteResult = await pool.query(
      'SELECT id FROM jobsites WHERE LOWER(client)=LOWER($1) AND LOWER(city)=LOWER($2) AND LOWER(jobsite)=LOWER($3) LIMIT 1',
      [binding.client, binding.city, binding.jobsite]
    );
    if (!targetJobsiteResult.rows[0]) {
      throw new Error('Selected target jobsite was not found in jobsites table.');
    }
    const targetJobsiteId = targetJobsiteResult.rows[0].id;

    let changed = 0;
    let inserted = 0;
    let updated = 0;

    for (const row of rows) {
      const rowKey = rowKeyFor(row);
      const rowHash = rowHashFor(row);
      const cacheResult = await pool.query(
        'SELECT id, row_hash FROM auto_import_row_cache WHERE project_id = $1 AND row_key = $2 LIMIT 1',
        [project.id, rowKey]
      );
      const cache = cacheResult.rows[0] || null;

      if (cache && cache.row_hash === rowHash) {
        await pool.query(
          'UPDATE auto_import_row_cache SET last_seen_at = NOW() WHERE id = $1',
          [cache.id]
        );
        continue;
      }

      const payload = {
        id: uid(),
        system: binding.system_type || 'storm',
        reference: row.reference,
        upstream: row.upstream || '',
        downstream: row.downstream || '',
        dia: row.dia || '',
        material: row.material || '',
        length: Number(row.length || row.footage || 0),
        footage: Number(row.footage || row.length || 0),
        versions: [buildVersion({
          status: 'neutral',
          notes: `Auto imported from ${project.display_name}`,
          recordedDate: nowIso().slice(0, 10),
          savedBy: username || 'System'
        })]
      };
      await writeSegment(targetJobsiteId, payload, username || 'System');
      changed += 1;

      if (cache) updated += 1;
      else inserted += 1;

      if (cache) {
        await pool.query(`
          UPDATE auto_import_row_cache
          SET row_hash = $3,
              system_type = $4,
              reference = $5,
              upstream = $6,
              downstream = $7,
              dia = $8,
              material = $9,
              length = $10,
              footage = $11,
              source_payload = $12::jsonb,
              last_seen_at = NOW()
          WHERE project_id = $1 AND row_key = $2
        `, [
          project.id,
          rowKey,
          rowHash,
          binding.system_type || 'storm',
          row.reference,
          row.upstream || '',
          row.downstream || '',
          row.dia || '',
          row.material || '',
          Number(row.length || 0),
          Number(row.footage || row.length || 0),
          JSON.stringify(row)
        ]);
      } else {
        await pool.query(`
          INSERT INTO auto_import_row_cache (
            id, project_id, row_key, row_hash, system_type, reference, upstream, downstream, dia, material, length, footage, source_payload
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)
        `, [
          uid(),
          project.id,
          rowKey,
          rowHash,
          binding.system_type || 'storm',
          row.reference,
          row.upstream || '',
          row.downstream || '',
          row.dia || '',
          row.material || '',
          Number(row.length || 0),
          Number(row.footage || row.length || 0),
          JSON.stringify(row)
        ]);
      }
    }

    return { changed, inserted, updated };
  }

  router.get('/projects', requireMike, async (req, res, next) => {
    try {
      const [projects, bindings] = await Promise.all([
        pool.query('SELECT * FROM auto_import_projects ORDER BY COALESCE(last_seen_at, created_at) DESC, display_name ASC'),
        pool.query('SELECT * FROM auto_import_bindings ORDER BY updated_at DESC')
      ]);
      const bindingMap = new Map(bindings.rows.map((row) => [row.project_id, row]));
      res.json({
        success: true,
        projects: projects.rows.map((project) => ({
          ...project,
          binding: bindingMap.get(project.id) || null
        }))
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/discover', requireMike, express.json(), async (req, res, next) => {
    try {
      const db3Path = clean(req.body.db3Path);
      if (!db3Path) return res.status(400).json({ error: 'db3Path is required.' });
      const rows = await parseDb3(db3Path);
      const project = await ensureProject({ db3Path, displayName: clean(req.body.displayName) });
      const sample = rows[0] || {};
      await pool.query(`
        UPDATE auto_import_projects
        SET detected_job_city = $2,
            detected_jobsite = $3,
            metadata = $4::jsonb,
            last_scan_at = NOW(),
            status = 'discovered',
            updated_at = NOW()
        WHERE id = $1
      `, [
        project.id,
        clean(sample.city),
        clean(sample.projectName || sample.street || project.display_name),
        JSON.stringify({ sampleRowCount: rows.length, source: 'manual-discover' })
      ]);
      res.json({ success: true, project: { ...project, rowCount: rows.length }, rows: rows.slice(0, 50) });
    } catch (error) {
      next(error);
    }
  });

  router.post('/bind/:projectId', requireMike, express.json(), async (req, res, next) => {
    try {
      const binding = await upsertBinding(req.params.projectId, req.body, req.session?.user?.username || 'System');
      res.json({ success: true, binding });
    } catch (error) {
      next(error);
    }
  });

  router.post('/mode/:projectId', requireMike, express.json(), async (req, res, next) => {
    try {
      const mode = normalizeMode(req.body.mode);
      const result = await pool.query(`
        UPDATE auto_import_projects
        SET detection_mode = $2,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
      `, [req.params.projectId, mode]);
      if (!result.rows[0]) return res.status(404).json({ error: 'Project not found.' });
      res.json({ success: true, project: result.rows[0] });
    } catch (error) {
      next(error);
    }
  });

  router.post('/preview', requireMike, upload.single('file'), async (req, res, next) => {
    try {
      const explicitPath = clean(req.body.db3Path);
      const filePath = req.file?.path || explicitPath;
      if (!filePath) return res.status(400).json({ error: 'DB3 file or db3Path is required.' });
      const rows = await parseDb3(filePath);
      const project = await ensureProject({ db3Path: filePath, displayName: clean(req.body.displayName) || path.basename(filePath) });
      res.json({ success: true, project, rows: rows.slice(0, 500), totalRows: rows.length });
    } catch (error) {
      next(error);
    }
  });

  router.post('/sync/:projectId', requireMike, express.json({ limit: '10mb' }), async (req, res, next) => {
    try {
      const projectResult = await pool.query('SELECT * FROM auto_import_projects WHERE id = $1 LIMIT 1', [req.params.projectId]);
      const project = projectResult.rows[0];
      if (!project) return res.status(404).json({ error: 'Project not found.' });
      const rows = Array.isArray(req.body.rows) && req.body.rows.length
        ? req.body.rows
        : await parseDb3(project.db3_path);
      const sync = await syncProjectRows(project, rows, req.session?.user?.username || 'System');
      const runId = uid();
      await pool.query(`
        INSERT INTO auto_import_runs (
          id, project_id, completed_at, active_db3_path, switch_reason, rows_found, rows_changed, rows_inserted, rows_updated, payload
        ) VALUES ($1,$2,NOW(),$3,$4,$5,$6,$7,$8,$9::jsonb)
      `, [
        runId,
        project.id,
        project.db3_path,
        clean(req.body.switchReason || 'manual sync'),
        rows.length,
        sync.changed,
        sync.inserted,
        sync.updated,
        JSON.stringify({ mode: project.detection_mode })
      ]);
      await pool.query(`
        UPDATE auto_import_projects
        SET status = 'synced',
            last_scan_at = NOW(),
            last_error = '',
            updated_at = NOW()
        WHERE id = $1
      `, [project.id]);
      res.json({ success: true, sync, totalRows: rows.length });
    } catch (error) {
      logger.error('AUTO IMPORT SYNC ERROR:', error);
      try {
        await pool.query(`
          UPDATE auto_import_projects
          SET status = 'error',
              last_error = $2,
              updated_at = NOW()
          WHERE id = $1
        `, [req.params.projectId, String(error.message || error)]);
      } catch {}
      next(error);
    }
  });

  router.get('/jobsite-options', requireAuth, async (req, res, next) => {
    try {
      const result = await pool.query(`
        SELECT id, client, city, jobsite
        FROM jobsites
        ORDER BY LOWER(client), LOWER(city), LOWER(jobsite)
      `);
      res.json({ success: true, jobsites: result.rows });
    } catch (error) {
      next(error);
    }
  });

  router.get('/runs/:projectId', requireMike, async (req, res, next) => {
    try {
      const result = await pool.query(
        'SELECT * FROM auto_import_runs WHERE project_id = $1 ORDER BY started_at DESC LIMIT 100',
        [req.params.projectId]
      );
      res.json({ success: true, runs: result.rows });
    } catch (error) {
      next(error);
    }
  });

  return { router, initSchema, parseDb3 };
}

module.exports = { createAutoImportPlugin };
