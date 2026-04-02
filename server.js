const express = require('express');
const cors = require('cors');
const session = require('express-session');
const PgSessionFactory = require('connect-pg-simple');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-now';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const PgSession = PgSessionFactory(session);

app.set('trust proxy', 1);

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      return callback(null, CORS_ORIGINS[0] || true);
    }
    if (!CORS_ORIGINS.length || CORS_ORIGINS.includes(origin)) {
      return callback(null, origin);
    }
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

app.use(session({
  store: new PgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  name: 'horizon.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: true,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 15 * 60 * 1000
  }
}));

function cleanString(value) {
  return String(value || '').trim();
}

function normalizeRoles(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return {
      camera: value.camera !== false,
      vac: value.vac !== false
    };
  }
  if (typeof value === 'string') {
    try {
      return normalizeRoles(JSON.parse(value));
    } catch (error) {
      return { camera: true, vac: true };
    }
  }
  return { camera: true, vac: true };
}

function normalizeUser(row) {
  return {
    id: row.id,
    username: row.username,
    name: row.display_name || row.username,
    displayName: row.display_name || row.username,
    isAdmin: !!row.is_admin,
    roles: normalizeRoles(row.roles),
    mustChangePassword: !!row.must_change_password
  };
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  req.user = req.session.user;
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  if (!req.session.user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  req.user = req.session.user;
  return next();
}

function parseJsonObject(value, fallback = {}) {
  if (!value) return fallback;
  if (typeof value === 'object') return value;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch (error) {
    return fallback;
  }
}

async function ensureSchema() {
  await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT NOT NULL UNIQUE,
      display_name TEXT,
      password TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT false,
      roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": false}'::jsonb,
      must_change_password BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS display_name TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": false}'::jsonb
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    UPDATE users
    SET display_name = username
    WHERE display_name IS NULL OR btrim(display_name) = ''
  `);

  await pool.query(`
    UPDATE users
    SET roles = '{"camera": true, "vac": false}'::jsonb
    WHERE roles IS NULL
  `);

  await pool.query(`
    UPDATE users
    SET must_change_password = false
    WHERE must_change_password IS NULL
  `);

  await pool.query(`
    UPDATE users
    SET updated_at = NOW()
    WHERE updated_at IS NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS planner_records (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      record_date DATE NOT NULL DEFAULT CURRENT_DATE,
      client TEXT NOT NULL DEFAULT '',
      city TEXT NOT NULL DEFAULT '',
      street TEXT NOT NULL DEFAULT '',
      jobsite TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT '',
      saved_by TEXT NOT NULL DEFAULT '',
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS record_date DATE NOT NULL DEFAULT CURRENT_DATE
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS client TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS street TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS jobsite TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS saved_by TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE planner_records
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    UPDATE planner_records
    SET client = ''
    WHERE client IS NULL
  `);

  await pool.query(`
    UPDATE planner_records
    SET city = ''
    WHERE city IS NULL
  `);

  await pool.query(`
    UPDATE planner_records
    SET street = ''
    WHERE street IS NULL
  `);

  await pool.query(`
    UPDATE planner_records
    SET jobsite = ''
    WHERE jobsite IS NULL
  `);

  await pool.query(`
    UPDATE planner_records
    SET status = ''
    WHERE status IS NULL
  `);

  await pool.query(`
    UPDATE planner_records
    SET saved_by = ''
    WHERE saved_by IS NULL
  `);

  await pool.query(`
    UPDATE planner_records
    SET data = '{}'::jsonb
    WHERE data IS NULL
  `);

  await pool.query(`
    UPDATE planner_records
    SET updated_at = NOW()
    WHERE updated_at IS NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pricing_rates (
      dia TEXT PRIMARY KEY,
      rate NUMERIC(12,2) NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_reports (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      report_date DATE NOT NULL DEFAULT CURRENT_DATE,
      notes TEXT NOT NULL DEFAULT '',
      images JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_by TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS jobsite_assets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      client TEXT NOT NULL DEFAULT '',
      city TEXT NOT NULL DEFAULT '',
      jobsite TEXT NOT NULL DEFAULT '',
      contact_name TEXT NOT NULL DEFAULT '',
      contact_phone TEXT NOT NULL DEFAULT '',
      contact_email TEXT NOT NULL DEFAULT '',
      notes TEXT NOT NULL DEFAULT '',
      drive_url TEXT NOT NULL DEFAULT '',
      files JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_by TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
    await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS client TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS jobsite TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS contact_name TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS contact_phone TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS drive_url TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS files JSONB NOT NULL DEFAULT '[]'::jsonb
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE jobsite_assets
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET client = ''
    WHERE client IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET city = ''
    WHERE city IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET jobsite = ''
    WHERE jobsite IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET contact_name = ''
    WHERE contact_name IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET contact_phone = ''
    WHERE contact_phone IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET contact_email = ''
    WHERE contact_email IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET notes = ''
    WHERE notes IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET drive_url = ''
    WHERE drive_url IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET files = '[]'::jsonb
    WHERE files IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET created_by = ''
    WHERE created_by IS NULL
  `);

  await pool.query(`
    UPDATE jobsite_assets
    SET updated_at = NOW()
    WHERE updated_at IS NULL
  `);

  const countResult = await pool.query('SELECT COUNT(*)::int AS count FROM users');
  if (countResult.rows[0].count === 0) {
    const defaults = [
      { username: 'mik', displayName: 'Mike Strickland', isAdmin: true, roles: { camera: true, vac: true } },
      { username: 'nick', displayName: 'Nick Krull', isAdmin: true, roles: { camera: true, vac: true } },
      { username: 'tyler', displayName: 'Tyler Clark', isAdmin: true, roles: { camera: true, vac: true } }
    ];

    for (const user of defaults) {
      const hash = await bcrypt.hash('1234', 10);
      await pool.query(
        `INSERT INTO users (username, display_name, password, is_admin, roles, must_change_password)
         VALUES ($1, $2, $3, $4, $5::jsonb, true)`,
        [user.username, user.displayName, hash, user.isAdmin, JSON.stringify(user.roles)]
      );
    }
  }
}

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'horizon-backend', timestamp: new Date().toISOString() });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, is_admin, roles, must_change_password
       FROM users
       ORDER BY LOWER(display_name), LOWER(username)`
    );
    const users = result.rows.map((row) => {
      const normalized = normalizeUser(row);
      if (req.session?.user?.isAdmin) return normalized;
      return {
        id: normalized.id,
        username: normalized.username,
        name: normalized.name,
        displayName: normalized.displayName
      };
    });
    res.json({ success: true, users });
  } catch (error) {
    console.error('USERS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/login', async (req, res) => {
  const submittedUsername = cleanString(req.body?.username);
  const submittedPassword = cleanString(req.body?.password);

  if (!submittedUsername || !submittedPassword) {
    return res.status(400).json({ success: false, error: 'Username and password are required' });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, display_name, password, is_admin, roles, must_change_password
       FROM users
       WHERE LOWER(username) = LOWER($1) OR LOWER(display_name) = LOWER($1)
       LIMIT 1`,
      [submittedUsername]
    );

    if (!result.rows.length) {
      return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }

    const row = result.rows[0];
    let passwordOk = false;
    let needsRehash = false;

    if (row.password && row.password.startsWith('$2')) {
      passwordOk = await bcrypt.compare(submittedPassword, row.password);
    } else if (row.password === submittedPassword) {
      passwordOk = true;
      needsRehash = true;
    }

    if (!passwordOk) {
      return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }

    if (needsRehash) {
      const hash = await bcrypt.hash(submittedPassword, 10);
      await pool.query('UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2', [hash, row.id]);
      row.password = hash;
    }

    const user = normalizeUser(row);
    req.session.user = user;

    return req.session.save((saveError) => {
      if (saveError) {
        console.error('SESSION SAVE ERROR:', saveError);
        return res.status(500).json({ success: false, error: 'Could not create session' });
      }
      return res.json({ success: true, user });
    });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/session', requireAuth, (req, res) => {
  res.json({ success: true, user: req.session.user });
});

app.post('/logout', (req, res) => {
  if (!req.session) return res.json({ success: true });
  req.session.destroy(() => {
    res.clearCookie('horizon.sid', {
      httpOnly: true,
      secure: true,
      sameSite: 'none'
    });
    res.json({ success: true });
  });
});

app.post('/change-password', requireAuth, async (req, res) => {
  const currentPassword = cleanString(req.body?.currentPassword);
  const newPassword = cleanString(req.body?.newPassword);

  if (newPassword.length < 4) {
    return res.status(400).json({ success: false, error: 'New password must be at least 4 characters' });
  }

  try {
    const result = await pool.query(
      'SELECT id, password FROM users WHERE id = $1 LIMIT 1',
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const row = result.rows[0];
    let currentOk = false;
    if (row.password && row.password.startsWith('$2')) {
      currentOk = await bcrypt.compare(currentPassword, row.password);
    } else {
      currentOk = row.password === currentPassword;
    }

    if (!currentOk) {
      return res.status(401).json({ success: false, error: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password = $1, must_change_password = false, updated_at = NOW() WHERE id = $2',
      [hash, req.user.id]
    );

    req.session.user = { ...req.session.user, mustChangePassword: false };
    res.json({ success: true, user: req.session.user });
  } catch (error) {
    console.error('CHANGE PASSWORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/create-user', requireAdmin, async (req, res) => {
  const username = cleanString(req.body?.username);
  const displayName = cleanString(req.body?.displayName || req.body?.name || username);
  const password = cleanString(req.body?.password || '1234');
  const isAdmin = !!req.body?.isAdmin;
  const roles = normalizeRoles(req.body?.roles);

  if (!username) {
    return res.status(400).json({ success: false, error: 'Username is required' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, display_name, password, is_admin, roles, must_change_password)
       VALUES ($1, $2, $3, $4, $5::jsonb, true)
       RETURNING id, username, display_name, is_admin, roles, must_change_password`,
      [username, displayName, hash, isAdmin, JSON.stringify(roles)]
    );
    res.status(201).json({ success: true, user: normalizeUser(result.rows[0]) });
  } catch (error) {
    console.error('CREATE USER ERROR:', error);
    if (error.code === '23505') {
      return res.status(409).json({ success: false, error: 'Username already exists' });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/users/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const displayName = cleanString(req.body?.displayName || req.body?.name);
    const isAdmin = req.body?.isAdmin === undefined ? null : !!req.body.isAdmin;
    const roles = req.body?.roles === undefined ? null : normalizeRoles(req.body.roles);
    const password = cleanString(req.body?.password || '');

    const currentResult = await pool.query(
      'SELECT id, username, display_name, is_admin, roles, must_change_password FROM users WHERE id = $1 LIMIT 1',
      [id]
    );
    if (!currentResult.rows.length) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    const current = currentResult.rows[0];

    const nextDisplayName = displayName || current.display_name;
    const nextIsAdmin = isAdmin === null ? current.is_admin : isAdmin;
    const nextRoles = roles === null ? normalizeRoles(current.roles) : roles;

    await pool.query(
      `UPDATE users
       SET display_name = $1,
           is_admin = $2,
           roles = $3::jsonb,
           updated_at = NOW()
       WHERE id = $4`,
      [nextDisplayName, nextIsAdmin, JSON.stringify(nextRoles), id]
    );

    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE users SET password = $1, must_change_password = false, updated_at = NOW() WHERE id = $2',
        [hash, id]
      );
    }

    const updatedResult = await pool.query(
      'SELECT id, username, display_name, is_admin, roles, must_change_password FROM users WHERE id = $1 LIMIT 1',
      [id]
    );

    res.json({ success: true, user: normalizeUser(updatedResult.rows[0]) });
  } catch (error) {
    console.error('UPDATE USER ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/records', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at
       FROM planner_records
       ORDER BY updated_at DESC, created_at DESC`
    );

    const rows = result.rows.map((row) => ({
      id: row.id,
      record_date: row.record_date,
      client: row.client,
      city: row.city,
      street: row.street,
      jobsite: row.jobsite,
      status: row.status,
      saved_by: row.saved_by,
      data: row.data,
      created_at: row.created_at,
      updated_at: row.updated_at
    }));

    res.json({ success: true, records: rows });
  } catch (error) {
    console.error('GET RECORDS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/records', requireAuth, async (req, res) => {
  try {
    const recordDate = cleanString(req.body?.record_date || req.body?.date || new Date().toISOString().slice(0, 10));
    const client = cleanString(req.body?.client);
    const city = cleanString(req.body?.city);
    const street = cleanString(req.body?.street);
    const jobsite = cleanString(req.body?.jobsite);
    const status = cleanString(req.body?.status);
    const savedBy = cleanString(req.body?.saved_by || req.body?.savedBy || req.user.username);
    const data = parseJsonObject(req.body?.data, {});

    const result = await pool.query(
      `INSERT INTO planner_records (record_date, client, city, street, jobsite, status, saved_by, data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
       RETURNING id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at`,
      [recordDate, client, city, street, jobsite, status, savedBy, JSON.stringify(data)]
    );

    res.status(201).json({ success: true, record: result.rows[0] });
  } catch (error) {
    console.error('CREATE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/records/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const recordDate = cleanString(req.body?.record_date || req.body?.date || new Date().toISOString().slice(0, 10));
    const client = cleanString(req.body?.client);
    const city = cleanString(req.body?.city);
    const street = cleanString(req.body?.street);
    const jobsite = cleanString(req.body?.jobsite);
    const status = cleanString(req.body?.status);
    const savedBy = cleanString(req.body?.saved_by || req.body?.savedBy || req.user.username);
    const data = parseJsonObject(req.body?.data, {});

    const result = await pool.query(
      `UPDATE planner_records
       SET record_date = $1,
           client = $2,
           city = $3,
           street = $4,
           jobsite = $5,
           status = $6,
           saved_by = $7,
           data = $8::jsonb,
           updated_at = NOW()
       WHERE id = $9
       RETURNING id, record_date, client, city, street, jobsite, status, saved_by, data, created_at, updated_at`,
      [recordDate, client, city, street, jobsite, status, savedBy, JSON.stringify(data), id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'Record not found' });
    }

    res.json({ success: true, record: result.rows[0] });
  } catch (error) {
    console.error('UPDATE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/records/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM planner_records WHERE id = $1 RETURNING id',
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'Record not found' });
    }

    res.json({ success: true, deletedId: result.rows[0].id });
  } catch (error) {
    console.error('DELETE RECORD ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/pricing-rates', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT dia, rate, updated_at FROM pricing_rates ORDER BY dia');
    res.json({ success: true, rates: result.rows });
  } catch (error) {
    console.error('GET PRICING RATES ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/pricing-rates/:dia', requireAdmin, async (req, res) => {
  try {
    const dia = cleanString(req.params.dia || req.body?.dia);
    const rate = Number(req.body?.rate);
    if (!dia) return res.status(400).json({ success: false, error: 'DIA is required' });
    if (!Number.isFinite(rate)) return res.status(400).json({ success: false, error: 'Rate must be numeric' });

    const result = await pool.query(
      `INSERT INTO pricing_rates (dia, rate, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (dia)
       DO UPDATE SET rate = EXCLUDED.rate, updated_at = NOW()
       RETURNING dia, rate, updated_at`,
      [dia, Number(rate.toFixed(2))]
    );

    res.json({ success: true, rate: result.rows[0] });
  } catch (error) {
    console.error('UPSERT PRICING RATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/pricing-rates/:dia', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM pricing_rates WHERE dia = $1 RETURNING dia', [req.params.dia]);
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: 'DIA rate not found' });
    }
    res.json({ success: true, deletedDia: result.rows[0].dia });
  } catch (error) {
    console.error('DELETE PRICING RATE ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/daily-reports', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM daily_reports ORDER BY report_date DESC, updated_at DESC');
    res.json({ success: true, reports: result.rows });
  } catch (error) {
    console.error('GET DAILY REPORTS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/daily-reports', requireAdmin, async (req, res) => {
  try {
    const reportDate = cleanString(req.body?.reportDate || req.body?.report_date || new Date().toISOString().slice(0, 10));
    const notes = cleanString(req.body?.notes);
    const images = Array.isArray(req.body?.images) ? req.body.images : [];
    const result = await pool.query(
      `INSERT INTO daily_reports (report_date, notes, images, created_by)
       VALUES ($1, $2, $3::jsonb, $4)
       RETURNING *`,
      [reportDate, notes, JSON.stringify(images), req.user.name]
    );
    res.status(201).json({ success: true, report: result.rows[0] });
  } catch (error) {
    console.error('CREATE DAILY REPORT ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/jobsite-assets', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jobsite_assets ORDER BY client, city, jobsite, updated_at DESC');
    res.json({ success: true, assets: result.rows });
  } catch (error) {
    console.error('GET JOBSITE ASSETS ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/jobsite-assets', requireAdmin, async (req, res) => {
  try {
    const payload = {
      client: cleanString(req.body?.client),
      city: cleanString(req.body?.city),
      jobsite: cleanString(req.body?.jobsite),
      contactName: cleanString(req.body?.contactName),
      contactPhone: cleanString(req.body?.contactPhone),
      contactEmail: cleanString(req.body?.contactEmail),
      notes: cleanString(req.body?.notes),
      driveUrl: cleanString(req.body?.driveUrl),
      files: Array.isArray(req.body?.files) ? req.body.files : []
    };
    const result = await pool.query(
      `INSERT INTO jobsite_assets
       (client, city, jobsite, contact_name, contact_phone, contact_email, notes, drive_url, files, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
       RETURNING *`,
      [
        payload.client,
        payload.city,
        payload.jobsite,
        payload.contactName,
        payload.contactPhone,
        payload.contactEmail,
        payload.notes,
        payload.driveUrl,
        JSON.stringify(payload.files),
        req.user.name
      ]
    );
    res.status(201).json({ success: true, asset: result.rows[0] });
  } catch (error) {
    console.error('CREATE JOBSITE ASSET ERROR:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.use((error, req, res, next) => {
  if (error && /CORS blocked/.test(error.message || '')) {
    return res.status(403).json({ success: false, error: error.message });
  }
  console.error('UNHANDLED ERROR:', error);
  return res.status(500).json({ success: false, error: error.message || 'Server error' });
});

ensureSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Horizon backend listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('BOOT ERROR:', error);
    process.exit(1);
  });
