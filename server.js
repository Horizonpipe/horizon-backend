const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type"]
}));

app.use(express.json({ limit: "10mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

function cleanString(value) {
  if (value === null || value === undefined) return "";
  return String(value).trim();
}

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function normalizeUser(userRow) {
  if (!userRow) return null;
  return {
    id: userRow.id,
    username: userRow.username,
    isAdmin: !!userRow.is_admin,
    roles: isObject(userRow.roles) ? userRow.roles : { camera: true, vac: true },
  };
}

function normalizeRecordInput(body = {}) {
  const data = isObject(body.data) ? body.data : {};
  const client = cleanString(body.client || data.client);
  const city = cleanString(body.city || data.city);
  const date = cleanString(body.date || data.date);
  const jobsite = cleanString(body.jobsite || body.jobsiteLabel || data.jobsite || data.jobsiteLabel);
  const psr = cleanString(body.psr || data.psr);
  const system = cleanString(body.system || data.system);
  const dia = cleanString(body.dia || data.dia);
  const material = cleanString(body.material || data.material);
  const footage = cleanString(body.footage || body.length || data.footage || data.length);
  const notes = cleanString(body.notes || data.notes);
  const status = cleanString(body.status || data.status);

  const mergedData = {
    ...data,
    client,
    city,
    date,
    jobsite,
    psr,
    system,
    dia,
    material,
    footage,
    notes,
    status,
  };

  return {
    client,
    city,
    date,
    jobsite,
    psr,
    system,
    dia,
    material,
    footage,
    notes,
    status,
    data: mergedData,
  };
}

function normalizePricingInput(body = {}) {
  const dia = cleanString(body.dia);
  const rate = Number(body.rate);
  return { dia, rate };
}

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
    `);

    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": true}'::jsonb;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id SERIAL PRIMARY KEY,
        name TEXT,
        data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS planner_records (
        id SERIAL PRIMARY KEY,
        client TEXT DEFAULT '',
        city TEXT DEFAULT '',
        record_date TEXT DEFAULT '',
        jobsite TEXT DEFAULT '',
        psr TEXT DEFAULT '',
        system TEXT DEFAULT '',
        dia TEXT DEFAULT '',
        material TEXT DEFAULT '',
        footage TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        status TEXT DEFAULT '',
        data JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_by TEXT DEFAULT '',
        updated_by TEXT DEFAULT '',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ✅ NEW PRICING TABLE
    await pool.query(`
      CREATE TABLE IF NOT EXISTS pricing_rates (
        id SERIAL PRIMARY KEY,
        dia TEXT UNIQUE NOT NULL,
        rate NUMERIC(10,2) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Database initialized");
  } catch (err) {
    console.error("DATABASE INIT ERROR:", err);
  }
}

initDB();

app.get("/", (req, res) => {
  res.send("Horizon Backend Running");
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});


// =========================
// PRICING ROUTES (NEW)
// =========================

// GET ALL RATES
app.get("/pricing-rates", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT dia, rate FROM pricing_rates ORDER BY dia ASC`
    );

    res.json({ success: true, rates: result.rows });
  } catch (err) {
    console.error("GET PRICING ERROR:", err);
    res.status(500).json({ success: false });
  }
});

// SAVE / UPDATE SINGLE
app.put("/pricing-rates/:dia", async (req, res) => {
  const dia = cleanString(req.params.dia);
  const rate = Number(req.body.rate);

  try {
    if (!dia || isNaN(rate)) {
      return res.json({ success: false, error: "Invalid input" });
    }

    await pool.query(
      `INSERT INTO pricing_rates (dia, rate)
       VALUES ($1, $2)
       ON CONFLICT (dia)
       DO UPDATE SET rate = EXCLUDED.rate, updated_at = CURRENT_TIMESTAMP`,
      [dia, rate]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("SAVE PRICING ERROR:", err);
    res.status(500).json({ success: false });
  }
});


// =========================
// EXISTING ROUTES (UNCHANGED)
// =========================

// LOGIN
app.post("/login", async (req, res) => {
  const username = cleanString(req.body?.username);
  const password = cleanString(req.body?.password);

  try {
    const result = await pool.query(
      `SELECT id, username, password, is_admin, roles
       FROM users
       WHERE username = $1 AND password = $2
       LIMIT 1`,
      [username, password]
    );

    if (!result.rows.length) {
      return res.json({ success: false });
    }

    res.json({
      success: true,
      user: normalizeUser(result.rows[0]),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// CREATE USER
app.post("/create-user", async (req, res) => {
  const username = cleanString(req.body?.username);
  const password = cleanString(req.body?.password);

  try {
    await pool.query(
      `INSERT INTO users (username, password) VALUES ($1, $2)`,
      [username, password]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// GET RECORDS
app.get("/records", async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM planner_records ORDER BY id DESC`);
    res.json({ success: true, records: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// CREATE RECORD
app.post("/records", async (req, res) => {
  const normalized = normalizeRecordInput(req.body || {});

  try {
    const result = await pool.query(
      `INSERT INTO planner_records (data)
       VALUES ($1::jsonb)
       RETURNING *`,
      [JSON.stringify(normalized.data)]
    );

    res.json({ success: true, record: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// UPDATE RECORD
app.put("/records/:id", async (req, res) => {
  const id = Number(req.params.id);
  const normalized = normalizeRecordInput(req.body || {});

  try {
    const result = await pool.query(
      `UPDATE planner_records
       SET data = $1::jsonb, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING *`,
      [JSON.stringify(normalized.data), id]
    );

    res.json({ success: true, record: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

app.listen(process.env.PORT, () => {
  console.log("Server running on port " + process.env.PORT);
});
