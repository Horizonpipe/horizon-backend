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

// =========================
// INIT DB
// =========================

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS planner_records (
        id SERIAL PRIMARY KEY,
        data JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ✅ PRICING TABLE
    await pool.query(`
      CREATE TABLE IF NOT EXISTS pricing_rates (
        id SERIAL PRIMARY KEY,
        dia TEXT UNIQUE NOT NULL,
        rate NUMERIC(10,2) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("DB READY");
  } catch (err) {
    console.error("DB ERROR:", err);
  }
}

initDB();

// =========================
// BASIC ROUTES
// =========================

app.get("/", (req, res) => {
  res.send("Backend Running");
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// =========================
// PRICING ROUTES
// =========================

// GET ALL
app.get("/pricing-rates", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT dia, rate FROM pricing_rates ORDER BY dia ASC`
    );
    res.json({ success: true, rates: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// GET ONE
app.get("/pricing-rates/:dia", async (req, res) => {
  const dia = cleanString(req.params.dia);

  try {
    const result = await pool.query(
      `SELECT dia, rate FROM pricing_rates WHERE dia = $1 LIMIT 1`,
      [dia]
    );

    if (!result.rows.length) {
      return res.json({ success: false });
    }

    res.json({ success: true, rate: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// SAVE ONE (MAIN ONE YOU USE)
app.put("/pricing-rates/:dia", async (req, res) => {
  const dia = cleanString(req.params.dia);
  const rate = Number(req.body.rate);

  try {
    if (!dia || isNaN(rate)) {
      return res.json({ success: false });
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
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// DELETE
app.delete("/pricing-rates/:dia", async (req, res) => {
  const dia = cleanString(req.params.dia);

  try {
    await pool.query(
      `DELETE FROM pricing_rates WHERE dia = $1`,
      [dia]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// BULK SAVE
app.post("/pricing-rates/bulk", async (req, res) => {
  try {
    const rates = req.body.rates;

    if (!Array.isArray(rates)) {
      return res.json({ success: false });
    }

    for (const r of rates) {
      if (!r.dia || isNaN(Number(r.rate))) continue;

      await pool.query(
        `INSERT INTO pricing_rates (dia, rate)
         VALUES ($1, $2)
         ON CONFLICT (dia)
         DO UPDATE SET rate = EXCLUDED.rate`,
        [r.dia, Number(r.rate)]
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// =========================
// RECORD ROUTES (UNCHANGED)
// =========================

app.get("/records", async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM planner_records ORDER BY id DESC`);
    res.json({ success: true, records: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

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

// =========================
// START SERVER
// =========================

app.listen(process.env.PORT, () => {
  console.log("Server running on port " + process.env.PORT);
});
