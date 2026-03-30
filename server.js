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

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_planner_records_record_date
      ON planner_records (record_date);
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_planner_records_client
      ON planner_records (client);
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_planner_records_city
      ON planner_records (city);
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_planner_records_jobsite
      ON planner_records (jobsite);
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_planner_records_status
      ON planner_records (status);
    `);

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

app.post("/login", async (req, res) => {
  const username = cleanString(req.body?.username);
  const password = cleanString(req.body?.password);

  try {
    if (!username || !password) {
      return res.json({
        success: false,
        error: "Username and password are required",
      });
    }

    const result = await pool.query(
      `SELECT id, username, password, is_admin, roles
       FROM users
       WHERE username = $1 AND password = $2
       LIMIT 1`,
      [username, password]
    );

    if (!result.rows.length) {
      return res.json({
        success: false,
        error: "Invalid username or password",
      });
    }

    return res.json({
      success: true,
      user: normalizeUser(result.rows[0]),
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.post("/create-user", async (req, res) => {
  const username = cleanString(req.body?.username);
  const password = cleanString(req.body?.password);
  const isAdmin = !!req.body?.isAdmin;
  const roles = isObject(req.body?.roles)
    ? req.body.roles
    : { camera: true, vac: true };

  try {
    if (!username || !password) {
      return res.json({
        success: false,
        error: "Username and password are required",
      });
    }

    const inserted = await pool.query(
      `INSERT INTO users (username, password, is_admin, roles)
       VALUES ($1, $2, $3, $4::jsonb)
       RETURNING id, username, is_admin, roles`,
      [username, password, isAdmin, JSON.stringify(roles)]
    );

    return res.json({
      success: true,
      message: "User created successfully",
      user: normalizeUser(inserted.rows[0]),
    });
  } catch (err) {
    console.error("CREATE USER ERROR:", err);

    if (err.code === "23505") {
      return res.json({
        success: false,
        error: "That username already exists",
      });
    }

    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.get("/users", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, is_admin, roles, created_at, updated_at
       FROM users
       ORDER BY username ASC`
    );

    return res.json({
      success: true,
      users: result.rows.map(normalizeUser),
    });
  } catch (err) {
    console.error("GET USERS ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.post("/save-job", async (req, res) => {
  const name = cleanString(req.body?.name);
  const data = isObject(req.body?.data) ? req.body.data : {};

  try {
    if (!name) {
      return res.json({
        success: false,
        error: "Job name is required",
      });
    }

    await pool.query(
      "INSERT INTO jobs (name, data) VALUES ($1, $2::jsonb)",
      [name, JSON.stringify(data)]
    );

    return res.json({
      success: true,
      message: "Job saved successfully",
    });
  } catch (err) {
    console.error("SAVE JOB ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.get("/jobs", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM jobs ORDER BY id DESC"
    );

    return res.json(result.rows);
  } catch (err) {
    console.error("LOAD JOBS ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.get("/records", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         id,
         client,
         city,
         record_date,
         jobsite,
         psr,
         system,
         dia,
         material,
         footage,
         notes,
         status,
         data,
         created_by,
         updated_by,
         created_at,
         updated_at
       FROM planner_records
       ORDER BY id DESC`
    );

    return res.json({
      success: true,
      records: result.rows,
    });
  } catch (err) {
    console.error("GET RECORDS ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.get("/records/:id", async (req, res) => {
  const id = Number(req.params.id);

  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid record id",
      });
    }

    const result = await pool.query(
      `SELECT
         id,
         client,
         city,
         record_date,
         jobsite,
         psr,
         system,
         dia,
         material,
         footage,
         notes,
         status,
         data,
         created_by,
         updated_by,
         created_at,
         updated_at
       FROM planner_records
       WHERE id = $1
       LIMIT 1`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        error: "Record not found",
      });
    }

    return res.json({
      success: true,
      record: result.rows[0],
    });
  } catch (err) {
    console.error("GET RECORD ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.post("/records", async (req, res) => {
  const normalized = normalizeRecordInput(req.body || {});
  const username = cleanString(req.body?.username || req.body?.savedBy || req.body?.createdBy);

  try {
    const inserted = await pool.query(
      `INSERT INTO planner_records (
         client,
         city,
         record_date,
         jobsite,
         psr,
         system,
         dia,
         material,
         footage,
         notes,
         status,
         data,
         created_by,
         updated_by
       )
       VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $13
       )
       RETURNING
         id,
         client,
         city,
         record_date,
         jobsite,
         psr,
         system,
         dia,
         material,
         footage,
         notes,
         status,
         data,
         created_by,
         updated_by,
         created_at,
         updated_at`,
      [
        normalized.client,
        normalized.city,
        normalized.date,
        normalized.jobsite,
        normalized.psr,
        normalized.system,
        normalized.dia,
        normalized.material,
        normalized.footage,
        normalized.notes,
        normalized.status,
        JSON.stringify(normalized.data),
        username,
      ]
    );

    return res.json({
      success: true,
      record: inserted.rows[0],
    });
  } catch (err) {
    console.error("CREATE RECORD ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.put("/records/:id", async (req, res) => {
  const id = Number(req.params.id);
  const normalized = normalizeRecordInput(req.body || {});
  const username = cleanString(req.body?.username || req.body?.savedBy || req.body?.updatedBy);

  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid record id",
      });
    }

    const updated = await pool.query(
      `UPDATE planner_records
       SET
         client = $1,
         city = $2,
         record_date = $3,
         jobsite = $4,
         psr = $5,
         system = $6,
         dia = $7,
         material = $8,
         footage = $9,
         notes = $10,
         status = $11,
         data = $12::jsonb,
         updated_by = $13,
         updated_at = CURRENT_TIMESTAMP
       WHERE id = $14
       RETURNING
         id,
         client,
         city,
         record_date,
         jobsite,
         psr,
         system,
         dia,
         material,
         footage,
         notes,
         status,
         data,
         created_by,
         updated_by,
         created_at,
         updated_at`,
      [
        normalized.client,
        normalized.city,
        normalized.date,
        normalized.jobsite,
        normalized.psr,
        normalized.system,
        normalized.dia,
        normalized.material,
        normalized.footage,
        normalized.notes,
        normalized.status,
        JSON.stringify(normalized.data),
        username,
        id,
      ]
    );

    if (!updated.rows.length) {
      return res.status(404).json({
        success: false,
        error: "Record not found",
      });
    }

    return res.json({
      success: true,
      record: updated.rows[0],
    });
  } catch (err) {
    console.error("UPDATE RECORD ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.delete("/records/:id", async (req, res) => {
  const id = Number(req.params.id);

  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid record id",
      });
    }

    const deleted = await pool.query(
      `DELETE FROM planner_records
       WHERE id = $1
       RETURNING id`,
      [id]
    );

    if (!deleted.rows.length) {
      return res.status(404).json({
        success: false,
        error: "Record not found",
      });
    }

    return res.json({
      success: true,
      deletedId: deleted.rows[0].id,
    });
  } catch (err) {
    console.error("DELETE RECORD ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/* =========================
   PRICING ROUTES
   ========================= */

app.get("/pricing-rates", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, dia, rate, updated_at
       FROM pricing_rates
       ORDER BY
         CASE
           WHEN regexp_replace(dia, '[^0-9]', '', 'g') = '' THEN 999999
           ELSE CAST(regexp_replace(dia, '[^0-9]', '', 'g') AS INTEGER)
         END ASC,
         dia ASC`
    );

    return res.json({
      success: true,
      rates: result.rows,
    });
  } catch (err) {
    console.error("GET PRICING RATES ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.get("/pricing-rates/:dia", async (req, res) => {
  const dia = cleanString(req.params.dia);

  try {
    if (!dia) {
      return res.status(400).json({
        success: false,
        error: "DIA is required",
      });
    }

    const result = await pool.query(
      `SELECT id, dia, rate, updated_at
       FROM pricing_rates
       WHERE dia = $1
       LIMIT 1`,
      [dia]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        error: "Pricing rate not found",
      });
    }

    return res.json({
      success: true,
      rate: result.rows[0],
    });
  } catch (err) {
    console.error("GET PRICING RATE ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.post("/pricing-rates", async (req, res) => {
  const { dia, rate } = normalizePricingInput(req.body || {});

  try {
    if (!dia || Number.isNaN(rate)) {
      return res.status(400).json({
        success: false,
        error: "Valid dia and rate are required",
      });
    }

    const result = await pool.query(
      `INSERT INTO pricing_rates (dia, rate, updated_at)
       VALUES ($1, $2, CURRENT_TIMESTAMP)
       ON CONFLICT (dia)
       DO UPDATE SET
         rate = EXCLUDED.rate,
         updated_at = CURRENT_TIMESTAMP
       RETURNING id, dia, rate, updated_at`,
      [dia, rate]
    );

    return res.json({
      success: true,
      rate: result.rows[0],
    });
  } catch (err) {
    console.error("CREATE PRICING RATE ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.put("/pricing-rates/:dia", async (req, res) => {
  const dia = cleanString(req.params.dia);
  const rate = Number(req.body?.rate);

  try {
    if (!dia || Number.isNaN(rate)) {
      return res.status(400).json({
        success: false,
        error: "Valid dia and rate are required",
      });
    }

    const result = await pool.query(
      `INSERT INTO pricing_rates (dia, rate, updated_at)
       VALUES ($1, $2, CURRENT_TIMESTAMP)
       ON CONFLICT (dia)
       DO UPDATE SET
         rate = EXCLUDED.rate,
         updated_at = CURRENT_TIMESTAMP
       RETURNING id, dia, rate, updated_at`,
      [dia, rate]
    );

    return res.json({
      success: true,
      rate: result.rows[0],
    });
  } catch (err) {
    console.error("UPDATE PRICING RATE ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.post("/pricing-rates/bulk", async (req, res) => {
  const rates = Array.isArray(req.body?.rates) ? req.body.rates : null;

  if (!rates) {
    return res.status(400).json({
      success: false,
      error: "rates must be an array",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const saved = [];

    for (const item of rates) {
      const dia = cleanString(item?.dia);
      const rate = Number(item?.rate);

      if (!dia || Number.isNaN(rate)) continue;

      const result = await client.query(
        `INSERT INTO pricing_rates (dia, rate, updated_at)
         VALUES ($1, $2, CURRENT_TIMESTAMP)
         ON CONFLICT (dia)
         DO UPDATE SET
           rate = EXCLUDED.rate,
           updated_at = CURRENT_TIMESTAMP
         RETURNING id, dia, rate, updated_at`,
        [dia, rate]
      );

      if (result.rows[0]) {
        saved.push(result.rows[0]);
      }
    }

    await client.query("COMMIT");

    return res.json({
      success: true,
      rates: saved,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("BULK PRICING RATE ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

app.delete("/pricing-rates/:dia", async (req, res) => {
  const dia = cleanString(req.params.dia);

  try {
    if (!dia) {
      return res.status(400).json({
        success: false,
        error: "DIA is required",
      });
    }

    const result = await pool.query(
      `DELETE FROM pricing_rates
       WHERE dia = $1
       RETURNING id, dia`,
      [dia]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        error: "Pricing rate not found",
      });
    }

    return res.json({
      success: true,
      deleted: result.rows[0],
    });
  } catch (err) {
    console.error("DELETE PRICING RATE ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
