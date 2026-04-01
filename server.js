
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const initSqlJs = require("sql.js");
const XLSX = require("xlsx");
const { createWorker } = require("tesseract.js");
const { Pool } = require("pg");
const path = require("path");

const app = express();
app.set("trust proxy", 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

const PgSession = connectPgSimple(session);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: Number(process.env.MAX_UPLOAD_MB || 20) * 1024 * 1024,
    files: Number(process.env.MAX_UPLOAD_FILES || 20),
  },
});

const ALLOWED_ORIGINS = String(process.env.CORS_ORIGINS || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (!ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));

app.use(session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET || "change-this-secret",
  name: "horizon.sid",
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    maxAge: 15 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  },
}));

function cleanString(value) {
  if (value === null || value === undefined) return "";
  return String(value).trim();
}

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

function normalizeRoles(roles) {
  if (!isObject(roles)) return { camera: true, vac: true };
  return {
    camera: roles.camera !== false,
    vac: roles.vac !== false,
  };
}

function normalizeUser(userRow) {
  if (!userRow) return null;
  return {
    id: userRow.id,
    username: userRow.username,
    isAdmin: !!userRow.is_admin,
    roles: normalizeRoles(userRow.roles),
    mustChangePassword: !!userRow.must_change_password,
  };
}

function sessionUser(req) {
  return normalizeUser(req.session?.user || null);
}

function isMikeUser(user) {
  return cleanString(user?.username).toLowerCase() === "mike strickland";
}

function requireAuth(req, res, next) {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
  req.currentUser = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
  if (!user.isAdmin) return res.status(403).json({ success: false, error: "Admin access required" });
  req.currentUser = user;
  next();
}

function requireMike(req, res, next) {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
  if (!isMikeUser(user)) return res.status(403).json({ success: false, error: "Mike-only importer access" });
  req.currentUser = user;
  next();
}

function isBcryptHash(value) {
  return /^\$2[aby]\$\d+\$/.test(String(value || ""));
}

async function verifyPasswordAndUpgrade(userRow, password) {
  const stored = cleanString(userRow?.password);
  if (!stored) return false;
  let ok = false;
  if (isBcryptHash(stored)) {
    ok = await bcrypt.compare(password, stored);
  } else {
    ok = stored === password;
    if (ok) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        `UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
        [hash, userRow.id]
      );
      userRow.password = hash;
    }
  }
  return ok;
}

function normalizeRecordInput(body = {}) {
  const data = isObject(body.data) ? body.data : {};
  const client = cleanString(body.client ?? data.client);
  const city = cleanString(body.city ?? data.city);
  const date = cleanString(body.date ?? body.record_date ?? data.date ?? data.record_date);
  const jobsite = cleanString(body.jobsite ?? body.jobsiteLabel ?? data.jobsite ?? data.jobsiteLabel);
  const psr = cleanString(body.psr ?? data.psr);
  const system = cleanString(body.system ?? data.system);
  const dia = cleanString(body.dia ?? data.dia);
  const material = cleanString(body.material ?? data.material);
  const footage = cleanString(body.footage ?? body.length ?? data.footage ?? data.length);
  const notes = cleanString(body.notes ?? data.notes);
  const status = cleanString(body.status ?? data.status);

  const mergedData = {
    ...data,
    client,
    city,
    date,
    record_date: date,
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
  return {
    dia: cleanString(body.dia),
    rate: Number(body.rate),
  };
}

function normalizeFileMeta(row) {
  return {
    id: row.id,
    label: cleanString(row.label),
    fileName: cleanString(row.file_name),
    contentType: cleanString(row.content_type),
    byteSize: Number(row.byte_size || 0),
    externalUrl: cleanString(row.external_url),
    createdAt: row.created_at,
    downloadUrl: cleanString(row.external_url) || `/files/${row.id}/download`,
  };
}

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
        roles JSONB NOT NULL DEFAULT '{"camera": true, "vac": true}'::jsonb,
        must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
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

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_planner_records_record_date ON planner_records (record_date);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_planner_records_client ON planner_records (client);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_planner_records_city ON planner_records (city);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_planner_records_jobsite ON planner_records (jobsite);`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS pricing_rates (
        id SERIAL PRIMARY KEY,
        dia TEXT UNIQUE NOT NULL,
        rate NUMERIC(10,2) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS daily_reports (
        id SERIAL PRIMARY KEY,
        report_date TEXT NOT NULL,
        notes TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        updated_by TEXT DEFAULT '',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS jobsite_assets (
        id SERIAL PRIMARY KEY,
        jobsite TEXT NOT NULL,
        site_contact TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        external_url TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        updated_by TEXT DEFAULT '',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS uploaded_files (
        id SERIAL PRIMARY KEY,
        owner_type TEXT NOT NULL,
        owner_id BIGINT NOT NULL,
        label TEXT DEFAULT '',
        file_name TEXT DEFAULT '',
        content_type TEXT DEFAULT '',
        byte_size BIGINT NOT NULL DEFAULT 0,
        file_data BYTEA,
        external_url TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_uploaded_files_owner ON uploaded_files (owner_type, owner_id);`);

    const countResult = await pool.query(`SELECT COUNT(*)::int AS count FROM users`);
    if (!countResult.rows[0]?.count) {
      const seeds = [
        { username: "Tyler Clark", isAdmin: true, roles: { camera: true, vac: true } },
        { username: "Nick Krull", isAdmin: true, roles: { camera: true, vac: true } },
        { username: "Mike Strickland", isAdmin: true, roles: { camera: true, vac: true } },
      ];
      for (const seed of seeds) {
        await pool.query(
          `INSERT INTO users (username, password, is_admin, roles, must_change_password, updated_at)
           VALUES ($1, $2, $3, $4::jsonb, TRUE, CURRENT_TIMESTAMP)`,
          [seed.username, await bcrypt.hash("1234", 10), seed.isAdmin, JSON.stringify(seed.roles)]
        );
      }
    }

    console.log("Database initialized");
  } catch (error) {
    console.error("DATABASE INIT ERROR:", error);
    throw error;
  }
}

const MATERIAL_LABELS = {
  PE: "Polyethylene",
  PVC: "Polyvinyl Chloride",
  PP: "Polypropylene",
  RCP: "Reinforced Concrete Pipe",
  DIP: "Ductile Iron Pipe",
  VCP: "Vitrified Clay Pipe",
  STL: "Steel Pipe",
};

const SHAPE_LABELS = {
  C: "Circular",
  O: "Oval",
  R: "Rectangular",
  E: "Egg",
  A: "Arch",
  U: "U-Shape",
};

function inferStructureType(ref) {
  const token = cleanString(ref).toUpperCase();
  if (token.startsWith("CB")) return "CATCH BASIN";
  if (token.startsWith("ME")) return "MITERED END";
  return "MANHOLE";
}

function parseDiaFromShape(shapeCode, size1, size2, unit) {
  if (!size1 && !size2) return "";
  const suffix = cleanString(unit) || "inch";
  if (size1 && size2) return `${size1}/${size2}${suffix}`;
  return `${size1}${suffix}`;
}

function normalizeImportedMaterial(materialCode) {
  const code = cleanString(materialCode).toUpperCase();
  return MATERIAL_LABELS[code] || cleanString(materialCode);
}

function normalizeImportedShape(shapeCode, size1, size2, unit) {
  const code = cleanString(shapeCode).toUpperCase();
  const label = SHAPE_LABELS[code] || cleanString(shapeCode);
  const dia = parseDiaFromShape(shapeCode, size1, size2, unit);
  return {
    code,
    label,
    dia,
    raw: [label, dia].filter(Boolean).join(" ").trim(),
  };
}

async function parseWinCanDb3Buffer(buffer, sourceName = "upload.db3") {
  const SQL = await initSqlJs();
  const db = new SQL.Database(new Uint8Array(buffer));
  const result = db.exec(`
    SELECT
      p.PRJ_Key AS project_name,
      s.OBJ_Key AS psr,
      COALESCE(si.INS_InspectedLength, s.OBJ_Length, s.OBJ_RealLength, s.OBJ_CMPLength) AS footage,
      COALESCE(si.INS_StartDate, p.PRJ_Date, '') AS inspection_date,
      TRIM(REPLACE(COALESCE(s.OBJ_City, ''), ',', '')) AS city,
      TRIM(COALESCE(s.OBJ_Street, '')) AS street,
      TRIM(COALESCE(fn.OBJ_Key, '')) AS upstream,
      TRIM(COALESCE(tn.OBJ_Key, '')) AS downstream,
      TRIM(COALESCE(s.OBJ_Material, '')) AS material_code,
      TRIM(COALESCE(s.OBJ_Shape, '')) AS shape_code,
      s.OBJ_Size1 AS size1,
      s.OBJ_Size2 AS size2,
      TRIM(COALESCE(s.OBJ_Unit, '')) AS unit
    FROM SECTION s
    LEFT JOIN PROJECT p ON p.PRJ_PK = s.OBJ_Project_FK
    LEFT JOIN NODE fn ON fn.OBJ_Node_REF = s.OBJ_FromNode_REF
    LEFT JOIN NODE tn ON tn.OBJ_Node_REF = s.OBJ_ToNode_REF
    LEFT JOIN (
      SELECT INS_Section_FK, MAX(INS_PK) AS latest_pk
      FROM SECINSP
      GROUP BY INS_Section_FK
    ) latest ON latest.INS_Section_FK = s.OBJ_PK
    LEFT JOIN SECINSP si ON si.INS_PK = latest.latest_pk
    ORDER BY s.OBJ_Key
  `);
  if (!result.length) {
    return { rows: [], stats: { sourceType: "db3", sourceName, projectName: "", count: 0 } };
  }

  const columns = result[0].columns;
  const rows = result[0].values.map((valueRow) => {
    const row = {};
    columns.forEach((column, index) => { row[column] = valueRow[index]; });
    const shape = normalizeImportedShape(row.shape_code, row.size1, row.size2, row.unit);
    const footageValue = Number(row.footage);
    const psr = cleanString(row.psr) || [cleanString(row.upstream), cleanString(row.downstream)].filter(Boolean).join("-");
    return {
      sourceType: "db3",
      sourceName,
      projectName: cleanString(row.project_name),
      psr,
      footage: Number.isFinite(footageValue) ? Number(footageValue.toFixed(3)) : "",
      city: cleanString(row.city),
      street: cleanString(row.street),
      upstream: cleanString(row.upstream),
      downstream: cleanString(row.downstream),
      material: normalizeImportedMaterial(row.material_code),
      materialCode: cleanString(row.material_code),
      shape: shape.label,
      shapeCode: shape.code,
      shapeRaw: shape.raw,
      dia: shape.dia,
      inspectionDate: cleanString(row.inspection_date).slice(0, 10),
      confidence: 0.99,
    };
  }).filter((row) => row.psr);

  return {
    rows,
    stats: {
      sourceType: "db3",
      sourceName,
      projectName: cleanString(rows[0]?.projectName),
      count: rows.length,
    },
  };
}

function groupWordsByLine(words) {
  const lines = [];
  const sorted = (words || []).filter(Boolean).sort((a, b) => (a.bbox.y0 - b.bbox.y0) || (a.bbox.x0 - b.bbox.x0));
  for (const word of sorted) {
    const centerY = (word.bbox.y0 + word.bbox.y1) / 2;
    const existing = lines.find((line) => Math.abs(line.centerY - centerY) < 12);
    if (existing) {
      existing.words.push(word);
      existing.centerY = (existing.centerY * (existing.words.length - 1) + centerY) / existing.words.length;
    } else {
      lines.push({ centerY, words: [word] });
    }
  }
  return lines
    .map((line) => ({
      centerY: line.centerY,
      words: line.words.sort((a, b) => a.bbox.x0 - b.bbox.x0),
    }))
    .sort((a, b) => a.centerY - b.centerY);
}

function headerColumnRanges(headerWords) {
  const buckets = [];
  const headerText = headerWords.map((w) => cleanString(w.text)).join(" ");
  const aliases = [
    { key: "psr", patterns: [/pipe/i, /segment/i, /refer/i] },
    { key: "footage", patterns: [/total/i, /length/i] },
    { key: "city", patterns: [/city/i] },
    { key: "street", patterns: [/street/i] },
    { key: "upstream", patterns: [/upstream/i] },
    { key: "downstream", patterns: [/downstream/i] },
    { key: "material", patterns: [/material/i] },
    { key: "shape", patterns: [/shape/i] },
  ];

  if (!headerText) return buckets;

  const lineText = headerWords.map((word) => ({
    text: cleanString(word.text),
    x0: word.bbox.x0,
    x1: word.bbox.x1,
  }));

  for (const alias of aliases) {
    const matching = lineText.filter((item) => alias.patterns.some((pattern) => pattern.test(item.text)));
    if (!matching.length) continue;
    buckets.push({
      key: alias.key,
      x0: Math.min(...matching.map((item) => item.x0)) - 12,
      x1: Math.max(...matching.map((item) => item.x1)) + 22,
    });
  }

  return buckets.sort((a, b) => a.x0 - b.x0);
}

function wordsToColumns(words, ranges) {
  const values = {};
  for (const range of ranges) values[range.key] = [];
  for (const word of words) {
    const centerX = (word.bbox.x0 + word.bbox.x1) / 2;
    const range = ranges.find((item) => centerX >= item.x0 && centerX <= item.x1)
      || ranges.find((item) => centerX < item.x1)
      || ranges[ranges.length - 1];
    if (range) values[range.key].push(cleanString(word.text));
  }
  Object.keys(values).forEach((key) => {
    values[key] = values[key].join(" ").replace(/\s+/g, " ").trim();
  });
  return values;
}

function parseShapeString(value) {
  const raw = cleanString(value);
  if (!raw) return { shape: "", dia: "", raw: "" };
  const diaMatch = raw.match(/(\d+\s*\/\s*\d+|\d+(?:\.\d+)?)\s*(?:inch|in\b|")/i);
  const dia = diaMatch ? diaMatch[1].replace(/\s+/g, "") + "inch" : "";
  const shape = raw.replace(diaMatch ? diaMatch[0] : "", "").trim();
  return { shape, dia, raw };
}

async function parseWinCanScreenshotBuffer(buffer, sourceName = "screenshot.png") {
  const worker = await createWorker("eng");
  try {
    const recognition = await worker.recognize(buffer);
    const words = (recognition?.data?.words || [])
      .filter((word) => cleanString(word.text) && Number(word.confidence || word.conf || 0) >= 20)
      .map((word) => ({
        text: word.text,
        confidence: Number(word.confidence || word.conf || 0),
        bbox: word.bbox,
      }));

    const lines = groupWordsByLine(words);
    const headerLine = lines.find((line) => {
      const text = line.words.map((word) => cleanString(word.text)).join(" ");
      return /pipe/i.test(text) && /segment/i.test(text) && /length/i.test(text);
    });

    if (!headerLine) {
      return { rows: [], stats: { sourceType: "screenshot", sourceName, count: 0, warning: "Could not detect WinCan table headers." } };
    }

    const ranges = headerColumnRanges(headerLine.words);
    const rows = lines
      .filter((line) => line.centerY > headerLine.centerY + 10)
      .map((line) => {
        const mapped = wordsToColumns(line.words, ranges);
        const shape = parseShapeString(mapped.shape);
        const psr = cleanString(mapped.psr);
        if (!psr || /pipe segment/i.test(psr)) return null;
        const footageValue = Number(String(mapped.footage || "").replace(/[^\d.]/g, ""));
        return {
          sourceType: "screenshot",
          sourceName,
          projectName: "",
          psr,
          footage: Number.isFinite(footageValue) ? Number(footageValue.toFixed(3)) : "",
          city: cleanString(mapped.city),
          street: cleanString(mapped.street),
          upstream: cleanString(mapped.upstream),
          downstream: cleanString(mapped.downstream),
          material: cleanString(mapped.material),
          materialCode: cleanString(mapped.material),
          shape: cleanString(shape.shape),
          shapeCode: "",
          shapeRaw: cleanString(mapped.shape),
          dia: cleanString(shape.dia),
          inspectionDate: "",
          confidence: Number((line.words.reduce((sum, word) => sum + Number(word.confidence || 0), 0) / Math.max(line.words.length, 1) / 100).toFixed(2)),
        };
      })
      .filter(Boolean);

    return {
      rows,
      stats: {
        sourceType: "screenshot",
        sourceName,
        count: rows.length,
      },
    };
  } finally {
    await worker.terminate();
  }
}

function parseSpreadsheetBuffer(buffer, sourceName = "import.xlsx") {
  const workbook = XLSX.read(buffer, { type: "buffer" });
  const firstSheetName = workbook.SheetNames[0];
  const rows = XLSX.utils.sheet_to_json(workbook.Sheets[firstSheetName], { defval: "" });
  const normalizedRows = rows.map((row) => {
    const psr = cleanString(row["Pipe Segment Reference"] || row["PSR"] || row["Pipe Segment Refer"]);
    const shapeCell = cleanString(row["Shape"] || "");
    const shape = parseShapeString(shapeCell);
    const footageValue = Number(row["Total Length [ft]"] || row["Total Length"] || row["Length"] || "");
    return {
      sourceType: "spreadsheet",
      sourceName,
      projectName: cleanString(row["Project"] || row["Project Name"]),
      psr,
      footage: Number.isFinite(footageValue) ? Number(footageValue.toFixed(3)) : "",
      city: cleanString(row["City"]),
      street: cleanString(row["Street"]),
      upstream: cleanString(row["Upstream MH"] || row["Upstream M"]),
      downstream: cleanString(row["Downstream MH"] || row["Downstream M"]),
      material: cleanString(row["Material"]),
      materialCode: cleanString(row["Material"]),
      shape: cleanString(shape.shape),
      shapeCode: "",
      shapeRaw: shapeCell,
      dia: cleanString(shape.dia),
      inspectionDate: cleanString(row["Date"] || row["Inspection Date"]).slice(0, 10),
      confidence: 0.95,
    };
  }).filter((row) => row.psr);
  return {
    rows: normalizedRows,
    stats: {
      sourceType: "spreadsheet",
      sourceName,
      count: normalizedRows.length,
    },
  };
}

async function parseUploadedImportFile(file) {
  const ext = path.extname(cleanString(file.originalname)).toLowerCase();
  if (ext === ".db3" || ext === ".sqlite" || ext === ".sqlite3") {
    return parseWinCanDb3Buffer(file.buffer, file.originalname);
  }
  if (ext === ".xlsx" || ext === ".xls" || ext === ".csv") {
    return parseSpreadsheetBuffer(file.buffer, file.originalname);
  }
  if ((file.mimetype || "").startsWith("image/")) {
    return parseWinCanScreenshotBuffer(file.buffer, file.originalname);
  }
  throw new Error(`Unsupported importer file type for ${file.originalname}`);
}

function buildImportedVersion(row, userName) {
  return {
    id: `import-${Math.random().toString(36).slice(2)}-${Date.now()}`,
    createdAt: new Date().toISOString(),
    savedBy: userName,
    savedById: null,
    mode: "import",
    flags: {
      videoComplete: false,
      videoFailed: false,
      rerun: false,
      rerunVideoed: false,
      rerunFailed: false,
      couldNotLocate: false,
      jetted: false,
    },
    failureReason: "",
    recordedDate: cleanString(row.inspectionDate) || todayISO(),
    notes: `Imported from ${row.sourceType.toUpperCase()} (${row.sourceName})`,
    status: "neutral",
    displayStatus: "Unmarked",
  };
}

function normalizeImportRows(rows) {
  return (Array.isArray(rows) ? rows : []).map((row) => ({
    sourceType: cleanString(row.sourceType || "db3"),
    sourceName: cleanString(row.sourceName || ""),
    projectName: cleanString(row.projectName || ""),
    psr: cleanString(row.psr),
    footage: cleanString(row.footage),
    city: cleanString(row.city),
    street: cleanString(row.street),
    upstream: cleanString(row.upstream),
    downstream: cleanString(row.downstream),
    material: cleanString(row.material),
    materialCode: cleanString(row.materialCode),
    shape: cleanString(row.shape),
    shapeCode: cleanString(row.shapeCode),
    shapeRaw: cleanString(row.shapeRaw),
    dia: cleanString(row.dia),
    inspectionDate: cleanString(row.inspectionDate).slice(0, 10),
    confidence: Number(row.confidence || 0),
  })).filter((row) => row.psr);
}

function groupImportedRows(rows, options = {}) {
  const mode = cleanString(options.groupMode || "street").toLowerCase();
  const system = cleanString(options.system || "storm").toLowerCase() === "sanitary" ? "sanitary" : "storm";
  const defaultClient = cleanString(options.client);
  const defaultJobsite = cleanString(options.singleJobsite);
  const defaultDate = cleanString(options.recordDate) || todayISO();
  const groups = new Map();

  for (const row of rows) {
    const client = defaultClient || row.projectName || "WinCan Import";
    const city = row.city || cleanString(options.city);
    const jobsite = mode === "single"
      ? (defaultJobsite || row.street || row.projectName || "Imported Job")
      : (row.street || defaultJobsite || row.projectName || "Imported Job");
    const recordDate = row.inspectionDate || defaultDate;
    const key = [client, city, jobsite, recordDate, system].join("|");

    if (!groups.has(key)) {
      groups.set(key, {
        client,
        city,
        jobsite,
        date: recordDate,
        system,
        rows: [],
      });
    }
    groups.get(key).rows.push(row);
  }

  return Array.from(groups.values());
}

async function fetchExistingRecord(client, group) {
  const result = await client.query(
    `SELECT id, client, city, record_date, jobsite, data
     FROM planner_records
     WHERE client = $1 AND city = $2 AND jobsite = $3 AND record_date = $4
     ORDER BY id DESC
     LIMIT 1`,
    [group.client, group.city, group.jobsite, group.date]
  );
  return result.rows[0] || null;
}

function ensureRecordDataShape(recordRow, group) {
  let data = recordRow?.data;
  if (!isObject(data)) {
    data = {};
  }
  if (typeof data === "string") {
    try { data = JSON.parse(data); } catch (_error) { data = {}; }
  }
  const systems = isObject(data.systems) ? data.systems : {};
  return {
    date: cleanString(data.date || recordRow?.record_date || group.date),
    client: cleanString(data.client || recordRow?.client || group.client),
    city: cleanString(data.city || recordRow?.city || group.city),
    jobsite: cleanString(data.jobsite || recordRow?.jobsite || group.jobsite),
    createStorm: systems.storm !== null,
    createSanitary: systems.sanitary !== null,
    systems: {
      storm: Array.isArray(systems.storm) ? systems.storm : [],
      sanitary: Array.isArray(systems.sanitary) ? systems.sanitary : [],
    },
  };
}

function importedSegmentFromRow(row, userName) {
  const version = buildImportedVersion(row, userName);
  return {
    id: `seg-${Math.random().toString(36).slice(2)}-${Date.now()}`,
    reference: row.psr,
    selectedVersionId: version.id,
    versions: [version],
    endpoints: {
      startType: inferStructureType(row.upstream),
      startRef: row.upstream,
      endType: inferStructureType(row.downstream),
      endRef: row.downstream,
    },
    dia: row.dia,
    material: row.material,
    footage: row.footage,
    length: row.footage,
  };
}

async function commitImportedRows(rows, options, user) {
  const groups = groupImportedRows(rows, options);
  const client = await pool.connect();
  const createdIds = [];
  try {
    await client.query("BEGIN");

    for (const group of groups) {
      const existing = await fetchExistingRecord(client, group);
      const recordData = ensureRecordDataShape(existing, group);
      const targetList = recordData.systems[group.system] || [];
      const existingRefs = new Set(targetList.map((segment) => cleanString(segment.reference).toLowerCase()));
      let importedCount = 0;

      for (const row of group.rows) {
        if (existingRefs.has(row.psr.toLowerCase())) continue;
        targetList.push(importedSegmentFromRow(row, user.username));
        existingRefs.add(row.psr.toLowerCase());
        importedCount += 1;
      }

      recordData.systems[group.system] = targetList;
      recordData.createStorm = recordData.systems.storm !== null;
      recordData.createSanitary = recordData.systems.sanitary !== null;

      const normalized = normalizeRecordInput({
        client: group.client,
        city: group.city,
        date: group.date,
        jobsite: group.jobsite,
        status: "",
        data: recordData,
      });

      if (existing) {
        await client.query(
          `UPDATE planner_records
           SET client = $1,
               city = $2,
               record_date = $3,
               jobsite = $4,
               data = $5::jsonb,
               updated_by = $6,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $7`,
          [
            normalized.client,
            normalized.city,
            normalized.date,
            normalized.jobsite,
            JSON.stringify(normalized.data),
            user.username,
            existing.id,
          ]
        );
        createdIds.push(existing.id);
      } else {
        const inserted = await client.query(
          `INSERT INTO planner_records (
            client, city, record_date, jobsite, psr, system, dia, material, footage,
            notes, status, data, created_by, updated_by
          )
          VALUES ($1,$2,$3,$4,'','','','','','','',$5::jsonb,$6,$6)
          RETURNING id`,
          [
            normalized.client,
            normalized.city,
            normalized.date,
            normalized.jobsite,
            JSON.stringify(normalized.data),
            user.username,
          ]
        );
        createdIds.push(inserted.rows[0].id);
      }
    }

    await client.query("COMMIT");
    return { createdIds, groupCount: groups.length };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function addFilesForOwner(ownerType, ownerId, files, createdBy, externalUrls = []) {
  const inserted = [];
  for (const file of files || []) {
    const row = await pool.query(
      `INSERT INTO uploaded_files (
        owner_type, owner_id, label, file_name, content_type, byte_size, file_data, external_url, created_by
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING id, label, file_name, content_type, byte_size, external_url, created_at`,
      [
        ownerType,
        ownerId,
        cleanString(file.originalname),
        cleanString(file.originalname),
        cleanString(file.mimetype),
        Number(file.size || file.buffer?.length || 0),
        file.buffer,
        "",
        createdBy,
      ]
    );
    inserted.push(normalizeFileMeta(row.rows[0]));
  }
  for (const url of externalUrls) {
    const cleanUrl = cleanString(url);
    if (!cleanUrl) continue;
    const row = await pool.query(
      `INSERT INTO uploaded_files (
        owner_type, owner_id, label, file_name, content_type, byte_size, file_data, external_url, created_by
      )
      VALUES ($1,$2,$3,'','',0,NULL,$4,$5)
      RETURNING id, label, file_name, content_type, byte_size, external_url, created_at`,
      [ownerType, ownerId, cleanUrl, cleanUrl, createdBy]
    );
    inserted.push(normalizeFileMeta(row.rows[0]));
  }
  return inserted;
}

async function mapFilesByOwner(ownerType, ownerIds) {
  if (!ownerIds.length) return new Map();
  const result = await pool.query(
    `SELECT id, owner_id, label, file_name, content_type, byte_size, external_url, created_at
     FROM uploaded_files
     WHERE owner_type = $1 AND owner_id = ANY($2::bigint[])
     ORDER BY created_at DESC`,
    [ownerType, ownerIds]
  );
  const map = new Map();
  for (const row of result.rows) {
    if (!map.has(row.owner_id)) map.set(row.owner_id, []);
    map.get(row.owner_id).push(normalizeFileMeta(row));
  }
  return map;
}

function parseExternalUrls(value) {
  if (Array.isArray(value)) return value.map(cleanString).filter(Boolean);
  const raw = cleanString(value);
  if (!raw) return [];
  if (raw.startsWith("[")) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.map(cleanString).filter(Boolean);
    } catch (_error) {}
  }
  return raw.split(/\r?\n|,/).map(cleanString).filter(Boolean);
}

app.get("/", (_req, res) => {
  res.send("Horizon Backend Running");
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/auth/usernames", async (_req, res) => {
  try {
    const result = await pool.query(`SELECT username FROM users ORDER BY username ASC`);
    return res.json({ success: true, usernames: result.rows.map((row) => row.username) });
  } catch (error) {
    console.error("USERNAME LIST ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/session", (req, res) => {
  const user = sessionUser(req);
  return res.json({ success: true, authenticated: !!user, user });
});

async function loginHandler(req, res) {
  const username = cleanString(req.body?.username);
  const password = cleanString(req.body?.password);
  try {
    if (!username || !password) {
      return res.status(400).json({ success: false, error: "Username and password are required" });
    }
    const result = await pool.query(
      `SELECT id, username, password, is_admin, roles, must_change_password
       FROM users
       WHERE LOWER(username) = LOWER($1)
       LIMIT 1`,
      [username]
    );
    if (!result.rows.length) {
      return res.status(401).json({ success: false, error: "Invalid username or password" });
    }
    const userRow = result.rows[0];
    const verified = await verifyPasswordAndUpgrade(userRow, password);
    if (!verified) {
      return res.status(401).json({ success: false, error: "Invalid username or password" });
    }
    const user = normalizeUser(userRow);
    req.session.user = user;
    return res.json({ success: true, user });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
}

app.post("/login", loginHandler);
app.post("/session/login", loginHandler);

app.post("/session/logout", requireAuth, (req, res) => {
  req.session.destroy((error) => {
    if (error) return res.status(500).json({ success: false, error: "Could not sign out" });
    res.clearCookie("horizon.sid");
    return res.json({ success: true });
  });
});

app.post("/change-password", requireAuth, async (req, res) => {
  const currentPassword = cleanString(req.body?.currentPassword);
  const newPassword = cleanString(req.body?.newPassword);
  try {
    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ success: false, error: "Use at least 4 characters for the new password" });
    }
    const result = await pool.query(
      `SELECT id, username, password FROM users WHERE id = $1 LIMIT 1`,
      [req.currentUser.id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    const verified = await verifyPasswordAndUpgrade(result.rows[0], currentPassword);
    if (!verified) {
      return res.status(400).json({ success: false, error: "Current password is incorrect" });
    }
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      `UPDATE users
       SET password = $1, must_change_password = FALSE, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [hash, req.currentUser.id]
    );
    req.session.user = { ...req.currentUser, mustChangePassword: false };
    return res.json({ success: true, user: req.session.user });
  } catch (error) {
    console.error("CHANGE PASSWORD ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/users/:id/reset-password", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const nextPassword = cleanString(req.body?.password || "1234");
  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ success: false, error: "Invalid user id" });
    }
    const hash = await bcrypt.hash(nextPassword, 10);
    const result = await pool.query(
      `UPDATE users
       SET password = $1, must_change_password = TRUE, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id, username, is_admin, roles, must_change_password`,
      [hash, id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    return res.json({ success: true, user: normalizeUser(result.rows[0]) });
  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/users", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, is_admin, roles, must_change_password, created_at, updated_at
       FROM users
       ORDER BY username ASC`
    );
    return res.json({ success: true, users: result.rows.map(normalizeUser) });
  } catch (error) {
    console.error("GET USERS ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

async function createUserHandler(req, res) {
  const username = cleanString(req.body?.username);
  const password = cleanString(req.body?.password || "1234");
  const isAdmin = !!req.body?.isAdmin;
  const roles = normalizeRoles(req.body?.roles);
  try {
    if (!username) {
      return res.status(400).json({ success: false, error: "Username is required" });
    }
    const hash = await bcrypt.hash(password, 10);
    const inserted = await pool.query(
      `INSERT INTO users (username, password, is_admin, roles, must_change_password, updated_at)
       VALUES ($1, $2, $3, $4::jsonb, TRUE, CURRENT_TIMESTAMP)
       RETURNING id, username, is_admin, roles, must_change_password`,
      [username, hash, isAdmin, JSON.stringify(roles)]
    );
    return res.json({ success: true, user: normalizeUser(inserted.rows[0]) });
  } catch (error) {
    console.error("CREATE USER ERROR:", error);
    if (error.code === "23505") {
      return res.status(409).json({ success: false, error: "That username already exists" });
    }
    return res.status(500).json({ success: false, error: error.message });
  }
}

app.post("/users", requireAdmin, createUserHandler);
app.post("/create-user", requireAdmin, createUserHandler);

app.put("/users/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const username = cleanString(req.body?.username);
  const isAdmin = !!req.body?.isAdmin;
  const roles = normalizeRoles(req.body?.roles);
  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ success: false, error: "Invalid user id" });
    }
    const result = await pool.query(
      `UPDATE users
       SET username = COALESCE(NULLIF($1, ''), username),
           is_admin = $2,
           roles = $3::jsonb,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $4
       RETURNING id, username, is_admin, roles, must_change_password`,
      [username, isAdmin, JSON.stringify(roles), id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    return res.json({ success: true, user: normalizeUser(result.rows[0]) });
  } catch (error) {
    console.error("UPDATE USER ERROR:", error);
    if (error.code === "23505") {
      return res.status(409).json({ success: false, error: "That username already exists" });
    }
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/save-job", requireAuth, async (req, res) => {
  const name = cleanString(req.body?.name);
  const data = isObject(req.body?.data) ? req.body.data : {};
  try {
    if (!name) return res.status(400).json({ success: false, error: "Job name is required" });
    await pool.query(`INSERT INTO jobs (name, data) VALUES ($1, $2::jsonb)`, [name, JSON.stringify(data)]);
    return res.json({ success: true });
  } catch (error) {
    console.error("SAVE JOB ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/jobs", requireAuth, async (_req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM jobs ORDER BY id DESC`);
    return res.json({ success: true, jobs: result.rows });
  } catch (error) {
    console.error("GET JOBS ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/records", requireAuth, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, client, city, record_date, jobsite, psr, system, dia, material, footage,
              notes, status, data, created_by, updated_by, created_at, updated_at
       FROM planner_records
       ORDER BY updated_at DESC, id DESC`
    );
    return res.json({ success: true, records: result.rows });
  } catch (error) {
    console.error("GET RECORDS ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/records/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ success: false, error: "Invalid record id" });
    }
    const result = await pool.query(
      `SELECT id, client, city, record_date, jobsite, psr, system, dia, material, footage,
              notes, status, data, created_by, updated_by, created_at, updated_at
       FROM planner_records
       WHERE id = $1
       LIMIT 1`,
      [id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: "Record not found" });
    }
    return res.json({ success: true, record: result.rows[0] });
  } catch (error) {
    console.error("GET RECORD ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

async function createOrUpdateRecord(req, res, mode) {
  const normalized = normalizeRecordInput(req.body || {});
  const username = req.currentUser?.username || cleanString(req.body?.username || req.body?.savedBy || req.body?.createdBy || req.body?.updatedBy);
  try {
    if (mode === "create") {
      const inserted = await pool.query(
        `INSERT INTO planner_records (
          client, city, record_date, jobsite, psr, system, dia, material, footage,
          notes, status, data, created_by, updated_by
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$13)
        RETURNING id, client, city, record_date, jobsite, psr, system, dia, material, footage,
                  notes, status, data, created_by, updated_by, created_at, updated_at`,
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
      return res.json({ success: true, record: inserted.rows[0] });
    }

    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ success: false, error: "Invalid record id" });
    }
    const updated = await pool.query(
      `UPDATE planner_records
       SET client = $1,
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
       RETURNING id, client, city, record_date, jobsite, psr, system, dia, material, footage,
                 notes, status, data, created_by, updated_by, created_at, updated_at`,
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
      return res.status(404).json({ success: false, error: "Record not found" });
    }
    return res.json({ success: true, record: updated.rows[0] });
  } catch (error) {
    console.error(mode === "create" ? "CREATE RECORD ERROR:" : "UPDATE RECORD ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
}

app.post("/records", requireAuth, (req, res) => createOrUpdateRecord(req, res, "create"));
app.put("/records/:id", requireAuth, (req, res) => createOrUpdateRecord(req, res, "update"));
app.patch("/records/:id", requireAuth, (req, res) => createOrUpdateRecord(req, res, "update"));

app.delete("/records/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ success: false, error: "Invalid record id" });
    }
    const deleted = await pool.query(`DELETE FROM planner_records WHERE id = $1 RETURNING id`, [id]);
    if (!deleted.rows.length) {
      return res.status(404).json({ success: false, error: "Record not found" });
    }
    return res.json({ success: true, deletedId: deleted.rows[0].id });
  } catch (error) {
    console.error("DELETE RECORD ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/pricing-rates", requireAuth, async (_req, res) => {
  try {
    const result = await pool.query(`SELECT id, dia, rate, updated_at FROM pricing_rates ORDER BY dia ASC`);
    return res.json({ success: true, rates: result.rows });
  } catch (error) {
    console.error("GET PRICING RATES ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/pricing-rates/:dia", requireAdmin, async (req, res) => {
  const dia = cleanString(req.params.dia);
  const rate = Number(req.body?.rate);
  try {
    if (!dia || Number.isNaN(rate)) {
      return res.status(400).json({ success: false, error: "Valid dia and rate are required" });
    }
    const result = await pool.query(
      `INSERT INTO pricing_rates (dia, rate, updated_at)
       VALUES ($1, $2, CURRENT_TIMESTAMP)
       ON CONFLICT (dia)
       DO UPDATE SET rate = EXCLUDED.rate, updated_at = CURRENT_TIMESTAMP
       RETURNING id, dia, rate, updated_at`,
      [dia, rate]
    );
    return res.json({ success: true, rate: result.rows[0] });
  } catch (error) {
    console.error("SAVE PRICING RATE ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.delete("/pricing-rates/:dia", requireAdmin, async (req, res) => {
  const dia = cleanString(req.params.dia);
  try {
    const deleted = await pool.query(`DELETE FROM pricing_rates WHERE dia = $1 RETURNING id, dia`, [dia]);
    if (!deleted.rows.length) {
      return res.status(404).json({ success: false, error: "Rate not found" });
    }
    return res.json({ success: true, deletedDia: deleted.rows[0].dia });
  } catch (error) {
    console.error("DELETE PRICING RATE ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/daily-reports", requireAuth, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, report_date, notes, created_by, updated_by, created_at, updated_at
       FROM daily_reports
       ORDER BY report_date DESC, created_at DESC`
    );
    const ids = result.rows.map((row) => row.id);
    const filesMap = await mapFilesByOwner("daily_report", ids);
    const reports = result.rows.map((row) => ({
      id: row.id,
      reportDate: row.report_date,
      notes: row.notes || "",
      createdBy: row.created_by || "",
      updatedBy: row.updated_by || "",
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      attachments: filesMap.get(row.id) || [],
    }));
    return res.json({ success: true, reports });
  } catch (error) {
    console.error("GET DAILY REPORTS ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/daily-reports", requireAdmin, upload.array("files", 8), async (req, res) => {
  const reportDate = cleanString(req.body?.reportDate || req.body?.date) || todayISO();
  const notes = cleanString(req.body?.notes);
  try {
    const inserted = await pool.query(
      `INSERT INTO daily_reports (report_date, notes, created_by, updated_by)
       VALUES ($1, $2, $3, $3)
       RETURNING id, report_date, notes, created_by, updated_by, created_at, updated_at`,
      [reportDate, notes, req.currentUser.username]
    );
    const report = inserted.rows[0];
    const attachments = await addFilesForOwner(
      "daily_report",
      report.id,
      req.files,
      req.currentUser.username,
      parseExternalUrls(req.body?.externalUrls)
    );
    return res.json({
      success: true,
      report: {
        id: report.id,
        reportDate: report.report_date,
        notes: report.notes || "",
        createdBy: report.created_by || "",
        updatedBy: report.updated_by || "",
        createdAt: report.created_at,
        updatedAt: report.updated_at,
        attachments,
      },
    });
  } catch (error) {
    console.error("CREATE DAILY REPORT ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.delete("/daily-reports/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ success: false, error: "Invalid report id" });
    }
    await pool.query(`DELETE FROM uploaded_files WHERE owner_type = 'daily_report' AND owner_id = $1`, [id]);
    const deleted = await pool.query(`DELETE FROM daily_reports WHERE id = $1 RETURNING id`, [id]);
    if (!deleted.rows.length) {
      return res.status(404).json({ success: false, error: "Report not found" });
    }
    return res.json({ success: true, deletedId: deleted.rows[0].id });
  } catch (error) {
    console.error("DELETE DAILY REPORT ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/jobsite-assets", requireAuth, async (req, res) => {
  const search = cleanString(req.query?.search).toLowerCase();
  try {
    const result = await pool.query(
      `SELECT id, jobsite, site_contact, notes, external_url, created_by, updated_by, created_at, updated_at
       FROM jobsite_assets
       ORDER BY updated_at DESC, id DESC`
    );
    const ids = result.rows.map((row) => row.id);
    const filesMap = await mapFilesByOwner("jobsite_asset", ids);
    const assets = result.rows
      .map((row) => ({
        id: row.id,
        jobsite: row.jobsite || "",
        siteContact: row.site_contact || "",
        notes: row.notes || "",
        externalUrl: row.external_url || "",
        createdBy: row.created_by || "",
        updatedBy: row.updated_by || "",
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        attachments: filesMap.get(row.id) || [],
      }))
      .filter((row) => {
        if (!search) return true;
        const hay = `${row.jobsite} ${row.siteContact} ${row.notes}`.toLowerCase();
        return hay.includes(search);
      });
    return res.json({ success: true, assets });
  } catch (error) {
    console.error("GET JOBSITE ASSETS ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/jobsite-assets", requireAuth, upload.array("files", 12), async (req, res) => {
  const jobsite = cleanString(req.body?.jobsite);
  const siteContact = cleanString(req.body?.siteContact);
  const notes = cleanString(req.body?.notes);
  const externalUrl = cleanString(req.body?.externalUrl);
  try {
    if (!jobsite) return res.status(400).json({ success: false, error: "Jobsite is required" });
    const inserted = await pool.query(
      `INSERT INTO jobsite_assets (jobsite, site_contact, notes, external_url, created_by, updated_by)
       VALUES ($1, $2, $3, $4, $5, $5)
       RETURNING id, jobsite, site_contact, notes, external_url, created_by, updated_by, created_at, updated_at`,
      [jobsite, siteContact, notes, externalUrl, req.currentUser.username]
    );
    const asset = inserted.rows[0];
    const attachments = await addFilesForOwner(
      "jobsite_asset",
      asset.id,
      req.files,
      req.currentUser.username,
      parseExternalUrls(req.body?.externalUrls)
    );
    return res.json({
      success: true,
      asset: {
        id: asset.id,
        jobsite: asset.jobsite || "",
        siteContact: asset.site_contact || "",
        notes: asset.notes || "",
        externalUrl: asset.external_url || "",
        createdBy: asset.created_by || "",
        updatedBy: asset.updated_by || "",
        createdAt: asset.created_at,
        updatedAt: asset.updated_at,
        attachments,
      },
    });
  } catch (error) {
    console.error("CREATE JOBSITE ASSET ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.delete("/jobsite-assets/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  try {
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ success: false, error: "Invalid asset id" });
    await pool.query(`DELETE FROM uploaded_files WHERE owner_type = 'jobsite_asset' AND owner_id = $1`, [id]);
    const deleted = await pool.query(`DELETE FROM jobsite_assets WHERE id = $1 RETURNING id`, [id]);
    if (!deleted.rows.length) return res.status(404).json({ success: false, error: "Asset not found" });
    return res.json({ success: true, deletedId: deleted.rows[0].id });
  } catch (error) {
    console.error("DELETE JOBSITE ASSET ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/files/:id/download", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  try {
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ success: false, error: "Invalid file id" });
    const result = await pool.query(
      `SELECT id, file_name, content_type, file_data, external_url
       FROM uploaded_files
       WHERE id = $1
       LIMIT 1`,
      [id]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, error: "File not found" });
    const file = result.rows[0];
    if (cleanString(file.external_url)) return res.redirect(file.external_url);
    res.setHeader("Content-Type", cleanString(file.content_type) || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${cleanString(file.file_name) || `file-${id}`}"`);
    return res.send(file.file_data);
  } catch (error) {
    console.error("FILE DOWNLOAD ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/imports/wincan/preview", requireMike, upload.array("files", 20), async (req, res) => {
  try {
    if (!req.files?.length) {
      return res.status(400).json({ success: false, error: "Upload at least one DB3, image, or spreadsheet file" });
    }
    const parsed = [];
    for (const file of req.files) {
      parsed.push(await parseUploadedImportFile(file));
    }
    const rows = parsed.flatMap((item) => item.rows);
    const stats = {
      totalRows: rows.length,
      files: parsed.map((item) => item.stats),
    };
    return res.json({ success: true, preview: { rows, stats } });
  } catch (error) {
    console.error("WINCAN PREVIEW ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/imports/wincan/commit", requireMike, async (req, res) => {
  try {
    const rows = normalizeImportRows(req.body?.rows);
    const options = isObject(req.body?.options) ? req.body.options : {};
    if (!rows.length) {
      return res.status(400).json({ success: false, error: "No preview rows supplied for import" });
    }
    const result = await commitImportedRows(rows, options, req.currentUser);
    return res.json({ success: true, ...result });
  } catch (error) {
    console.error("WINCAN COMMIT ERROR:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

initDB()
  .then(() => {
    const PORT = process.env.PORT || 10000;
    app.listen(PORT, () => {
      console.log(`Server listening on ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Startup failed:", error);
    process.exit(1);
  });
