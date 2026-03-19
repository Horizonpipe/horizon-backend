const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

// Connect to Render Postgres
const pool = new Pool({
connectionString: process.env.DATABASE_URL,
ssl: { rejectUnauthorized: false },
});

// Create tables (runs automatically)
async function initDB() {
await pool.query(`     CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT
    );
  `);

await pool.query(`     CREATE TABLE IF NOT EXISTS jobs (
      id SERIAL PRIMARY KEY,
      name TEXT,
      data JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

console.log("Database initialized");
}

initDB();

// 🔐 LOGIN
app.post("/login", async (req, res) => {
const { username, password } = req.body;

const result = await pool.query(
"SELECT * FROM users WHERE username=$1 AND password=$2",
[username, password]
);

if (result.rows.length > 0) {
res.json({ success: true, user: result.rows[0] });
} else {
res.json({ success: false });
}
});

// ➕ CREATE USER
app.post("/create-user", async (req, res) => {
const { username, password } = req.body;

try {
await pool.query(
"INSERT INTO users (username, password) VALUES ($1, $2)",
[username, password]
);

```
res.json({ success: true });
```

} catch (err) {
res.json({ success: false, error: "User may already exist" });
}
});

// 💾 SAVE JOB
app.post("/save-job", async (req, res) => {
const { name, data } = req.body;

await pool.query(
"INSERT INTO jobs (name, data) VALUES ($1, $2)",
[name, data]
);

res.json({ success: true });
});

// 📂 LOAD JOBS
app.get("/jobs", async (req, res) => {
const result = await pool.query("SELECT * FROM jobs ORDER BY id DESC");
res.json(result.rows);
});

// 🧪 Health check
app.get("/", (req, res) => {
res.send("Horizon Backend Running");
});

// Start server
app.listen(process.env.PORT, () => {
console.log("Server running on port " + process.env.PORT);
});
