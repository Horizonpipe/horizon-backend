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

// Initialize database tables
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
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

    console.log("Database initialized");
  } catch (err) {
    console.error("DATABASE INIT ERROR:", err);
  }
}

initDB();

// Health check
app.get("/", (req, res) => {
  res.send("Horizon Backend Running");
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.json({
        success: false,
        error: "Username and password are required",
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1 AND password = $2",
      [username, password]
    );

    if (result.rows.length > 0) {
      return res.json({
        success: true,
        user: {
          id: result.rows[0].id,
          username: result.rows[0].username,
        },
      });
    }

    return res.json({
      success: false,
      error: "Invalid username or password",
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

// Create user
app.post("/create-user", async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.json({
        success: false,
        error: "Username and password are required",
      });
    }

    const trimmedUsername = String(username).trim();
    const trimmedPassword = String(password).trim();

    if (!trimmedUsername || !trimmedPassword) {
      return res.json({
        success: false,
        error: "Username and password cannot be blank",
      });
    }

    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      [trimmedUsername, trimmedPassword]
    );

    return res.json({
      success: true,
      message: "User created successfully",
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

// Save job
app.post("/save-job", async (req, res) => {
  const { name, data } = req.body;

  try {
    if (!name) {
      return res.json({
        success: false,
        error: "Job name is required",
      });
    }

    await pool.query(
      "INSERT INTO jobs (name, data) VALUES ($1, $2)",
      [name, data || {}]
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

// Load jobs
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

// Start server
app.listen(process.env.PORT, () => {
  console.log("Server running on port " + process.env.PORT);
});
