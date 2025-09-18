const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
require("dotenv").config({ path: path.resolve(__dirname, ".env") });
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());


// PostgreSQL Connection
const pool = new Pool({
  user: process.env.PGUSER || "postgres",
  host: process.env.PGHOST || "localhost",
  database: process.env.PGDATABASE || "todo_demo",
  password: String(process.env.PGPASSWORD ?? ""),
  port: Number(process.env.PGPORT || 5432),
});

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// Create HTTP server and Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  },
});

io.on("connection", (socket) => {
  // Client should emit 'authenticate' with JWT to join personal room
  socket.on("authenticate", (token) => {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const room = `user-${payload.userId}`;
      socket.join(room);
      socket.emit("authenticated", { ok: true });
    } catch (_e) {
      socket.emit("auth_error", { error: "Invalid token" });
    }
  });
});

// Ensure table exists and migrate schema (idempotent)
async function initDb() {
  // Users table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      reset_token TEXT,
      reset_token_expires TIMESTAMP WITH TIME ZONE
    );
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT UNIQUE`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
    );
  `);
  // Add new columns if missing
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS description TEXT`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS priority TEXT DEFAULT 'medium'`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS due_date DATE`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'own'`);
  // Backfill existing rows so filters work as expected
  await pool.query(`UPDATE tasks SET category='own' WHERE category IS NULL`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS due_time TIME`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE CASCADE`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS type TEXT DEFAULT 'work'`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS project_id INTEGER`);
  await pool.query(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS important BOOLEAN DEFAULT FALSE`);
  // Basic constraint for priority values (not strict if existing invalid values)
  // We won't add a CHECK to avoid migration failures; enforce at app level instead.

  // Projects table (for office/personal projects)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'personal', -- 'office' | 'personal'
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
  `);

  // Time logs table (work vs learning hours per day)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS time_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      day DATE NOT NULL,
      category TEXT NOT NULL, -- 'work' | 'learning'
      minutes INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_time_logs_unique ON time_logs (user_id, day, category)`);
}

initDb().catch((e) => {
  console.error("DB init failed:", e);
});

// Auth helpers
function authOptional(req, _res, next) {
  const auth = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = { id: payload.userId, username: payload.username };
    } catch (_e) {
      req.user = null;
    }
  } else {
    req.user = null;
  }
  next();
}

function authRequired(req, res, next) {
  const auth = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.userId, username: payload.username };
    next();
  } catch (_e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Auth endpoints
app.post("/auth/register", async (req, res) => {
  try {
    const { username, phone, password } = req.body;
    if (!username || !password || !phone) return res.status(400).json({ error: "username, phone and password are required" });
    if (String(username).length < 3) return res.status(400).json({ error: "username must be at least 3 chars" });
    if (!/^\d{10,15}$/.test(String(phone))) return res.status(400).json({ error: "phone must be 10-15 digits" });
    if (String(password).length < 6) return res.status(400).json({ error: "password must be at least 6 chars" });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, phone, password_hash) VALUES ($1, $2, $3) RETURNING id, username, phone`,
      [username, phone, hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user });
  } catch (err) {
    const msg = String(err.message || "");
    if (msg.includes("duplicate key") && msg.includes("users_username_key")) {
      return res.status(409).json({ error: "username already exists" });
    }
    if (msg.includes("duplicate key") && msg.includes("users_phone_key")) {
      return res.status(409).json({ error: "phone already registered" });
    }
    console.error("POST /auth/register error:", err);
    res.status(500).json({ error: "Failed to register" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "username and password are required" });
    const result = await pool.query(`SELECT id, username, password_hash FROM users WHERE username=$1`, [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error("POST /auth/login error:", err);
    res.status(500).json({ error: "Failed to login" });
  }
});

// Demo-only forgot: change password by username and new_password
app.post("/auth/forgot", async (req, res) => {
  try {
    const { username, new_password } = req.body;
    if (!username || !new_password) return res.status(400).json({ error: "username and new_password are required" });
    const hash = await bcrypt.hash(new_password, 10);
    const result = await pool.query(`UPDATE users SET password_hash=$1 WHERE username=$2 RETURNING id, username`, [hash, username]);
    if (!result.rowCount) return res.status(404).json({ error: "user not found" });
    res.json({ success: true });
  } catch (err) {
    console.error("POST /auth/forgot error:", err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// Routes
app.get("/tasks", authOptional, async (req, res) => {
  try {
    const { status, priority, category, type, project_id, important, q, sort = 'id', order = 'asc' } = req.query;
    const where = [];
    const values = [];
    let idx = 1;

    if (req.user) {
      where.push(`user_id = $${idx++}`);
      values.push(req.user.id);
    }
    if (status) {
      where.push(`status = $${idx++}`);
      values.push(status);
    }
    if (priority) {
      where.push(`priority = $${idx++}`);
      values.push(priority);
    }
    if (category) {
      where.push(`category = $${idx++}`);
      values.push(category);
    }
    if (type) {
      where.push(`type = $${idx++}`);
      values.push(type);
    }
    if (project_id) {
      where.push(`project_id = $${idx++}`);
      values.push(project_id);
    }
    if (important !== undefined) {
      const val = String(important).toLowerCase();
      if (val === 'true' || val === '1') {
        where.push(`important = TRUE`);
      } else if (val === 'false' || val === '0') {
        where.push(`important = FALSE`);
      }
    }
    if (q) {
      where.push(`(title ILIKE $${idx} OR COALESCE(description,'') ILIKE $${idx})`);
      values.push(`%${q}%`);
      idx++;
    }

    const allowedSort = new Set(["id", "title", "status", "priority", "category", "type", "due_date", "due_time", "project_id", "created_at", "updated_at"]);
    const sortBy = allowedSort.has(String(sort)) ? String(sort) : "id";
    const sortOrder = String(order).toLowerCase() === "desc" ? "DESC" : "ASC";

    const query = `SELECT * FROM tasks ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY ${sortBy} ${sortOrder}`;
    const result = await pool.query(query, values);
    res.json(result.rows);
  } catch (err) {
    console.error("GET /tasks error:", err);
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});

app.post("/tasks", authOptional, async (req, res) => {
  try {
    const { title, status, description, priority, due_date, due_time, category, type, project_id, important } = req.body;
    if (!title || !title.trim()) {
      return res.status(400).json({ error: "Title is required" });
    }
    const st = status ?? 'pending';
    const pr = priority ?? 'medium';
    const cat = category ?? 'own';
    const ty = type ?? 'work';
    const cols = ["title", "status", "description", "priority", "due_date", "due_time", "category", "type", "project_id", "important"]; 
    const vals = [title.trim(), st, description ?? null, pr, due_date ?? null, due_time ?? null, cat, ty, project_id ?? null, Boolean(important)];
    const placeholders = ["$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10"];
    if (req.user) {
      cols.push("user_id");
      vals.push(req.user.id);
      placeholders.push(`$${placeholders.length + 1}`);
    }
    const result = await pool.query(
      `INSERT INTO tasks (${cols.join(", ")}) VALUES (${placeholders.join(", ")}) RETURNING *`,
      vals
    );
    const task = result.rows[0];
    // Emit real-time event to owner room if authenticated
    if (req.user) {
      io.to(`user-${req.user.id}`).emit("task_created", task);
    } else {
      io.emit("task_created", task);
    }
    res.json(task);
  } catch (err) {
    console.error("POST /tasks error:", err);
    res.status(500).json({ error: "Failed to create task" });
  }
});

app.put("/tasks/:id", authOptional, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, title, description, priority, due_date, due_time, category, type, project_id, important } = req.body;

    if (status === undefined && title === undefined && description === undefined && priority === undefined && due_date === undefined && due_time === undefined && category === undefined && type === undefined && project_id === undefined && important === undefined) {
      return res.status(400).json({ error: "Nothing to update" });
    }

    // Build dynamic update
    const fields = [];
    const values = [];
    let idx = 1;
    if (title !== undefined) {
      fields.push(`title=$${idx++}`);
      values.push(title);
    }
    if (status !== undefined) {
      fields.push(`status=$${idx++}`);
      values.push(status);
    }
    if (description !== undefined) {
      fields.push(`description=$${idx++}`);
      values.push(description);
    }
    if (priority !== undefined) {
      fields.push(`priority=$${idx++}`);
      values.push(priority);
    }
    if (due_date !== undefined) {
      fields.push(`due_date=$${idx++}`);
      values.push(due_date);
    }
    if (due_time !== undefined) {
      fields.push(`due_time=$${idx++}`);
      values.push(due_time);
    }
    if (category !== undefined) {
      fields.push(`category=$${idx++}`);
      values.push(category);
    }
    if (type !== undefined) {
      fields.push(`type=$${idx++}`);
      values.push(type);
    }
    if (project_id !== undefined) {
      fields.push(`project_id=$${idx++}`);
      values.push(project_id);
    }
    if (important !== undefined) {
      fields.push(`important=$${idx++}`);
      values.push(Boolean(important));
    }
    fields.push(`updated_at=NOW()`);

    // ownership condition if authenticated
    if (req.user) {
      // Load old task for comparison (assignment changes)
      const prev = await pool.query(`SELECT * FROM tasks WHERE id=$1 AND user_id=$2`, [id, req.user.id]);
      const oldTask = prev.rows[0];
      values.push(id);
      values.push(req.user.id);
      const query = `UPDATE tasks SET ${fields.join(", ")} WHERE id=$${idx++} AND user_id=$${idx} RETURNING *`;
      const result = await pool.query(query, values);
      if (!result.rowCount) return res.status(404).json({ error: "Task not found" });
      const updated = result.rows[0];
      io.to(`user-${req.user.id}`).emit("task_updated", updated);
      // Notify new assignee if changed
      if (oldTask && updated.assigned_to && updated.assigned_to !== oldTask.assigned_to) {
        io.to(`user-${updated.assigned_to}`).emit("notification", {
          type: "TASK_ASSIGNED",
          title: "New Task Assigned",
          message: `You have been assigned: ${updated.title}`,
          taskId: updated.id,
        });
      }
      // Optionally notify previous assignee
      if (oldTask && oldTask.assigned_to && updated.assigned_to !== oldTask.assigned_to) {
        io.to(`user-${oldTask.assigned_to}`).emit("notification", {
          type: "TASK_UNASSIGNED",
          title: "Task Unassigned",
          message: `You are no longer assigned: ${oldTask.title}`,
          taskId: oldTask.id,
        });
      }
      return res.json(updated);
    }
    // legacy: no auth
    values.push(id);
    const query = `UPDATE tasks SET ${fields.join(", ")} WHERE id=$${idx} RETURNING *`;
    const result = await pool.query(query, values);
    const updated = result.rows[0] || { id, ...req.body };
    io.emit("task_updated", updated);
    res.json(updated);
  } catch (err) {
    console.error("PUT /tasks/:id error:", err);
    res.status(500).json({ error: "Failed to update task" });
  }
});

app.delete("/tasks/:id", authOptional, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user) {
      const result = await pool.query("DELETE FROM tasks WHERE id=$1 AND user_id=$2", [id, req.user.id]);
      if (!result.rowCount) return res.status(404).json({ error: "Task not found" });
      io.to(`user-${req.user.id}`).emit("task_deleted", { id: Number(id) });
      return res.json({ success: true });
    }
    await pool.query("DELETE FROM tasks WHERE id=$1", [id]);
    io.emit("task_deleted", { id: Number(id) });
    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /tasks/:id error:", err);
    res.status(500).json({ error: "Failed to delete task" });
  }
});

// Bulk actions
app.post("/tasks/clear-completed", authOptional, async (req, res) => {
  try {
    if (req.user) {
      await pool.query("DELETE FROM tasks WHERE status='done' AND user_id=$1", [req.user.id]);
    } else {
      await pool.query("DELETE FROM tasks WHERE status='done'");
    }
    res.json({ success: true });
  } catch (err) {
    console.error("POST /tasks/clear-completed error:", err);
    res.status(500).json({ error: "Failed to clear completed" });
  }
});

app.post("/tasks/mark-all-done", authOptional, async (req, res) => {
  try {
    if (req.user) {
      await pool.query("UPDATE tasks SET status='done', updated_at=NOW() WHERE status<>'done' AND user_id=$1", [req.user.id]);
    } else {
      await pool.query("UPDATE tasks SET status='done', updated_at=NOW() WHERE status<>'done'");
    }
    res.json({ success: true });
  } catch (err) {
    console.error("POST /tasks/mark-all-done error:", err);
    res.status(500).json({ error: "Failed to mark all done" });
  }
});

// Projects
app.get("/projects", authRequired, async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM projects WHERE user_id=$1 ORDER BY created_at DESC", [req.user.id]);
    res.json(r.rows);
  } catch (err) {
    console.error("GET /projects error:", err);
    res.status(500).json({ error: "Failed to fetch projects" });
  }
});

app.post("/projects", authRequired, async (req, res) => {
  try {
    const { name, kind } = req.body;
    if (!name) return res.status(400).json({ error: "name is required" });
    const kd = kind === 'office' ? 'office' : 'personal';
    const r = await pool.query("INSERT INTO projects (user_id, name, kind) VALUES ($1,$2,$3) RETURNING *", [req.user.id, name, kd]);
    res.json(r.rows[0]);
  } catch (err) {
    console.error("POST /projects error:", err);
    res.status(500).json({ error: "Failed to create project" });
  }
});

// Time logs
app.post("/time-logs", authRequired, async (req, res) => {
  try {
    const { day, category, minutes } = req.body;
    if (!day || !category) return res.status(400).json({ error: "day and category are required" });
    const cat = category === 'learning' ? 'learning' : 'work';
    const mins = Math.max(0, Number(minutes || 0));
    const r = await pool.query(
      `INSERT INTO time_logs (user_id, day, category, minutes) VALUES ($1,$2,$3,$4)
       ON CONFLICT (user_id, day, category) DO UPDATE SET minutes=EXCLUDED.minutes
       RETURNING *`,
      [req.user.id, day, cat, mins]
    );
    res.json(r.rows[0]);
  } catch (err) {
    console.error("POST /time-logs error:", err);
    res.status(500).json({ error: "Failed to upsert time log" });
  }
});

// Dashboard overview
app.get("/dashboard/overview", authRequired, async (req, res) => {
  try {
    const userId = req.user.id;
    const today = new Date();
    const r1 = await pool.query(
      `SELECT COUNT(*)::int AS total,
              SUM(CASE WHEN status='done' THEN 1 ELSE 0 END)::int AS done
       FROM tasks WHERE user_id=$1 AND due_date = CURRENT_DATE`,
      [userId]
    );
    const todayTotal = r1.rows[0].total || 0;
    const todayDone = r1.rows[0].done || 0;
    const todayPending = Math.max(0, todayTotal - todayDone);

    const r2 = await pool.query(
      `SELECT kind, COUNT(*)::int AS cnt FROM projects WHERE user_id=$1 GROUP BY kind`,
      [userId]
    );
    let officeProjects = 0, personalProjects = 0;
    for (const row of r2.rows) {
      if (row.kind === 'office') officeProjects = row.cnt; else personalProjects = row.cnt;
    }

    const r3 = await pool.query(
      `SELECT category, COALESCE(SUM(minutes),0)::int AS mins FROM time_logs WHERE user_id=$1 AND day=CURRENT_DATE GROUP BY category`,
      [userId]
    );
    let workMins = 0, learningMins = 0;
    for (const row of r3.rows) {
      if (row.category === 'learning') learningMins = row.mins; else workMins = row.mins;
    }

    const r4 = await pool.query(
      `SELECT COUNT(*)::int AS overdue FROM tasks WHERE user_id=$1 AND due_date < CURRENT_DATE AND status<>'done'`,
      [userId]
    );
    const overdue = r4.rows[0].overdue || 0;

    const r5 = await pool.query(
      `SELECT * FROM tasks WHERE user_id=$1 AND type='work' AND status<>'done' ORDER BY COALESCE(due_date, CURRENT_DATE), created_at DESC LIMIT 20`,
      [userId]
    );
    const r6 = await pool.query(
      `SELECT * FROM tasks WHERE user_id=$1 AND type='learning' AND status<>'done' ORDER BY COALESCE(due_date, CURRENT_DATE), created_at DESC LIMIT 20`,
      [userId]
    );

    const goalPct = todayTotal > 0 ? Math.round((todayDone / todayTotal) * 100) : 0;

    res.json({
      today: today.toISOString().slice(0,10),
      tasksToday: { total: todayTotal, done: todayDone, pending: todayPending, goalPercent: goalPct },
      projects: { office: officeProjects, personal: personalProjects },
      time: { workMinutes: workMins, learningMinutes: learningMins },
      overdue,
      lists: { work: r5.rows, learning: r6.rows }
    });
  } catch (err) {
    console.error("GET /dashboard/overview error:", err);
    res.status(500).json({ error: "Failed to load dashboard" });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Start server
const PORT = Number(process.env.PORT || 5000);
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
