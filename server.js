const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const WebSocket = require("ws");

const app = express();

const FILE = "data.txt";
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL environment variable.");
  process.exit(1);
}

if (!SESSION_SECRET) {
  console.error("Missing SESSION_SECRET environment variable.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
});

app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

let notesCache = new Map();
let usersCache = new Map();
let wss;
let updateChain = Promise.resolve();

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(normalized + padding, "base64").toString("utf8");
}

function signTokenPayload(payload) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
}

function createSessionToken(user) {
  const payload = JSON.stringify({
    userId: user.id,
    username: user.username,
    exp: Date.now() + SESSION_TTL_MS,
  });
  const encodedPayload = base64UrlEncode(payload);
  const signature = signTokenPayload(encodedPayload);
  return `${encodedPayload}.${signature}`;
}

function verifySessionToken(token) {
  if (typeof token !== "string") {
    return null;
  }

  const [encodedPayload, signature] = token.split(".");

  if (!encodedPayload || !signature) {
    return null;
  }

  const expectedSignature = signTokenPayload(encodedPayload);
  const actualSignature = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (
    actualSignature.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(actualSignature, expectedBuffer)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));

    if (payload.exp < Date.now()) {
      return null;
    }

    return payload;
  } catch (_error) {
    return null;
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (typeof storedHash !== "string" || !storedHash.includes(":")) {
    return false;
  }

  const [salt, expectedHash] = storedHash.split(":");
  const actualHash = crypto.scryptSync(password, salt, 64).toString("hex");
  const expectedBuffer = Buffer.from(expectedHash, "hex");
  const actualBuffer = Buffer.from(actualHash, "hex");

  return (
    expectedBuffer.length === actualBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, actualBuffer)
  );
}

function getBearerToken(req) {
  const header = req.get("authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice("Bearer ".length);
}

function ensureAuthorized(req, res, next) {
  const token = getBearerToken(req);
  const payload = verifySessionToken(token);

  if (!payload) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const user = usersCache.get(payload.userId);

  if (!user) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  req.user = user;
  next();
}

function makeNoteSummary(note) {
  return {
    id: note.id,
    title: note.title,
    version: note.version,
    updatedAt: note.updated_at,
  };
}

function getUserNotes(userId) {
  return Array.from(notesCache.values())
    .filter((note) => note.owner_id === userId)
    .sort((left, right) => {
      return new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime();
    });
}

function getUserNoteSummaries(userId) {
  return getUserNotes(userId).map(makeNoteSummary);
}

function broadcastToUser(userId, payload) {
  wss.clients.forEach((client) => {
    if (
      client.readyState === WebSocket.OPEN &&
      client.isAuthenticated &&
      client.userId === userId
    ) {
      client.send(JSON.stringify(payload));
    }
  });
}

function broadcastNotesList(userId) {
  broadcastToUser(userId, {
    type: "notes-list",
    notes: getUserNoteSummaries(userId),
  });
}

async function refreshUsersCache() {
  const result = await pool.query(`
    SELECT id, username, password_hash, created_at
    FROM users
  `);

  usersCache = new Map(result.rows.map((row) => [row.id, row]));
}

async function refreshNotesCache() {
  const result = await pool.query(`
    SELECT id, owner_id, title, content, version, updated_at
    FROM notes
  `);

  notesCache = new Map(result.rows.map((row) => [row.id, row]));
}

async function initializeStorage() {
  const seedText = fs.existsSync(FILE) ? fs.readFileSync(FILE, "utf8") : "";

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notes (
      id UUID PRIMARY KEY,
      owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      version INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE notes
    ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES users(id) ON DELETE CASCADE
  `);

  await pool.query(`
    ALTER TABLE notes
    ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 0
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS shared_note (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      content TEXT NOT NULL DEFAULT '',
      version INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const noteCountResult = await pool.query("SELECT COUNT(*)::int AS count FROM notes");

  if ((noteCountResult.rows[0]?.count || 0) === 0) {
    const legacyResult = await pool.query(
      "SELECT content FROM shared_note WHERE id = 1 LIMIT 1"
    );
    const legacyText = legacyResult.rows[0]?.content ?? seedText;

    if (legacyText) {
      await pool.query(
        `
          INSERT INTO notes (id, owner_id, title, content)
          VALUES ($1, NULL, $2, $3)
        `,
        [crypto.randomUUID(), "My First Note", legacyText]
      );
    }
  }

  await refreshUsersCache();
  await refreshNotesCache();
}

async function getUserByUsername(username) {
  const normalizedUsername = username.trim().toLowerCase();

  const result = await pool.query(
    `
      SELECT id, username, password_hash, created_at
      FROM users
      WHERE username = $1
      LIMIT 1
    `,
    [normalizedUsername]
  );

  return result.rows[0] || null;
}

async function createUser(username, password) {
  const normalizedUsername = username.trim().toLowerCase();
  const passwordHash = hashPassword(password);
  const userId = crypto.randomUUID();

  const result = await pool.query(
    `
      INSERT INTO users (id, username, password_hash)
      VALUES ($1, $2, $3)
      RETURNING id, username, password_hash, created_at
    `,
    [userId, normalizedUsername, passwordHash]
  );

  const user = result.rows[0];
  usersCache.set(user.id, user);

  const usersCountResult = await pool.query("SELECT COUNT(*)::int AS count FROM users");

  if ((usersCountResult.rows[0]?.count || 0) === 1) {
    await pool.query(
      `
        UPDATE notes
        SET owner_id = $1
        WHERE owner_id IS NULL
      `,
      [user.id]
    );
    await refreshNotesCache();
  }

  return user;
}

async function updateUserPassword(userId, nextPassword) {
  const passwordHash = hashPassword(nextPassword);

  const result = await pool.query(
    `
      UPDATE users
      SET password_hash = $1
      WHERE id = $2
      RETURNING id, username, password_hash, created_at
    `,
    [passwordHash, userId]
  );

  const user = result.rows[0] || null;

  if (user) {
    usersCache.set(user.id, user);
  }

  return user;
}

async function createNote(ownerId, title, content = "") {
  const noteId = crypto.randomUUID();
  const trimmedTitle = typeof title === "string" ? title.trim() : "";
  const safeTitle = trimmedTitle || "Untitled Note";

  const result = await pool.query(
    `
      INSERT INTO notes (id, owner_id, title, content)
      VALUES ($1, $2, $3, $4)
      RETURNING id, owner_id, title, content, version, updated_at
    `,
    [noteId, ownerId, safeTitle, content]
  );

  const note = result.rows[0];
  notesCache.set(note.id, note);
  return note;
}

function getNoteByIdForUser(noteId, userId) {
  const note = notesCache.get(noteId) || null;

  if (!note || note.owner_id !== userId) {
    return null;
  }

  return note;
}

async function saveNoteContent(noteId, ownerId, nextText) {
  const result = await pool.query(
    `
      UPDATE notes
      SET content = $1, version = version + 1, updated_at = NOW()
      WHERE id = $2 AND owner_id = $3
      RETURNING id, owner_id, title, content, version, updated_at
    `,
    [nextText, noteId, ownerId]
  );

  const note = result.rows[0] || null;

  if (note) {
    notesCache.set(note.id, note);
  }

  return note;
}

async function renameNote(noteId, ownerId, nextTitle) {
  const trimmedTitle = typeof nextTitle === "string" ? nextTitle.trim() : "";
  const safeTitle = trimmedTitle || "Untitled Note";

  const result = await pool.query(
    `
      UPDATE notes
      SET title = $1, updated_at = NOW()
      WHERE id = $2 AND owner_id = $3
      RETURNING id, owner_id, title, content, version, updated_at
    `,
    [safeTitle, noteId, ownerId]
  );

  const note = result.rows[0] || null;

  if (note) {
    notesCache.set(note.id, note);
  }

  return note;
}

async function deleteNote(noteId, ownerId) {
  const result = await pool.query(
    `
      DELETE FROM notes
      WHERE id = $1 AND owner_id = $2
      RETURNING id, owner_id, title, content, version, updated_at
    `,
    [noteId, ownerId]
  );

  const note = result.rows[0] || null;

  if (note) {
    notesCache.delete(note.id);
  }

  return note;
}

function enqueueNoteUpdate(noteId, ownerId, nextText, sourceClientId) {
  updateChain = updateChain
    .then(async () => {
      const note = await saveNoteContent(noteId, ownerId, nextText);

      if (!note) {
        return;
      }

      broadcastToUser(ownerId, {
        type: "note-update",
        noteId: note.id,
        text: note.content,
        version: note.version,
        updatedAt: note.updated_at,
        sourceClientId: sourceClientId || null,
      });

      broadcastNotesList(ownerId);
    })
    .catch((error) => {
      console.error("Failed to persist update:", error);
    });

  return updateChain;
}

function attachAuthRoutes() {
  app.post("/api/auth/register", async (req, res) => {
    try {
      const username = typeof req.body?.username === "string" ? req.body.username : "";
      const password = typeof req.body?.password === "string" ? req.body.password : "";

      if (username.trim().length < 3 || password.length < 6) {
        res.status(400).json({
          error: "Username must be at least 3 characters and password at least 6.",
        });
        return;
      }

      if (await getUserByUsername(username)) {
        res.status(409).json({ error: "Username already exists." });
        return;
      }

      const user = await createUser(username, password);
      const token = createSessionToken(user);

      res.status(201).json({
        token,
        user: {
          id: user.id,
          username: user.username,
        },
      });
    } catch (error) {
      console.error("Failed to register:", error);
      res.status(500).json({ error: "Could not register user." });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    try {
      const username = typeof req.body?.username === "string" ? req.body.username : "";
      const password = typeof req.body?.password === "string" ? req.body.password : "";
      const user = await getUserByUsername(username);

      if (!user || !verifyPassword(password, user.password_hash)) {
        res.status(401).json({ error: "Invalid username or password." });
        return;
      }

      const token = createSessionToken(user);

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
        },
      });
    } catch (error) {
      console.error("Failed to login:", error);
      res.status(500).json({ error: "Could not log in." });
    }
  });

  app.get("/api/auth/me", ensureAuthorized, (req, res) => {
    res.json({
      user: {
        id: req.user.id,
        username: req.user.username,
      },
    });
  });

  app.post("/api/auth/change-password", ensureAuthorized, async (req, res) => {
    try {
      const currentPassword =
        typeof req.body?.currentPassword === "string" ? req.body.currentPassword : "";
      const newPassword =
        typeof req.body?.newPassword === "string" ? req.body.newPassword : "";

      if (!verifyPassword(currentPassword, req.user.password_hash)) {
        res.status(401).json({ error: "Current password is incorrect." });
        return;
      }

      if (newPassword.length < 6) {
        res.status(400).json({ error: "New password must be at least 6 characters." });
        return;
      }

      if (verifyPassword(newPassword, req.user.password_hash)) {
        res.status(400).json({ error: "New password must be different from the current password." });
        return;
      }

      await updateUserPassword(req.user.id, newPassword);
      const refreshedUser = usersCache.get(req.user.id);
      const token = createSessionToken(refreshedUser);

      res.json({
        token,
        user: {
          id: refreshedUser.id,
          username: refreshedUser.username,
        },
      });
    } catch (error) {
      console.error("Failed to change password:", error);
      res.status(500).json({ error: "Could not change password." });
    }
  });
}

function attachNoteRoutes() {
  app.get("/api/notes", ensureAuthorized, (req, res) => {
    res.json({ notes: getUserNoteSummaries(req.user.id) });
  });

  app.get("/api/notes/:id", ensureAuthorized, (req, res) => {
    const note = getNoteByIdForUser(req.params.id, req.user.id);

    if (!note) {
      res.status(404).json({ error: "Note not found" });
      return;
    }

    res.json({
      note: {
        id: note.id,
        title: note.title,
        text: note.content,
        version: note.version,
        updatedAt: note.updated_at,
      },
    });
  });

  app.post("/api/notes", ensureAuthorized, async (req, res) => {
    try {
      const title = typeof req.body?.title === "string" ? req.body.title : "";
      const note = await createNote(req.user.id, title, "");

      broadcastToUser(req.user.id, {
        type: "note-created",
        note: makeNoteSummary(note),
      });
      broadcastNotesList(req.user.id);

      res.status(201).json({
        note: {
          id: note.id,
          title: note.title,
          text: note.content,
          version: note.version,
          updatedAt: note.updated_at,
        },
      });
    } catch (error) {
      console.error("Failed to create note:", error);
      res.status(500).json({ error: "Could not create note" });
    }
  });

  app.patch("/api/notes/:id", ensureAuthorized, async (req, res) => {
    try {
      const title = typeof req.body?.title === "string" ? req.body.title : "";
      const note = await renameNote(req.params.id, req.user.id, title);

      if (!note) {
        res.status(404).json({ error: "Note not found" });
        return;
      }

      broadcastToUser(req.user.id, {
        type: "note-renamed",
        note: makeNoteSummary(note),
      });
      broadcastNotesList(req.user.id);

      res.json({
        note: {
          id: note.id,
          title: note.title,
          text: note.content,
          version: note.version,
          updatedAt: note.updated_at,
        },
      });
    } catch (error) {
      console.error("Failed to rename note:", error);
      res.status(500).json({ error: "Could not rename note" });
    }
  });

  app.delete("/api/notes/:id", ensureAuthorized, async (req, res) => {
    try {
      const note = await deleteNote(req.params.id, req.user.id);

      if (!note) {
        res.status(404).json({ error: "Note not found" });
        return;
      }

      broadcastToUser(req.user.id, {
        type: "note-deleted",
        note: makeNoteSummary(note),
      });
      broadcastNotesList(req.user.id);

      res.json({
        deleted: true,
        noteId: note.id,
      });
    } catch (error) {
      console.error("Failed to delete note:", error);
      res.status(500).json({ error: "Could not delete note" });
    }
  });
}

function attachWebSocketServer(server) {
  wss = new WebSocket.Server({ server });

  wss.on("connection", (ws) => {
    ws.isAuthenticated = false;
    ws.clientId = null;
    ws.userId = null;

    ws.on("message", async (message) => {
      try {
        const data = JSON.parse(message);

        if (data.type === "auth") {
          const payload = verifySessionToken(data.token);
          const user = payload ? usersCache.get(payload.userId) : null;

          if (!user) {
            ws.send(JSON.stringify({ type: "auth-error" }));
            ws.close();
            return;
          }

          ws.isAuthenticated = true;
          ws.clientId = typeof data.clientId === "string" ? data.clientId : null;
          ws.userId = user.id;

          const notes = getUserNoteSummaries(user.id);
          const firstNote = notes[0] ? getNoteByIdForUser(notes[0].id, user.id) : null;

          ws.send(
            JSON.stringify({
              type: "init",
              user: {
                id: user.id,
                username: user.username,
              },
              notes,
              activeNote: firstNote
                ? {
                    id: firstNote.id,
                    title: firstNote.title,
                    text: firstNote.content,
                    version: firstNote.version,
                    updatedAt: firstNote.updated_at,
                  }
                : null,
            })
          );
          return;
        }

        if (!ws.isAuthenticated || !ws.userId) {
          ws.close();
          return;
        }

        if (data.type === "update-note") {
          const noteId = typeof data.noteId === "string" ? data.noteId : "";
          const nextText = typeof data.text === "string" ? data.text : "";

          if (!getNoteByIdForUser(noteId, ws.userId)) {
            return;
          }

          await enqueueNoteUpdate(noteId, ws.userId, nextText, ws.clientId);
        }
      } catch (error) {
        console.error("Error:", error);
      }
    });
  });
}

async function start() {
  await initializeStorage();
  attachAuthRoutes();
  attachNoteRoutes();

  const server = app.listen(PORT, () => {
    console.log("Running on port " + PORT);
  });

  attachWebSocketServer(server);
}

start().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
