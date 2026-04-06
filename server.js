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
const PASSCODE = process.env.NOTEPAD_PASSCODE;
const MAX_AUTH_ATTEMPTS = 5;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL environment variable.");
  process.exit(1);
}

if (!PASSCODE) {
  console.error("Missing NOTEPAD_PASSCODE environment variable.");
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
let wss;
let updateChain = Promise.resolve();

function isValidPasscode(input) {
  if (typeof input !== "string") {
    return false;
  }

  const expected = Buffer.from(PASSCODE, "utf8");
  const actual = Buffer.from(input, "utf8");

  if (expected.length !== actual.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, actual);
}

function ensureAuthorized(req, res, next) {
  const passcode = req.get("x-notepad-passcode");

  if (!isValidPasscode(passcode)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

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

function getSortedNoteSummaries() {
  return Array.from(notesCache.values())
    .sort((left, right) => {
      return new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime();
    })
    .map(makeNoteSummary);
}

function broadcast(payload) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.isAuthenticated) {
      client.send(JSON.stringify(payload));
    }
  });
}

function broadcastNotesList() {
  broadcast({
    type: "notes-list",
    notes: getSortedNoteSummaries(),
  });
}

async function initializeStorage() {
  const seedText = fs.existsSync(FILE) ? fs.readFileSync(FILE, "utf8") : "";

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notes (
      id UUID PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      version INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
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
  const noteCount = noteCountResult.rows[0]?.count || 0;

  if (noteCount === 0) {
    const legacyResult = await pool.query(
      "SELECT content FROM shared_note WHERE id = 1 LIMIT 1"
    );
    const legacyText = legacyResult.rows[0]?.content ?? seedText;

    await createNote("My First Note", legacyText);
  }

  await refreshNotesCache();
}

async function refreshNotesCache() {
  const result = await pool.query(`
    SELECT id, title, content, version, updated_at
    FROM notes
  `);

  notesCache = new Map(result.rows.map((row) => [row.id, row]));
}

async function createNote(title, content = "") {
  const noteId = crypto.randomUUID();
  const trimmedTitle = typeof title === "string" ? title.trim() : "";
  const safeTitle = trimmedTitle || "Untitled Note";

  const result = await pool.query(
    `
      INSERT INTO notes (id, title, content)
      VALUES ($1, $2, $3)
      RETURNING id, title, content, version, updated_at
    `,
    [noteId, safeTitle, content]
  );

  const note = result.rows[0];
  notesCache.set(note.id, note);
  return note;
}

function getNoteById(noteId) {
  return notesCache.get(noteId) || null;
}

async function saveNoteContent(noteId, nextText) {
  const result = await pool.query(
    `
      UPDATE notes
      SET content = $1, version = version + 1, updated_at = NOW()
      WHERE id = $2
      RETURNING id, title, content, version, updated_at
    `,
    [nextText, noteId]
  );

  const note = result.rows[0] || null;

  if (note) {
    notesCache.set(note.id, note);
  }

  return note;
}

function enqueueNoteUpdate(noteId, nextText, sourceClientId) {
  updateChain = updateChain
    .then(async () => {
      const note = await saveNoteContent(noteId, nextText);

      if (!note) {
        return;
      }

      broadcast({
        type: "note-update",
        noteId: note.id,
        text: note.content,
        version: note.version,
        updatedAt: note.updated_at,
        sourceClientId: sourceClientId || null,
      });

      broadcastNotesList();
    })
    .catch((error) => {
      console.error("Failed to persist update:", error);
    });

  return updateChain;
}

function attachApiRoutes() {
  app.get("/api/notes", ensureAuthorized, (_req, res) => {
    res.json({ notes: getSortedNoteSummaries() });
  });

  app.get("/api/notes/:id", ensureAuthorized, (req, res) => {
    const note = getNoteById(req.params.id);

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
      const note = await createNote(title, "");
      broadcast({
        type: "note-created",
        note: makeNoteSummary(note),
      });
      broadcastNotesList();
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
}

function attachWebSocketServer(server) {
  wss = new WebSocket.Server({ server });

  wss.on("connection", (ws) => {
    ws.isAuthenticated = false;
    ws.failedAuthAttempts = 0;
    ws.clientId = null;

    ws.on("message", async (message) => {
      try {
        const data = JSON.parse(message);

        if (data.type === "auth") {
          if (!isValidPasscode(data.pass)) {
            ws.failedAuthAttempts += 1;
            ws.send(JSON.stringify({ type: "auth-error" }));

            if (ws.failedAuthAttempts >= MAX_AUTH_ATTEMPTS) {
              ws.close();
            }

            return;
          }

          ws.isAuthenticated = true;
          ws.clientId = typeof data.clientId === "string" ? data.clientId : null;
          ws.failedAuthAttempts = 0;

          const notes = getSortedNoteSummaries();
          const firstNote = notes[0] ? getNoteById(notes[0].id) : null;

          ws.send(
            JSON.stringify({
              type: "init",
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

        if (!ws.isAuthenticated) {
          ws.close();
          return;
        }

        if (data.type === "update-note") {
          const noteId = typeof data.noteId === "string" ? data.noteId : "";
          const nextText = typeof data.text === "string" ? data.text : "";

          if (!getNoteById(noteId)) {
            return;
          }

          await enqueueNoteUpdate(noteId, nextText, ws.clientId);
        }
      } catch (error) {
        console.error("Error:", error);
      }
    });
  });
}

async function start() {
  await initializeStorage();
  attachApiRoutes();

  const server = app.listen(PORT, () => {
    console.log("Running on port " + PORT);
  });

  attachWebSocketServer(server);
}

start().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
