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

app.use(express.static(path.join(__dirname)));

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

let currentText = "";
let currentVersion = 0;
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

function broadcastCurrentText() {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.isAuthenticated) {
      client.send(
        JSON.stringify({
          type: "update",
          text: currentText,
          version: currentVersion,
        })
      );
    }
  });
}

function ensureAuthorized(req, res, next) {
  const passcode = req.get("x-notepad-passcode");

  if (!isValidPasscode(passcode)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  next();
}

async function initializeStorage() {
  const seedText = fs.existsSync(FILE) ? fs.readFileSync(FILE, "utf8") : "";

  await pool.query(`
    CREATE TABLE IF NOT EXISTS shared_note (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      content TEXT NOT NULL DEFAULT '',
      version INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE shared_note
    ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 0
  `);

  await pool.query(
    `
      INSERT INTO shared_note (id, content)
      VALUES (1, $1)
      ON CONFLICT (id) DO NOTHING
    `,
    [seedText]
  );

  const result = await pool.query(
    "SELECT content, version FROM shared_note WHERE id = 1 LIMIT 1"
  );

  currentText = result.rows[0]?.content || "";
  currentVersion = result.rows[0]?.version || 0;
}

async function saveCurrentText(nextText) {
  const result = await pool.query(
    `
      UPDATE shared_note
      SET content = $1, version = version + 1, updated_at = NOW()
      WHERE id = 1
      RETURNING version
    `,
    [nextText]
  );

  currentVersion = result.rows[0]?.version || currentVersion;
}

function enqueueUpdate(nextText) {
  updateChain = updateChain
    .then(async () => {
      currentText = nextText;
      await saveCurrentText(currentText);
      broadcastCurrentText();
    })
    .catch((error) => {
      console.error("Failed to persist update:", error);
    });

  return updateChain;
}

function attachWebSocketServer(server) {
  wss = new WebSocket.Server({ server });

  wss.on("connection", (ws) => {
    console.log("Client connected");
    ws.isAuthenticated = false;
    ws.failedAuthAttempts = 0;

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
          ws.failedAuthAttempts = 0;
          ws.send(
            JSON.stringify({
              type: "init",
              text: currentText,
              version: currentVersion,
            })
          );
          return;
        }

        if (!ws.isAuthenticated) {
          ws.close();
          return;
        }

        if (data.type === "update") {
          const nextText = typeof data.text === "string" ? data.text : "";
          await enqueueUpdate(nextText);
        }
      } catch (err) {
        console.error("Error:", err);
      }
    });
  });
}

async function start() {
  await initializeStorage();

  app.get("/api/note", ensureAuthorized, (_req, res) => {
    res.json({
      text: currentText,
      version: currentVersion,
    });
  });

  const server = app.listen(PORT, () => {
    console.log("Running on port " + PORT);
  });

  attachWebSocketServer(server);
}

start().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
