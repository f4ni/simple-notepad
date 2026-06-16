# Simple Notepad

A private, multi-note web app with live sync, basic rich text, sharing, and installable app support. Each account owns its own notes, edits stream to other open tabs and collaborators over WebSockets, and everything persists in PostgreSQL.

## About

- Name: Simple Notepad. The package name is `simple-notepad`, and the same display name "Simple Notepad" is used for the browser title, the web manifest, the apple mobile web app title, and the Electron window.
- Version: 1.0.0 (from `package.json`).
- License: ISC.
- Type: CommonJS Node project (`"type": "commonjs"`), no build step.
- Entry points: `server.js` for the web server (`npm start`), `electron-main.js` for the desktop wrapper (`npm run desktop`), and `index.html` as the single-file client.
- Description (from the page meta tag): a private multi-note app with sync, formatting, and installable app support.
- Theme color: `#1f1a14`, with a default page background of `#f3f0e8`.

Runtime dependencies are `express` (HTTP and static serving), `ws` (WebSocket sync), `pg` (PostgreSQL access), `electron` (desktop shell), and `cors` (listed but currently unused).

## What you can do

You sign in or register, then create as many notes as you want from the sidebar. Selecting a note opens it on a centered editor sheet where you can type, make text bold or underlined, add bullet or numbered lists, and watch changes save on their own. The sidebar filters notes by All, My Notes, or Shared, and a search box in the top bar filters the list by title. You can rename a note, share it with another user as a viewer or editor through a collaborator dialog, and delete notes you own. Theme, editor background color, and font size are set in the settings dialog and remembered per browser. The app can be installed as a standalone app on desktop or mobile through its web manifest and service worker, and there is an Electron wrapper that loads a hosted instance in a desktop window.

The interface follows the Serene Script design system in `stitch_responsive_cross_platform_ui/serene_script/DESIGN.md`: Hanken Grotesk for UI text, Source Serif 4 for the editor, a fixed 280px sidebar, an 800px editor column, and the four named themes.

## Architecture at a glance

The whole client lives in a single `index.html` file: markup, CSS, and a vanilla JavaScript app with no build step. The backend is one Express server in `server.js` that serves the static files, exposes a JSON API for auth and notes, and runs a WebSocket server on the same HTTP server for live updates. State is kept in PostgreSQL (`pg` pool) and mirrored in in-memory caches for fast reads and broadcasts. `electron-main.js` is a thin desktop shell that loads a remote URL.

```
Browser (index.html)
  |  REST (fetch)  ->  Express routes (auth + notes)
  |  WebSocket     ->  ws server (init, live note updates, list changes)
  v
Express (server.js)  ->  PostgreSQL (users, notes, note_permissions)
                         in-memory caches mirror the tables
```

## Features

### Accounts and sessions

Registration requires a username of at least 3 characters and a password of at least 6. Usernames are normalized to lowercase and must be unique. Passwords are hashed with `scrypt` and a per-user random salt, stored as `salt:hash`. Verification uses a constant-time compare.

Sessions use a signed token, not a server-side session store. On login the server builds a payload of `userId`, `username`, and an expiry (`exp`), base64url encodes it, and appends an HMAC-SHA256 signature keyed by `SESSION_SECRET`. Tokens live for 30 days (`SESSION_TTL_MS`). The client stores the token in `localStorage` under `simple-notepad-session` and sends it as `Authorization: Bearer <token>` on API calls and in the WebSocket `auth` message. Any 401 from the API clears the stored session and returns the user to the sign-in screen.

Users can change their password from the settings dialog. The server checks the current password, requires the new one to be at least 6 characters and different from the old, then issues a fresh token.

### Notes

Notes belong to an owner and carry a title, content, an integer `version`, and an `updated_at` timestamp. Creating a note from the sidebar defaults an empty title to "Untitled Note". Titles are truncated to 200 characters (`MAX_TITLE_LENGTH`) and content over 1,000,000 characters (`MAX_NOTE_CONTENT_LENGTH`) is dropped before it persists. Content is stored as sanitized HTML so formatting survives a reload. The note list is sorted by most recently updated.

Every content save increments `version` and updates `updated_at`. The client tracks the active note's version so it can tell its own echoed updates from changes made elsewhere and avoid clobbering what you are typing.

### Live editing and sync

Typing in the editor is debounced about 60ms, then the current HTML is sent over the WebSocket as an `update-note` message. The server writes updates through a single promise chain (`updateChain`) so concurrent saves apply in order, then broadcasts a `note-update` to every user who can access that note. Each broadcast carries the `sourceClientId` so the tab that made the edit can update its metadata without replacing the editor contents. Other tabs and collaborators that are behind apply the new text.

As a backup to the live channel, the client polls every 5 seconds to refresh the note list and re-pull the active note if its version moved. If the socket drops, the client retries the connection after 1 second.

### Sharing and permissions

A note has three access roles: owner, editor, and viewer. The owner is the user in `notes.owner_id`. Editors and viewers come from the `note_permissions` table. Owners and editors can change content and rename; viewers are read-only and the editor switches to non-editable for them. Only the owner can share, revoke access, or delete a note.

The owner opens the share dialog from the top bar Share button. It lists current collaborators with their roles, loads them from `GET /api/notes/:id/shares`, and lets the owner invite by username, change a collaborator's role inline (an upsert, so re-sharing updates the existing role), and remove access. Revoking access sends a `note-access-revoked` message to that user so the note disappears from their list in real time. When a shared note changes, the server figures out every user with access (owner plus everyone in the permission map) and broadcasts to all of them.

### Rich text editor

The editor is a `contenteditable` region on a paper-like sheet with a sticky toolbar. Bold, underline, bullet list, and numbered list use `document.execCommand`, and the bold and underline buttons reflect the current selection state. Pasting is intercepted and inserted as plain text converted to safe HTML, so you do not paste styled markup from elsewhere. Before content is shown, incoming HTML is run through a sanitizer that allows only a small tag set (`b`, `strong`, `u`, `br`, `div`, `p`, `ul`, `ol`, `li`) and strips everything else. Italic is not offered because `i` and `em` are not in that allowlist.

### Appearance preferences

The settings dialog holds four theme cards (sand, mist, forest, midnight), a background color picker for the editor surface, and a font size slider (14 to 32) with a live preview. Sand and mist are light, forest and midnight are dark, and each theme drives a set of CSS variables defined in the `THEMES` object. Editor text color is chosen automatically for contrast against the background using a brightness calculation, and font size also changes with Ctrl plus mouse wheel over the editor. All three preferences are saved in `localStorage` under `simple-notepad-preferences`, so they are per-browser, not per-account.

### Installable app (PWA) and desktop

`index.html` links a web manifest and registers `service-worker.js`. The service worker pre-caches the app shell (manifest and icons) and serves cached assets when offline, while always fetching the root document fresh from the network so the app code stays current. `electron-main.js` opens a 1280x840 window with the menu bar hidden, loads the URL from `ELECTRON_APP_URL`, and forces external links to open in the system browser.

## API reference

All note routes and `/api/auth/me` and `/api/auth/change-password` require a valid bearer token.

Auth:

- `POST /api/auth/register` with `{ username, password }`, returns `{ token, user }`.
- `POST /api/auth/login` with `{ username, password }`, returns `{ token, user }`.
- `GET /api/auth/me`, returns the current `{ user }`.
- `POST /api/auth/change-password` with `{ currentPassword, newPassword }`, returns a new `{ token, user }`.

Notes:

- `GET /api/notes`, returns summaries of every note you can access.
- `GET /api/notes/:id`, returns the full note with your `accessRole`.
- `POST /api/notes` with `{ title }`, creates a note you own.
- `PATCH /api/notes/:id` with `{ title }`, renames (owner or editor only).
- `DELETE /api/notes/:id`, deletes (owner only).
- `GET /api/notes/:id/shares`, lists collaborators (owner only).
- `POST /api/notes/:id/share` with `{ username, role }` where role is `viewer` or `editor` (owner only).
- `DELETE /api/notes/:id/share/:userId`, revokes a collaborator (owner only).

## WebSocket protocol

The client connects to the same host, then sends `{ type: "auth", token, clientId }`. On success the server replies with an `init` message containing the user, the note list, and the first note's full contents. After that the client sends `{ type: "update-note", noteId, text }` to save edits.

Messages the server sends:

- `init`: user, notes, and the active note on connect.
- `notes-list`: a refreshed list of note summaries.
- `note-created`, `note-renamed`, `note-deleted`: list changes.
- `note-update`: new content, `version`, `updatedAt`, and `sourceClientId`.
- `note-access-revoked`: a note you can no longer see.
- `auth-error`: the token was rejected; the client signs out.

## Data model

`users`: `id` (UUID), `username` (unique), `password_hash`, `created_at`.

`notes`: `id` (UUID), `owner_id` (references users, cascade delete), `title`, `content`, `version`, `updated_at`.

`note_permissions`: composite key of `note_id` and `user_id`, a `role` constrained to `viewer` or `editor`, plus `granted_by` and `created_at`.

`shared_note`: a legacy single-row table kept for migration. On first run, if there are no notes, the server seeds one note from this table or from a local `data.txt` file, and assigns ownership to the first user who registers.

On startup `initializeStorage` creates the tables if missing, adds the `owner_id` and `version` columns to `notes` if an older schema is found, runs the one-time seed, and loads users, notes, and permissions into the in-memory caches.

## Running it

Install dependencies, set the required environment variables, then start the server.

```bash
npm install
```

Set these (see `.env.example`):

- `DATABASE_URL`: PostgreSQL connection string. Required; the server exits without it.
- `SESSION_SECRET`: long random string used to sign session tokens. Required; the server exits without it.
- `PORT`: optional, defaults to 3000.

Start the web server:

```bash
npm start
```

Open `http://localhost:3000`.

To run the desktop wrapper, set `ELECTRON_APP_URL` to your hosted instance (see `desktop.env.example`) and run:

```bash
npm run desktop
```

## Gotchas

Preferences live in `localStorage`, so themes and font size do not follow you to another device or browser. Sessions are stateless tokens with no server-side revocation; changing your password issues a new token but does not invalidate old ones before they expire. The `alert` and `prompt`-style flows for share results use the browser's native `alert`. The seed logic that imports `data.txt` or the legacy `shared_note` row only runs when the `notes` table is empty.
