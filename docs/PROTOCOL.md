# omakeepickd protocol

`omakeepickd` is the helper daemon behind the OmaKeePick shell plugin. It is the only
process that ever opens the KDBX file or holds decrypted secrets. The QML plugin talks to it
with newline-delimited JSON (one JSON object per line, UTF-8).

## Transport

* The daemon (`omakeepickd serve`) listens on `$XDG_RUNTIME_DIR/omakeepick/sock`
  (directory `0700`, socket `0600`). Connections from other uids are rejected (`SO_PEERCRED`).
* `omakeepickd attach` is the bridge used by QML: it connects to the socket (spawning
  `omakeepickd serve` in its own session if nothing is listening yet), copies stdin lines to
  the socket and socket lines to stdout. It exits when either side closes. The daemon keeps
  running (and stays unlocked) when the shell restarts.
* `omakeepickd ctl <cmd> [json-args]` sends one request and prints the reply line, e.g.
  `omakeepickd ctl lock`, `omakeepickd ctl status`, `omakeepickd ctl search '{"query":"git"}'`.
  Useful from hooks and for testing. It never auto-spawns the daemon (exit code 3 if the daemon
  is not running).

## Messages

Request (client → daemon):

```json
{"id": 7, "cmd": "search", "query": "git", "limit": 50}
```

`id` is any integer chosen by the client; it is echoed in the reply. Requests are answered
in order per connection, except `unlock`, `quickUnlock`, `act` and `pickFile`, which can take a
while and may be answered after later requests.

Reply (daemon → client):

```json
{"id": 7, "ok": true, ...result fields}
{"id": 7, "ok": false, "error": "locked", "message": "Database is locked"}
```

A `message` never quotes database contents (entry titles, field values, auto-type sequences),
so a client may show it in a desktop notification.

Event (daemon → client, unsolicited, no `id`):

```json
{"event": "state", ...state fields}
{"event": "notice", "level": "info" | "warning" | "error", "message": "Database reloaded"}
```

A `state` event is sent right after a client connects and after every state change.

## State

```json
{
  "event": "state",
  "phase": "closed" | "locked" | "unlocked",
  "busy": false,
  "quickUnlock": false,
  "pinAttemptsLeft": 0,
  "db": "/home/me/Secrets.kdbx",
  "keyfile": "/home/me/Secrets.keyx",
  "dbName": "Secrets",
  "entryCount": 0,
  "lockAt": 1761400000000,
  "idleLockMinutes": 30,
  "lockReason": "manual" | "idle" | "screen" | "sleep" | "pin" | "closed" | null
}
```

* `phase`
  * `closed`: no database is open and no quick-unlock key exists. `db`/`keyfile` hold the
    *last used* paths (for pre-filling the unlock card) or `null`.
  * `locked`: a database was open and is now locked. `db`/`keyfile` are its paths. If
    `quickUnlock` is true the PIN (`quickUnlock` command) re-opens it; otherwise a full
    `unlock` is required.
  * `unlocked`: entries can be searched and used.
* `busy`: an unlock (key derivation) or reload is in progress. Show a spinner, ignore input.
* `pinAttemptsLeft`: remaining PIN tries while `quickUnlock` is true (starts at 3).
* `lockAt`: Unix epoch milliseconds when the idle timer will lock the database, or `null`.
  Every `search`, `act` and `touch` pushes it forward.
* `lockReason`: why the database last left the unlocked phase.
  `sleep` and `pin` (too many wrong PINs) and `closed` always wipe the quick-unlock key.

## Commands

| cmd | arguments | success result | errors |
|---|---|---|---|
| `status` | — | `{"state": {…}}` | — |
| `configure` | `settings: {…}` (see below, all optional) | `{}` | `bad_request` |
| `unlock` | `db` (path), `keyfile` (path or null), `password` (string, may be empty if a key file is given), `pin` (string or null) | `{}` | `busy`, `not_found`, `bad_credentials`, `keyfile_error`, `format_error`, `bad_request` |
| `quickUnlock` | `pin` | `{}` | `no_quick_unlock`, `bad_pin` (+ `attemptsLeft`), `busy` |
| `lock` | `reason` (optional, `manual` default; `screen` from the lock-screen watcher) | `{}` | — |
| `close` | — | `{}` | — |
| `search` | `query` (string), `limit` (int, default 50) | `{"entries": [Entry…], "total": n}` | `locked` |
| `act` | `entry` (entry id), `action` (see below) | `{}`; copy actions: `{"clearsIn": seconds, "copied": "password"}` | `locked`, `not_found`, `no_field`, `autotype_disabled`, `tool_missing`, `failed` |
| `pickFile` | `kind`: `db` or `keyfile` | `{"path": "/abs/path", "keyfile": "/abs/path" \| null}` (for `db`: the key file last used with that database) | `cancelled`, `failed` |
| `touch` | — | `{}` | — |
| `quit` | — | `{}` (the daemon locks, wipes and exits) | — |

`search` with an empty query returns the most recently / frequently used entries
(at most `recentCount` of them, possibly none).

### Entry (search result)

Never contains secrets: no password, notes, custom field values or TOTP secret.

```json
{
  "id": "6f1c…-uuid",
  "title": "GitHub",
  "username": "madev",
  "group": "Personal/Dev",
  "hasUsername": true,
  "hasPassword": true,
  "hasUrl": true,
  "hasTotp": false,
  "autotype": true
}
```

`group` is the path below the root group (root name omitted), `/`-separated, `""` for the root.

### Actions

| action | what the daemon does |
|---|---|
| `autotype` | waits `autotypeStartDelayMs` (so the overlay can hide and focus return), then types the entry's auto-type sequence into the focused window |
| `typePassword` | same, but types only `{PASSWORD}` |
| `copyUsername`, `copyPassword`, `copyUrl`, `copyTotp` | copies the value with `wl-copy --sensitive`; clears the clipboard after `clipboardClearSeconds` if it still holds that value |

The client must hide the overlay **before** sending `autotype` / `typePassword`.

### Settings (`configure`)

| key | default | meaning |
|---|---|---|
| `idleLockMinutes` | 30 | lock after this many minutes without `search`/`act`/`touch`; 0 disables |
| `clipboardClearSeconds` | 15 | 0 disables clearing |
| `autotypeSequence` | `{USERNAME}{TAB}{PASSWORD}{ENTER}` | default sequence (KeePass syntax); entry / group sequences override it |
| `typeDelayMs` | 8 | delay between typed characters |
| `autotypeStartDelayMs` | 250 | delay before typing starts |
| `recentCount` | 8 | number of entries returned for an empty query |
