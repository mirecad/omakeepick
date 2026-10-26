const test = require("node:test")
const assert = require("node:assert/strict")

const Model = require("../Model.js")

const { KEYS, MODS } = Model

function state(overrides = {}) {
  return {
    event: "state",
    phase: "unlocked",
    busy: false,
    quickUnlock: false,
    pinAttemptsLeft: 0,
    db: "/home/me/Secrets.kdbx",
    keyfile: null,
    dbName: "Secrets",
    entryCount: 245,
    lockAt: 1761400000000,
    idleLockMinutes: 30,
    lockReason: null,
    ...overrides
  }
}

// ------------------------------------------------------------- keys

test("Qt key and modifier values match Qt's enums", () => {
  assert.equal(KEYS.Escape, 0x01000000)
  assert.equal(KEYS.Return, 0x01000004)
  assert.equal(KEYS.Enter, 0x01000005)
  assert.equal(KEYS.Down, 0x01000015)
  assert.equal(KEYS.B, "B".charCodeAt(0))
  assert.equal(KEYS.T, "T".charCodeAt(0))
  assert.equal(MODS.Control, 0x04000000)
  assert.equal(MODS.Keypad, 0x20000000)
})

test("search keys map to the documented actions", () => {
  const c = (key, mods = 0, text = "") => Model.searchCommand(key, mods, text)
  assert.equal(c(KEYS.Return), "copyPassword")
  assert.equal(c(KEYS.Enter, MODS.Keypad), "copyPassword")
  assert.equal(c(KEYS.Return, MODS.Shift), "copyPassword", "a Shift left down from a capital")
  assert.equal(c(KEYS.Return, MODS.Control), "autotype")
  assert.equal(c(KEYS.Enter, MODS.Control | MODS.Keypad), "autotype")
  assert.equal(c(KEYS.Return, MODS.Control | MODS.Shift), "typePassword")
  assert.equal(c(KEYS.Enter, MODS.Control | MODS.Shift | MODS.Keypad), "typePassword")
  assert.equal(c(KEYS.B, MODS.Control, "\x02"), "copyUsername")
  assert.equal(c(KEYS.C, MODS.Control, "\x03"), "copyPassword")
  assert.equal(c(KEYS.T, MODS.Control, "\x14"), "copyTotp")
  assert.equal(c(KEYS.L, MODS.Control, "\x0c"), "copyUrl")
  assert.equal(c(KEYS.Escape), "escape")
  assert.equal(c(KEYS.Up), "up")
  assert.equal(c(KEYS.Down), "down")
  assert.equal(c(KEYS.PageUp), "pageUp")
  assert.equal(c(KEYS.PageDown), "pageDown")
  assert.equal(c(KEYS.Home), "home")
  assert.equal(c(KEYS.End), "end")
})

test("the search card's footer tells the truth about the key map", () => {
  const lines = Model.searchHints()
  assert.equal(lines[0][0].keys, "Enter")
  assert.equal(lines[0][0].action, "copyPassword")
  for (const hint of lines.flat()) {
    const parts = hint.keys.split("+")
    const name = parts.pop()
    const mods = parts.reduce((m, p) => m | { Ctrl: MODS.Control, Shift: MODS.Shift }[p], 0)
    const key = name === "Enter" ? KEYS.Return : KEYS[name]
    assert.ok(key, `unknown key in "${hint.keys}"`)
    assert.equal(Model.searchCommand(key, mods, ""), hint.action, hint.keys)
    assert.ok(Model.isCopyAction(hint.action) || Model.isTypeAction(hint.action), hint.action)
  }
})

test("plain and shifted characters type into the query; shortcuts do not", () => {
  const c = (key, mods, text) => Model.searchCommand(key, mods, text)
  assert.equal(c(0x47, 0, "g"), "type")
  assert.equal(c(0x47, MODS.Shift, "G"), "type")
  assert.equal(c(0x31, MODS.Keypad, "1"), "type")
  assert.equal(c(0x40, MODS.GroupSwitch, "@"), "type")
  assert.equal(c(0x20, 0, " "), "type")
  assert.equal(c(0x47, MODS.Alt, "g"), "")
  assert.equal(c(0x47, MODS.Control, "\x07"), "")
  assert.equal(c(KEYS.U, MODS.Control, "\x15"), "", "Ctrl+U belongs to Util.editsFilter")
  assert.equal(c(KEYS.Backspace, 0, "\b"), "", "Backspace belongs to Util.editsFilter")
  assert.equal(c(KEYS.Return, MODS.Alt), "")
  assert.equal(c(KEYS.Down, MODS.Control), "")
})

test("form keys cover submit, field switching and the file pickers", () => {
  const c = (key, mods = 0) => Model.formCommand(key, mods)
  assert.equal(c(KEYS.Return), "submit")
  assert.equal(c(KEYS.Enter, MODS.Keypad), "submit")
  assert.equal(c(KEYS.Escape), "escape")
  assert.equal(c(KEYS.Tab), "next")
  assert.equal(c(KEYS.Backtab, MODS.Shift), "previous")
  assert.equal(c(KEYS.Tab, MODS.Shift), "previous")
  assert.equal(c(KEYS.O, MODS.Control), "pickDatabase")
  assert.equal(c(KEYS.K, MODS.Control), "pickKeyfile")
  assert.equal(c(KEYS.U, MODS.Control), "clearField")
  assert.equal(c(0x41, 0), "")
  assert.equal(c(KEYS.O, 0), "")
})

test("moveSelection wraps arrows and clamps pages", () => {
  assert.equal(Model.moveSelection(0, 5, "up", 8), 4)
  assert.equal(Model.moveSelection(4, 5, "down", 8), 0)
  assert.equal(Model.moveSelection(2, 20, "pageDown", 8), 10)
  assert.equal(Model.moveSelection(18, 20, "pageDown", 8), 19)
  assert.equal(Model.moveSelection(3, 20, "pageUp", 8), 0)
  assert.equal(Model.moveSelection(7, 20, "home", 8), 0)
  assert.equal(Model.moveSelection(7, 20, "end", 8), 19)
  assert.equal(Model.moveSelection(9, 3, "noop", 8), 2)
  assert.equal(Model.moveSelection(0, 0, "down", 8), 0)
})

// ------------------------------------------------------------- settings

test("settings are read off the plugin's bar entry", () => {
  const barConfig = {
    layout: {
      left: [{ id: "omarchy.menu" }],
      center: [],
      right: [{ id: "omarchy.audio" }, { id: "mirecad.omakeepick", idleLockMinutes: 5, notifyOnCopy: false }]
    }
  }
  assert.deepEqual(Model.entrySettings(barConfig, "mirecad.omakeepick"), { idleLockMinutes: 5, notifyOnCopy: false })
  assert.deepEqual(Model.entrySettings(barConfig, "someone.else"), {})
  assert.deepEqual(Model.entrySettings(null, "mirecad.omakeepick"), {})
  assert.deepEqual(
    Model.entrySettings({}, "mirecad.omakeepick", [{ id: "mirecad.omakeepick", recentCount: 3 }]),
    { recentCount: 3 })
})

test("configure always sends every daemon setting, clamped", () => {
  assert.deepEqual(Model.daemonSettings({}), {
    idleLockMinutes: 30,
    clipboardClearSeconds: 15,
    autotypeSequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}",
    typeDelayMs: 8,
    autotypeStartDelayMs: 250,
    recentCount: 8
  })
  const custom = Model.daemonSettings({
    idleLockMinutes: "0",
    clipboardClearSeconds: -4,
    autotypeSequence: "  ",
    typeDelayMs: 99999,
    recentCount: "abc",
    notifyOnCopy: false
  })
  assert.equal(custom.idleLockMinutes, 0)
  assert.equal(custom.clipboardClearSeconds, 0)
  assert.equal(custom.autotypeSequence, "{USERNAME}{TAB}{PASSWORD}{ENTER}")
  assert.equal(custom.typeDelayMs, 200, "clamped to the daemon's limit")
  assert.equal(custom.recentCount, 8)
  assert.equal("notifyOnCopy" in custom, false, "notifyOnCopy stays in the plugin")
})

test("boolSetting accepts the usual spellings", () => {
  assert.equal(Model.boolSetting({}, "notifyOnCopy", true), true)
  assert.equal(Model.boolSetting({ notifyOnCopy: false }, "notifyOnCopy", true), false)
  assert.equal(Model.boolSetting({ notifyOnCopy: "off" }, "notifyOnCopy", true), false)
  assert.equal(Model.boolSetting({ notifyOnCopy: "yes" }, "notifyOnCopy", false), true)
  assert.equal(Model.boolSetting({ notifyOnCopy: "maybe" }, "notifyOnCopy", true), true)
})

// ------------------------------------------------------------- protocol

test("requests carry id and cmd and cannot be overridden by arguments", () => {
  const line = Model.buildRequest(7, "search", { query: "git", limit: 50, id: 99, cmd: "close" })
  assert.deepEqual(JSON.parse(line), { id: 7, cmd: "search", query: "git", limit: 50 })
  assert.equal(line.indexOf("\n"), -1, "one request is one line")
  assert.deepEqual(JSON.parse(Model.buildRequest(1, "touch")), { id: 1, cmd: "touch" })
})

test("a password with newlines and quotes still serialises to one line", () => {
  const line = Model.buildRequest(3, "unlock", { db: "/x.kdbx", keyfile: null, password: "a\"b\nc\\", pin: null })
  assert.equal(line.indexOf("\n"), -1)
  assert.equal(JSON.parse(line).password, "a\"b\nc\\")
})

test("daemon lines are classified without throwing", () => {
  assert.equal(Model.parseLine("").kind, "empty")
  assert.equal(Model.parseLine("not json").kind, "invalid")
  assert.equal(Model.parseLine("[1,2]").kind, "invalid")
  assert.equal(Model.parseLine("{\"foo\":1}").kind, "invalid")
  const reply = Model.parseLine("{\"id\":7,\"ok\":true,\"entries\":[]}")
  assert.equal(reply.kind, "reply")
  assert.equal(reply.id, 7)
  const event = Model.parseLine("{\"event\":\"notice\",\"level\":\"info\",\"message\":\"Database reloaded\"}\r")
  assert.equal(event.kind, "event")
  assert.equal(event.event, "notice")
})

test("state events normalise to safe defaults", () => {
  const s = Model.normalizeState(state({ keyfile: null, lockReason: null, lockAt: null }))
  assert.equal(s.phase, "unlocked")
  assert.equal(s.keyfile, "")
  assert.equal(s.lockReason, "")
  assert.equal(s.lockAt, 0)
  assert.equal(Model.normalizeState({ phase: "bogus" }).phase, "closed")
  assert.equal(Model.normalizeState({ phase: "locked", db: "/a/My Vault.kdbx" }).dbName, "My Vault")
  assert.equal(Model.normalizeState(null).phase, "closed")
})

test("entries keep only known, non-secret fields", () => {
  const entries = Model.normalizeEntries([
    { id: "a", title: "GitHub", username: "madev", group: "Personal/Dev", hasTotp: false, password: "nope" },
    { title: "no id" },
    null
  ])
  assert.equal(entries.length, 1)
  assert.equal(entries[0].title, "GitHub")
  assert.equal("password" in entries[0], false)
  assert.equal(entries[0].hasTotp, false)
  assert.equal(entries[0].hasPassword, true, "an absent flag defers to the daemon")
})

test("reconnect backoff doubles and caps at 30s", () => {
  assert.equal(Model.backoffDelay(0), 500)
  assert.equal(Model.backoffDelay(1), 1000)
  assert.equal(Model.backoffDelay(3), 4000)
  assert.equal(Model.backoffDelay(6), 30000)
  assert.equal(Model.backoffDelay(50), 30000)
})

test("daemon candidates prefer an override, then bin/, then cargo builds", () => {
  assert.deepEqual(Model.daemonCandidates("/p/plugin/", ""), [
    "/p/plugin/bin/omakeepickd",
    "/p/plugin/daemon/target/release/omakeepickd",
    "/p/plugin/daemon/target/debug/omakeepickd"
  ])
  assert.equal(Model.daemonCandidates("/p", "/opt/omakeepickd")[0], "/opt/omakeepickd")
  assert.equal(Model.fileUrlPath("file:///home/me/My%20Plugins/omakeepick/"), "/home/me/My Plugins/omakeepick")
})

// ------------------------------------------------------------- messages

test("error text prefers the daemon's message, then a friendly default", () => {
  assert.equal(Model.errorText({ ok: false, error: "bad_credentials" }), "Wrong password or key file")
  assert.equal(Model.errorText({ ok: false, error: "tool_missing", message: "wtype is not installed" }), "wtype is not installed")
  assert.equal(Model.errorText({ ok: false, error: "never_heard_of_it" }), "Something went wrong")
  assert.equal(Model.errorText({ ok: false, error: "cancelled" }), "")
  assert.equal(Model.errorText(null), "Something went wrong")
})

test("copy notifications name the field and the countdown", () => {
  assert.equal(Model.copiedText("copyPassword", 15), "Password copied · clears in 15s")
  assert.equal(Model.copiedText("copyTotp", 0), "TOTP copied")
  assert.equal(Model.copiedText("copyUsername"), "Username copied")
  assert.equal(Model.isCopyAction("copyUrl"), true)
  assert.equal(Model.isCopyAction("autotype"), false)
  assert.equal(Model.isTypeAction("typePassword"), true)
})

test("actions are pre-checked against the entry's flags", () => {
  const entry = Model.normalizeEntry({ id: "a", hasTotp: false, autotype: false })
  assert.equal(Model.entrySupports(entry, "copyTotp"), false)
  assert.equal(Model.entrySupports(entry, "autotype"), false)
  assert.equal(Model.entrySupports(entry, "copyPassword"), true)
  assert.equal(Model.entrySupports(entry, "bogus"), false)
  assert.equal(Model.missingFieldText("copyTotp"), "No TOTP")
})

test("notification text cannot start with an option dash", () => {
  assert.equal(Model.notificationText("-u critical"), " -u critical")
  assert.equal(Model.notificationText("GitHub"), "GitHub")
  assert.equal(Model.notificationText(null), "")
  assert.equal(Model.noticeUrgency("error"), "critical")
  assert.equal(Model.noticeUrgency("info"), "low")
})

// ------------------------------------------------------------- display

test("rows read username · group, dropping what is missing", () => {
  assert.equal(Model.entryDetail({ username: "madev", group: "Personal/Dev" }), "madev · Personal/Dev")
  assert.equal(Model.entryDetail({ username: "", group: "Work" }), "Work")
  assert.equal(Model.entryDetail({ username: "root", group: "" }), "root")
  assert.equal(Model.entryDetail({}), "")
})

test("placeholders count entries and PIN tries", () => {
  assert.equal(Model.searchPlaceholder(245), "Type to search 245 entries")
  assert.equal(Model.searchPlaceholder(1), "Type to search 1 entry")
  assert.equal(Model.searchPlaceholder(0), "Type to search…")
  assert.equal(Model.pinPlaceholder(3), "Enter PIN · 3 tries left")
  assert.equal(Model.pinPlaceholder(1), "Enter PIN · 1 try left")
  assert.equal(Model.pinPlaceholder(0), "Enter PIN")
})

test("the picker shows the card the state calls for", () => {
  assert.equal(Model.pickerView(false, "unlocked", false, false, false), "offline")
  assert.equal(Model.pickerView(true, "unlocked", false, false, false), "search")
  assert.equal(Model.pickerView(true, "unlocked", false, true, false), "unlock", "Open database… over an open one")
  assert.equal(Model.pickerView(true, "locked", true, false, false), "pin")
  assert.equal(Model.pickerView(true, "locked", true, false, true), "unlock", "Use master password")
  assert.equal(Model.pickerView(true, "locked", false, false, false), "unlock")
  assert.equal(Model.pickerView(true, "closed", false, false, false), "unlock")
})

test("countdowns read in minutes for the bar and as a clock in the panel", () => {
  const now = 1_000_000
  assert.equal(Model.secondsUntil(now + 12 * 60 * 1000, now), 720)
  assert.equal(Model.secondsUntil(0, now), -1)
  assert.equal(Model.secondsUntil(now - 5000, now), 0)
  assert.equal(Model.formatRemaining(720), "12 min")
  assert.equal(Model.formatRemaining(61), "2 min")
  assert.equal(Model.formatRemaining(45), "45 s")
  assert.equal(Model.formatRemaining(3 * 3600 + 120), "3 h 2 min")
  assert.equal(Model.formatRemaining(-1), "")
  assert.equal(Model.formatClock(725), "12:05")
  assert.equal(Model.formatClock(3725), "1:02:05")
  assert.equal(Model.formatClock(9), "0:09")
})

test("bar tooltip and glyph follow the phase", () => {
  const now = 1_000_000
  const unlocked = Model.normalizeState(state({ lockAt: now + 12 * 60 * 1000 }))
  assert.equal(Model.phaseKey(true, unlocked), "unlocked")
  assert.equal(Model.phaseKey(false, unlocked), "offline")
  assert.equal(Model.barTooltip("unlocked", unlocked, now), "OmaKeePick · unlocked · locks in 12 min")
  assert.equal(Model.barTooltip("unlocked", Model.normalizeState(state({ lockAt: 0 })), now), "OmaKeePick · unlocked")
  assert.equal(Model.barTooltip("locked", Model.normalizeState(state({ phase: "locked", lockReason: "idle" })), now),
    "OmaKeePick · locked after inactivity")
  assert.equal(Model.barTooltip("locked", Model.normalizeState(state({ phase: "locked", quickUnlock: true })), now),
    "OmaKeePick · locked · PIN ready")
  assert.equal(Model.barTooltip("closed", Model.emptyState(), now), "OmaKeePick · no database open")
  assert.equal(Model.barTooltip("offline", null, now), "OmaKeePick · daemon not running")
  assert.notEqual(Model.barGlyph("unlocked"), Model.barGlyph("locked"))
  assert.equal(Model.barGlyph("closed"), Model.barGlyph("locked"))
})

test("IPC status is plain, secret-free JSON", () => {
  const status = Model.publicStatus(true, Model.normalizeState(state()))
  assert.deepEqual(Object.keys(status).sort(), [
    "busy", "connected", "db", "dbName", "entryCount", "keyfile", "lockAt", "lockReason", "phase", "quickUnlock"
  ])
  assert.equal(status.phase, "unlocked")
  assert.equal(Model.publicStatus(false, null).phase, "offline")
})

test("paths shorten under home", () => {
  assert.equal(Model.displayPath("/home/me/Secrets.kdbx", "/home/me"), "~/Secrets.kdbx")
  assert.equal(Model.displayPath("/home/meadow/x.kdbx", "/home/me"), "/home/meadow/x.kdbx")
  assert.equal(Model.displayPath("/srv/x.kdbx", ""), "/srv/x.kdbx")
  assert.equal(Model.baseName("/a/b/Secrets.kdbx"), "Secrets.kdbx")
})

test("offline card explains a missing or installing helper", () => {
  assert.equal(Model.offlineTitle(null), "OmaKeePick service is not loaded")
  assert.equal(Model.offlineTitle({ installing: true, daemonMissing: true }), "Installing the KeePass helper…")
  assert.equal(Model.offlineSubtitle({ installing: true, daemonMissing: true }), "")
  assert.equal(Model.offlineTitle({ installing: false, daemonMissing: false }), "Starting omakeepickd…")
  assert.equal(
    Model.offlineSubtitle({ installing: false, daemonMissing: true, installError: "download failed" }),
    "download failed · Run bin/install in the plugin folder"
  )
})
