// Pure logic for the OmaKeePick plugin.
//
// Everything here is a plain function over plain data so it can be exercised
// from node (`tests/model.test.js`) without a running shell. The QML side
// loads this with `import "Model.js" as Model`; nothing in here may touch a
// QML type, a singleton, the filesystem, or a secret. Passwords and PINs are
// never handed to this file: the Service serialises the unlock request inline
// and drops it the moment it is written.

// ------------------------------------------------------------- constants

// Qt::Key and Qt::KeyboardModifier values. They are part of Qt's stable ABI,
// and spelling them out lets the key maps below run under node too.
var KEYS = {
  Escape: 0x01000000,
  Tab: 0x01000001,
  Backtab: 0x01000002,
  Backspace: 0x01000003,
  Return: 0x01000004,
  Enter: 0x01000005,
  Home: 0x01000010,
  End: 0x01000011,
  Left: 0x01000012,
  Up: 0x01000013,
  Right: 0x01000014,
  Down: 0x01000015,
  PageUp: 0x01000016,
  PageDown: 0x01000017,
  B: 0x42,
  C: 0x43,
  K: 0x4b,
  L: 0x4c,
  O: 0x4f,
  T: 0x54,
  U: 0x55
}

var MODS = {
  Shift: 0x02000000,
  Control: 0x04000000,
  Alt: 0x08000000,
  Meta: 0x10000000,
  Keypad: 0x20000000,
  GroupSwitch: 0x40000000
}

// Daemon settings (PROTOCOL.md "Settings"), with the ranges the plugin clamps
// them to before they go over the wire. notifyOnCopy is plugin-side only.
var SETTINGS = [
  { key: "idleLockMinutes", type: "integer", fallback: 30, min: 0, max: 1440 },
  { key: "clipboardClearSeconds", type: "integer", fallback: 15, min: 0, max: 600 },
  { key: "autotypeSequence", type: "string", fallback: "{USERNAME}{TAB}{PASSWORD}{ENTER}" },
  { key: "typeDelayMs", type: "integer", fallback: 8, min: 0, max: 200 },
  { key: "autotypeStartDelayMs", type: "integer", fallback: 250, min: 50, max: 5000 },
  { key: "recentCount", type: "integer", fallback: 8, min: 0, max: 50 }
]

var ACTIONS = {
  autotype: { flag: "autotype", label: "Auto-type", missing: "Auto-type is off for this entry" },
  typePassword: { flag: "hasPassword", label: "Password", missing: "No password" },
  copyUsername: { flag: "hasUsername", label: "Username", missing: "No username", copy: true },
  copyPassword: { flag: "hasPassword", label: "Password", missing: "No password", copy: true },
  copyUrl: { flag: "hasUrl", label: "URL", missing: "No URL", copy: true },
  copyTotp: { flag: "hasTotp", label: "TOTP", missing: "No TOTP", copy: true }
}

var ERROR_TEXT = {
  disconnected: "omakeepickd is not running",
  timeout: "omakeepickd did not answer",
  busy: "Still busy, try again in a moment",
  locked: "The database is locked",
  not_found: "Not found",
  bad_credentials: "Wrong password or key file",
  keyfile_error: "The key file could not be read",
  format_error: "Not a KeePass database",
  bad_request: "The request was rejected",
  no_quick_unlock: "Quick unlock is no longer available",
  bad_pin: "Wrong PIN",
  no_field: "This entry has no such field",
  autotype_disabled: "Auto-type is off for this entry",
  tool_missing: "A required tool is missing",
  failed: "Something went wrong",
  cancelled: ""
}

// --------------------------------------------------------------- paths

function fileUrlPath(url) {
  var text = String(url || "")
  if (text.indexOf("file://") === 0) text = text.slice(7)
  try {
    text = decodeURIComponent(text)
  } catch (error) {
    // Leave a malformed encoding alone rather than losing the path entirely.
  }
  return text.replace(/\/+$/, "")
}

// Where omakeepickd may live, in the order it is looked for: an explicit
// override, the installed binary, then a local cargo build for development.
function daemonCandidates(pluginDir, override) {
  var dir = String(pluginDir || "").replace(/\/+$/, "")
  var out = []
  var explicit = String(override || "").trim()
  if (explicit) out.push(explicit)
  if (dir) {
    out.push(dir + "/bin/omakeepickd")
    out.push(dir + "/daemon/target/release/omakeepickd")
    out.push(dir + "/daemon/target/debug/omakeepickd")
  }
  return out
}

function displayPath(path, home) {
  var text = String(path || "")
  var base = String(home || "").replace(/\/+$/, "")
  if (base && (text === base || text.indexOf(base + "/") === 0)) return "~" + text.slice(base.length)
  return text
}

function baseName(path) {
  var text = String(path || "").replace(/\/+$/, "")
  var slash = text.lastIndexOf("/")
  return slash === -1 ? text : text.slice(slash + 1)
}

// -------------------------------------------------------------- settings

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

// Settings are inline on the plugin's shell.json entry. The bar layout is the
// usual home (the widget lands there when the plugin is enabled); a top-level
// plugins[] entry is honoured too for a bar-less setup.
function entrySettings(barConfig, pluginId, plugins) {
  var id = String(pluginId || "")
  var found = null
  var layout = isPlainObject(barConfig) && isPlainObject(barConfig.layout) ? barConfig.layout : null
  var sections = ["left", "center", "right"]
  for (var s = 0; layout && !found && s < sections.length; s++) {
    var entries = layout[sections[s]]
    if (!Array.isArray(entries)) continue
    for (var i = 0; i < entries.length; i++) {
      if (isPlainObject(entries[i]) && String(entries[i].id || "") === id) { found = entries[i]; break }
    }
  }
  if (!found && Array.isArray(plugins)) {
    for (var j = 0; j < plugins.length; j++) {
      if (isPlainObject(plugins[j]) && String(plugins[j].id || "") === id) { found = plugins[j]; break }
    }
  }
  var out = {}
  if (!found) return out
  for (var key in found) if (key !== "id") out[key] = found[key]
  return out
}

function setting(settings, name, fallback) {
  var value = isPlainObject(settings) ? settings[name] : undefined
  return value === undefined || value === null ? fallback : value
}

function intSetting(settings, name, fallback, min, max) {
  var n = parseInt(String(setting(settings, name, fallback)), 10)
  if (!isFinite(n)) n = fallback
  return Math.max(min, Math.min(max, n))
}

function boolSetting(settings, name, fallback) {
  var value = setting(settings, name, fallback)
  if (value === true || value === false) return value
  var text = String(value).trim().toLowerCase()
  if (text === "true" || text === "1" || text === "yes" || text === "on") return true
  if (text === "false" || text === "0" || text === "no" || text === "off") return false
  return fallback
}

function stringSetting(settings, name, fallback) {
  var value = setting(settings, name, fallback)
  var text = String(value)
  return text.trim() === "" ? fallback : text
}

// The full `configure` payload. Every key is always sent, defaults included,
// so removing a setting from shell.json puts the daemon back on its default.
function daemonSettings(settings) {
  var out = {}
  for (var i = 0; i < SETTINGS.length; i++) {
    var spec = SETTINGS[i]
    if (spec.type === "integer") out[spec.key] = intSetting(settings, spec.key, spec.fallback, spec.min, spec.max)
    else out[spec.key] = stringSetting(settings, spec.key, spec.fallback)
  }
  return out
}

// ------------------------------------------------------------- protocol

function buildRequest(id, cmd, args) {
  var message = { id: id, cmd: String(cmd) }
  if (isPlainObject(args)) for (var key in args) if (key !== "id" && key !== "cmd") message[key] = args[key]
  return JSON.stringify(message)
}

// One stdout line from `omakeepickd attach`, classified. Never throws.
function parseLine(line) {
  var text = String(line || "").trim()
  if (text === "") return { kind: "empty" }
  var message
  try {
    message = JSON.parse(text)
  } catch (error) {
    return { kind: "invalid" }
  }
  if (!isPlainObject(message)) return { kind: "invalid" }
  if (typeof message.event === "string") return { kind: "event", event: message.event, message: message }
  if (typeof message.id === "number") return { kind: "reply", id: message.id, message: message }
  return { kind: "invalid" }
}

function emptyState() {
  return {
    phase: "closed",
    busy: false,
    quickUnlock: false,
    pinAttemptsLeft: 0,
    db: "",
    keyfile: "",
    dbName: "",
    entryCount: 0,
    lockAt: 0,
    idleLockMinutes: 0,
    lockReason: ""
  }
}

function normalizeState(message) {
  var m = isPlainObject(message) ? message : {}
  var phase = String(m.phase || "")
  if (phase !== "closed" && phase !== "locked" && phase !== "unlocked") phase = "closed"
  var lockAt = Number(m.lockAt)
  return {
    phase: phase,
    busy: m.busy === true,
    quickUnlock: m.quickUnlock === true,
    pinAttemptsLeft: Math.max(0, Math.floor(Number(m.pinAttemptsLeft) || 0)),
    db: m.db ? String(m.db) : "",
    keyfile: m.keyfile ? String(m.keyfile) : "",
    dbName: m.dbName ? String(m.dbName) : (m.db ? baseName(String(m.db)).replace(/\.kdbx$/i, "") : ""),
    entryCount: Math.max(0, Math.floor(Number(m.entryCount) || 0)),
    lockAt: isFinite(lockAt) && lockAt > 0 ? lockAt : 0,
    idleLockMinutes: Math.max(0, Math.floor(Number(m.idleLockMinutes) || 0)),
    lockReason: m.lockReason ? String(m.lockReason) : ""
  }
}

function normalizeEntry(entry) {
  var e = isPlainObject(entry) ? entry : {}
  return {
    id: String(e.id || ""),
    title: String(e.title || ""),
    username: String(e.username || ""),
    group: String(e.group || ""),
    // Capability flags only gate the picker's local pre-check; the daemon has
    // the final say, so a flag it leaves out counts as present.
    hasUsername: e.hasUsername !== false,
    hasPassword: e.hasPassword !== false,
    hasUrl: e.hasUrl !== false,
    hasTotp: e.hasTotp !== false,
    autotype: e.autotype !== false
  }
}

function normalizeEntries(list) {
  var out = []
  if (!Array.isArray(list)) return out
  for (var i = 0; i < list.length; i++) {
    var entry = normalizeEntry(list[i])
    if (entry.id) out.push(entry)
  }
  return out
}

// Exponential reconnect delay for the attach bridge, capped at 30s.
function backoffDelay(attempt) {
  var n = Math.max(0, Math.floor(Number(attempt) || 0))
  return Math.min(30000, 500 * Math.pow(2, Math.min(n, 6)))
}

// ------------------------------------------------------------- messages

function errorText(reply) {
  var r = isPlainObject(reply) ? reply : {}
  var message = String(r.message || "").trim()
  if (message) return message
  var code = String(r.error || "failed")
  return ERROR_TEXT[code] !== undefined ? ERROR_TEXT[code] : ERROR_TEXT.failed
}

function isCopyAction(action) {
  var spec = ACTIONS[String(action || "")]
  return !!spec && spec.copy === true
}

function isTypeAction(action) {
  return action === "autotype" || action === "typePassword"
}

// Whether the entry advertises what the action needs.
function entrySupports(entry, action) {
  var spec = ACTIONS[String(action || "")]
  if (!spec || !isPlainObject(entry)) return false
  return entry[spec.flag] !== false
}

function missingFieldText(action) {
  var spec = ACTIONS[String(action || "")]
  return spec ? spec.missing : ""
}

function copiedText(action, clearsIn) {
  var spec = ACTIONS[String(action || "")]
  var label = spec ? spec.label : "Value"
  var seconds = Math.floor(Number(clearsIn) || 0)
  return label + " copied" + (seconds > 0 ? " · clears in " + seconds + "s" : "")
}

// A leading dash would be read as an option by omarchy-notification-send.
function notificationText(value) {
  var text = String(value === undefined || value === null ? "" : value)
  return text.charAt(0) === "-" ? " " + text : text
}

function noticeUrgency(level) {
  if (level === "error") return "critical"
  if (level === "warning") return "normal"
  return "low"
}

// ------------------------------------------------------------- display

function entryDetail(entry) {
  var e = isPlainObject(entry) ? entry : {}
  var parts = []
  if (e.username) parts.push(String(e.username))
  if (e.group) parts.push(String(e.group))
  return parts.join(" · ")
}

function plural(n, one, many) {
  return n + " " + (n === 1 ? one : many)
}

function searchPlaceholder(entryCount) {
  var n = Math.floor(Number(entryCount) || 0)
  return n > 0 ? "Type to search " + plural(n, "entry", "entries") : "Type to search…"
}

function pinPlaceholder(attemptsLeft) {
  var n = Math.floor(Number(attemptsLeft) || 0)
  return n > 0 ? "Enter PIN · " + plural(n, "try", "tries") + " left" : "Enter PIN"
}

function lockReasonText(reason) {
  switch (String(reason || "")) {
  case "manual": return "Locked"
  case "idle": return "Locked after inactivity"
  case "screen": return "Locked with the screen"
  case "sleep": return "Locked for sleep"
  case "pin": return "Too many wrong PINs"
  case "closed": return "Closed"
  default: return "Locked"
  }
}

// Which card the picker shows.
// The picker's card while omakeepickd is not reachable.
function offlineTitle(service) {
  if (!service) return "OmaKeePick service is not loaded"
  if (service.installing) return "Installing the KeePass helper…"
  if (service.daemonMissing) return "The KeePass helper is not installed"
  return "Starting omakeepickd…"
}

function offlineSubtitle(service) {
  if (!service || service.installing || !service.daemonMissing) return ""
  var reason = String(service.installError || "")
  return (reason ? reason + " · " : "") + "Run bin/install in the plugin folder"
}

function pickerView(connected, phase, quickUnlock, forceUnlock, useMasterPassword) {
  if (!connected) return "offline"
  if (phase === "unlocked" && !forceUnlock) return "search"
  if (phase === "locked" && quickUnlock && !forceUnlock && !useMasterPassword) return "pin"
  return "unlock"
}

function secondsUntil(lockAt, now) {
  var at = Number(lockAt)
  if (!isFinite(at) || at <= 0) return -1
  return Math.max(0, Math.ceil((at - Number(now || 0)) / 1000))
}

// "12 min", "45 s" -- coarse, for the tooltip and status line.
function formatRemaining(seconds) {
  var s = Math.floor(Number(seconds))
  if (!isFinite(s) || s < 0) return ""
  if (s < 60) return s + " s"
  var minutes = Math.ceil(s / 60)
  if (minutes < 60) return minutes + " min"
  var hours = Math.floor(minutes / 60)
  var rest = minutes % 60
  return hours + " h" + (rest > 0 ? " " + rest + " min" : "")
}

// "12:05" or "1:02:05" -- the live countdown in the status panel.
function formatClock(seconds) {
  var s = Math.floor(Number(seconds))
  if (!isFinite(s) || s < 0) return ""
  var h = Math.floor(s / 3600)
  var m = Math.floor((s % 3600) / 60)
  var sec = s % 60
  var mm = h > 0 && m < 10 ? "0" + m : String(m)
  var ss = sec < 10 ? "0" + sec : String(sec)
  return (h > 0 ? h + ":" : "") + mm + ":" + ss
}

// One word for where things stand, shared by the bar, panel and IPC status.
function phaseKey(connected, state) {
  if (!connected) return "offline"
  var s = isPlainObject(state) ? state : {}
  return s.phase === "unlocked" || s.phase === "locked" ? s.phase : "closed"
}

function barGlyph(key) {
  return key === "unlocked" ? "󰿆" : "󰌾"
}

function statusText(key, state, now) {
  var s = isPlainObject(state) ? state : {}
  if (key === "offline") return "daemon not running"
  if (key === "closed") return "no database open"
  if (key === "locked") return s.quickUnlock ? "locked · PIN ready" : lockReasonText(s.lockReason).toLowerCase()
  var remaining = secondsUntil(s.lockAt, now)
  return remaining >= 0 ? "unlocked · locks in " + formatRemaining(remaining) : "unlocked"
}

function barTooltip(key, state, now) {
  return "OmaKeePick · " + statusText(key, state, now)
}

function publicStatus(connected, state) {
  var s = isPlainObject(state) ? state : emptyState()
  return {
    connected: connected === true,
    phase: phaseKey(connected, s),
    busy: s.busy === true,
    quickUnlock: s.quickUnlock === true,
    db: s.db || "",
    keyfile: s.keyfile || "",
    dbName: s.dbName || "",
    entryCount: s.entryCount || 0,
    lockAt: s.lockAt || 0,
    lockReason: s.lockReason || ""
  }
}

// -------------------------------------------------------------- keys

function plainModifiers(modifiers) {
  return Number(modifiers || 0) & (MODS.Shift | MODS.Control | MODS.Alt | MODS.Meta)
}

// A key that should land in the query: one printable character with no
// shortcut modifier. Shift, keypad and AltGr (group switch) still type.
function isTypingKey(text, modifiers) {
  var t = String(text || "")
  if (t.length !== 1) return false
  var code = t.charCodeAt(0)
  if (code < 32 || code === 127) return false
  return (plainModifiers(modifiers) & (MODS.Control | MODS.Alt | MODS.Meta)) === 0
}

// The search card's key map. Text editing (Backspace, Ctrl+Backspace,
// Ctrl+U) is Commons.Util's and is checked before this; anything unmapped
// returns "" so the caller leaves the event alone.
//
// Plain Enter only copies: typing into whatever window is underneath takes a
// deliberate Ctrl chord. Shift alone does not change Enter, since it is often
// still down from a capital at the end of the query.
function searchCommand(key, modifiers, text) {
  var mods = plainModifiers(modifiers)
  if (key === KEYS.Escape) return "escape"
  if (key === KEYS.Return || key === KEYS.Enter) {
    if (mods === MODS.Control) return "autotype"
    if (mods === (MODS.Control | MODS.Shift)) return "typePassword"
    if ((mods & ~MODS.Shift) === 0) return "copyPassword"
    return ""
  }
  if (mods === MODS.Control) {
    if (key === KEYS.B) return "copyUsername"
    if (key === KEYS.C) return "copyPassword"
    if (key === KEYS.T) return "copyTotp"
    if (key === KEYS.L) return "copyUrl"
    return ""
  }
  if (mods === 0) {
    if (key === KEYS.Up) return "up"
    if (key === KEYS.Down) return "down"
    if (key === KEYS.PageUp) return "pageUp"
    if (key === KEYS.PageDown) return "pageDown"
    if (key === KEYS.Home) return "home"
    if (key === KEYS.End) return "end"
  }
  if (isTypingKey(text, modifiers)) return "type"
  return ""
}

// The search card's footer, one array per line. Ctrl+C is left out: Enter
// does the same.
function searchHints() {
  return [
    [
      { keys: "Enter", label: "copy password", action: "copyPassword" },
      { keys: "Ctrl+Enter", label: "auto-type", action: "autotype" },
      { keys: "Ctrl+Shift+Enter", label: "type password", action: "typePassword" }
    ],
    [
      { keys: "Ctrl+B", label: "copy username", action: "copyUsername" },
      { keys: "Ctrl+T", label: "copy TOTP", action: "copyTotp" },
      { keys: "Ctrl+L", label: "copy URL", action: "copyUrl" }
    ]
  ]
}

// The unlock and PIN cards' key map, read off the focused field.
function formCommand(key, modifiers) {
  var mods = plainModifiers(modifiers)
  if (key === KEYS.Escape) return "escape"
  if (key === KEYS.Return || key === KEYS.Enter) return "submit"
  if (key === KEYS.Backtab || (key === KEYS.Tab && mods === MODS.Shift)) return "previous"
  if (key === KEYS.Tab && mods === 0) return "next"
  if (mods === MODS.Control) {
    if (key === KEYS.O) return "pickDatabase"
    if (key === KEYS.K) return "pickKeyfile"
    if (key === KEYS.U) return "clearField"
  }
  return ""
}

// Cursor movement over `count` rows. Arrows wrap like the stock menus; page
// and home/end clamp.
function moveSelection(index, count, command, pageSize) {
  var n = Math.floor(Number(count) || 0)
  if (n <= 0) return 0
  var i = Math.max(0, Math.min(n - 1, Math.floor(Number(index) || 0)))
  var page = Math.max(1, Math.floor(Number(pageSize) || 1))
  if (command === "up") return (i - 1 + n) % n
  if (command === "down") return (i + 1) % n
  if (command === "pageUp") return Math.max(0, i - page)
  if (command === "pageDown") return Math.min(n - 1, i + page)
  if (command === "home") return 0
  if (command === "end") return n - 1
  return i
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    KEYS: KEYS,
    MODS: MODS,
    SETTINGS: SETTINGS,
    fileUrlPath: fileUrlPath,
    daemonCandidates: daemonCandidates,
    displayPath: displayPath,
    baseName: baseName,
    entrySettings: entrySettings,
    setting: setting,
    intSetting: intSetting,
    boolSetting: boolSetting,
    stringSetting: stringSetting,
    daemonSettings: daemonSettings,
    buildRequest: buildRequest,
    parseLine: parseLine,
    emptyState: emptyState,
    normalizeState: normalizeState,
    normalizeEntry: normalizeEntry,
    normalizeEntries: normalizeEntries,
    backoffDelay: backoffDelay,
    errorText: errorText,
    isCopyAction: isCopyAction,
    isTypeAction: isTypeAction,
    entrySupports: entrySupports,
    missingFieldText: missingFieldText,
    copiedText: copiedText,
    notificationText: notificationText,
    noticeUrgency: noticeUrgency,
    entryDetail: entryDetail,
    plural: plural,
    searchPlaceholder: searchPlaceholder,
    pinPlaceholder: pinPlaceholder,
    lockReasonText: lockReasonText,
    offlineTitle: offlineTitle,
    offlineSubtitle: offlineSubtitle,
    pickerView: pickerView,
    secondsUntil: secondsUntil,
    formatRemaining: formatRemaining,
    formatClock: formatClock,
    phaseKey: phaseKey,
    barGlyph: barGlyph,
    statusText: statusText,
    barTooltip: barTooltip,
    publicStatus: publicStatus,
    isTypingKey: isTypingKey,
    searchCommand: searchCommand,
    searchHints: searchHints,
    formCommand: formCommand,
    moveSelection: moveSelection
  }
}
