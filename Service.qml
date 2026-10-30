import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

// Owns the only conversation with omakeepickd: one long-lived `attach`
// bridge, request ids and the callbacks waiting on them, the state the daemon
// pushes, and the screen-lock watcher. The picker, the bar widget and the IPC
// handler read state from here and never start a process themselves.
//
// Secrets pass through here exactly once. unlock() and quickUnlock() build
// the request inline, write it to the bridge's stdin and let go of it: no
// property, log line or pending-request record ever holds a password or PIN.
Item {
  id: root

  property var shell: null
  property var manifest: null
  property string omarchyPath: Quickshell.env("OMARCHY_PATH")

  readonly property string pluginId: manifest && manifest.id ? String(manifest.id) : "mirecad.omakeepick"
  readonly property string pluginDirectory: Model.fileUrlPath(Qt.resolvedUrl("."))
  readonly property string omarchyBin: omarchyPath ? omarchyPath + "/bin/" : ""

  // Settings are inline on the plugin's entry in shell.json, which is the bar
  // layout entry once the plugin is enabled. The bar injects them into the
  // widget but nothing injects them into a service, so they are read off the
  // scoped shell facade's detached barConfig snapshot instead. The host
  // refreshes that snapshot on every shell.json change, and it is there even
  // when no bar surface is hosting the widget.
  readonly property var settings: Model.entrySettings(shell ? shell.barConfig : null, pluginId)
  readonly property var daemonSettings: Model.daemonSettings(settings)
  readonly property bool notifyOnCopy: Model.boolSetting(settings, "notifyOnCopy", true)

  // ------------------------------------------------------------ published

  readonly property bool connected: _connected
  readonly property bool daemonMissing: _daemonMissing
  readonly property string daemonPath: _daemonPath
  readonly property bool installing: installer.running
  readonly property string installError: _installError

  readonly property var daemonState: _state
  readonly property string phase: _state.phase
  readonly property bool busy: _state.busy
  readonly property bool quickUnlock: _state.quickUnlock
  readonly property int pinAttemptsLeft: _state.pinAttemptsLeft
  readonly property string db: _state.db
  readonly property string keyfile: _state.keyfile
  readonly property string dbName: _state.dbName
  readonly property int entryCount: _state.entryCount
  readonly property double lockAt: _state.lockAt
  readonly property string lockReason: _state.lockReason
  readonly property string phaseKey: Model.phaseKey(_connected, _state)

  // The newest search the daemon answered. Entries never carry secrets.
  readonly property var results: _results
  readonly property int resultsTotal: _resultsTotal
  readonly property string resultsQuery: _resultsQuery
  readonly property bool searching: _searchId !== 0 || searchDebounce.running

  // -------------------------------------------------------------- private

  property bool _connected: false
  property bool _daemonMissing: false
  property string _daemonPath: ""
  // bin/install runs at most once per reason per shell session, so a failing
  // download cannot loop.
  property var _installTried: ({})
  property string _installError: ""
  property string _installLastLine: ""
  property bool _stopping: false
  property double _startedAt: 0
  property int _attempt: 0
  property var _state: Model.emptyState()
  property var _results: []
  property int _resultsTotal: 0
  property string _resultsQuery: ""
  property string _pendingQuery: ""
  property int _searchId: 0
  property int _nextId: 0
  // id -> { cmd, callback, deadline }. Only ever the command name and who to
  // call back: request arguments are not kept.
  property var _pending: ({})
  property int _pendingCount: 0
  property string _configured: ""

  // ------------------------------------------------------------- requests

  // Sends one request and calls `callback(reply)` with the daemon's answer,
  // or with { ok: false, error: "disconnected" | "timeout" }. Returns the id.
  function request(cmd, args, callback, timeoutMs) {
    if (!_connected || !attach.running) {
      if (callback) Qt.callLater(function() { root.invoke(callback, cmd, { ok: false, error: "disconnected" }) })
      return 0
    }
    var id = ++_nextId
    _pending[id] = { cmd: cmd, callback: callback || null, deadline: timeoutMs > 0 ? Date.now() + timeoutMs : 0 }
    _pendingCount += 1
    attach.write(Model.buildRequest(id, cmd, args) + "\n")
    return id
  }

  function invoke(callback, cmd, reply) {
    try {
      callback(reply)
    } catch (error) {
      // The caller may have been torn down by a plugin reload mid-request.
      console.warn("omakeepick: " + cmd + " reply handler failed: " + error)
    }
  }

  function resolve(id, reply) {
    var pending = _pending[id]
    if (!pending) return
    delete _pending[id]
    _pendingCount = Math.max(0, _pendingCount - 1)
    if (reply.ok !== true) reply.ok = false
    if (pending.callback) invoke(pending.callback, pending.cmd, reply)
  }

  function failPending(error) {
    var ids = Object.keys(_pending)
    for (var i = 0; i < ids.length; i++) resolve(ids[i], { ok: false, error: error })
    _pending = ({})
    _pendingCount = 0
  }

  function expirePending() {
    var now = Date.now()
    var ids = Object.keys(_pending)
    for (var i = 0; i < ids.length; i++) {
      var pending = _pending[ids[i]]
      if (pending && pending.deadline > 0 && now > pending.deadline) resolve(ids[i], { ok: false, error: "timeout" })
    }
  }

  // ------------------------------------------------------------- commands

  // The password and PIN live only in this argument list and the one-shot
  // JSON line built from it; both are dropped when this returns.
  function unlock(dbPath, keyfilePath, password, pin, callback) {
    return request("unlock", {
      db: String(dbPath || ""),
      keyfile: keyfilePath ? String(keyfilePath) : null,
      password: String(password || ""),
      pin: pin ? String(pin) : null
    }, callback, 0)
  }

  function quickUnlockWith(pin, callback) {
    return request("quickUnlock", { pin: String(pin || "") }, callback, 0)
  }

  function lock(reason, callback) {
    return request("lock", { reason: reason || "manual" }, callback, 15000)
  }

  function closeDatabase(callback) {
    return request("close", {}, callback, 15000)
  }

  function touch() {
    return request("touch", {}, null, 15000)
  }

  function pickFile(kind, callback) {
    return request("pickFile", { kind: kind === "keyfile" ? "keyfile" : "db" }, callback, 0)
  }

  // Runs an entry action and reports the outcome as a desktop notification.
  // Callers hide their surface first; auto-type types into whatever has focus.
  // The notification never names the entry: its text goes on the command line
  // of omarchy-notification-send, which other users can read, and Omarchy keeps
  // it in the notification history.
  function perform(entry, action, callback) {
    if (!entry || !entry.id) return 0
    return request("act", { entry: entry.id, action: action }, function(reply) {
      if (!reply.ok) {
        if (reply.error !== "cancelled") root.notify("OmaKeePick", Model.errorText(reply), "normal")
      } else if (Model.isCopyAction(action) && root.notifyOnCopy) {
        root.notify(Model.copiedText(action, reply.clearsIn), "", "low")
      }
      if (callback) callback(reply)
    }, 0)
  }

  // Debounced, so a burst of keystrokes costs one round trip. Replies to a
  // superseded query are dropped.
  function search(query) {
    _pendingQuery = String(query || "")
    searchDebounce.restart()
  }

  function searchNow(query) {
    searchDebounce.stop()
    _pendingQuery = String(query || "")
    sendSearch()
  }

  function sendSearch() {
    if (!_connected || phase !== "unlocked") {
      clearResults()
      return
    }
    var query = _pendingQuery
    var id = request("search", { query: query, limit: 50 }, function(reply) {
      if (id !== root._searchId) return
      root._searchId = 0
      if (!reply.ok) {
        if (reply.error === "locked") root.clearResults()
        return
      }
      root._results = Model.normalizeEntries(reply.entries)
      root._resultsTotal = Math.max(0, Number(reply.total) || root._results.length)
      root._resultsQuery = query
    }, 15000)
    _searchId = id
  }

  function clearResults() {
    _searchId = 0
    if (_results.length > 0) _results = []
    _resultsTotal = 0
    _resultsQuery = ""
  }

  function pushSettings(force) {
    if (!_connected) return
    var payload = JSON.stringify(daemonSettings)
    if (force !== true && payload === _configured) return
    _configured = payload
    request("configure", { settings: daemonSettings }, function(reply) {
      if (!reply.ok) {
        root._configured = ""
        console.warn("omakeepick: configure rejected: " + Model.errorText(reply))
      }
    }, 15000)
  }

  onDaemonSettingsChanged: Qt.callLater(root.pushSettings)

  // ------------------------------------------------------------- messages

  function handleLine(line) {
    var parsed = Model.parseLine(line)
    if (parsed.kind === "reply") {
      resolve(parsed.id, parsed.message)
    } else if (parsed.kind === "event") {
      if (parsed.event === "state") applyState(parsed.message)
      else if (parsed.event === "notice") handleNotice(parsed.message)
    } else if (parsed.kind === "invalid") {
      // The line itself is not echoed: nothing from the bridge is logged.
      console.warn("omakeepick: ignoring a malformed line from omakeepickd")
    }
  }

  function applyState(message) {
    _state = Model.normalizeState(message)
    if (!_connected) {
      _connected = true
      _daemonMissing = false
      pushSettings(true)
      // `omarchy plugin update` brings new QML but leaves the old binary.
      var daemonVersion = String(message.version || "")
      var pluginVersion = manifest && manifest.version ? String(manifest.version) : ""
      if (daemonVersion && pluginVersion && daemonVersion !== pluginVersion) runInstall("outdated")
    }
    if (_state.phase !== "unlocked") clearResults()
  }

  function handleNotice(message) {
    var text = String(message.message || "").trim()
    if (text) notify("OmaKeePick", text, Model.noticeUrgency(String(message.level || "info")))
  }

  function notify(title, body, urgency) {
    Quickshell.execDetached([
      root.omarchyBin + "omarchy-notification-send",
      "--app-name", "OmaKeePick",
      "-g", "󰌾",
      "-u", urgency || "low",
      Model.notificationText(title || "OmaKeePick"),
      Model.notificationText(body || "")
    ])
  }

  // --------------------------------------------------------------- picker

  function openPicker(payloadJson) {
    if (!shell || typeof shell.summon !== "function") return false
    return shell.summon(pluginId, payloadJson || "{}") === true
  }

  function closePicker() {
    if (shell && typeof shell.hide === "function") shell.hide(pluginId)
  }

  function togglePicker() {
    if (shell && typeof shell.toggle === "function") shell.toggle(pluginId, "{}")
  }

  // ------------------------------------------------------------ screen lock

  // omarchy.lock is an authentication service: the host keeps it out of the
  // service map, so serviceFor() cannot reach it from a third-party plugin.
  // Its IPC target is the supported way to ask, the same one omarchy.idle
  // uses, and it is only asked while there is something to lock.
  function screenLocked() {
    if (phase !== "unlocked") return
    closePicker()
    lock("screen", null)
  }

  // ---------------------------------------------------------------- bridge

  function start() {
    if (_stopping || attach.running || resolver.running) return
    var candidates = Model.daemonCandidates(pluginDirectory, Quickshell.env("OMAKEEPICKD"))
    resolver.command = ["bash", "-c",
      "for candidate in \"$@\"; do [[ -f $candidate && -x $candidate ]] && { printf '%s\\n' \"$candidate\"; exit 0; }; done; exit 1",
      "omakeepick"].concat(candidates)
    resolver.running = true
  }

  function startBridge(path) {
    if (_stopping || attach.running) return
    _daemonMissing = false
    _daemonPath = path
    _startedAt = Date.now()
    attach.command = [path, "attach"]
    attach.running = true
  }

  function daemonNotFound() {
    if (!_daemonMissing)
      console.warn("omakeepick: omakeepickd not found in " + pluginDirectory + "/bin or daemon/target")
    _daemonMissing = true
    _daemonPath = ""
    if (runInstall("missing")) return
    // Someone may be building it right now; look again in a while.
    reconnect.interval = 10000
    reconnect.restart()
  }

  function bridgeExited(exitCode) {
    var wasConnected = _connected
    _connected = false
    _configured = ""
    failPending("disconnected")
    clearResults()
    if (_stopping) return
    // A bridge that stayed up a while earns a fresh, fast retry.
    if (Date.now() - _startedAt > 10000) _attempt = 0
    reconnect.interval = Model.backoffDelay(_attempt)
    _attempt += 1
    reconnect.restart()
    if (wasConnected) console.warn("omakeepick: lost omakeepickd (exit " + exitCode + "), reconnecting")
  }

  // Fetches (or builds) bin/omakeepickd; see bin/install.
  function runInstall(reason) {
    if (installer.running || _installTried[reason]) return false
    _installTried[reason] = true
    _installError = ""
    _installLastLine = ""
    if (reason === "missing") notify("OmaKeePick", "Installing the KeePass helper…", "low")
    installer.reason = reason
    installer.command = ["bash", pluginDirectory + "/bin/install"]
    installer.running = true
    return true
  }

  function installFinished(exitCode, reason) {
    if (exitCode === 0) {
      _installError = ""
      if (reason === "missing") notify("OmaKeePick", "KeePass helper installed", "low")
      // An outdated daemon was stopped by the installer; the bridge reconnects to the new one.
      if (!_connected && !attach.running) {
        reconnect.interval = 200
        reconnect.restart()
      }
    } else {
      _installError = _installLastLine || "bin/install failed"
      notify("OmaKeePick", "Could not install the KeePass helper: " + _installError, "normal")
      if (!_connected) daemonNotFound()
    }
  }

  Process {
    id: installer
    property string reason: ""
    stderr: SplitParser {
      onRead: function(line) {
        var text = String(line).replace(/^omakeepick install: /, "").trim()
        if (text !== "") root._installLastLine = text
      }
    }
    onExited: function(exitCode) { root.installFinished(exitCode, installer.reason) }
  }

  Process {
    id: resolver
    stdout: StdioCollector { id: resolverOut; waitForEnd: true }
    onExited: function(exitCode) {
      var path = String(resolverOut.text || "").trim()
      if (exitCode === 0 && path !== "") root.startBridge(path)
      else root.daemonNotFound()
    }
  }

  Process {
    id: attach
    stdinEnabled: true
    stdout: SplitParser {
      onRead: function(line) { root.handleLine(line) }
    }
    stderr: SplitParser {
      // The daemon's own diagnostics. It never writes secrets there.
      onRead: function(line) { if (String(line).trim() !== "") console.warn("omakeepickd: " + line) }
    }
    onExited: function(exitCode) { root.bridgeExited(exitCode) }
  }

  Timer {
    id: reconnect
    interval: 500
    repeat: false
    onTriggered: root.start()
  }

  // Backstop for a bridge that never started (a failed exec reports no exit)
  // or started and never said hello.
  Timer {
    interval: 15000
    repeat: true
    running: !root._connected && !root._stopping
    onTriggered: {
      if (attach.running && Date.now() - root._startedAt > 15000) attach.running = false
      else if (!attach.running && !resolver.running && !reconnect.running) root.start()
    }
  }

  Timer {
    interval: 1000
    repeat: true
    running: root._pendingCount > 0
    onTriggered: root.expirePending()
  }

  Timer {
    id: searchDebounce
    interval: 40
    repeat: false
    onTriggered: root.sendSearch()
  }

  // One `omarchy-shell lock isLocked` costs ~25ms of CPU, so ask only while a
  // database is unlocked, and not often: while the screen is locked nobody
  // can reach the picker anyway, so a few seconds of lag cost nothing.
  Timer {
    interval: 10000
    repeat: true
    running: root._connected && root.phase === "unlocked"
    triggeredOnStart: true
    onTriggered: if (!screenLockCheck.running) screenLockCheck.running = true
  }

  Process {
    id: screenLockCheck
    command: [root.omarchyBin + "omarchy-shell", "lock", "isLocked"]
    stdout: StdioCollector { id: screenLockOut; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0 && String(screenLockOut.text || "").trim() === "true") root.screenLocked()
    }
  }

  IpcHandler {
    target: "omakeepick"

    function open(): string { return root.openPicker("{}") ? "ok" : "unknown" }
    function close(): void { root.closePicker() }
    function toggle(): void { root.togglePicker() }
    function lock(): string {
      if (!root.connected) return "offline"
      root.lock("manual", null)
      return "ok"
    }
    function closeDatabase(): string {
      if (!root.connected) return "offline"
      root.closeDatabase(null)
      return "ok"
    }
    function status(): string { return JSON.stringify(Model.publicStatus(root.connected, root.daemonState)) }
  }

  Component.onCompleted: start()

  Component.onDestruction: {
    // The daemon outlives us (and stays unlocked across a shell restart);
    // only the bridge goes.
    _stopping = true
    attach.running = false
  }
}
