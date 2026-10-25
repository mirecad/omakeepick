import QtQuick
import qs.Ui
import "Model.js" as Model

// The bar button and the host of its status popup (StatusPanel.qml).
//
// A closed padlock while the database is locked, and an open one in the
// bar's active colour while it is unlocked -- the "in use" treatment the
// microphone widget gives a live mic. With no database open, or no daemon,
// the padlock dims like an idle indicator.
//
// Left click opens the status panel, right click locks, middle click opens
// the picker. The bar mounts one of these per monitor; they all share the
// one Service.
Panel {
  id: root
  moduleName: "mirecad.omakeepick"
  manageIpc: false

  readonly property var keepass: bar && bar.shell && typeof bar.shell.serviceFor === "function"
    ? bar.shell.serviceFor(moduleName)
    : null
  readonly property string phaseKey: keepass ? keepass.phaseKey : "offline"
  readonly property var daemonState: keepass ? keepass.daemonState : Model.emptyState()
  property double now: Date.now()

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function lockNow() {
    if (root.keepass && root.phaseKey === "unlocked") root.keepass.lock("manual", null)
  }

  function openPicker() {
    root.close()
    if (root.keepass) root.keepass.openPicker("{}")
  }

  function closeDatabase() {
    if (root.keepass) root.keepass.closeDatabase(null)
  }

  // Pick a file first, then bring up the picker's unlock card on it.
  function openDatabase() {
    root.close()
    var target = root.keepass
    if (!target) return
    target.pickFile("db", function(reply) {
      if (reply.ok && reply.path) {
        target.openPicker(JSON.stringify({
          unlock: true,
          db: String(reply.path),
          keyfile: reply.keyfile ? String(reply.keyfile) : ""
        }))
      }
      else if (reply.error !== "cancelled") target.notify("OmaKeePick", Model.errorText(reply), "normal")
    })
  }

  onOpenedChanged: if (opened) root.now = Date.now()

  Timer {
    // Minutes are enough for the tooltip; the open panel counts seconds.
    interval: root.opened ? 1000 : 15000
    repeat: true
    running: root.phaseKey === "unlocked" && root.daemonState.lockAt > 0
    triggeredOnStart: true
    onTriggered: root.now = Date.now()
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: Model.barGlyph(root.phaseKey)
    active: root.phaseKey === "unlocked"
    dimmed: root.phaseKey === "offline" || root.phaseKey === "closed"
    tooltipText: Model.barTooltip(root.phaseKey, root.daemonState, root.now)
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) root.lockNow()
      else if (buttonCode === Qt.MiddleButton) root.openPicker()
      else root.toggle()
    }
  }

  StatusPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    host: root
    open: root.opened
  }
}
