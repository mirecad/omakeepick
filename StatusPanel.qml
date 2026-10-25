pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// The bar widget's popup: which database, where it stands, how long until it
// locks itself, and the four things to do about it. Composed like the stock
// power panel -- hero over facts over a grid of bordered buttons that the
// arrow keys walk.
//
// BarWidget.qml owns the button and the open state and is the `host` here.
KeyboardPanel {
  id: panel

  required property var host

  readonly property var keepass: host.keepass
  readonly property string phaseKey: host.phaseKey
  readonly property var daemonState: host.daemonState
  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color accent: Commons.Color.accent
  readonly property color dim: Qt.darker(foreground, 1.4)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string home: Quickshell.env("HOME")
  readonly property int remaining: phaseKey === "unlocked" ? Model.secondsUntil(daemonState.lockAt, host.now) : -1
  // What the plugin last configured, which the daemon's state echoes.
  readonly property int idleLockMinutes: keepass ? keepass.daemonSettings.idleLockMinutes : daemonState.idleLockMinutes

  property int cursor: 0
  property bool cursorActive: false

  readonly property var actions: [
    { key: "picker", icon: "󰍉", label: "Open picker", enabled: phaseKey !== "offline" },
    { key: "lock", icon: "󰌾", label: "Lock", enabled: phaseKey === "unlocked" },
    { key: "close", icon: "󰅙", label: "Close database", enabled: phaseKey === "unlocked" || phaseKey === "locked" },
    { key: "open", icon: "󰝰", label: "Open database…", enabled: phaseKey !== "offline" }
  ]

  focusTarget: keyCatcher
  contentWidth: panel.fittedContentWidth(Style.space(380))
  contentHeight: panel.fittedContentHeight(column.implicitHeight)

  onOpenChanged: if (open) {
    panel.cursorActive = false
    panel.cursor = 0
  }

  function run(action) {
    if (!action || !action.enabled) return
    if (action.key === "picker") panel.host.openPicker()
    else if (action.key === "lock") panel.host.lockNow()
    else if (action.key === "close") panel.host.closeDatabase()
    else if (action.key === "open") panel.host.openDatabase()
  }

  // Moves through the two-column grid (a row is two steps), passing over
  // buttons that do nothing in the current state.
  function moveCursor(delta) {
    var count = panel.actions.length
    var step = delta > 0 ? 1 : -1
    var next = ((panel.cursor + delta) % count + count) % count
    for (var i = 0; i < count && !panel.actions[next].enabled; i++) next = (next + step + count) % count
    if (panel.actions[next].enabled) panel.cursor = next
  }

  PanelKeyCatcher {
    id: keyCatcher
    anchors.fill: parent
    onMoveRequested: function(dx, dy) {
      if (!panel.cursorActive) {
        panel.cursorActive = true
        if (!panel.actions[panel.cursor].enabled) panel.moveCursor(1)
        return
      }
      panel.moveCursor(dx !== 0 ? dx : dy * 2)
    }
    onActivateRequested: panel.run(panel.cursorActive ? panel.actions[panel.cursor] : panel.actions[0])
    onCloseRequested: panel.host.close()
    onTabRequested: function(direction) { panel.host.switchPanel(direction) }

    Column {
      id: column
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(14)

      // ---------- Hero: padlock · database/status · countdown ----------
      Item {
        width: parent.width
        implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight, heroClock.implicitHeight)

        Text {
          id: heroIcon
          textFormat: Text.PlainText
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          text: Model.barGlyph(panel.phaseKey)
          color: panel.phaseKey === "unlocked" ? panel.accent : panel.foreground
          opacity: panel.phaseKey === "offline" || panel.phaseKey === "closed" ? 0.5 : 1
          font.family: panel.fontFamily
          font.pixelSize: Style.font.display

          Behavior on color { ColorAnimation { duration: 200 } }
        }

        Column {
          id: heroLabels
          anchors.left: heroIcon.right
          anchors.leftMargin: Style.space(14)
          anchors.right: heroClock.left
          anchors.rightMargin: Style.space(10)
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(2)

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: panel.daemonState.dbName || "OmaKeePick"
            color: panel.foreground
            font.family: panel.fontFamily
            font.pixelSize: Style.font.title
            font.bold: true
            elide: Text.ElideRight
          }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: Model.statusText(panel.phaseKey, panel.daemonState, panel.host.now).toUpperCase()
            color: panel.dim
            font.family: panel.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            font.letterSpacing: 1.2
            elide: Text.ElideRight
          }
        }

        Text {
          id: heroClock
          textFormat: Text.PlainText
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: panel.remaining >= 0
          width: visible ? implicitWidth : 0
          text: Model.formatClock(panel.remaining)
          color: panel.foreground
          font.family: panel.fontFamily
          font.pixelSize: Style.font.display
          font.bold: true
        }
      }

      // ---------- Facts ----------
      Column {
        width: parent.width
        spacing: Style.spacing.labelGap

        InfoPair {
          label: "Database"
          value: panel.daemonState.db ? Model.displayPath(panel.daemonState.db, panel.home) : "None"
        }
        InfoPair {
          label: "Key file"
          value: panel.daemonState.keyfile ? Model.displayPath(panel.daemonState.keyfile, panel.home) : "None"
        }
        InfoPair {
          visible: panel.phaseKey === "unlocked"
          label: "Entries"
          value: String(panel.daemonState.entryCount)
        }
        InfoPair {
          visible: panel.phaseKey !== "offline"
          label: "Auto-lock"
          value: panel.idleLockMinutes > 0
            ? "after " + Model.plural(panel.idleLockMinutes, "minute", "minutes") + " idle"
            : "off"
        }
      }

      PanelSeparator {
        foreground: panel.foreground
      }

      // ---------- Actions ----------
      Grid {
        id: actionGrid
        width: parent.width
        columns: 2
        columnSpacing: Style.space(6)
        rowSpacing: Style.space(6)

        readonly property real cellWidth: (width - columnSpacing) / 2

        Repeater {
          model: panel.actions

          Button {
            required property var modelData
            required property int index

            width: actionGrid.cellWidth
            iconText: modelData.icon
            iconSize: Style.font.title
            text: modelData.label
            fontSize: Style.font.bodySmall
            foreground: panel.foreground
            fontFamily: panel.fontFamily
            horizontalPadding: Style.spacing.controlPaddingX
            verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
            bordered: true
            enabled: modelData.enabled
            opacity: enabled ? 1 : 0.45
            hasCursor: panel.cursorActive && panel.cursor === index && enabled
            onClicked: panel.run(modelData)
            onHovered: function(hovered) {
              if (hovered && modelData.enabled) {
                panel.cursorActive = true
                panel.cursor = index
              }
            }
          }
        }
      }
    }
  }

  // A label on the left and its value on the right, eliding in the middle
  // so a long path keeps both its folder and its file name.
  component InfoPair: Item {
    id: pair
    property string label: ""
    property string value: ""

    width: parent ? parent.width : implicitWidth
    implicitHeight: Math.max(pairLabel.implicitHeight, pairValue.implicitHeight)

    Text {
      id: pairLabel
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      text: pair.label
      color: panel.foreground
      opacity: 0.6
      font.family: panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    Text {
      id: pairValue
      textFormat: Text.PlainText
      anchors.left: pairLabel.right
      anchors.leftMargin: Style.space(16)
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      horizontalAlignment: Text.AlignRight
      text: pair.value
      color: panel.foreground
      font.family: panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      elide: Text.ElideMiddle
    }
  }
}
