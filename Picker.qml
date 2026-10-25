pragma ComponentBehavior: Bound
import Quickshell
import Quickshell.Wayland
import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// The picker overlay. One card, three faces:
//   search  -- the database is open: type, pick a row, Enter auto-types it
//   unlock  -- database + key file + master password (+ optional PIN)
//   pin     -- the database was locked with a quick-unlock PIN on file
// plus a fourth, "offline", while omakeepickd is not reachable.
//
// The card keeps one top edge for all faces, set where the search card would
// sit centered at its full eight rows, so results drop down from a still
// input and unlocking does not move the card.
//
// Passwords and PINs only ever live in the fields' own buffers. Submitting
// hands the text straight to the Service, which writes it to the daemon, and
// the fields are emptied in the same turn; closing the picker empties them
// too.
Item {
  id: root

  // Injected by omarchy-shell when the overlay loads.
  property string omarchyPath: Quickshell.env("OMARCHY_PATH")
  property var shell: null
  property var manifest: null
  property var service: null

  readonly property string pluginId: manifest && manifest.id ? String(manifest.id) : "mirecad.omakeepick"
  // The host hands over the service at load; look it up again if the service
  // was recreated after that.
  readonly property var keepass: service || (shell && typeof shell.serviceFor === "function" ? shell.serviceFor(pluginId) : null)
  readonly property string home: Quickshell.env("HOME")

  property bool opened: false
  property string filterText: ""
  property int selectedIndex: 0
  property bool cursorActive: true
  property var entries: []

  // Unlock card. Paths are not secret; they are pre-filled from the daemon's
  // last-used database and replaced by whatever the user picks.
  property string draftDb: ""
  property string draftKeyfile: ""
  property bool draftPicked: false
  property bool unlockRequested: false
  property bool useMasterPassword: false
  property bool submitting: false
  property bool unlockAccepted: false
  property bool pickingFile: false
  property int pickSerial: 0
  property string unlockError: ""
  property string flashText: ""
  property int shakeOffset: 0

  readonly property bool connected: keepass ? keepass.connected : false
  readonly property string phase: keepass ? keepass.phase : "closed"
  readonly property bool unlocking: submitting || (keepass ? keepass.busy : false)
  readonly property string view: Model.pickerView(connected, phase, keepass ? keepass.quickUnlock : false, unlockRequested, useMasterPassword)
  readonly property string draftName: draftDb ? Model.baseName(draftDb).replace(/\.kdbx$/i, "") : ""
  readonly property string headerNote: flashText !== ""
    ? flashText
    : (filterText !== "" && keepass && !keepass.searching && entries.length === 0 ? "No matches" : "")

  // Shares the [menu] surface tokens, like the emoji and clipboard pickers,
  // so themes that style the menu also style this card.
  property color background: Commons.Color.menu.background
  property color foreground: Commons.Color.menu.text
  property color border: Commons.Color.menu.border
  property var borderSpec: Border.surfaceSpec("menu", "border", border, Math.max(1, Style.space(2)))
  property color scrim: Commons.Color.menu.scrim
  property color selectedBackground: Commons.Color.menu.selectedBackground
  property color selectedText: Commons.Color.menu.selectedText
  property color selectedBorder: Commons.Color.menu.selectedBorder
  property var selectedBorderSpec: Border.surfaceSpec("menu", "selected-border", selectedBorder, 0)
  property color accent: Commons.Color.accent
  property color errorColor: Commons.Color.urgent
  readonly property real rowReservedBorderLeft: Border.left(selectedBorderSpec)
  readonly property real rowReservedBorderRight: Border.right(selectedBorderSpec)
  readonly property int cornerRadius: Style.cornerRadius
  property string fontFamily: Style.font.menuFamily
  property int contentMargin: Style.spacing.panelPadding
  property int headerHeight: Math.max(Style.space(34), Style.font.title + Style.spacing.controlPaddingY * 2)
  property int contentSpacing: Style.spacing.md
  property int rowHeight: Math.max(Style.space(58), Style.font.body + Style.font.caption + Style.spacing.rowPaddingX * 2)
  property int rowSpacing: Style.spacing.xs
  property int maxVisibleRows: 8
  property int cardWidth: Math.min(Style.space(640), panel.width - Style.gapsOut * 2)

  readonly property int visibleRows: Math.min(displayModel.count, maxVisibleRows)
  readonly property int listHeight: visibleRows > 0 ? visibleRows * rowHeight + (visibleRows - 1) * rowSpacing : 0
  readonly property int fullSearchHeight: contentMargin * 2 + headerHeight + contentSpacing + maxVisibleRows * rowHeight + (maxVisibleRows - 1) * rowSpacing
  readonly property int cardHeight: {
    if (view === "search") return contentMargin * 2 + headerHeight + (visibleRows > 0 ? contentSpacing + listHeight : 0)
    if (view === "pin") return contentMargin * 2 + pinColumn.implicitHeight
    if (view === "unlock") return contentMargin * 2 + unlockColumn.implicitHeight
    return contentMargin * 2 + offlineColumn.implicitHeight
  }

  // ------------------------------------------------------------ lifecycle

  function open(payloadJson) {
    var payload = ({})
    try { payload = JSON.parse(payloadJson || "{}") || ({}) } catch (e) { payload = ({}) }

    root.pickSerial += 1
    root.pickingFile = false
    root.filterText = ""
    root.selectedIndex = 0
    root.cursorActive = true
    root.unlockError = ""
    root.flashText = ""
    root.useMasterPassword = false
    root.submitting = false
    root.unlockAccepted = false
    root.clearSecrets()

    // `{"unlock":true,"db":"/path"}` opens the unlock card on that file, even
    // over an unlocked database (the bar panel's "Open database…").
    var requestedDb = typeof payload.db === "string" ? payload.db : ""
    root.unlockRequested = payload.unlock === true || requestedDb !== ""
    if (requestedDb !== "") {
      root.draftDb = requestedDb
      root.draftKeyfile = typeof payload.keyfile === "string" ? payload.keyfile : ""
      root.draftPicked = true
    } else {
      root.draftPicked = false
      root.prefillDrafts()
    }

    pointerGate.reset()
    root.opened = true
    if (root.view === "search" && root.keepass) {
      // Last time's results for another query would flash up for a frame.
      if (root.keepass.resultsQuery !== "") root.keepass.clearResults()
      root.keepass.searchNow("")
    }
    root.rebuildDisplay()
    Qt.callLater(root.focusView)
  }

  function close() {
    // Cancels the reopen a pending file pick would do.
    root.pickSerial += 1
    root.pickingFile = false
    root.opened = false
    root.clearSecrets()
  }

  function dismiss() {
    root.close()
    if (root.shell && typeof root.shell.hide === "function") root.shell.hide(root.pluginId)
  }

  function toggle() {
    if (root.opened) root.dismiss()
    else root.open("{}")
  }

  function reopen() {
    root.opened = true
    Qt.callLater(root.focusView)
  }

  function clearSecrets() {
    passwordField.text = ""
    pinField.text = ""
    quickPinField.text = ""
  }

  function prefillDrafts() {
    root.draftDb = root.keepass ? root.keepass.db : ""
    root.draftKeyfile = root.keepass ? root.keepass.keyfile : ""
  }

  function focusView() {
    if (!root.opened) return
    if (root.view === "unlock") {
      if (!pinField.activeFocus) passwordField.forceActiveFocus()
    } else if (root.view === "pin") {
      quickPinField.forceActiveFocus()
    } else {
      keyCatcher.forceActiveFocus()
    }
  }

  onViewChanged: {
    if (!root.opened) return
    root.unlockError = ""
    if (root.view === "search" && root.keepass) root.keepass.searchNow(root.filterText)
    else root.rebuildDisplay()
    Qt.callLater(root.focusView)
  }

  // The unlock reply and the state event that follows it can arrive in
  // either order. The card changes face on the state, so it never flashes the
  // PIN card between "accepted" and "unlocked".
  onPhaseChanged: if (root.phase === "unlocked" && root.unlockAccepted) root.finishUnlock()

  function finishUnlock() {
    root.unlockAccepted = false
    root.unlockRequested = false
    root.useMasterPassword = false
    root.draftPicked = false
  }

  Connections {
    target: root.keepass
    function onResultsChanged() { root.rebuildDisplay() }
    function onDbChanged() {
      if (!root.draftPicked) root.prefillDrafts()
      // A database switched under an open search card: rerun the query.
      if (root.opened && root.view === "search" && root.keepass) root.keepass.searchNow(root.filterText)
    }
    function onKeyfileChanged() { if (!root.draftPicked) root.prefillDrafts() }
  }

  // --------------------------------------------------------------- search

  function setFilter(nextFilter) {
    root.filterText = nextFilter
    root.selectedIndex = 0
    root.cursorActive = true
    root.flashText = ""
    pointerGate.reset()
    if (root.keepass) root.keepass.search(nextFilter)
  }

  function rebuildDisplay() {
    var list = root.view === "search" && root.keepass ? root.keepass.results : []
    root.entries = list

    displayModel.clear()
    for (var i = 0; i < list.length; i++) {
      displayModel.append({
        title: list[i].title || "(untitled)",
        detail: Model.entryDetail(list[i])
      })
    }

    if (displayModel.count === 0) root.selectedIndex = 0
    else if (root.selectedIndex >= displayModel.count) root.selectedIndex = displayModel.count - 1

    Qt.callLater(function() {
      if (displayModel.count > 0) resultList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
    })
  }

  function select(command) {
    if (displayModel.count === 0) return
    pointerGate.reset()
    root.cursorActive = true
    root.selectedIndex = Model.moveSelection(root.selectedIndex, displayModel.count, command, root.maxVisibleRows)
    resultList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
  }

  function selectFromPointer(index, item, mouse) {
    if (!pointerGate.moved(item, mouse)) return
    root.cursorActive = true
    root.selectedIndex = index
  }

  // The overlay goes away before anything is typed or copied: auto-type must
  // land in the window underneath, and a copy has nothing left to show here.
  function runAction(index, action) {
    if (!root.keepass || index < 0 || index >= root.entries.length) return
    var entry = root.entries[index]
    if (!Model.entrySupports(entry, action)) {
      root.flash(Model.missingFieldText(action))
      return
    }
    var target = root.keepass
    root.dismiss()
    if (Model.isTypeAction(action)) Qt.callLater(function() { target.perform(entry, action, null) })
    else target.perform(entry, action, null)
  }

  function flash(text) {
    root.flashText = text
    flashTimer.restart()
  }

  function handleSearchKey(event) {
    if (event.key === Qt.Key_Escape) {
      if (root.filterText) root.setFilter("")
      else root.dismiss()
      event.accepted = true
      return
    }
    if (Util.editsFilter(event, root.filterText)) {
      root.setFilter(Util.editedFilter(event, root.filterText))
      event.accepted = true
      return
    }
    var command = Model.searchCommand(event.key, event.modifiers, event.text)
    if (command === "") return
    event.accepted = true
    if (command === "type") root.setFilter(root.filterText + event.text)
    else if (command === "up" || command === "down" || command === "pageUp" || command === "pageDown" || command === "home" || command === "end") root.select(command)
    else root.runAction(root.selectedIndex, command)
  }

  // --------------------------------------------------------------- unlock

  function handleFormKey(event, field) {
    var command = Model.formCommand(event.key, event.modifiers)
    if (command === "") return
    event.accepted = true
    if (command === "escape") {
      root.dismiss()
    } else if (command === "submit") {
      if (root.view === "pin") root.submitPin()
      else root.submitUnlock()
    } else if (command === "next" || command === "previous") {
      if (root.view === "pin") root.useFullCard()
      else if (field === passwordField) pinField.forceActiveFocus()
      else passwordField.forceActiveFocus()
    } else if (command === "pickDatabase") {
      root.pickFile("db")
    } else if (command === "pickKeyfile") {
      root.pickFile("keyfile")
    } else if (command === "clearField") {
      field.text = ""
    }
  }

  function useFullCard() {
    root.useMasterPassword = true
    root.unlockError = ""
    quickPinField.text = ""
  }

  function submitUnlock() {
    if (!root.keepass || root.unlocking) return
    if (root.draftDb === "") {
      root.failUnlock("Choose a database first · Ctrl+O")
      return
    }
    if (passwordField.text.length === 0 && root.draftKeyfile === "") {
      root.failUnlock("Enter the master password")
      return
    }
    root.submitting = true
    root.unlockError = ""
    root.keepass.unlock(root.draftDb, root.draftKeyfile, passwordField.text, pinField.text, function(reply) {
      root.submitting = false
      if (!reply.ok) {
        root.failUnlock(Model.errorText(reply))
      } else if (root.phase === "unlocked") {
        root.finishUnlock()
      } else {
        root.unlockAccepted = true
      }
    })
    passwordField.text = ""
    pinField.text = ""
  }

  function submitPin() {
    if (!root.keepass || root.unlocking || quickPinField.text.length === 0) return
    root.submitting = true
    root.unlockError = ""
    root.keepass.quickUnlockWith(quickPinField.text, function(reply) {
      root.submitting = false
      if (reply.ok) return
      if (reply.error === "no_quick_unlock") root.useMasterPassword = true
      root.failUnlock(Model.errorText(reply))
    })
    quickPinField.text = ""
  }

  function failUnlock(message) {
    // Closed mid-unlock: there is no card left to show it on.
    if (!root.opened) {
      if (root.keepass && message) root.keepass.notify("OmaKeePick", message, "normal")
      return
    }
    root.unlockError = message
    shakeAnimation.restart()
    Qt.callLater(root.focusView)
  }

  // The file chooser is its own window, so the card steps aside while it is
  // up and comes back with the chosen path filled in.
  function pickFile(kind) {
    if (!root.keepass || root.pickingFile || root.unlocking) return
    if (root.view === "pin") root.useFullCard()
    var serial = ++root.pickSerial
    root.pickingFile = true
    root.opened = false
    root.keepass.pickFile(kind, function(reply) {
      if (serial !== root.pickSerial) return
      root.pickingFile = false
      if (reply.ok && reply.path) {
        var path = String(reply.path)
        if (kind === "keyfile") {
          root.draftKeyfile = path
        } else {
          // The daemon remembers which key file went with each database.
          if (path !== root.draftDb) root.draftKeyfile = reply.keyfile ? String(reply.keyfile) : ""
          root.draftDb = path
        }
        root.draftPicked = true
        root.unlockError = ""
      } else if (reply.error !== "cancelled") {
        root.unlockError = Model.errorText(reply)
      }
      root.reopen()
    })
  }

  function clearKeyfile() {
    root.draftKeyfile = ""
    root.draftPicked = true
    Qt.callLater(root.focusView)
  }

  ListModel { id: displayModel }

  PointerMoveGate {
    id: pointerGate
    referenceItem: card
  }

  Timer {
    id: flashTimer
    interval: 1600
    repeat: false
    onTriggered: root.flashText = ""
  }

  SequentialAnimation {
    id: shakeAnimation
    NumberAnimation { target: root; property: "shakeOffset"; to: -8; duration: 35; easing.type: Easing.OutQuad }
    NumberAnimation { target: root; property: "shakeOffset"; to: 8; duration: 50; easing.type: Easing.InOutQuad }
    NumberAnimation { target: root; property: "shakeOffset"; to: 0; duration: 55; easing.type: Easing.OutQuad }
  }

  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "omakeepick"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    readonly property int cardTop: Math.max(Style.gapsOut, Math.round((height - Math.min(root.fullSearchHeight, height - Style.gapsOut * 2)) / 2))

    Rectangle {
      anchors.fill: parent
      color: root.scrim
    }

    MouseArea {
      anchors.fill: parent
      onClicked: root.dismiss()
    }

    BorderSurface {
      id: card
      width: root.cardWidth
      height: Math.min(root.cardHeight, panel.height - Style.gapsOut - panel.cardTop)
      radius: root.cornerRadius
      anchors.horizontalCenter: parent.horizontalCenter
      anchors.horizontalCenterOffset: root.shakeOffset
      y: panel.cardTop
      color: root.background
      borderSpec: root.borderSpec
      padding: root.contentMargin
      clip: true

      MouseArea { anchors.fill: parent; onClicked: root.focusView() }

      Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true

        Keys.priority: Keys.BeforeItem
        Keys.onPressed: function(event) {
          if (root.view === "search") {
            root.handleSearchKey(event)
          } else if (event.key === Qt.Key_Escape) {
            root.dismiss()
            event.accepted = true
          }
        }
      }

      // ------------------------------------------------------------ search

      Column {
        id: searchColumn
        visible: root.view === "search"
        anchors.fill: parent
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.bottomMargin: card.contentBottomInset
        anchors.leftMargin: card.contentLeftInset
        spacing: root.contentSpacing

        Item {
          width: parent.width
          height: root.headerHeight

          readonly property int caretWidth: Math.max(1, Style.space(2))

          Text {
            id: queryText
            textFormat: Text.PlainText
            anchors.left: parent.left
            anchors.right: noteText.left
            anchors.rightMargin: noteText.text ? Style.space(12) : 0
            anchors.verticalCenter: parent.verticalCenter
            leftPadding: root.filterText ? 0 : parent.caretWidth + Style.space(4)
            text: root.filterText || Model.searchPlaceholder(root.keepass ? root.keepass.entryCount : 0)
            color: root.foreground
            opacity: root.filterText ? 1 : 0.58
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading
            // A long query keeps its newest characters, where the caret is.
            elide: root.filterText ? Text.ElideLeft : Text.ElideRight
          }

          Rectangle {
            x: root.filterText ? Math.min(queryText.contentWidth, queryText.width) + Style.space(1) : 0
            width: parent.caretWidth
            height: Math.round(Style.font.heading * 1.4)
            anchors.verticalCenter: parent.verticalCenter
            color: root.foreground
          }

          Text {
            id: noteText
            textFormat: Text.PlainText
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: root.headerNote
            color: root.foreground
            opacity: 0.52
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
        }

        Item {
          width: parent.width
          height: root.listHeight
          visible: root.visibleRows > 0

          ListView {
            id: resultList
            anchors.fill: parent
            model: displayModel
            clip: true
            spacing: root.rowSpacing
            boundsBehavior: Flickable.StopAtBounds

            delegate: BorderSurface {
              id: row
              required property int index
              required property string title
              required property string detail

              readonly property bool hasCursor: root.cursorActive && row.index === root.selectedIndex

              width: ListView.view.width
              height: root.rowHeight
              radius: root.cornerRadius
              color: row.hasCursor ? root.selectedBackground : "transparent"
              borderSpec: row.hasCursor ? root.selectedBorderSpec : Border.none()

              Column {
                anchors.left: parent.left
                anchors.leftMargin: root.rowReservedBorderLeft + Style.space(18)
                anchors.right: parent.right
                anchors.rightMargin: root.rowReservedBorderRight + Style.space(18)
                anchors.verticalCenter: parent.verticalCenter
                spacing: Style.space(3)

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: row.title
                  color: row.hasCursor ? root.selectedText : root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.heading
                  font.bold: true
                  elide: Text.ElideRight
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  visible: row.detail.length > 0
                  text: row.detail
                  color: root.foreground
                  opacity: 0.52
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  elide: Text.ElideRight
                }
              }

              MouseArea {
                id: rowMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onPositionChanged: function(mouse) { root.selectFromPointer(row.index, row, mouse) }
                onClicked: {
                  root.cursorActive = true
                  root.selectedIndex = row.index
                }
                onDoubleClicked: root.runAction(row.index, "autotype")
              }
            }
          }

          // Scroll scrims, as in the Omarchy menu: each edge fades by how
          // much is still hidden past it.
          Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Math.min(Style.space(28), parent.height / 2)
            visible: opacity > 0
            opacity: resultList.contentHeight > resultList.height
              ? Math.max(0, Math.min(1, (resultList.contentY - resultList.originY) / height))
              : 0
            gradient: Gradient {
              GradientStop { position: 0; color: root.background }
              GradientStop { position: 1; color: Util.alpha(root.background, 0) }
            }
          }

          Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: Math.min(Style.space(28), parent.height / 2)
            visible: opacity > 0
            opacity: resultList.contentHeight > resultList.height
              ? Math.max(0, Math.min(1, (resultList.originY + resultList.contentHeight - resultList.height - resultList.contentY) / height))
              : 0
            gradient: Gradient {
              GradientStop { position: 0; color: Util.alpha(root.background, 0) }
              GradientStop { position: 1; color: root.background }
            }
          }
        }
      }

      // ------------------------------------------------------------ unlock

      Column {
        id: unlockColumn
        visible: root.view === "unlock"
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.leftMargin: card.contentLeftInset
        spacing: Style.space(10)

        CardTitle {
          width: parent.width
          title: root.draftName || "Open a KeePass database"
          subtitle: root.phase === "locked" && !root.unlockRequested ? Model.lockReasonText(root.keepass ? root.keepass.lockReason : "") : ""
        }

        PathPicker {
          width: parent.width
          height: passwordField.implicitHeight
          icon: "󰆼"
          path: root.draftDb
          placeholder: "Choose a database"
          shortcut: "Ctrl+O"
          onPicked: root.pickFile("db")
        }

        PathPicker {
          width: parent.width
          height: passwordField.implicitHeight
          icon: "󰌆"
          path: root.draftKeyfile
          placeholder: "No key file"
          shortcut: "Ctrl+K"
          clearable: true
          onPicked: root.pickFile("keyfile")
          onCleared: root.clearKeyfile()
        }

        TextField {
          id: passwordField
          width: parent.width
          password: true
          foreground: root.foreground
          font.family: root.fontFamily
          placeholderText: root.unlocking ? "Unlocking…" : "Master password"
          readOnly: root.unlocking
          Keys.onPressed: function(event) { root.handleFormKey(event, passwordField) }
          onTextChanged: if (text.length > 0) root.unlockError = ""
        }

        TextField {
          id: pinField
          width: parent.width
          password: true
          foreground: root.foreground
          font.family: root.fontFamily
          placeholderText: "Quick-unlock PIN (optional)"
          readOnly: root.unlocking
          Keys.onPressed: function(event) { root.handleFormKey(event, pinField) }
        }

        StatusLine {
          width: parent.width
          error: root.unlockError
          busy: root.unlocking
          hint: "Enter unlocks · Tab switches fields"
        }
      }

      // --------------------------------------------------------------- pin

      Column {
        id: pinColumn
        visible: root.view === "pin"
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.leftMargin: card.contentLeftInset
        spacing: Style.space(10)

        CardTitle {
          width: parent.width
          title: root.keepass && root.keepass.dbName ? root.keepass.dbName : root.draftName
          subtitle: Model.lockReasonText(root.keepass ? root.keepass.lockReason : "")
        }

        TextField {
          id: quickPinField
          width: parent.width
          password: true
          foreground: root.foreground
          font.family: root.fontFamily
          placeholderText: root.unlocking ? "Unlocking…" : Model.pinPlaceholder(root.keepass ? root.keepass.pinAttemptsLeft : 0)
          readOnly: root.unlocking
          Keys.onPressed: function(event) { root.handleFormKey(event, quickPinField) }
          onTextChanged: if (text.length > 0) root.unlockError = ""
        }

        Item {
          width: parent.width
          height: Math.max(statusPin.implicitHeight, masterLink.implicitHeight)

          StatusLine {
            id: statusPin
            anchors.left: parent.left
            anchors.right: masterLink.left
            anchors.rightMargin: Style.space(12)
            anchors.verticalCenter: parent.verticalCenter
            error: root.unlockError
            busy: root.unlocking
            hint: ""
          }

          Text {
            id: masterLink
            textFormat: Text.PlainText
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: "Use master password · Tab"
            color: linkMouse.containsMouse ? root.selectedText : root.foreground
            opacity: linkMouse.containsMouse ? 1 : 0.58
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.underline: linkMouse.containsMouse

            MouseArea {
              id: linkMouse
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: root.useFullCard()
            }
          }
        }
      }

      // ----------------------------------------------------------- offline

      Column {
        id: offlineColumn
        visible: root.view === "offline"
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.leftMargin: card.contentLeftInset
        spacing: Style.space(10)

        CardTitle {
          width: parent.width
          title: Model.offlineTitle(root.keepass)
          subtitle: Model.offlineSubtitle(root.keepass)
          dim: true
        }
      }
    }
  }

  // ------------------------------------------------------------ components

  // Lock glyph, a bold title and an optional dim line under it, laid out
  // like the polkit prompt's lock-and-field row.
  component CardTitle: Item {
    id: cardTitle
    property string title: ""
    property string subtitle: ""
    property bool dim: false

    implicitHeight: Math.max(titleGlyph.implicitHeight, titleColumn.implicitHeight)

    Text {
      id: titleGlyph
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      width: Style.space(26)
      text: "󰌾"
      color: root.unlockError !== "" ? root.errorColor : (cardTitle.dim ? root.foreground : root.accent)
      opacity: cardTitle.dim ? 0.58 : 1
      font.family: root.fontFamily
      font.pixelSize: Style.font.iconLarge
      horizontalAlignment: Text.AlignHCenter
    }

    Column {
      id: titleColumn
      anchors.left: titleGlyph.right
      anchors.leftMargin: Style.space(10)
      anchors.right: spinner.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(2)

      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: cardTitle.title
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.title
        font.bold: true
        elide: Text.ElideRight
      }

      Text {
        textFormat: Text.PlainText
        width: parent.width
        visible: text !== ""
        text: cardTitle.subtitle
        color: root.foreground
        opacity: 0.52
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        elide: Text.ElideRight
      }
    }

    Text {
      id: spinner
      textFormat: Text.PlainText
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      visible: root.unlocking || (cardTitle.dim && root.keepass !== null && (root.keepass.installing || !root.keepass.daemonMissing))
      text: "󰑐"
      color: root.foreground
      opacity: 0.58
      font.family: root.fontFamily
      font.pixelSize: Style.font.icon

      RotationAnimation on rotation {
        from: 0
        to: 360
        duration: 900
        loops: Animation.Infinite
        running: spinner.visible && root.opened
      }
    }
  }

  // A file path that opens the daemon's file chooser when clicked, drawn as
  // the same control surface as the text fields below it.
  component PathPicker: BorderSurface {
    id: picker
    property string icon: ""
    property string path: ""
    property string placeholder: ""
    property string shortcut: ""
    property bool clearable: false

    signal picked()
    signal cleared()

    readonly property bool hot: pickerMouse.containsMouse
    readonly property var controlBorderSpec: Border.controlSpec(hot ? "hover-cursor" : "normal", root.foreground, root.accent)

    color: Style.controlFill(false, hot, root.foreground, root.accent)
    borderSpec: controlBorderSpec
    radius: Style.cornerRadius

    MouseArea {
      id: pickerMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      enabled: !root.unlocking
      onClicked: picker.picked()
    }

    Text {
      id: pickerIcon
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.leftMargin: Style.spacing.controlPaddingX + Border.left(picker.controlBorderSpec)
      anchors.verticalCenter: parent.verticalCenter
      text: picker.icon
      color: root.foreground
      opacity: 0.58
      font.family: root.fontFamily
      font.pixelSize: Style.font.icon
    }

    Text {
      textFormat: Text.PlainText
      anchors.left: pickerIcon.right
      anchors.leftMargin: Style.space(8)
      anchors.right: pickerTrail.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      text: picker.path ? Model.displayPath(picker.path, root.home) : picker.placeholder
      color: root.foreground
      opacity: picker.path ? 1 : 0.58
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
      elide: Text.ElideMiddle
    }

    Row {
      id: pickerTrail
      anchors.right: parent.right
      anchors.rightMargin: Style.space(4) + Border.right(picker.controlBorderSpec)
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(6)

      Text {
        textFormat: Text.PlainText
        anchors.verticalCenter: parent.verticalCenter
        text: picker.shortcut
        color: root.foreground
        opacity: 0.4
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        rightPadding: picker.clearable && picker.path ? 0 : Style.spacing.controlPaddingX - Style.space(4)
      }

      PanelActionButton {
        anchors.verticalCenter: parent.verticalCenter
        visible: picker.clearable && picker.path !== ""
        size: Math.max(Style.space(20), picker.height - Style.space(8))
        iconText: "󰅖"
        tooltipText: "Remove key file"
        foreground: root.foreground
        fontFamily: root.fontFamily
        fontSize: Style.font.iconSmall
        onClicked: picker.cleared()
      }
    }
  }

  // The line under a form: an error in the urgent colour, "Unlocking…"
  // while the key derivation runs, otherwise a dim hint.
  component StatusLine: Text {
    property string error: ""
    property bool busy: false
    property string hint: ""

    textFormat: Text.PlainText
    text: error !== "" ? error : (busy ? "Unlocking…" : hint)
    visible: text !== ""
    color: error !== "" ? root.errorColor : root.foreground
    opacity: error !== "" ? 1 : 0.52
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    elide: Text.ElideRight
  }
}
