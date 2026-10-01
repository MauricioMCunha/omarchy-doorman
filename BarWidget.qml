import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "NotifyState.js" as NotifyState

// Bar icon + broker client for Doorman, and the host for the summary popup
// (Panel.qml). All broker/process state lives here so it survives across
// the popup being opened and closed, and so SecureOverlay — which must be
// able to appear even while the popup is closed — always has it available.
BarWidget {
  id: root
  moduleName: "mauricio.doorman"

  property var requests: []
  property var selected: null
  property var metrics: ({})
  property bool brokerOnline: false
  property bool serviceBusy: false
  property bool serviceDesired: false
  property bool decisionBusy: false
  property string pendingApprovalSecret: ""
  property string approvalRequestId: ""
  property string approvalNonce: ""
  // Id of the current toast (0 = none). A retry changes the request_id
  // (deduped by NotifyState), but it's still the same visual notification
  // slot — resending with -r <id> updates the existing toast instead of
  // stacking a second, stale one next to it.
  property int notificationId: 0
  readonly property string commercialName: "Doorman"

  readonly property color foreground: bar && bar.foreground ? bar.foreground : Color.foreground
  readonly property string fontFamily: bar && bar.fontFamily ? bar.fontFamily : Style.font.family
  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") + "/omarchy-doorman"
  readonly property string socketPath: runtimeDir + "/broker.sock"
  readonly property string tokenPath: runtimeDir + "/token"
  function localPath(url) {
    var value = String(url)
    return value.indexOf("file://") === 0 ? value.slice(7) : value
  }
  readonly property string bridgePath: root.localPath(Qt.resolvedUrl("bridge.py"))

  implicitWidth: button.implicitWidth
  implicitHeight: bar ? bar.barSize : 26

  function poll() {
    if (!pollProc.running) pollProc.running = true
    if (!statsProc.running) statsProc.running = true
  }
  function notifyNewRequests(list) {
    var seen = {}
    var fresh = []
    for (var i = 0; i < list.length; i++) {
      seen[list[i].request_id] = true
      if (NotifyState.claimOnce(list[i].request_id)) fresh.push(list[i])
    }
    NotifyState.forgetExcept(seen)
    if (fresh.length === 0 || notifyProc.running) return
    // The title stays fixed even on a retry: omarchy-notification-dismiss
    // matches by title, and it's what closes the toast once the queue empties.
    var title = fresh.length === 1 ? "Authorization pending" : (fresh.length + " authorizations pending")
    var body
    if (fresh.length === 1) {
      var item = fresh[0]
      var retry = Number(item.attempt || 1) > 1
      body = (retry ? "Wrong password — attempt " + item.attempt + "  ·  " : "") +
        (item.command || "sudo") + "  ·  expires in " + Math.max(0, Math.floor(item.expires_at - Date.now() / 1000)) + "s"
    } else {
      body = fresh.map(function (item) { return item.command || "sudo" }).join(", ")
    }
    var command = ["/usr/share/omarchy/bin/omarchy-notification-send",
      "--app-name", root.commercialName, "-g", "󰠚", "-u", "critical", "-p"]
    if (root.notificationId > 0) command.push("-r", String(root.notificationId))
    command.push(title, body)
    notifyProc.command = command
    notifyProc.running = true
  }
  function metric(name) { return Number(root.metrics[name] || 0) }
  function duration(seconds) {
    var value = Number(seconds || 0)
    if (value < 60) return Math.max(0, Math.floor(value)) + "s"
    return Math.floor(value / 60) + "m " + Math.floor(value % 60) + "s"
  }
  function nextExpiry() {
    if (!root.requests.length) return 0
    var soonest = Number(root.requests[0].expires_at || 0)
    for (var i = 1; i < root.requests.length; i++)
      soonest = Math.min(soonest, Number(root.requests[i].expires_at || soonest))
    return Math.max(0, Math.floor(soonest - Date.now() / 1000))
  }
  function toggleBroker() {
    if (root.serviceBusy) return
    root.serviceDesired = !root.brokerOnline
    serviceProc.command = ["/usr/bin/systemctl", "--user", root.serviceDesired ? "start" : "stop", "omarchy-doorman.service"]
    serviceProc.running = true
  }
  function approveSecret(secret) {
    if (!root.selected || !secret || root.decisionBusy) return
    var requestId = root.selected.request_id
    var nonce = root.selected.nonce
    root.decisionBusy = true
    root.approvalRequestId = requestId
    root.approvalNonce = nonce
    root.requests = root.requests.filter(function (item) { return item.request_id !== requestId })
    approveProc.command = ["/usr/bin/python3", root.bridgePath, "--socket", root.socketPath,
      "--token-file", root.tokenPath, "approve", requestId, nonce]
    root.pendingApprovalSecret = secret
    approveProc.running = true
  }
  function cancelRequest() {
    if (!root.selected || root.decisionBusy) return
    var requestId = root.selected.request_id
    var nonce = root.selected.nonce
    root.decisionBusy = true
    root.requests = root.requests.filter(function (item) { return item.request_id !== requestId })
    cancelProc.command = ["/usr/bin/python3", root.bridgePath, "--socket", root.socketPath,
      "--token-file", root.tokenPath, "cancel", requestId, nonce]
    cancelProc.running = true
  }

  Process {
    id: pollProc
    command: ["/usr/bin/python3", root.bridgePath, "--socket", root.socketPath, "--token-file", root.tokenPath, "pending"]
    stdout: StdioCollector {
      onStreamFinished: {
        try {
          var value = JSON.parse(text || "{}")
          var hadPending = root.requests.length > 0
          root.requests = value.requests || []
          root.notifyNewRequests(root.requests)
          if (hadPending && root.requests.length === 0 && !dismissNotifyProc.running) {
            dismissNotifyProc.command = ["/usr/share/omarchy/bin/omarchy-notification-dismiss", "Authorization pending"]
            dismissNotifyProc.running = true
            root.notificationId = 0
          }
          if (!root.decisionBusy && root.selected && !root.requests.some(function (item) { return item.request_id === root.selected.request_id })) root.selected = null
          if (root.requests.length > 0 && !root.selected) root.selected = root.requests[0]
        } catch (e) { root.requests = [] }
      }
    }
    onExited: pollTimer.restart()
  }

  Process {
    id: notifyProc
    stdout: StdioCollector {
      onStreamFinished: {
        var value = parseInt(text, 10)
        if (!isNaN(value) && value > 0) root.notificationId = value
      }
    }
  }

  Process {
    id: dismissNotifyProc
    stdout: StdioCollector {}
  }

  Process {
    id: statsProc
    command: ["/usr/bin/python3", root.bridgePath, "--socket", root.socketPath, "--token-file", root.tokenPath, "stats"]
    stdout: StdioCollector {
      onStreamFinished: {
        try {
          var value = JSON.parse(text || "{}")
          root.metrics = value
          root.brokerOnline = value.ok === true
          if (!root.serviceBusy) root.serviceDesired = root.brokerOnline
        } catch (e) { root.brokerOnline = false; root.metrics = ({}) }
      }
    }
  }

  Process {
    id: approveProc
    stdinEnabled: true
    stdout: StdioCollector {
      id: approveOut
    }
    onStarted: {
      write(root.pendingApprovalSecret + "\n")
      root.pendingApprovalSecret = ""
    }
    onExited: function (code) {
      if (code !== 0 && root.approvalRequestId !== "" && !cancelProc.running) {
        cancelProc.command = ["/usr/bin/python3", root.bridgePath, "--socket", root.socketPath,
          "--token-file", root.tokenPath, "cancel", root.approvalRequestId, root.approvalNonce]
        cancelProc.running = true
      }
    }
  }

  Process {
    id: cancelProc
    stdout: StdioCollector {}
    onExited: root.poll()
  }

  Process {
    id: serviceProc
    onStarted: root.serviceBusy = true
    onExited: {
      root.serviceBusy = false
      root.poll()
    }
  }

  SecureOverlay {
    id: secureOverlay
    open: root.selected !== null && (root.requests.length > 0 || root.decisionBusy)
    request: root.selected
    onApproved: function (secret) { root.approveSecret(secret) }
    onCancelled: root.cancelRequest()
    onDecisionFinished: {
      root.selected = null
      root.requests = []
      root.decisionBusy = false
      root.approvalRequestId = ""
      root.approvalNonce = ""
      root.poll()
    }
  }

  Timer {
    id: pollTimer
    interval: 1500
    repeat: true
    running: true
    onTriggered: root.poll()
  }
  Component.onCompleted: root.poll()

  // ---- Summary popup. Shape contract for shell.summon/hide/toggle
  //      routing: Bar.findPanelWidget requires open/close/opened on the
  //      bar-widget root.
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  function open() {
    if (panelLoader.item) panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item) panelLoader.item.close()
  }

  function togglePanel() {
    if (panelLoader.item) panelLoader.item.toggle()
  }

  // Forwarded so this widget can stand in for the panel as the bar's popout
  // identity: Bar.requestPopout prefers closeForPopoutSwitch over close, and
  // KeyboardPanel reads popoutSwitchClosing back off its owner.
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  IpcHandler {
    target: "mauricio.doorman"

    function refresh(): void { root.broadcast("poll") }
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.togglePanel() }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰠚"
    tooltipText: root.commercialName
    active: root.opened || root.requests.length > 0
    Accessible.role: Accessible.Button
    Accessible.name: root.commercialName

    onPressed: function(mouseButton) {
      if (mouseButton === Qt.LeftButton) root.togglePanel()
    }
  }
}
