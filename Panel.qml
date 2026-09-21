import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "NotifyState.js" as NotifyState

Item {
  id: root

  property var bar
  property string moduleName
  property var settings
  property bool open: false
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

  implicitWidth: 34
  implicitHeight: bar ? bar.barSize : 26

  function triggerPress(button) { root.open = !root.open; if (root.open) poll() }
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
    var title = fresh.length === 1 ? "Autorização pendente" : (fresh.length + " autorizações pendentes")
    var body = fresh.length === 1
      ? (fresh[0].command || "sudo") + "  ·  expira em " + Math.max(0, Math.floor(fresh[0].expires_at - Date.now() / 1000)) + "s"
      : fresh.map(function (item) { return item.command || "sudo" }).join(", ")
    notifyProc.command = ["/usr/share/omarchy/bin/omarchy-notification-send",
      "--app-name", root.commercialName, "-g", "󰌾", "-u", "critical", title, body]
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
            dismissNotifyProc.command = ["/usr/share/omarchy/bin/omarchy-notification-dismiss", "Autorização pendente"]
            dismissNotifyProc.running = true
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
    stdout: StdioCollector {}
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

  BarIconButton {
    id: barButton
    anchors.fill: parent
    bar: root.bar
    text: "󰌾"
    tooltipText: root.commercialName
    active: root.open || root.requests.length > 0
    Accessible.role: Accessible.Button
    Accessible.name: root.commercialName

    onPressed: function(mouseButton) {
      if (mouseButton === Qt.LeftButton) root.triggerPress(mouseButton)
    }
  }

  PopupCard {
    id: popup
    anchorItem: root
    bar: root.bar
    owner: root
    open: root.open
    contentWidth: popup.fittedContentWidth(Style.space(380))
    contentHeight: popup.fittedContentHeight(panelColumn.implicitHeight)

    Column {
      id: panelColumn
      width: parent.width
      spacing: Style.space(12)

      PanelHero {
        width: parent.width
        title: "Doorman"
        meta: root.brokerOnline ? "LOCAL SESSION · ONLINE" : "LOCAL SESSION · OFFLINE"
        detail: root.requests.length > 0 ? String(root.requests.length) : ""
        foreground: root.foreground
        fontFamily: root.fontFamily
        trailingControl: Component {
          ToggleSwitch {
            checked: root.serviceDesired
            busy: root.serviceBusy
            foreground: root.foreground
            accent: Color.accent
            onToggled: root.toggleBroker()
          }
        }
        iconComponent: Component {
          Text { text: "󰌾"; color: root.requests.length > 0 ? Color.accent : root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.display }
        }
      }

      PanelSeparator { foreground: root.foreground }
      PanelSectionHeader { text: root.requests.length > 0 ? "ATTENTION" : "STATUS"; foreground: root.foreground; fontFamily: root.fontFamily }

      Button {
        width: parent.width
        leftAlign: true
        text: root.requests.length > 0
          ? (root.requests.length + " solicitação" + (root.requests.length > 1 ? "ões" : "") + " · expira em " + root.duration(root.nextExpiry()))
          : (root.brokerOnline ? "Nenhuma autorização pendente" : "Broker indisponível")
        iconText: root.requests.length > 0 ? "󰀦" : (root.brokerOnline ? "󰄬" : "󰀪")
        active: root.requests.length > 0
        focusable: true
        onClicked: if (root.requests.length > 0) root.open = false
      }

      BorderSurface {
        visible: root.requests.length > 0
        width: parent.width
        implicitHeight: requestDetails.implicitHeight + Style.space(12)
        padding: Style.space(6)
        color: "transparent"
        borderSpec: Border.flat(root.foreground, Style.normalBorderWidth)
        radius: Style.cornerRadius
        Column {
          id: requestDetails
          width: parent.width
          spacing: Style.space(3)
          PanelSectionHeader { text: "REQUEST"; foreground: root.foreground; fontFamily: root.fontFamily }
          Text { width: parent.width; text: root.selected ? root.selected.command : ""; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.body; elide: Text.ElideMiddle; textFormat: Text.PlainText }
          Text { width: parent.width; text: root.selected ? ((root.selected.tty || "local session") + "  ·  PID " + root.selected.pid) : ""; color: Qt.darker(root.foreground, 1.4); font.family: root.fontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight; textFormat: Text.PlainText }
        }
      }

      PanelSeparator { foreground: root.foreground }
      PanelSectionHeader { text: "SESSION"; foreground: root.foreground; fontFamily: root.fontFamily }
      Column {
        width: parent.width
        spacing: Style.space(2)
        Text { width: parent.width; text: "APPROVED   " + root.metric("approved") + "    CANCELLED   " + root.metric("cancelled"); color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.bodySmall; textFormat: Text.PlainText }
        Text { width: parent.width; text: "EXPIRED    " + root.metric("expired") + "    UPTIME      " + root.duration(root.metric("uptime")); color: Qt.darker(root.foreground, 1.4); font.family: root.fontFamily; font.pixelSize: Style.font.caption; textFormat: Text.PlainText }
      }

      Button { width: parent.width; text: "Refresh"; iconText: "󰑐"; focusable: true; onClicked: root.poll() }
    }
  }
}
