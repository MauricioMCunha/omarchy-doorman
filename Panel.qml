import QtQuick
import qs.Ui
import qs.Commons

// Doorman's summary popup: broker status, the currently selected request
// (if any) and session counters. All state and process management live on
// the hosting BarWidget.qml — this panel only reads it off `hostWidget`, the
// same split clock's BarWidget.qml/Panel.qml pair uses.
//
// The actual approve/deny prompt is SecureOverlay, owned by BarWidget.qml
// directly and shown independently of whether this popup is open — it has
// to be visible (and grab exclusive keyboard focus) even when nobody has
// clicked the bar icon.
Panel {
  id: root
  moduleName: "mauricio.doorman"
  ipcTarget: "mauricio.doorman"
  manageIpc: false

  property var anchorItem: null

  // The bar tracks the widget mounted in its slot — BarWidget.qml — not this
  // nested panel. Everything the bar identifies a panel by has to be that
  // widget, matching clock's Panel.qml.
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property color contentForeground: hostWidget ? hostWidget.foreground : (bar ? bar.foreground : Color.foreground)
  readonly property string contentFontFamily: hostWidget ? hostWidget.fontFamily : Style.font.family

  function open() {
    if (root.hostWidget) root.hostWidget.poll()
    root.controller.show()
  }

  function close() {
    root.controller.hide()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if ((t === "r" || t === "R") && root.hostWidget) root.hostWidget.poll()
      }

      Column {
        id: panelColumn
        width: parent.width
        spacing: Style.space(12)

        PanelHero {
          width: parent.width
          title: "Doorman"
          meta: root.hostWidget && root.hostWidget.brokerOnline ? "LOCAL SESSION · ONLINE" : "LOCAL SESSION · OFFLINE"
          detail: root.hostWidget && root.hostWidget.requests.length > 0 ? String(root.hostWidget.requests.length) : ""
          foreground: root.contentForeground
          fontFamily: root.contentFontFamily
          trailingControl: Component {
            ToggleSwitch {
              checked: root.hostWidget ? root.hostWidget.serviceDesired : false
              busy: root.hostWidget ? root.hostWidget.serviceBusy : false
              foreground: root.contentForeground
              accent: Color.accent
              onToggled: if (root.hostWidget) root.hostWidget.toggleBroker()
            }
          }
          iconComponent: Component {
            Text { text: "󰠚"; color: (root.hostWidget && root.hostWidget.requests.length > 0) ? Color.accent : root.contentForeground; font.family: root.contentFontFamily; font.pixelSize: Style.font.display }
          }
        }

        PanelSeparator { foreground: root.contentForeground }
        PanelSectionHeader { text: (root.hostWidget && root.hostWidget.requests.length > 0) ? "ATTENTION" : "STATUS"; foreground: root.contentForeground; fontFamily: root.contentFontFamily }

        Button {
          width: parent.width
          leftAlign: true
          text: root.hostWidget && root.hostWidget.requests.length > 0
            ? (root.hostWidget.requests.length + " solicitação" + (root.hostWidget.requests.length > 1 ? "ões" : "") + " · expira em " + root.hostWidget.duration(root.hostWidget.nextExpiry()))
            : (root.hostWidget && root.hostWidget.brokerOnline ? "Nenhuma autorização pendente" : "Broker indisponível")
          iconText: (root.hostWidget && root.hostWidget.requests.length > 0) ? "󰀦" : ((root.hostWidget && root.hostWidget.brokerOnline) ? "󰄬" : "󰀪")
          active: root.hostWidget ? root.hostWidget.requests.length > 0 : false
          focusable: true
          onClicked: if (root.hostWidget && root.hostWidget.requests.length > 0) root.close()
        }

        BorderSurface {
          visible: root.hostWidget ? root.hostWidget.requests.length > 0 : false
          width: parent.width
          implicitHeight: requestDetails.implicitHeight + Style.space(12)
          padding: Style.space(6)
          color: "transparent"
          borderSpec: Border.flat(root.contentForeground, Style.normalBorderWidth)
          radius: Style.cornerRadius
          Column {
            id: requestDetails
            width: parent.width
            spacing: Style.space(3)
            PanelSectionHeader { text: "REQUEST"; foreground: root.contentForeground; fontFamily: root.contentFontFamily }
            Text { width: parent.width; text: (root.hostWidget && root.hostWidget.selected) ? root.hostWidget.selected.command : ""; color: root.contentForeground; font.family: root.contentFontFamily; font.pixelSize: Style.font.body; elide: Text.ElideMiddle; textFormat: Text.PlainText }
            Text { width: parent.width; text: (root.hostWidget && root.hostWidget.selected) ? ((root.hostWidget.selected.tty || "local session") + "  ·  PID " + root.hostWidget.selected.pid) : ""; color: Qt.darker(root.contentForeground, 1.4); font.family: root.contentFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight; textFormat: Text.PlainText }
          }
        }

        PanelSeparator { foreground: root.contentForeground }
        PanelSectionHeader { text: "SESSION"; foreground: root.contentForeground; fontFamily: root.contentFontFamily }
        Column {
          width: parent.width
          spacing: Style.space(2)
          Text { width: parent.width; text: "APPROVED   " + (root.hostWidget ? root.hostWidget.metric("approved") : 0) + "    CANCELLED   " + (root.hostWidget ? root.hostWidget.metric("cancelled") : 0); color: root.contentForeground; font.family: root.contentFontFamily; font.pixelSize: Style.font.bodySmall; textFormat: Text.PlainText }
          Text { width: parent.width; text: "EXPIRED    " + (root.hostWidget ? root.hostWidget.metric("expired") : 0) + "    UPTIME      " + (root.hostWidget ? root.hostWidget.duration(root.hostWidget.metric("uptime")) : "0s"); color: Qt.darker(root.contentForeground, 1.4); font.family: root.contentFontFamily; font.pixelSize: Style.font.caption; textFormat: Text.PlainText }
        }

        Button { width: parent.width; text: "Refresh"; iconText: "󰑐"; focusable: true; onClicked: if (root.hostWidget) root.hostWidget.poll() }
      }
    }
  }
}
