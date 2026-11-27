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
// clicked the bar icon. This panel is status-only: it never releases a
// credential, so it carries no password field and no authorize/deny action.
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

  // Health model, read once and reused across the header, status box and glyphs.
  readonly property int pendingCount: (hostWidget && hostWidget.requests) ? hostWidget.requests.length : 0
  readonly property bool online: !!(hostWidget && hostWidget.brokerOnline)
  readonly property bool setupOk: !hostWidget || hostWidget.metric("askpass_identity_available") !== 0
  readonly property bool healthy: online && setupOk
  readonly property color okColor: Color.accent
  readonly property color statusColor: healthy ? okColor : Color.urgent
  readonly property string statusGlyph: healthy ? "󰄬" : "󰀪"
  readonly property string statusTitle: online
    ? (setupOk ? "No pending authorization" : "Setup incomplete")
    : "Broker unavailable"
  readonly property string statusSubtitle: online
    ? (setupOk ? "All clear — new requests appear here." : "Install the omarchy-doorman package to finish setup.")
    : "sudo systemctl enable --now omarchy-doorman.service"

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

        // ---- Header: identity + service state, with a boxed Refresh action
        // pinned to the trailing edge (matches the native panel hero). ----
        PanelHero {
          width: parent.width
          title: "Doorman"
          meta: root.online ? "SYSTEM SERVICE · ONLINE" : "SYSTEM SERVICE · OFFLINE"
          foreground: root.contentForeground
          fontFamily: root.contentFontFamily
          iconComponent: Component {
            Text {
              text: "󰠚"
              color: root.pendingCount > 0 ? Color.accent : root.contentForeground
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.display
            }
          }
          trailingControl: Component {
            PanelActionButton {
              iconText: "󰑐"
              tooltipText: "Refresh"
              bordered: true
              focusable: true
              foreground: root.contentForeground
              fontFamily: root.contentFontFamily
              onClicked: if (root.hostWidget) root.hostWidget.poll()
            }
          }
        }

        PanelSeparator { foreground: root.contentForeground }
        PanelSectionHeader {
          text: root.pendingCount > 0 ? "ATTENTION" : "STATUS"
          foreground: root.contentForeground
          fontFamily: root.contentFontFamily
        }

        // ---- Idle / degraded status box: icon + title + subtitle. ----
        BorderSurface {
          id: statusBox
          visible: root.pendingCount === 0
          width: parent.width
          implicitHeight: statusRow.implicitHeight + statusBox.contentTopInset + statusBox.contentBottomInset
          padding: Style.space(12)
          color: Util.alpha(root.statusColor, 0.06)
          borderSpec: Border.flat(Util.alpha(root.statusColor, 0.5), Style.normalBorderWidth)
          radius: Style.cornerRadius

          Row {
            id: statusRow
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.topMargin: statusBox.contentTopInset
            anchors.leftMargin: statusBox.contentLeftInset
            anchors.rightMargin: statusBox.contentRightInset
            spacing: Style.space(12)

            Text {
              anchors.verticalCenter: parent.verticalCenter
              text: root.statusGlyph
              color: root.statusColor
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.display
            }

            Column {
              width: parent.width - Style.space(48)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(2)

              Text {
                width: parent.width
                text: root.statusTitle
                color: root.contentForeground
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.body
                font.bold: true
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
              }
              Text {
                width: parent.width
                text: root.statusSubtitle
                color: Qt.darker(root.contentForeground, 1.4)
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
              }
            }
          }
        }

        // ---- Pending request card (status-only; the decision happens in the
        // secure modal). Accent-bordered, with a count badge and the real
        // broker-supplied command. Clicking it dismisses the popup so the
        // secure window is unobstructed. ----
        BorderSurface {
          id: pendingBox
          visible: root.pendingCount > 0
          width: parent.width
          implicitHeight: pendingCol.implicitHeight + pendingBox.contentTopInset + pendingBox.contentBottomInset
          padding: Style.space(12)
          color: Util.alpha(Color.accent, 0.06)
          borderSpec: Border.flat(Color.accent, Style.normalBorderWidth)
          radius: Style.cornerRadius

          Column {
            id: pendingCol
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.topMargin: pendingBox.contentTopInset
            anchors.leftMargin: pendingBox.contentLeftInset
            anchors.rightMargin: pendingBox.contentRightInset
            spacing: Style.space(6)

            BorderSurface {
              implicitWidth: badgeText.implicitWidth + Style.space(12)
              implicitHeight: badgeText.implicitHeight + Style.space(5)
              color: Util.alpha(Color.accent, 0.2)
              borderSpec: Border.flat(Util.alpha(Color.accent, 0.6), Style.normalBorderWidth)
              radius: Style.cornerRadius
              Text {
                id: badgeText
                anchors.centerIn: parent
                text: root.pendingCount + " PENDING"
                color: Color.accent
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.0
                textFormat: Text.PlainText
              }
            }

            Text {
              width: parent.width
              text: "Authorization request"
              color: root.contentForeground
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.body
              font.bold: true
              textFormat: Text.PlainText
            }

            PanelSectionHeader { text: "COMMAND"; foreground: root.contentForeground; fontFamily: root.contentFontFamily }
            Text {
              width: parent.width
              text: (root.hostWidget && root.hostWidget.selected) ? root.hostWidget.selected.command : ""
              color: root.contentForeground
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.body
              elide: Text.ElideRight
              textFormat: Text.PlainText
            }
            Text {
              width: parent.width
              text: (root.hostWidget && root.hostWidget.selected)
                ? ((root.hostWidget.selected.tty || "local session") + "  ·  PID " + root.hostWidget.selected.pid
                   + "  ·  expires in " + root.hostWidget.duration(root.hostWidget.nextExpiry()))
                : ""
              color: Qt.darker(root.contentForeground, 1.4)
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.caption
              elide: Text.ElideRight
              textFormat: Text.PlainText
            }
            Text {
              width: parent.width
              text: "Respond in the secure window →"
              color: Color.accent
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              textFormat: Text.PlainText
            }
          }

          MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.close() }
        }

        PanelSeparator { foreground: root.contentForeground }
        PanelSectionHeader { text: "THIS SESSION"; foreground: root.contentForeground; fontFamily: root.contentFontFamily }

        // ---- Session counters: three columns split by thin dividers. ----
        Item {
          width: parent.width
          height: statsRow.implicitHeight

          Row {
            id: statsRow
            width: parent.width
            readonly property real dividerW: Math.max(1, Style.space(1))
            readonly property real cellW: (width - 2 * dividerW) / 3

            Repeater {
              model: [
                { label: "APPROVED",  value: root.hostWidget ? root.hostWidget.metric("approved")  : 0, accent: true },
                { label: "CANCELLED", value: root.hostWidget ? root.hostWidget.metric("cancelled") : 0, accent: false },
                { label: "EXPIRED",   value: root.hostWidget ? root.hostWidget.metric("expired")   : 0, accent: false }
              ]

              Row {
                required property var modelData
                required property int index

                Rectangle {
                  visible: index > 0
                  width: statsRow.dividerW
                  height: Style.space(30)
                  anchors.verticalCenter: parent.verticalCenter
                  color: Util.alpha(root.contentForeground, 0.18)
                }

                Column {
                  width: statsRow.cellW
                  spacing: Style.space(2)

                  Text {
                    width: parent.width
                    text: String(modelData.value)
                    horizontalAlignment: Text.AlignHCenter
                    color: modelData.accent ? Color.accent : root.contentForeground
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.title
                    font.bold: true
                    textFormat: Text.PlainText
                  }
                  Text {
                    width: parent.width
                    text: modelData.label
                    horizontalAlignment: Text.AlignHCenter
                    color: Qt.darker(root.contentForeground, 1.4)
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.caption
                    font.letterSpacing: 0.8
                    textFormat: Text.PlainText
                  }
                }
              }
            }
          }
        }

        PanelSeparator { foreground: root.contentForeground }

        // ---- Uptime footer: clock glyph + value + freshness line. ----
        Row {
          width: parent.width
          spacing: Style.space(12)

          Text {
            anchors.verticalCenter: parent.verticalCenter
            text: "󰅐"
            color: Qt.darker(root.contentForeground, 1.4)
            font.family: root.contentFontFamily
            font.pixelSize: Style.font.title
          }
          Column {
            width: parent.width - Style.space(36)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(1)

            Text {
              width: parent.width
              text: "Uptime  " + (root.hostWidget ? root.hostWidget.duration(root.hostWidget.metric("uptime")) : "0s")
              color: root.contentForeground
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.bodySmall
              font.bold: true
              textFormat: Text.PlainText
            }
            Text {
              width: parent.width
              text: "Updated just now"
              color: Qt.darker(root.contentForeground, 1.4)
              font.family: root.contentFontFamily
              font.pixelSize: Style.font.caption
              textFormat: Text.PlainText
            }
          }
        }
      }
    }
  }
}
