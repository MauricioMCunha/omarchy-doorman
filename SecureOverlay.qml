import QtQuick
import QtQuick.Controls as Controls
import Quickshell
import Quickshell.Hyprland
import Quickshell.Wayland
import qs.Commons
import qs.Ui

Item {
  id: root

  property bool open: false
  property var request: null
  property bool submitting: false
  property string pendingSecret: ""
  property int waitSeconds: 0
  property int secondsRemaining: 0
  property real totalSeconds: 0
  readonly property bool expiringSoon: root.secondsRemaining > 0 && root.secondsRemaining <= 10
  signal approved(string secret)
  signal cancelled()
  signal decisionFinished()

  onOpenChanged: if (!root.open) root.submitting = false

  function refreshSecondsRemaining() {
    if (!root.request || !root.request.expires_at) {
      root.secondsRemaining = 0
      return
    }
    root.secondsRemaining = Math.max(0, Math.round(root.request.expires_at - Date.now() / 1000))
  }

  onRequestChanged: {
    refreshSecondsRemaining()
    root.totalSeconds = root.secondsRemaining
  }

  Timer {
    id: expiryTimer
    interval: 1000
    repeat: true
    triggeredOnStart: true
    running: root.open && !root.submitting && root.request !== null
    onTriggered: root.refreshSecondsRemaining()
  }

  Timer {
    id: waitTimer
    interval: 1000
    repeat: true
    onTriggered: {
      if (root.waitSeconds > 1) {
        root.waitSeconds -= 1
        return
      }
      stop()
      root.waitSeconds = 0
      root.submitting = false
      root.decisionFinished()
    }
  }

  Timer {
    id: decisionDispatch
    interval: 1
    repeat: false
    onTriggered: {
      var secret = root.pendingSecret
      root.pendingSecret = ""
      if (secret.length > 0) root.approved(secret)
      else root.cancelled()
    }
  }

  function screenNamed(name) {
    var wanted = String(name || "")
    for (var i = 0; i < Quickshell.screens.length; i++) {
      var candidate = Quickshell.screens[i]
      if (candidate && String(candidate.name || "") === wanted) return candidate
    }
    return null
  }

  function fallbackScreen() {
    var focused = Hyprland.focusedMonitor
    if (focused) {
      var focusedName = String(focused.name || "")
      var focusedScreen = screenNamed(focusedName)
      if (focusedScreen) return focusedScreen
    }
    return Quickshell.screens.length > 0 ? Quickshell.screens[0] : null
  }

  // O broker pode não conhecer o monitor do processo. Nesse caso, o modal
  // deve acompanhar o monitor que Hyprland considera focado, não o primeiro
  // output enumerado pelo Wayland.
  readonly property var targetScreen: screenNamed(root.request ? root.request.screen : "") || fallbackScreen()

  Variants {
    model: Quickshell.screens

    PanelWindow {
      id: overlayWindow
      required property var modelData
      screen: modelData
      visible: root.open && root.targetScreen !== null && modelData === root.targetScreen
      anchors { top: true; bottom: true; left: true; right: true }
      color: "transparent"
      exclusionMode: ExclusionMode.Ignore
      WlrLayershell.namespace: "mauricio-doorman"
      WlrLayershell.layer: WlrLayer.Overlay
      WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive : WlrKeyboardFocus.None

      Keys.onPressed: function (event) {
        if (event.isAutoRepeat) return
        if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
          passwordInput.submitSecret()
          event.accepted = true
        } else if (event.key === Qt.Key_Escape) {
          passwordInput.cancelDecision()
          event.accepted = true
        }
      }
      onVisibleChanged: if (visible) Qt.callLater(passwordInput.forceActiveFocus)

      Rectangle {
        anchors.fill: parent
        color: Util.alpha(Color.background, 0.72)

        BorderSurface {
          id: card
          anchors.centerIn: parent
          width: Math.min(500, Math.max(380, parent.width - Style.space(48)))
          height: content.implicitHeight + card.contentTopInset + card.contentBottomInset
          padding: Style.space(22)
          color: Color.background
          borderSpec: Border.surfaceSpec("popups", "border", Color.popups.border, Math.max(1, Style.space(2)))
          radius: Style.cornerRadius

          Column {
            id: content
            anchors.top: parent.top
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            anchors.topMargin: card.contentTopInset
            anchors.rightMargin: card.contentRightInset
            anchors.bottomMargin: card.contentBottomInset
            anchors.leftMargin: card.contentLeftInset
            spacing: Style.space(12)

            Row {
              width: parent.width
              spacing: Style.space(12)

              BorderSurface {
                width: Style.space(36)
                height: Style.space(36)
                anchors.verticalCenter: parent.verticalCenter
                color: Util.alpha(Color.accent, 0.12)
                borderSpec: Border.flat(Util.alpha(Color.accent, 0.55), Style.normalBorderWidth)
                radius: Style.cornerRadius

                Text {
                  anchors.centerIn: parent
                  text: "󰌾"
                  color: Color.accent
                  font.family: Style.font.family
                  font.pixelSize: Style.font.icon
                }
              }

              Column {
                width: parent.width - Style.space(48)
                spacing: Style.space(3)

                Text {
                  width: parent.width
                  text: root.submitting ? "Aguarde" : "Autorização segura"
                  color: Color.popups.text
                  font.family: Style.font.family
                  font.pixelSize: Style.font.title
                  font.bold: true
                }

                Text {
                  width: parent.width
                  text: root.submitting
                    ? "WAIT " + root.waitSeconds + "s"
                    : "LLM local  •  expira em " + root.secondsRemaining + "s"
                  color: root.submitting ? Color.accent : (root.expiringSoon ? Color.urgent : Color.accent)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  font.bold: root.expiringSoon
                }
              }
            }

            Controls.ProgressBar {
              id: expiryProgress
              width: parent.width
              height: Style.space(4)
              visible: !root.submitting && root.totalSeconds > 0
              from: 0
              to: root.totalSeconds
              value: root.secondsRemaining
              background: Rectangle {
                implicitHeight: Style.space(4)
                radius: Style.space(2)
                color: Util.alpha(Color.popups.text, 0.12)
              }
              contentItem: Item {
                Rectangle {
                  width: parent.width * expiryProgress.visualPosition
                  height: parent.height
                  radius: Style.space(2)
                  color: root.expiringSoon ? Color.urgent : Color.accent
                }
              }
            }

            Text {
              width: parent.width
              visible: !root.submitting
              text: "Revise a solicitação antes de liberar esta credencial."
              color: Util.alpha(Color.popups.text, 0.68)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }

            BorderSurface {
              id: detailsCard
              visible: !root.submitting
              width: parent.width
              implicitHeight: details.implicitHeight + detailsCard.contentTopInset + detailsCard.contentBottomInset
              padding: Style.space(12)
              color: Util.alpha(Color.popups.text, 0.035)
              borderSpec: Border.flat(Util.alpha(Color.popups.border, 0.72), Style.normalBorderWidth)
              radius: Style.cornerRadius

              Column {
                id: details
                anchors.top: parent.top
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.topMargin: detailsCard.contentTopInset
                anchors.rightMargin: detailsCard.contentRightInset
                anchors.bottomMargin: detailsCard.contentBottomInset
                anchors.leftMargin: detailsCard.contentLeftInset
                spacing: Style.space(5)

                Text {
                  width: parent.width
                  text: "SOLICITAÇÃO"
                  color: Util.alpha(Color.popups.text, 0.55)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Text {
                  width: parent.width
                  text: root.request ? root.request.command : ""
                  color: Color.popups.text
                  font.family: Style.font.family
                  font.pixelSize: Style.font.body
                  wrapMode: Text.WordWrap
                  maximumLineCount: 3
                  elide: Text.ElideMiddle
                  textFormat: Text.PlainText
                }

                Text {
                  width: parent.width
                  visible: !!root.request && root.request.cwd !== ""
                  text: root.request ? root.request.cwd : ""
                  color: Util.alpha(Color.popups.text, 0.5)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideMiddle
                  textFormat: Text.PlainText
                }

                Text {
                  width: parent.width
                  visible: !!root.request && (root.request.tty !== "" || root.request.pid !== "")
                  text: root.request ? ((root.request.tty || "sessão local") +
                                        (root.request.pid ? "   •   PID " + root.request.pid : "")) : ""
                  color: Util.alpha(Color.popups.text, 0.58)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                  textFormat: Text.PlainText
                }
              }
            }

            Text {
              width: parent.width
              visible: root.submitting
              text: "WAIT " + root.waitSeconds + "s"
              color: Color.accent
              font.family: Style.font.family
              font.pixelSize: Style.font.display
              font.bold: true
              horizontalAlignment: Text.AlignHCenter
            }

            Text {
              width: parent.width
              visible: root.submitting
              text: "Processando autorização…"
              color: Util.alpha(Color.popups.text, 0.68)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              horizontalAlignment: Text.AlignHCenter
            }

            Controls.ProgressBar {
              id: waitProgress
              width: parent.width
              height: Style.space(8)
              visible: root.submitting
              from: 0
              to: 3
              value: 3 - root.waitSeconds
              background: Rectangle {
                implicitHeight: Style.space(8)
                radius: Style.space(4)
                color: Util.alpha(Color.popups.text, 0.12)
              }
              contentItem: Item {
                Rectangle {
                  width: parent.width * waitProgress.visualPosition
                  height: parent.height
                  radius: Style.space(4)
                  color: Color.accent
                }
              }
            }

            Text {
              width: parent.width
              visible: !root.submitting
              text: root.request && root.request.prompt ? root.request.prompt : "Senha"
              color: Color.popups.text
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            TextField {
              id: passwordInput
              width: parent.width
              height: Style.space(42)
              focus: root.open
              visible: !root.submitting
              enabled: !root.submitting
              activeFocusOnPress: true
              Keys.priority: Keys.BeforeItem
              password: true
              placeholderText: "Digite a senha nesta janela segura"
              function submitSecret() {
                if (root.submitting) return
                root.submitting = true
                root.waitSeconds = 3
                waitTimer.restart()
                root.pendingSecret = text
                text = ""
                decisionDispatch.restart()
              }
              function cancelDecision() {
                if (root.submitting) return
                root.submitting = true
                root.waitSeconds = 3
                waitTimer.restart()
                root.pendingSecret = ""
                // Cancelamento é uma decisão explícita da pessoa. Não passe
                // pelo dispatcher da senha: uma string vazia nunca deve ser
                // interpretada como cancelamento implícito.
                root.cancelled()
              }
              onAccepted: submitSecret()
              Keys.onPressed: function (event) {
                // O TextInput subjacente aceita toda tecla incondicionalmente
                // em seu próprio processamento, mesmo sem fazer nada com ela.
                // Por isso o Escape nunca chegava ao Keys.onPressed da janela
                // (overlayWindow): precisa ser tratado aqui, no mesmo nível
                // já usado para o Enter, antes que o TextInput o engula.
                if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                  submitSecret()
                  event.accepted = true
                } else if (event.key === Qt.Key_Escape) {
                  cancelDecision()
                  event.accepted = true
                }
              }
              Component.onCompleted: Qt.callLater(forceActiveFocus)
            }

            Text {
              width: parent.width
              visible: !root.submitting
              text: "Enter  autoriza    ·    Esc  cancela"
              color: Util.alpha(Color.popups.text, 0.56)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              horizontalAlignment: Text.AlignRight
            }
          }
        }
      }
    }
  }
}
