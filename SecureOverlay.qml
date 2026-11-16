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
  // An "attempt" > 1 means sudo rejected the previous try's password and
  // asked again (see RETRY_WINDOW_SECONDS in broker.py). Doorman never
  // validates the password itself — it only knows there was an earlier
  // attempt with the same parent sudo process.
  readonly property bool wrongPassword: !!root.request && Number(root.request.attempt || 1) > 1

  // This modal is the exact analog of Omarchy's own PolkitAgent: a
  // full-screen, keyboard-exclusive credential-authorization dialog. It
  // tracks the active theme live by binding to the central [polkit] role set
  // (Commons.Color.polkit.*) and uses the menu font like every other summoned
  // overlay, so it looks identical to the native polkit prompt on any theme.
  property string fontFamily: Style.font.menuFamily
  property color accent: Color.polkit.accent
  property color background: Color.polkit.background
  property color foreground: Color.polkit.text
  property color border: Color.polkit.border
  property color borderError: Color.polkit.borderError
  property color textError: Color.polkit.textError
  property color scrim: Color.polkit.scrim

  // Safety settle-guard: this modal is raised by a *background* agent, not by
  // the person, so it can appear over whatever they are doing and steal
  // keyboard focus. For a brief window after it becomes visible (or after a
  // new request loads into it), authorizing is a no-op — so queued type-ahead
  // (including a stray Enter, or a password being typed into another window)
  // can't instantly release the credential. Denying is never blocked.
  property bool armed: false

  signal approved(string secret)
  signal cancelled()
  signal decisionFinished()

  onOpenChanged: {
    if (!root.open) {
      root.submitting = false
      root.armed = false
    }
  }

  function refreshSecondsRemaining() {
    if (!root.request || !root.request.expires_at) {
      root.secondsRemaining = 0
      return
    }
    root.secondsRemaining = Math.max(0, Math.round(root.request.expires_at - Date.now() / 1000))
  }

  function rearmSettle() {
    root.armed = false
    settleTimer.restart()
  }

  onRequestChanged: {
    refreshSecondsRemaining()
    root.totalSeconds = root.secondsRemaining
    // Re-arm on every request so a fresh command can't inherit the momentum
    // of the previous decision when the next queued request slides in.
    if (root.open) rearmSettle()
    if (root.wrongPassword) shakeAnim.restart()
  }

  Timer {
    id: settleTimer
    interval: 400
    repeat: false
    onTriggered: root.armed = true
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

  // The broker may not know the process's monitor. In that case, the modal
  // should follow whichever monitor Hyprland considers focused, not just
  // the first output Wayland happens to enumerate.
  readonly property var targetScreen: screenNamed(root.request ? root.request.screen : "") || fallbackScreen()

  Variants {
    model: Quickshell.screens

    PanelWindow {
      id: overlayWindow
      required property var modelData
      screen: modelData
      visible: root.open && root.targetScreen !== null && modelData === root.targetScreen
      // Right-to-left languages read this window mirrored, like the native
      // polkit dialog and every other summoned overlay in the shell.
      Binding { target: overlayWindow.contentItem; property: "LayoutMirroring.enabled"; value: I18n.rightToLeft }
      Binding { target: overlayWindow.contentItem; property: "LayoutMirroring.childrenInherit"; value: true }
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
      onVisibleChanged: {
        if (visible) {
          root.rearmSettle()
          Qt.callLater(passwordInput.forceActiveFocus)
        }
      }

      Rectangle {
        anchors.fill: parent
        color: root.scrim

        // A stray click on the scrim must never fall through to the app
        // behind the overlay, and must never silently dismiss the prompt —
        // it just refocuses the password field, like PolkitAgent.
        MouseArea {
          anchors.fill: parent
          onClicked: passwordInput.forceActiveFocus()
        }

        BorderSurface {
          id: card
          anchors.centerIn: parent
          width: Math.min(500, Math.max(380, parent.width - Style.space(48)))
          height: content.implicitHeight + card.contentTopInset + card.contentBottomInset
          padding: Style.space(22)
          color: root.background
          borderSpec: Border.surfaceSpec("polkit", root.wrongPassword ? "border-error" : "border",
                                         root.wrongPassword ? root.borderError : root.border,
                                         Math.max(1, Style.space(2)), "border-alpha")
          radius: Style.cornerRadius
          // Imperative offset via transform, not via `x`: `x` already has
          // a binding from anchors.centerIn, and a property animation would
          // overwrite that binding for good after running once, off-centering
          // the card on any resize.
          transform: Translate { id: shakeTranslate }

          SequentialAnimation {
            id: shakeAnim
            NumberAnimation { target: shakeTranslate; property: "x"; to: -8; duration: 55 }
            NumberAnimation { target: shakeTranslate; property: "x"; to: 8; duration: 55 }
            NumberAnimation { target: shakeTranslate; property: "x"; to: -6; duration: 55 }
            NumberAnimation { target: shakeTranslate; property: "x"; to: 6; duration: 55 }
            NumberAnimation { target: shakeTranslate; property: "x"; to: 0; duration: 55 }
          }

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
                color: Util.alpha(root.wrongPassword ? root.textError : root.accent, 0.12)
                borderSpec: Border.flat(Util.alpha(root.wrongPassword ? root.textError : root.accent, 0.55), Style.normalBorderWidth)
                radius: Style.cornerRadius

                Text {
                  anchors.centerIn: parent
                  text: "󰠚"
                  color: root.wrongPassword ? root.textError : root.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.icon
                }
              }

              Column {
                width: parent.width - Style.space(48)
                spacing: Style.space(3)

                Text {
                  width: parent.width
                  text: root.submitting ? "Please wait" : (root.wrongPassword ? "Wrong password" : "Secure authorization")
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.title
                  font.bold: true
                }

                Text {
                  width: parent.width
                  text: root.submitting
                    ? "WAIT " + root.waitSeconds + "s"
                    : (root.wrongPassword
                        ? "Attempt " + root.request.attempt + "  •  expires in " + root.secondsRemaining + "s"
                        : "Local session  •  expires in " + root.secondsRemaining + "s")
                  color: root.submitting ? root.accent : ((root.expiringSoon || root.wrongPassword) ? root.textError : root.accent)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: root.expiringSoon || root.wrongPassword
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
                color: Util.alpha(root.foreground, 0.12)
              }
              contentItem: Item {
                Rectangle {
                  width: parent.width * expiryProgress.visualPosition
                  height: parent.height
                  radius: Style.space(2)
                  color: root.expiringSoon ? root.textError : root.accent
                }
              }
            }

            Text {
              width: parent.width
              visible: !root.submitting
              text: root.wrongPassword
                ? "The previous password wasn't accepted by the system. Review it and try again."
                : "Review the request before releasing this credential."
              color: root.wrongPassword ? root.textError : Util.alpha(root.foreground, 0.68)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: root.wrongPassword
              wrapMode: Text.WordWrap
            }

            BorderSurface {
              id: detailsCard
              visible: !root.submitting
              width: parent.width
              implicitHeight: details.implicitHeight + detailsCard.contentTopInset + detailsCard.contentBottomInset
              padding: Style.space(12)
              color: Util.alpha(root.foreground, 0.035)
              borderSpec: Border.flat(Util.alpha(root.border, 0.5), Style.normalBorderWidth)
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
                  text: "REQUEST"
                  color: Util.alpha(root.foreground, 0.55)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                // The command is the exact thing being authorized, so it must
                // be fully legible — NEVER middle-elided. A caller who gets a
                // legitimate escalation could otherwise craft a command that
                // reads benignly at both ends while a destructive clause hides
                // in the elided gap. A long command scrolls here instead of
                // truncating; the expiry countdown bounds the dialog's life.
                Item {
                  id: commandBox
                  width: parent.width
                  height: commandFlick.height

                  Flickable {
                    id: commandFlick
                    width: parent.width
                    height: Math.min(commandText.implicitHeight, Style.space(132))
                    contentHeight: commandText.implicitHeight
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    interactive: contentHeight > height

                    Text {
                      id: commandText
                      width: commandFlick.width
                      text: root.request ? root.request.command : ""
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      wrapMode: Text.Wrap
                      textFormat: Text.PlainText
                    }
                  }

                  // Fades signal there is more command above/below the viewport
                  // when it scrolls, so nothing looks like the whole command.
                  Rectangle {
                    anchors { left: commandFlick.left; right: commandFlick.right; top: commandFlick.top }
                    height: Style.space(16)
                    visible: commandFlick.interactive && !commandFlick.atYBeginning
                    gradient: Gradient {
                      GradientStop { position: 0.0; color: root.background }
                      GradientStop { position: 1.0; color: Util.alpha(root.background, 0.0) }
                    }
                  }
                  Rectangle {
                    anchors { left: commandFlick.left; right: commandFlick.right; bottom: commandFlick.bottom }
                    height: Style.space(16)
                    visible: commandFlick.interactive && !commandFlick.atYEnd
                    gradient: Gradient {
                      GradientStop { position: 0.0; color: Util.alpha(root.background, 0.0) }
                      GradientStop { position: 1.0; color: root.background }
                    }
                  }
                  Text {
                    anchors { right: commandFlick.right; bottom: commandFlick.bottom }
                    visible: commandFlick.interactive && !commandFlick.atYEnd
                    text: "󰁅"
                    color: Util.alpha(root.foreground, 0.7)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                Text {
                  width: parent.width
                  visible: !!root.request && root.request.cwd !== ""
                  text: root.request ? root.request.cwd : ""
                  color: Util.alpha(root.foreground, 0.7)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideMiddle
                  textFormat: Text.PlainText
                }

                Text {
                  width: parent.width
                  visible: !!root.request && (root.request.tty !== "" || root.request.pid !== "")
                  text: root.request ? ((root.request.tty || "local session") +
                                        (root.request.pid ? "   •   PID " + root.request.pid : "")) : ""
                  color: Util.alpha(root.foreground, 0.7)
                  font.family: root.fontFamily
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
              color: root.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.display
              font.bold: true
              horizontalAlignment: Text.AlignHCenter
            }

            Text {
              width: parent.width
              visible: root.submitting
              text: "Processing authorization…"
              color: Util.alpha(root.foreground, 0.68)
              font.family: root.fontFamily
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
                color: Util.alpha(root.foreground, 0.12)
              }
              contentItem: Item {
                Rectangle {
                  width: parent.width * waitProgress.visualPosition
                  height: parent.height
                  radius: Style.space(4)
                  color: root.accent
                }
              }
            }

            Text {
              width: parent.width
              visible: !root.submitting
              text: root.request && root.request.prompt ? root.request.prompt : "Password"
              color: root.foreground
              font.family: root.fontFamily
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
              accent: root.wrongPassword ? root.textError : root.accent
              placeholderText: "Type the password in this secure window"
              function submitSecret() {
                if (root.submitting) return
                // Settle-guard: swallow authorize attempts in the brief window
                // after the modal appears / a new request loads, so queued
                // type-ahead can't release the credential by accident.
                if (!root.armed) return
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
                // Cancelling is an explicit decision by the person. Don't
                // route it through the password dispatcher: an empty string
                // must never be interpreted as an implicit cancel.
                root.cancelled()
              }
              onAccepted: submitSecret()
              Keys.onPressed: function (event) {
                // The underlying TextInput accepts every key unconditionally
                // in its own processing, even when it does nothing with it.
                // That's why Escape never reached overlayWindow's own
                // Keys.onPressed: it has to be handled here, at the same
                // level already used for Enter, before TextInput swallows it.
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

            // Explicit, mouse-clickable, screen-reader-reachable controls.
            // Deny is always available (safe default: refusing is never harder
            // than approving); Authorize only lights up once the modal has
            // settled and a password has been typed, so it can't be the easy
            // accidental path. Keyboard Enter/Esc remain as accelerators.
            Row {
              width: parent.width
              visible: !root.submitting
              spacing: Style.space(10)

              BorderSurface {
                id: denyButton
                width: (parent.width - Style.space(10)) / 2
                height: Style.space(36)
                color: denyHover.containsMouse ? Util.alpha(root.textError, 0.22) : "transparent"
                borderSpec: Border.flat(root.textError, Style.normalBorderWidth)
                radius: Style.cornerRadius
                Accessible.role: Accessible.Button
                Accessible.name: "Deny this sudo authorization request"

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: "Deny"
                  color: root.textError
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                }

                MouseArea {
                  id: denyHover
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: passwordInput.cancelDecision()
                }
              }

              BorderSurface {
                id: authorizeButton
                width: (parent.width - Style.space(10)) / 2
                height: Style.space(36)
                readonly property bool ready: root.armed && passwordInput.text.length > 0
                opacity: ready ? 1 : 0.4
                color: (authHover.containsMouse && ready) ? Util.alpha(root.accent, 0.22) : "transparent"
                borderSpec: Border.flat(Util.alpha(root.accent, ready ? 1 : 0.5), Style.normalBorderWidth)
                radius: Style.cornerRadius
                Accessible.role: Accessible.Button
                Accessible.name: "Authorize this sudo request"

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: "Authorize"
                  color: root.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                }

                MouseArea {
                  id: authHover
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: authorizeButton.ready ? Qt.PointingHandCursor : Qt.ArrowCursor
                  onClicked: if (authorizeButton.ready) passwordInput.submitSecret()
                }
              }
            }

            Text {
              width: parent.width
              visible: !root.submitting
              text: "Enter  authorizes    ·    Esc  denies"
              color: Util.alpha(root.foreground, 0.56)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              horizontalAlignment: Text.AlignRight
            }
          }
        }
      }
    }
  }
}
