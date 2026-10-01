.pragma library

// State shared within the Quickshell process. The topbar widget runs one
// instance per connected monitor, all reading the same broker; without
// this, each instance would notify the same request, duplicating the
// notification once per monitor. `.pragma library` makes this module a
// singleton per QML engine, shared across instances — unlike state declared
// inside Panel.qml itself, which is per-instance.
var claimed = ({})

function claimOnce(requestId) {
  if (claimed[requestId]) return false
  claimed[requestId] = true
  return true
}

// Called by any instance on every poll to forget requests that already left
// the broker's list (approved/cancelled/expired), or the set would grow
// without bound for the lifetime of the Quickshell process.
function forgetExcept(currentIds) {
  for (var id in claimed) {
    if (!currentIds[id]) delete claimed[id]
  }
}
