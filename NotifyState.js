.pragma library

// Estado compartilhado dentro do processo do Quickshell. O widget do topbar
// roda uma instância por monitor conectado, todas lendo o mesmo broker; sem
// isso, cada instância notificaria o mesmo pedido, duplicando a notificação
// uma vez por monitor. `.pragma library` faz este módulo ser um singleton
// por engine QML, compartilhado entre as instâncias — ao contrário de estado
// declarado dentro do próprio Panel.qml, que é por instância.
var claimed = ({})

function claimOnce(requestId) {
  if (claimed[requestId]) return false
  claimed[requestId] = true
  return true
}

// Chamado por qualquer instância a cada poll para esquecer pedidos que já
// saíram da lista do broker (aprovados/cancelados/expirados), senão o
// conjunto cresce sem limite pela vida do processo do Quickshell.
function forgetExcept(currentIds) {
  for (var id in claimed) {
    if (!currentIds[id]) delete claimed[id]
  }
}
