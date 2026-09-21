# doorman

Plugin Omarchy para autorização gráfica de comandos privilegiados.

## Componentes

- `Panel.qml` e `SecureOverlay.qml`: widget e modal seguro do Quickshell;
- `services/doorman_broker/broker.py`: serviço local e protocolo;
- `services/doorman_broker/askpass.py`: helper compatível com sudo;
- `services/doorman_broker/bridge.py`: bridge sem segredo em argumentos;
- `tests/`: testes sem credenciais reais.

O contrato completo está em [`../../openspec/doorman.md`](../../openspec/doorman.md).
