# Modelo mínimo de segurança

- Socket Unix com permissões restritas ao usuário.
- Cada pedido usa nonce e pode ser consumido uma única vez.
- O pedido exibe comando, PID, diretório, terminal e prazo de validade.
- Mudança de PID, start time, PTY ou comando invalida o pedido.
- Timeout curto e cancelamento explícito.
- Nenhum segredo em arquivo, clipboard, log, telemetria ou resposta do agente.
- Testes obrigatórios com processo errado, concorrência, expiração e
  cancelamento.

Este documento não autoriza ainda o uso em operações financeiras ou em
ambiente de produção. A liberação dependerá dos testes e da revisão do
threat model.
