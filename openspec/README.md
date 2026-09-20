# OpenSpec do Omarchy Plugins Lab

Esta pasta contém a especificação executável do primeiro plugin do monorepo.
Cada requisito tem critérios de aceitação que devem ser cobertos por testes,
validação estática ou uma verificação manual documentada.

O sistema entrega uma solicitação de autorização local para uma UI Quickshell
e devolve um segredo apenas ao processo solicitante, por uma conexão Unix
privada. Ele não é um cofre, não intercepta prompts arbitrários e não envia
segredos para o agente, logs, clipboard ou rede.

## Fluxo normativo

1. O processo autorizado chama o helper `askpass`.
2. O broker autentica o token de sessão e a capacidade da origem `llm`.
3. O broker cria um pedido com nonce, prazo e identidade do processo.
4. A UI lista o pedido e mostra comando, PID, terminal e monitor.
5. A aprovação ou cancelamento exige o nonce do pedido e é de uso único.
6. O segredo é entregue somente na conexão bloqueada do helper; depois o
   pedido é removido.

## Fora de escopo

- credenciais persistentes ou recuperação de senha;
- operações financeiras ou produção sem revisão de threat model;
- captura global de teclado, clipboard, PTY ou comandos arbitrários;
- instalação automática em `/usr/share/omarchy`.
