# OpenSpec: doorman v0.1

## Requisitos funcionais

### R1 — Pedido autenticado

O broker MUST aceitar pedidos apenas com token de sessão válido, `origin=llm`
e capacidade correspondente. Pedidos sem PID positivo ou cujo processo não
exista MUST ser rejeitados.

### R2 — Contexto verificável

O pedido MUST exibir comando, PID, diretório, TTY, prompt, monitor, nonce e
prazo. O broker MUST capturar e revalidar start time, UID e cmdline do PID no
momento da aprovação, rejeitando processos encerrados ou reutilizados.

### R3 — Uso único e expiração

Cada pedido MUST ter `request_id` e nonce criptograficamente aleatórios, prazo
entre 1 e 300 segundos e estado terminal único: aprovado, cancelado ou expirado.
Replays MUST fail closed.

### R4 — Segredo fora da superfície de observação

O segredo MUST NOT aparecer em argumentos, logs, arquivos, clipboard, respostas
da UI ou mensagens do agente. O helper pode escrevê-lo somente em stdout para
o consumidor `sudo askpass`.

### R5 — Cancelamento autenticado

Cancelamento MUST exigir request id e nonce válidos. Um cancelamento inválido
não pode alterar o pedido.

### R6 — Transporte local

O socket MUST ser Unix, criado com `0600`, sob diretório `0700`, e o serviço
MUST usar `umask 0077`, `NoNewPrivileges` e diretório temporário privado.

## Critérios de aceitação

- `python3 -m unittest discover -s tests -p 'test_*.py'` passa;
- o diagnóstico Graphify não reporta endpoints ausentes, loops ou arestas
  duplicadas exatas (arestas com relações distintas podem aparecer como uma
  colisão relacional informativa);
- testes cobrem token errado, origem inválida, PID ausente, expiração,
  aprovação, replay e cancelamento com nonce errado/correto;
- nenhuma alteração de deploy real ocorre sem instalação explícita do unit.
