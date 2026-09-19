# Arquitetura do Omarchy Plugins Lab

## Camadas

1. **Plugin visual** — executa no Quickshell/Omarchy Shell, apresenta pedidos
   e coleta consentimento local.
2. **Broker local** — serviço de usuário com socket Unix privado, nonce,
   timeout, associação ao processo e limpeza de buffers.
3. **Helper de autenticação** — integração limitada com `sudo askpass`, sem
   receber comandos arbitrários do plugin.
4. **Operação privilegiada** — `sudo` ou `pkexec`, sempre com escopo e origem
   verificáveis.

## Fluxo inicial

```text
comando autorizado
    └─ sudo -A / SUDO_ASKPASS
         └─ broker local
              └─ plugin Omarchy
                   └─ usuário confirma e digita localmente
```

O conteúdo da senha não retorna ao agente, ao chat, ao clipboard ou ao log.

## Limite da primeira versão

A primeira versão atenderá somente comandos preparados para `sudo -A` e
`SUDO_ASKPASS`. Não haverá captura global de teclado, leitura arbitrária de
PTYs nem tentativa de interceptar todo prompt de terminal.
