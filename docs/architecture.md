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
    └─ sudo / sudo -A / SUDO_ASKPASS
         └─ broker local
              └─ plugin Omarchy
                   └─ usuário confirma e digita localmente
```

O conteúdo da senha não retorna ao agente, ao chat, ao clipboard ou ao log.

## Limite da primeira versão

A integração não invasiva pode configurar somente `SUDO_ASKPASS`, sem
substituir `sudo`, alterar `sudoers` ou capturar comandos globalmente. O
comportamento exato depende da versão/política do sudo; nesta máquina, o
helper não é chamado sem `-A`, inclusive em execução sem TTY. O wrapper
opcional acrescenta `-A` apenas quando o usuário o invoca diretamente. O
launcher `secure-input-run` cria um PATH temporário para um único processo,
permitindo que um executor de LLM use `sudo comando` sem lembrar a flag, sem
alterar o PATH global do usuário.
