# Revisão de segurança para publicação

## Limite de confiança

O catálogo Omarchy valida o manifesto e a estrutura do plugin, mas não
sandboxa nem audita a segurança do código. Um plugin roda dentro do
`omarchy-shell`, com as permissões do usuário. Portanto, esta revisão é parte
do projeto e deve acompanhar qualquer submissão.

## Decisões de segurança

- O plugin não captura teclado global, PTY, clipboard ou comandos arbitrários.
- O segredo não entra em argumentos, arquivos, logs ou mensagens do agente.
- A UI só aprova um pedido autenticado por token, nonce, prazo e identidade
  do processo.
- O broker aceita somente `origin=llm` com capacidade de sessão válida.
- O socket e os arquivos de sessão são privados ao usuário (`0700`/`0600`).
- A UI chama executáveis absolutos e o bridge é empacotado ao lado do plugin;
  não há override de caminho por variável de ambiente.
- O serviço é explícito e reversível; o plugin não instala serviço ou pacote
  silenciosamente.

## Blockers antes da submissão

1. ~~Publicar o plugin como repositório próprio, em vez de submeter este
   monorepo diretamente.~~ Feito em 2026-09-27: este repositório é o
   resultado dessa extração (via `git filter-repo`, preservando a autoria e
   o histórico de `omarchy-plugins`). O monorepo de origem
   (`github.com/MauricioMCunha/omarchy-plugins`) passa a ser só um laboratório
   de criação/teste de novos plugins.
2. ~~Adicionar o entrypoint `BarWidget.qml` conforme o contrato Quattro e
   mover o painel para o ciclo de vida `Panel`/`KeyboardPanel` oficial.~~
   Feito em 2026-09-27: `BarWidget.qml` hospeda o ícone e todo o estado do
   broker; `Panel.qml` estende `Panel`/`KeyboardPanel` e só lê esse estado via
   `hostWidget`, no mesmo padrão de `omarchy.clock`. Validado ao vivo: ícone,
   popup, coordenação de popout (dismiss-twin no outro monitor) e o
   SecureOverlay (que continua fora desse ciclo de vida, de propósito — ver
   §3 do SPEC) continuam funcionando.
3. Documentar instalação, ativação, parada e remoção do serviço de usuário.
4. Testar em uma conta limpa: instalação, reinício do shell, toggle do broker,
   aprovação, cancelamento, expiração, remoção e rollback.
5. ~~Adicionar revisão de dependências, `qmllint`, testes Python e inspeção
   de segredos ao CI.~~ Parcial em 2026-09-27: o CI (`.github/workflows/ci.yml`)
   ganhou um job `security` com `gitleaks` (inspeção de segredos) e
   `dependency-review-action` (roda em PRs; hoje é só um cabo-terra, já que o
   projeto não tem dependência de terceiros — ver `pyproject.toml`). Testes
   Python já rodavam. `qmllint` **não** entrou no CI: ele depende de um
   Quickshell/Omarchy instalados de verdade para resolver o import reservado
   `qs.*` e os módulos `Quickshell.*`, e nenhum dos dois tem pacote para
   Ubuntu/Debian — compilar o Quickshell a cada run seria desproporcional
   para o tamanho deste projeto. Em vez disso, `scripts/qmllint-check` roda
   localmente (mesma máquina onde já se testa o plugin) e fica documentado
   no README como passo antes de enviar uma mudança de QML.

Não submeter enquanto qualquer blocker acima estiver aberto.
