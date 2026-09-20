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

1. Publicar o plugin como repositório próprio, em vez de submeter este
   monorepo diretamente.
2. Adicionar o entrypoint `BarWidget.qml` conforme o contrato Quattro e mover
   o painel para o ciclo de vida `Panel`/`KeyboardPanel` oficial.
3. Documentar instalação, ativação, parada e remoção do serviço de usuário.
4. Testar em uma conta limpa: instalação, reinício do shell, toggle do broker,
   aprovação, cancelamento, expiração, remoção e rollback.
5. Adicionar revisão de dependências, `qmllint`, testes Python e inspeção de
   segredos ao CI.

Não submeter enquanto qualquer blocker acima estiver aberto.
