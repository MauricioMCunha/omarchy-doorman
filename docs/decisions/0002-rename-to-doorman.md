# ADR 0002 — Renomear "Secure Input" para "Doorman"

## Decisão

Renomear o plugin e todos os identificadores internos (id do manifesto,
diretório do plugin, pacote Python do broker, unit systemd, diretório de
runtime, scripts e variáveis de ambiente) de `secure-input`/`SECURE_INPUT`
para `doorman`/`DOORMAN`.

## Motivo

"Secure Input" colide com um termo de segurança de SO já estabelecido
("Secure Input Mode", proteção de teclado contra keyloggers) que descreve
algo diferente do que este plugin faz. O nome também era genérico
comparado aos outros plugins instalados no catálogo (Radio Atlas, Loose
Ends, Snipper, Port Watch), que tendem a nomes mais distintivos.

"Doorman" descreve a metáfora central do plugin sem ambiguidade: um
processo bate à porta pedindo `sudo`, e uma pessoa — só ela, numa janela
local — decide se deixa entrar.

## Consequência

O id do manifesto muda (`mauricio.secure-input` → `mauricio.doorman`), o
que faz o Omarchy tratar isso como um plugin diferente do ponto de vista
do layout da barra: `~/.config/omarchy/shell.json` guarda os widgets
ativos por id, então a referência antiga precisou ser atualizada
manualmente para o widget continuar aparecendo na topbar após a
migração — renomear o id de um plugin não migra automaticamente sua
posição na barra.
