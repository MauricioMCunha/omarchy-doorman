# Doorman Broker

Protótipo local do broker para o plugin `doorman`.

## Executar

```bash
./scripts/run-doorman-broker
```

Com o broker ativo, o helper pronto para `sudo -A` é
`scripts/doorman-askpass`. Exemplo de configuração temporária:

```bash
export SUDO_ASKPASS="$PWD/scripts/doorman-askpass"
sudo -A id
```

O unit do broker deve estar ativo na sessão do usuário e a UI do plugin deve
estar carregada para aprovar a solicitação.

Para instalação persistente, use o unit em
`packaging/omarchy-doorman.service` como serviço `systemd --user`.

O broker não possui UI própria. O comando `ui_test.py` simula a futura
interface Quickshell e deve ser usado somente com segredos fictícios.

## Limites do protótipo

- socket Unix local com modo `0600`;
- token de sessão obrigatório;
- nonce e request id por solicitação;
- autorização de uso único com timeout;
- nenhum log do valor secreto;
- sem integração com `sudo` real nesta fase.
