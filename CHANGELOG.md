# Changelog

## 2026-08-31

### Unbound ISP FULL v1.3
- Painel web opcional para DNS1.
- Integração DNS2 via Agent.
- Troubleshooting normal e profundo pelo painel.
- Teste direcionado por domínio informado pelo operador.
- Diagnóstico de cache, DNSSEC, recursão, UDP/TCP, sistema e comparação externa.
- Estrutura preparada para múltiplos nós.

### Unbound Original + named.cache v3
- Instalação sem painel web.
- `named.cache` oficial salvo como `/var/lib/unbound/root.hints`.
- Reexecução conservadora sem sobrescrever configuração existente.
- Confirmação das redes ACL inseridas.
- Opção explícita para `0.0.0.0/0` com alerta de open resolver.
- Troubleshooting standalone instalado em `/root/unbound-troubleshooting.sh`.

### Troubleshooting standalone v1
- Teste de serviço, UDP/TCP 53, resolução, cache e DNSSEC.
- Detecção de `forward-zone`.
- Verificação de root hints/auth-zone.
- Estatísticas do Unbound e saúde de CPU/RAM/rede.
- Modo profundo para root/TLD/TCP.
