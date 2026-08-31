# Changelog

## 2026-08-31

### Unbound ISP FULL v1.4
- Troubleshooting validado em produção fixado na revisão `c85e77e01a52cbaea7b7a8b6f7abba255e7691b2`.
- DNS1 e DNS2 passam a instalar automaticamente essa revisão estável.
- Instalação posterior do Painel Web também garante o troubleshooting estável sem alterar a configuração do Unbound.
- Agent mantém execução allowlisted de `/root/unbound-troubleshooting.sh` para modo normal, profundo e teste por domínio.
- Revisão instalada registrada em `/etc/unbound-isp/troubleshooting.version`.
- Menu de gerenciamento do painel permite reinstalar somente o troubleshooting estável.

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
