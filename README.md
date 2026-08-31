# Unbound ISP

Projeto para implantação, operação e troubleshooting de servidores DNS recursivos com Unbound.

## Componentes

### 1. Unbound Original + named.cache
Instalação direta do Unbound, sem painel web. Mantém a proposta original do resolver, adicionando `named.cache`/`root.hints`, DNSSEC, ACLs configuráveis e rotina segura para reexecução.

Arquivo: `installer/unbound-original-named-cache.sh`

### 2. Unbound ISP FULL
Versão completa com DNS1/DNS2, Agent local, painel web opcional, integração entre nós, auditoria, diagnóstico e troubleshooting remoto.

Arquivo: `installer/unbound-isp-full.sh`

### 3. Troubleshooting standalone
Ferramenta independente para diagnóstico rápido durante incidentes de lentidão, falhas de abertura de páginas, problemas de cache, DNSSEC, recursão, UDP/TCP 53 e saúde do servidor.

Arquivo: `troubleshooting/unbound-troubleshooting.sh`

## Uso rápido

### Instalação original sem painel
```bash
bash installer/unbound-original-named-cache.sh
```

### Instalação FULL
```bash
bash installer/unbound-isp-full.sh
```

### Troubleshooting
```bash
bash troubleshooting/unbound-troubleshooting.sh
```

Modo profundo:
```bash
bash troubleshooting/unbound-troubleshooting.sh --deep
```

## Segurança

O painel web é opcional e não é dependência do serviço DNS. O `unbound-control` permanece local. A comunicação entre painel e nós deve usar o Agent autenticado, sem exposição de shell genérico ou credenciais SSH root.

## Versão atual

- Unbound ISP FULL: v1.3
- Unbound Original + named.cache: v3
- Troubleshooting standalone: v1
