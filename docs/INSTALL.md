# Instalação

## Qual versão usar?

Use **Unbound Original + named.cache** quando quiser somente o DNS recursivo, sem painel, Agent ou banco de dados.

Use **Unbound ISP FULL** quando quiser gerenciar DNS1/DNS2, painel web, pareamento entre nós e troubleshooting remoto.

## Original
```bash
chmod +x installer/unbound-original-named-cache.sh
./installer/unbound-original-named-cache.sh
```

## FULL
```bash
chmod +x installer/unbound-isp-full.sh
./installer/unbound-isp-full.sh
```

O painel web do FULL é opcional e também pode ser instalado posteriormente sem reinstalar o Unbound.
