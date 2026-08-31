# Troubleshooting

Execute quando houver reclamações como:

- páginas demorando para abrir;
- domínio específico não resolvendo;
- resolução intermitente;
- suspeita de problema de cache ou DNSSEC;
- suspeita de perda UDP/TCP 53;
- dúvida se o problema está no Unbound ou na conectividade externa.

## Normal
```bash
/root/unbound-troubleshooting.sh
```

## Profundo
```bash
/root/unbound-troubleshooting.sh --deep
```

O diagnóstico verifica serviço, porta 53, resolução, cache, DNSSEC, configuração de forward, root hints, estatísticas do Unbound, requestlist, latência de recursão, CPU, RAM, swap e contadores UDP.

No painel FULL também existe troubleshooting por nó e teste direcionado por domínio.
