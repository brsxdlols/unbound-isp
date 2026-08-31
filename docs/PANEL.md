# Painel Web - Unbound ISP FULL

O painel é opcional e não participa do caminho crítico de resolução DNS. Se painel, banco ou collector pararem, o Unbound continua funcionando.

## Funções principais

- visão de DNS1 e DNS2;
- métricas de cache e desempenho;
- troubleshooting normal e profundo;
- teste de domínio específico, como `instagram.com`;
- ações seguras via Agent;
- configuração com backup, validação e rollback;
- gerenciamento de ACLs;
- visualização de logs e auditoria.

## Teste direcionado por domínio

No DNS selecionado, informe apenas o domínio, por exemplo `instagram.com`. O painel envia o teste ao Agent daquele nó e executa o troubleshooting pelo próprio servidor DNS.

O teste direcionado inclui resolução A e AAAA, primeira e segunda consulta para observar cache, UDP/53, TCP/53, DNSSEC quando aplicável e comparação diagnóstica com resolvers externos. No modo profundo também é feito um resumo do `+trace` da delegação.

## Segurança

O painel não armazena senha SSH root nem expõe shell arbitrário. As ações remotas são executadas por endpoints allowlisted do Agent. O campo de domínio é validado e não aceita comandos ou URLs arbitrárias.
