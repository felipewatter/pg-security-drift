# Changelog

## [0.1.0] — 2026-11-01

- Projeto original de auditoria read-only de PostgreSQL RLS e grants, com CLI Python.
- Captura de `pg_catalog` por SQL estático em transação `READ ONLY`, sem dados de tabelas de negócio.
- Detecção heurística de exposição por grants sem RLS, políticas desativadas, policies permissivas literais e bypass RLS.
- Auditoria de views no contexto do proprietário, materialized views, funções `SECURITY DEFINER` e `search_path` local.
- Snapshot com JSON estrito, limites de memória/objetos, bloqueio de symlink e arquivo exclusivo.
- Análise offline e comparação incremental de novos, resolvidos e alterados; limiares para CI.
- Exportação texto, JSON, SARIF, testes sintéticos e job de integração PostgreSQL 17 descartável.
- README, SECURITY, THREAT_MODEL, documentação de arquitetura, contribuidores e licença MIT.

**Sem alegação de certificação de segurança ou execução de auditoria real contra projetos de clientes.**
