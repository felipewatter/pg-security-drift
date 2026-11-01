# Arquitetura de auditoria e comparação

```text
 PostgreSQL / Supabase / Neon (libpq)
             |
        psql -X -w
             |
  BEGIN REPEATABLE READ READ ONLY
             |
       pg_catalog
             |
 JSON com atributos selecionados
             |
   validação de esquema / limites
             |
       snapshot v1
         /      \
     audit     compare ← baseline protegido
        \        /
       regras determinísticas
              |
       JSON / Texto / SARIF
              |
      exit 0 / 1 / 2
```

## Componentes

- `sql/catalog.sql`: consulta de metadados em CTEs, com coleta de relações, policies, funções e roles conhecidos. Não realiza SQL dinâmico nem acesso a dados de negócio.
- `capture.py`: subprocesso `psql` com stdin/stderr desabilitados, timeout, arquivo temporário e leitura de conteúdo delimitado. Erros nunca mostram DSNs ou conteúdo bruto do banco.
- `model.py`: validação com chaves JSON únicas, estrutura estrita, limites, proibição de nomes de objetos malformados e leitura que rejeita symlinks.
- `checks.py`: heurísticas distintas de integridade RLS, privilégios de API, views e funções; diff incremental de achados por identificador estável; exportação SARIF.
- `cli.py`: interpretação dos parâmetros e código de saída fail-closed.

## Catálogos consultados

`pg_class`, `pg_namespace`, `pg_policy`, `pg_proc`, `pg_roles` e funções de introspecção `to_regrole`, `has_schema_privilege`, `has_table_privilege`, `has_function_privilege`, `pg_get_expr` e `pg_get_function_identity_arguments`.

**Ausências intencionais:** não exporta as condições completas das policies, os corpos de funções, hash de senhas, usuários e registros da aplicação, segredos de Supabase nem valores de tabelas.

## Versionamento dos snapshots

`schemaVersion=1`; arrays `relations`, `functions`, `roles`, objeto `limits`. As regras usam nomes qualificados e principal para produzir identificadores estáveis. Renomear um objeto é tratado como ocorrência nova e resolução antiga.

## Segurança do baseline

É uma fonte de dados local, não prova de integridade. Faça revisão cruzada, retenção imutável e uso em pipeline com permissões separadas. A comparação não edita nem reaprova baseline automaticamente. A ferramenta não utiliza hashes de senhas nem algoritmos de assinatura para esse recurso; use sistema de proveniência externo.

## Compatibilidade

Projetado para PostgreSQL 15–18 e sistemas gerenciados compatíveis. A query de CI roda contra PostgreSQL 17. Sem validação de produção em todas as versões ainda; não assuma que a execução remota está garantida antes dos testes de CI.
