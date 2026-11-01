# Matriz de qualidade e validação

## Regressões locais

```bash
python -m pip install -e .
python -m unittest discover -s tests -p 'test_*.py' -v
python -m compileall -q src
pg-security-drift compare --baseline examples/baseline.json --current examples/current.json --fail-on high
```

Os testes offline usam metadados **sintéticos**, sem conexões com PostgreSQL do usuário. Cobrem RLS desligado, grants, policies, funções, views, exportação SARIF, comparação incremental, JSON hostil, falhas fechadas e subprocesso `psql` simulado.

## PostgreSQL real em CI

O GitHub Actions provisiona uma instância **descartável PostgreSQL 17**, cria exclusivamente nela duas roles e objetos de teste, executa o SQL de catálogo e valida os findings retornados. O SQL de captura continua sendo somente leitura. O SQL de **fixture** (`tests/sql/fixture.sql`) é DDL, executado somente contra banco de teste isolado, nunca pela CLI no banco do operador.

A matriz offline cobre Python 3.11–3.14 em Ubuntu, Windows e macOS (12 combinações), mais o job de PostgreSQL real e o job de empacotamento. Esses jobs **só serão considerados aprovados após a publicação e a execução real no GitHub Actions**.

## Limitações da validação

A suíte não comprova comportamento de dados sob JWT real, políticas SQL complexas, bugs em versões específicas não testadas, configuração de supabase-js/PostgREST, serviços na nuvem ou permissões de extensões. O detector é heurístico e complementa testes de autorização específicos da aplicação.
