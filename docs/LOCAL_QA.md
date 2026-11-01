# Relatório de validação local — PG Security Drift v0.1.0

Data: 2026-11-01. Este relatório separa **resultados executados** de **resultados de CI projetados**.

## Verificações concluídas

- **62/62 testes automatizados PASS** em Python 3.13, `unittest` (metadados sintéticos e mock do subprocesso `psql`).
- `python -m compileall -q src`: PASS.
- Wheel `pg_security_drift-0.1.0-py3-none-any.whl`: construído localmente, sem dependências Python de runtime.
- Package-data: o wheel contém `pg_security_drift/sql/catalog.sql`, sem interpolação de SQL do usuário.
- Demo offline `compare`: detectou dois achados novos quando RLS foi desabilitado, **exit code 1**.
- Relatório SARIF 2.1.0: formato gerado sem queries completas das policies, corpos de funções ou dados de tabelas.
- Saída de snapshot: criação exclusiva `O_EXCL`, permissão 0600 e rejeição de symlinks de entrada.

## Pendente de execução remota

- CI para Python 3.11, 3.12, 3.13 e 3.14 em Ubuntu, Windows e macOS (12 jobs).
- Execução do SQL de catálogo contra PostgreSQL 17 **descartável**, disponível no workflow `live-postgres`.
- Job de empacotamento no GitHub e a primeira release oficial.
- Compatibilidade prática com versões PostgreSQL diferentes de 17, ambientes Supabase/Neon reais e conexão TLS remota.

**Não há alegação de auditoria independente ou garantia de produção.**
