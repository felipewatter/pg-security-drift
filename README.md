# PG Security Drift — PostgreSQL RLS & Privilege Drift Guard

**Auditor de segurança de permissões e RLS para PostgreSQL, Supabase e Neon, com captura somente de leitura, snapshots comparáveis e bloqueio de regressões em CI/CD.**

> **v0.1.0 — experimental.** Heurísticas de metadados de segurança não equivalem a um teste de autorização real. **Não lê linhas de negócio, não executa funções de usuário, não instala extensões e não altera esquemas ou dados.** O teste de integração configura objetos exclusivamente em um banco PostgreSQL descartável do GitHub Actions.

[![Security CI](https://github.com/felipewatter/pg-security-drift/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/pg-security-drift/actions/workflows/ci.yml)

## Problema que resolve

Tabelas podem ter permissões efetivas de `SELECT`, `INSERT`, `UPDATE` ou `DELETE` acessíveis por papéis de API sem proteção RLS; políticas podem existir, mas ter sido desabilitadas; views podem executar como proprietárias; funções `SECURITY DEFINER` expostas podem contornar a autorização esperada; novos grants e alterações podem passar despercebidos entre migrações.

O PostgreSQL documenta a semântica de RLS, incluindo exceções para proprietários e roles `BYPASSRLS`. O Supabase mantém seus próprios **Security Advisors**. O PG Security Drift **não substitui esses recursos**: complementa-os com snapshots versionáveis, comparação de mudanças e integração simples para pipelines que utilizam PostgreSQL gerenciado, incluindo Neon e Supabase.

**Privacidade por design:** o SQL de inventário retorna apenas nomes de objetos, tipos, flags de RLS, grants efetivos dos papéis `anon`/`authenticated`, nomes e metadados mínimos de policies, flags de funções e roles. **Não exporta dados de tabelas, senhas, corpo de funções ou expressões SQL completas das policies**. Nomes de tabelas e funções ainda podem ser sensíveis: proteja os relatórios.

## Funcionalidades

| Recurso | Implementação |
| --- | --- |
| Auditoria somente de leitura | `pg_catalog` em transação `REPEATABLE READ, READ ONLY`; `psql` não interativo |
| RLS desabilitado com grants de API | Distingue gravidade para `anon` e `authenticated` |
| Policies registradas com RLS desativado | Identifica quando as policies não são efetivamente aplicadas |
| Policies permissivas com literal `true` | Alerta contextual sem afirmar exploração confirmada |
| Views sem `security_invoker` | Identifica views consultáveis via papéis de API que executam no contexto do proprietário |
| Materialized views consultáveis | Indica objetos com dados materializados e grants efetivos |
| Funções `SECURITY DEFINER` | Verifica grants e ausência de `SET search_path` per-function |
| Roles `BYPASSRLS`/superuser | Marca atribuições de alto impacto para `anon` e `authenticated` |
| Controle de mudanças | Snapshots comparáveis: findings novos, resolvidos e alterados |
| Policy gates para CI | `--fail-on` com limiares e comparação incremental, sem tratar auditoria incompleta como sucesso |
| Exportações | Texto, JSON e SARIF 2.1.0 |
| Zero dependências externas de runtime | Biblioteca Python padrão + **cliente PostgreSQL `psql`** para captura |
| Restrições | Sem interpolação SQL; limite de 5.000 relações e 5.000 funções; limite de 8 MiB de snapshot |

## Arquitetura

```text
 PostgreSQL / Supabase / Neon
     pg_catalog (metadata)
         |
   BEGIN READ ONLY + psql
         |
  Snapshot JSON validado ──> auditor de posture ──> Text / JSON / SARIF
         |                        |
         v                        v
  Baseline independente ── compare ── novos achados / resolvidos / alterados
                                      |
                              pipeline CI (exit 0/1/2)
```

### O que os achados significam?

- **CRITICAL — `EXPOSED_TABLE_NO_RLS`:** role `anon` consegue usar o schema e possui grant de tabela, mas RLS está desativado.
- **HIGH — `EXPOSED_TABLE_NO_RLS`:** cenário equivalente para `authenticated`.
- **HIGH — `POLICY_RLS_DISABLED`:** existem policies na tabela, porém `relrowsecurity = false`.
- **HIGH — `VIEW_OWNER_CONTEXT`:** view consultável por role de API sem `security_invoker=true`.
- **HIGH/MEDIUM — `DEFINER_CALLABLE_BY_API_ROLE`:** função `SECURITY DEFINER` executável por role de API, exigindo revisão da intenção.
- **HIGH — `DEFINER_MUTABLE_SEARCH_PATH`:** função `SECURITY DEFINER` não configura `search_path` localmente.
- **MEDIUM — `BROAD_PERMISSIVE_POLICY`:** policy permissiva com expressão SQL literalmente igual a `true`.
- **MEDIUM — `EXPOSED_MATERIALIZED_VIEW`:** acesso `SELECT` efetivo a materialized view via role de API.
- **LOW — `RLS_WITHOUT_POLICIES`:** tabela com RLS habilitado sem policies, normalmente negando acesso (problema potencial de disponibilidade).
- **CRITICAL — `ROLE_BYPASS_RLS`:** `anon` ou `authenticated` recebeu `BYPASSRLS` ou privilégios de superuser.

Essas classificações são **heurísticas**, não comprovam exposição pública via PostgREST ou exploração. Para provar a autorização, são necessários testes como papéis distintos e tentativas controladas de acesso no ambiente autorizado.

## Instalação

**Requisitos:** Python 3.11 ou superior, `psql` compatível com o servidor PostgreSQL. O código de auditoria offline (`audit`/`compare`) funciona **sem conexão nem `psql`**. Nenhuma dependência Python runtime é exigida.

```bash
git clone https://github.com/felipewatter/pg-security-drift.git
cd pg-security-drift
python -m pip install -e .
pg-security-drift --help
```

A existência de um wheel GitHub não implica publicação no PyPI.

## Configuração segura do PostgreSQL

Configure parâmetros libpq em variáveis do ambiente de execução ou serviço PostgreSQL. Evite passar DSNs contendo senha em argumentos da CLI, URLs de logs ou arquivos commitados.

```bash
export PGHOST='db.seu-projeto.example'
export PGPORT='5432'
export PGDATABASE='postgres'
export PGUSER='auditor_leitura'
export PGSSLMODE='verify-full'
# PGPASSWORD pode ser injetado como secret do CI, ou use um .pgpass protegido.
```

**Permissões:** use um papel com os menores privilégios necessários para consultar `pg_catalog` e as funções de introspecção de privilégios. Não é necessário `SUPERUSER`, `BYPASSRLS`, `service_role` ou `SECURITY DEFINER`. A captura executa `BEGIN ... READ ONLY`, desabilita prompts de senha e executa um script SQL estático. A CLI nunca executa comandos DDL/DML contra o banco.

**Supabase:** o `PGSSLMODE=verify-full` exige certificado/CA correto. Revise se o host, certificado e configuração do pooler são compatíveis; não desative verificação TLS em produção. A ferramenta **não consulta o Supabase Storage, Edge Functions, permissões JWT ou a configuração externa da Data API**.

## Exemplos

### 1. Capturar snapshot de segurança (somente leitura)

```bash
pg-security-drift snapshot --output baseline.snapshot.json
```

O arquivo só é criado se não existir; a ferramenta **não sobrescreve** snapshots. Coloque o baseline em armazenamento revisado e protegido contra alterações pelo mesmo ator que modifica o banco.

### 2. Auditar snapshot offline

```bash
pg-security-drift audit --input baseline.snapshot.json --format text --fail-on high
pg-security-drift audit --input baseline.snapshot.json --format sarif --output resultado.sarif --fail-on none
```

Por padrão, o escopo é **schema `public`**; para mais schemas, repita `--schema`:

```bash
pg-security-drift audit --input baseline.snapshot.json --schema public --schema app --format json
```

### 3. Auditar diretamente o banco

```bash
pg-security-drift scan --schema public --format json --fail-on critical
```

### 4. Detectar regressões desde um baseline

```bash
pg-security-drift snapshot --output atual.snapshot.json
pg-security-drift compare \
  --baseline baseline.snapshot.json \
  --current atual.snapshot.json \
  --format json --fail-on high
```

A comparação bloqueia **apenas achados novos ou agravados** no limiar selecionado. Achados antigos permanecem documentados, mas não bloqueiam o código de saída incremental. A política de produção pode optar por bloquear todos os achados com `audit`.

### 5. Rodar a demo sem banco

```bash
pg-security-drift compare \
  --baseline examples/baseline.json \
  --current examples/current.json \
  --format text --fail-on high
```

**Resultado esperado: código de saída 1**. A demo contém metadados inventados e simula uma mudança que remove a proteção RLS.

## Códigos de saída

| Código | Significado |
| --- | --- |
| **0** | A auditoria terminou e nenhum achado ultrapassou o limiar escolhido; riscos menores podem existir |
| **1** | Achado de segurança no limiar ou acima dele; compare considera apenas novos/agravados |
| **2** | Falha operacional, SQL incompleto, arquivo inválido, excesso de limites ou snapshot não confiável; **não equivale a banco seguro** |

## CI/CD e baseline

O `.github/workflows/ci.yml` executa testes sintéticos em **Python 3.11–3.14 em Ubuntu/Windows/macOS**, empacotamento e **uma integração real com PostgreSQL 17 descartável**. Não há acesso a bancos de terceiros ou do usuário no workflow.

Para CI em um banco real, distribua um baseline aprovado por canal independente e execute `snapshot` seguido de `compare`. **Não use a saída de `snapshot` da mesma execução para criar automaticamente um novo baseline aprovado**, pois isso eliminaria a capacidade de identificar alterações inesperadas.

## Limitações importantes

- Os grants são calculados com `has_table_privilege`/`has_function_privilege` e o direito de `USAGE` no schema para `anon` e `authenticated`. Não se interpreta o JWT real, PostgREST, configurações de publicação, privilégios de outros papéis nem direitos indiretos de funções no código.
- `pg_get_expr(...)` é usado **somente** para comparar se a expressão de uma policy é o literal `true`; a expressão completa não é exportada nem interpretada semanticamente.
- Uma função `SECURITY DEFINER` com `search_path` definido **ainda pode ser insegura** se usar um schema gravável por terceiros. A regra identifica somente ausência da configuração.
- Views de versões anteriores ao PostgreSQL 15 não oferecem `security_invoker` nativo. Comportamento proprietário é um alerta, não prova automática de exposição.
- Tabelas sem grants efetivos podem permanecer fora dos alertas de exposição. Pode haver exposição por RPC, views, ownership, outros roles ou falhas não observadas.
- A captura coleta até 5.000 relações e 5.000 funções de schemas não sistêmicos; volumes acima disso causam erro de integridade da captura.
- O snapshot inclui **nomes de objetos e assinaturas de funções**, que devem receber classificação e retenção apropriadas. Não há assinatura criptográfica do baseline; proteja sua proveniência e integridade no CI.
- O pacote não executa reparos automáticos nem utiliza credenciais administrativas. A intervenção deve ser feita com revisão humana.

## Qualidade, governança e documentação

- [SECURITY.md](SECURITY.md): divulgação responsável e limitações.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): fluxo de dados, SQL de catálogo e ameaças.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): controles, riscos residuais e modelo operacional.
- [docs/TEST_MATRIX.md](docs/TEST_MATRIX.md): matriz reproduzível e testes de integração.
- [CONTRIBUTING.md](CONTRIBUTING.md): colaboração segura.
- [CHANGELOG.md](CHANGELOG.md): evolução.

### Referências

- [PostgreSQL — Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL — pg_policy](https://www.postgresql.org/docs/current/catalog-pg-policy.html)
- [Supabase — Securing your API](https://supabase.com/docs/guides/api/securing-your-api)
- [Supabase — Security Advisors](https://supabase.com/docs/guides/observability/advisors)

**Licença:** MIT © 2026 Felipe Watter. Ferramenta aberta, local e defensiva. Não foi submetida a auditoria de segurança independente.
