# Política de segurança — PG Security Drift

Use GitHub **Private Vulnerability Reporting / Security Advisories** quando disponível. Não coloque connection strings, nomes internos de bancos de clientes, credenciais ou capturas reais em issues públicas.

## Modelo de segurança

O aplicativo executa uma consulta **somente de leitura** ao `pg_catalog`, dentro de transação `REPEATABLE READ, READ ONLY`. Nunca tenta ler linhas de tabelas de negócio nem executar corpo de funções. A política de análise é offline e não precisa de acesso ao banco após a captura. `psql` recebe um **arquivo SQL estático empacotado**, não SQL construído com parâmetros de usuário. O processo executa com `-X -w`, `ON_ERROR_STOP=1`, timeout e stderr descartado para evitar divulgação de informações do servidor.

Snapshots aceitos são JSON estritamente validados quanto a campos, tipos, duplicações, tamanhos, limites de 5.000 relações/funções e permissões por papéis conhecidos. Arquivos simbólicos de entrada são rejeitados. A saída é criada com modo exclusivo, sem sobrescrever resultados existentes. Falha ou varredura incompleta retorna **exit 2**.

## Riscos residuais e escopo

- **Metadados não equivalem a exploração comprovada**. A detecção de `relrowsecurity=false` e grants é somente indício contextual; exposição real depende da API, de roles/ownership e da arquitetura da aplicação.
- **Os snapshots não são assinados**. Um atacante com permissão para alterar o baseline pode ocultar mudanças. Mantenha a referência em armazenamento e workflow independentes e protegidos por revisão.
- **Credenciais libpq herdadas** do ambiente são responsabilidade do operador. Prefira roles somente de leitura; `PGSSLMODE=verify-full` e certificados CA corretos em produção remota.
- **SQL fixo** pode usar funções nativas do catálogo (ex.: `pg_get_expr`, `has_table_privilege`). Elas não executam funções de usuário, mas podem retornar erro por configurações não suportadas: falhe fechado.
- **RLS é aplicado por relação**, e comportamento de views depende da versão do PostgreSQL. Não tratamos o fato de possuir uma policy como prova de proteção.
- Políticas SQL complexas não são avaliadas semanticamente; a regra `BROAD_PERMISSIVE_POLICY` cobre apenas a expressão literal `true`.
- Funções `SECURITY DEFINER` merecem revisão individual de corpo, grants, ownership e `search_path`. Não exportamos o corpo da função.
- `psql`/libpq e `PGOPTIONS` do sistema precisam ser atualizados. O timeout de processo é limitado, porém a gestão de cancelamento depende de `subprocess` e do servidor. Configure statement_timeout na instância.
- O projeto não se conecta automaticamente a projetos Supabase/Neon nem audita buckets Storage, JWT, APIs externas, PostgreSQL extensions ou ambientes não declarados.
- Os relatórios podem expor **nomes de schemas e assinaturas**. Restrinja a retenção de artefatos do CI e sua visibilidade.
- Não concede nem modifica grants, RLS, roles, policies, schemas, extensões ou dados.

## Operação recomendada

1. Revisar o SQL de `src/pg_security_drift/sql/catalog.sql` antes do primeiro uso.
2. Configurar role com os menores privilégios possíveis e conexão TLS verificada.
3. Capturar baseline, revisá-lo separadamente e proteger sua integridade.
4. Habilitar comparação incremental no CI e revisar novos achados antes do merge.
5. Testar acesso com contas distintas em **ambiente autorizado isolado** para verificar se o indício é problema efetivo.

## Códigos de retorno

`0` = verificação completa sem achados no limiar, `1` = risco no limiar, `2` = falha ou verificação incompleta. **Não trate 0 como certificação.**
