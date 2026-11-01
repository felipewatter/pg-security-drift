# Modelo de ameaças

**Ativos:** integridade das políticas RLS, segurança de grants do banco, confiança no baseline, sigilo de metadados internos, disponibilidade da pipeline de revisão.

**Atores:** operador autorizado do banco, sistema CI, atacante com permissão para mudar DDL/grants, mantenedor do baseline, usuário anônimo/autenticado da API.

| Ameaça | Controle implementado | Risco residual |
| --- | --- | --- |
| Acesso anônimo a tabela sem RLS | Verificação de grants de tabela e schema e `relrowsecurity` | Configuração externa Data API não examinada |
| Policy definida, mas não aplicada | `relrowsecurity=false` + policies presentes | Policies podem não ser utilizadas por design |
| View contorna RLS como proprietário | Inspeção `security_invoker` e grants | Políticas subjacentes podem oferecer controles adicionais |
| Função privilegiada exposta | `prosecdef` + EXECUTE + USAGE | Corpo SQL não é inspecionado; falso positivo e negativo |
| Função definer com `search_path` mutável | Busca de configuração `SET search_path` | Um path fixo ainda pode incluir schemas não confiáveis |
| Anon/auth ganha `BYPASSRLS` | Metadados de `pg_roles` | Outros papéis e ownership não avaliados |
| Alteração inesperada de políticas | Snapshot diff e gate de achados novos | Mudanças sem efeito no conjunto de regras podem não ser alertadas |
| Injeção de SQL via argumentos | SQL estático, nenhum parâmetro interpolado | Cliente `psql`/SO ainda é parte da TCB |
| Leitura de dados do usuário | `pg_catalog` somente e transação `READ ONLY` | Nomes de metadados podem ser sensíveis |
| Dados excessivos/malformados | Limite de objetos/bytes, parser com chaves únicas | Volume de catálogo pode causar falha intencional |
| Baseline adulterado | Nenhuma aprovação automática de baseline | Proteção externa indispensável |
| Exposição de senha em erro | Sem stderr/connection string nos relatórios | Variáveis env e logs externos da aplicação permanecem no escopo do operador |

**Não objetivos:** RLS tester que se conecta como cada role para consultar dados, SQL injection scanner, correções automáticas, comparações de dados de produção, análise de permissões JWT ou concessão de privilégios no banco.
