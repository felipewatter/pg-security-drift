# Contribuindo

PRs devem incluir escopo, impacto de segurança, testes de regressão e atualização de documentação. Nenhum SQL que altere tabelas de negócio deve ser introduzido no modo de captura. Novas regras devem especificar condições, falso-positivos esperados, gravidade contextual e fixtures mínimas.

Execute:

```bash
python -m pip install -e .
python -m unittest discover -s tests -p 'test_*.py' -v
python -m compileall -q src
```

Novos testes com PostgreSQL real devem usar exclusivamente uma instância descartável. Não faça upload de dumps, credenciais, DSNs, tokens JWT, arquivos de produção ou screenshots sensíveis.

Consulte `SECURITY.md` para divulgar vulnerabilidades de modo privado.
