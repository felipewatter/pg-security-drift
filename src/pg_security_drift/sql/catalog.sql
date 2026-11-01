-- PG Security Drift v0.1.0
-- Reviewed read-only query: no table data, policies' SQL expression bodies,
-- SQL function bodies, credentials, or user records are selected.
-- Keep this file static. No user-controlled SQL interpolation is performed.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;
WITH
roles AS (
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'name', rolname, 'bypassrls', rolbypassrls, 'superuser', rolsuper
  ) ORDER BY rolname), '[]'::jsonb) AS content
  FROM pg_catalog.pg_roles
  WHERE rolname IN ('anon', 'authenticated')
),
rels AS (
  SELECT c.oid, n.oid AS schema_oid, n.nspname AS schema_name,
         c.relname AS relation_name, c.relkind, c.relrowsecurity, c.relforcerowsecurity,
         c.reloptions
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
    AND n.nspname <> 'information_schema'
    AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  ORDER BY n.nspname, c.relname
  LIMIT 5001
),
rel_values AS (
  SELECT jsonb_build_object(
    'schema', r.schema_name,
    'name', r.relation_name,
    'kind', r.relkind,
    'rls', r.relrowsecurity,
    'force_rls', r.relforcerowsecurity,
    'security_invoker', ('security_invoker=true' = ANY(COALESCE(r.reloptions, ARRAY[]::text[]))),
    'grants', jsonb_build_object(
      'anon', jsonb_build_object(
        'usage', CASE WHEN to_regrole('anon') IS NULL THEN false ELSE has_schema_privilege(to_regrole('anon'), r.schema_oid, 'USAGE') END,
        'select', CASE WHEN to_regrole('anon') IS NULL THEN false ELSE has_table_privilege(to_regrole('anon'), r.oid, 'SELECT') END,
        'insert', CASE WHEN to_regrole('anon') IS NULL THEN false ELSE has_table_privilege(to_regrole('anon'), r.oid, 'INSERT') END,
        'update', CASE WHEN to_regrole('anon') IS NULL THEN false ELSE has_table_privilege(to_regrole('anon'), r.oid, 'UPDATE') END,
        'delete', CASE WHEN to_regrole('anon') IS NULL THEN false ELSE has_table_privilege(to_regrole('anon'), r.oid, 'DELETE') END
      ),
      'authenticated', jsonb_build_object(
        'usage', CASE WHEN to_regrole('authenticated') IS NULL THEN false ELSE has_schema_privilege(to_regrole('authenticated'), r.schema_oid, 'USAGE') END,
        'select', CASE WHEN to_regrole('authenticated') IS NULL THEN false ELSE has_table_privilege(to_regrole('authenticated'), r.oid, 'SELECT') END,
        'insert', CASE WHEN to_regrole('authenticated') IS NULL THEN false ELSE has_table_privilege(to_regrole('authenticated'), r.oid, 'INSERT') END,
        'update', CASE WHEN to_regrole('authenticated') IS NULL THEN false ELSE has_table_privilege(to_regrole('authenticated'), r.oid, 'UPDATE') END,
        'delete', CASE WHEN to_regrole('authenticated') IS NULL THEN false ELSE has_table_privilege(to_regrole('authenticated'), r.oid, 'DELETE') END
      )
    ),
    'policies', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'name', p.polname,
        'cmd', p.polcmd,
        'permissive', p.polpermissive,
        'roles', COALESCE((SELECT jsonb_agg(CASE WHEN pr.role_id = 0 THEN 'public' ELSE pg_catalog.pg_get_userbyid(pr.role_id) END ORDER BY pr.role_id)
          FROM unnest(p.polroles) AS pr(role_id)), '[]'::jsonb),
        'using_true', COALESCE(trim(pg_catalog.pg_get_expr(p.polqual, p.polrelid)) IN ('true', '(true)'), false),
        'check_true', COALESCE(trim(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)) IN ('true', '(true)'), false)
      ) ORDER BY p.polname)
      FROM pg_catalog.pg_policy p WHERE p.polrelid = r.oid
    ), '[]'::jsonb)
  ) AS item
  FROM rels r
),
funcs AS (
  SELECT p.oid, n.nspname AS schema_name, n.oid AS schema_oid, p.proname, p.prosecdef,
         pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_args,
         p.proconfig
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE p.prokind = 'f'
    AND n.nspname <> 'information_schema'
    AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  ORDER BY n.nspname, p.proname, p.oid
  LIMIT 5001
),
func_values AS (
  SELECT jsonb_build_object(
    'schema', f.schema_name,
    'name', f.proname,
    'identity_args', f.identity_args,
    'security_definer', f.prosecdef,
    'search_path_set', EXISTS(SELECT 1 FROM unnest(COALESCE(f.proconfig, ARRAY[]::text[])) AS c(setting) WHERE c.setting LIKE 'search_path=%'),
    'grants', jsonb_build_object(
      'anon', CASE WHEN to_regrole('anon') IS NULL THEN false ELSE has_schema_privilege(to_regrole('anon'), f.schema_oid, 'USAGE') AND has_function_privilege(to_regrole('anon'), f.oid, 'EXECUTE') END,
      'authenticated', CASE WHEN to_regrole('authenticated') IS NULL THEN false ELSE has_schema_privilege(to_regrole('authenticated'), f.schema_oid, 'USAGE') AND has_function_privilege(to_regrole('authenticated'), f.oid, 'EXECUTE') END
    )
  ) AS item
  FROM funcs f
)
SELECT jsonb_build_object(
  'schemaVersion', 1,
  'source', 'pg_catalog',
  'relations', COALESCE((SELECT jsonb_agg(item ORDER BY item->>'schema', item->>'name') FROM rel_values), '[]'::jsonb),
  'functions', COALESCE((SELECT jsonb_agg(item ORDER BY item->>'schema', item->>'name', item->>'identity_args') FROM func_values), '[]'::jsonb),
  'roles', (SELECT content FROM roles),
  'limits', jsonb_build_object('relations', (SELECT COUNT(*) FROM rels), 'functions', (SELECT COUNT(*) FROM funcs))
);
COMMIT;
