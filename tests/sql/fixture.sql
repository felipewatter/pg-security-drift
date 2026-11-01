-- Runs ONLY against an isolated disposable CI postgres service.
-- Never run against production: this fixture intentionally creates objects.
\set ON_ERROR_STOP on
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
GRANT USAGE ON SCHEMA public TO anon, authenticated;
CREATE TABLE public.pg_drift_example (id bigint PRIMARY KEY, owner_id text);
GRANT SELECT ON public.pg_drift_example TO anon;
CREATE VIEW public.pg_drift_example_view AS SELECT id FROM public.pg_drift_example;
GRANT SELECT ON public.pg_drift_example_view TO anon;
CREATE FUNCTION public.pg_drift_definer() RETURNS integer
  LANGUAGE sql SECURITY DEFINER AS $$SELECT 1$$;
GRANT EXECUTE ON FUNCTION public.pg_drift_definer() TO anon;
