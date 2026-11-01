"""Small synthetic PostgreSQL catalog fixture, with no real identities or data."""
from copy import deepcopy

def relation(name='orders', *, schema='public',kind='r',rls=True,force=False,anon=False,authenticated=False,
             policies=None,security_invoker=False):
    def grants(enabled):return dict(usage=True,select=enabled,insert=False,update=False,delete=False)
    return dict(schema=schema,name=name,kind=kind,rls=rls,force_rls=force,security_invoker=security_invoker,
                grants=dict(anon=grants(anon),authenticated=grants(authenticated)),policies=policies or [])

def policy(name='read_own',roles=None,using_true=False,check_true=False,permissive=True,cmd='r'):
    return dict(name=name,roles=roles if roles is not None else ['authenticated'],cmd=cmd,permissive=permissive,
                using_true=using_true,check_true=check_true)

def function(name='secure_change',*,schema='public',definer=True,search_path=True,anon=False,authenticated=False):
    return dict(schema=schema,name=name,identity_args='user_id uuid',security_definer=definer,
                search_path_set=search_path,grants=dict(anon=anon,authenticated=authenticated))

def snapshot(relations=None,functions=None,roles=None):
    rel=deepcopy(relations if relations is not None else [relation()])
    fun=deepcopy(functions if functions is not None else [])
    return dict(schemaVersion=1,source='pg_catalog',relations=rel,functions=fun,roles=deepcopy(roles or []),
                limits=dict(relations=len(rel),functions=len(fun)))
