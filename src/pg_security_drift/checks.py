"""Deterministic, evidence-minimizing risk heuristics. No data-row inspection."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from urllib.parse import quote
from .errors import InputError
from .model import validate_snapshot

SEVERITIES = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    object: str
    principal: str
    detail: str

    @property
    def key(self):
        return f'{self.rule}|{self.object}|{self.principal}'

    def as_dict(self):
        return asdict(self) | {'key': self.key}


def analyze(data: dict, schemas=('public',)) -> list[Finding]:
    validate_snapshot(data)
    if not schemas or len(schemas) > 20 or any(not isinstance(x, str) or not x or len(x) > 256 for x in schemas):
        raise InputError('Invalid schema scope')
    names = set(schemas)
    found: list[Finding] = []
    def add(rule, sev, obj, principal, detail):
        found.append(Finding(rule, sev, obj, principal, detail))
    for role in data['roles']:
        if role['bypassrls'] or role['superuser']:
            add('ROLE_BYPASS_RLS','critical','role:'+role['name'],role['name'],
                'A role intended for API use has bypass RLS or superuser privileges.')
    for rel in data['relations']:
        if rel['schema'] not in names: continue
        obj = f"{rel['schema']}.{rel['name']}"
        is_table = rel['kind'] in ('r','p')
        if is_table and rel['policies'] and not rel['rls']:
            add('POLICY_RLS_DISABLED','high',obj,'-',
                'Policies are defined but RLS is disabled; policies are not applied.')
        for role in ('anon','authenticated'):
            access = rel['grants'][role]
            methods = tuple(op for op in ('select','insert','update','delete') if access[op])
            if not (access['usage'] and methods):continue
            if is_table and not rel['rls']:
                add('EXPOSED_TABLE_NO_RLS','critical' if role=='anon' else 'high',obj,role,
                    'Effective table and schema privileges exist with RLS disabled.')
            if rel['kind']=='v' and not rel['security_invoker']:
                add('VIEW_OWNER_CONTEXT','high',obj,role,
                    'Callable view runs with owner privileges by default; inspect underlying policies.')
            if rel['kind']=='m' and access['select']:
                add('EXPOSED_MATERIALIZED_VIEW','medium',obj,role,
                    'Materialized-view data is exposed by an effective SELECT grant.')
            if is_table and rel['rls'] and not rel['policies']:
                add('RLS_WITHOUT_POLICIES','low',obj,role,
                    'RLS enabled without policies; likely denies normal access (availability review).')
            if is_table and rel['rls']:
                for policy in rel['policies']:
                    roles=set(policy['roles'])
                    if role not in roles and 'public' not in roles:continue
                    if not policy['permissive']:continue
                    if not (policy['cmd']=='*' or
                            policy['cmd']=='r' and 'select' in methods or
                            policy['cmd']=='a' and 'insert' in methods or
                            policy['cmd']=='w' and 'update' in methods or
                            policy['cmd']=='d' and 'delete' in methods):continue
                    if (policy['using_true'] and (policy['cmd'] in ('*','r','w','d')) or
                        policy['check_true'] and (policy['cmd'] in ('*','a','w'))):
                        add('BROAD_PERMISSIVE_POLICY','medium',obj,role,
                            'At least one permissive policy has a literal-true expression; assess all policies and intended access.')
    for f in data['functions']:
        if f['schema'] not in names or not f['security_definer']:continue
        obj = f"{f['schema']}.{f['name']}({f['identity_args']})"
        if not f['search_path_set']:
            add('DEFINER_MUTABLE_SEARCH_PATH','high',obj,'-',
                'SECURITY DEFINER function has no explicit per-function search_path.')
        for role in ('anon','authenticated'):
            if f['grants'][role]:
                add('DEFINER_CALLABLE_BY_API_ROLE','high' if role=='anon' else 'medium',obj,role,
                    'SECURITY DEFINER function is executable through an API role.')
    # Canonical deterministic rule ordering, without duplicate key collisions.
    dedup = {}
    for f in found: dedup[f.key] = f
    return sorted(dedup.values(),key=lambda x:(-SEVERITIES[x.severity],x.object,x.rule,x.principal))


def posture(data: dict, schemas=('public',)) -> dict:
    items = analyze(data, schemas)
    counts = {sev: sum(x.severity==sev for x in items) for sev in SEVERITIES}
    return {'schemaVersion':1, 'scope':list(schemas), 'findings':[x.as_dict() for x in items],
            'counts':counts,'total':len(items),'note':'Catalog heuristics only. No database row access or proof of exploitability.'}


def changes(before: dict, after: dict, schemas=('public',)) -> dict:
    old = {x.key:x for x in analyze(before,schemas)}
    new = {x.key:x for x in analyze(after,schemas)}
    added = [new[k].as_dict() for k in sorted(new.keys()-old.keys())]
    resolved = [old[k].as_dict() for k in sorted(old.keys()-new.keys())]
    changed = [{'before':old[k].as_dict(),'after':new[k].as_dict()} for k in sorted(old.keys() & new.keys())
               if (old[k].severity,old[k].detail)!=(new[k].severity,new[k].detail)]
    return {'schemaVersion':1,'scope':list(schemas),'new':added,'resolved':resolved,'changed':changed,
            'summary':{'new':len(added),'resolved':len(resolved),'changed':len(changed)},
            'note':'Comparison assumes both snapshots come from reviewed, independently protected sources.'}


def sarif(report: dict) -> dict:
    findings = report.get('findings',report.get('new',[]))
    rules = sorted(set(item['rule'] for item in findings))
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{'name':'PG Security Drift','version':'0.1.0',
                                      'rules':[{'id':r,'shortDescription':{'text':r}} for r in rules]}},
                     'results':[{'ruleId':f['rule'],
                                 'level':'error' if f['severity'] in ('critical','high') else 'warning',
                                 'message':{'text':f['detail']},
                                 'locations':[{'physicalLocation':{'artifactLocation':
                                     {'uri':'postgresql-catalog/'+quote(f['object'],safe='')}}}]} for f in findings]}]}


def text_report(report: dict) -> str:
    findings=report.get('findings',report.get('new',[]))
    prefix='NEW ' if 'new' in report else ''
    lines=['PG Security Drift — read-only catalog security review',
           f'Scope: {", ".join(report["scope"])}', f'{prefix}Findings: {len(findings)}']
    for f in findings:
        # Use JSON escaped names; do not emit raw control strings on terminals.
        import json
        lines.append(f'[{f["severity"].upper()}] {f["rule"]} {json.dumps(f["object"], ensure_ascii=True)} role={f["principal"]}')
    lines.append('Findings are heuristics; verify access in an isolated authorized test environment.')
    return '\n'.join(lines)
