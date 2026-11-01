"""Bounded, strict versioned metadata snapshots (never row or function body data)."""
from __future__ import annotations
from pathlib import Path
import json
import os
import stat

from .errors import InputError

MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 5000
VALID_KINDS = {'r', 'p', 'v', 'm', 'f'}
VALID_COMMANDS = {'r', 'a', 'w', 'd', '*'}

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError('Duplicate JSON property')
        result[key] = value
    return result

def _name(value, max_length=512):
    if (not isinstance(value, str) or not value or len(value) > max_length
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise InputError('Invalid catalog identifier')
    return value

def _keys(data, required, optional=()):
    if not isinstance(data, dict) or not set(required).issubset(data) or set(data) - (set(required) | set(optional)):
        raise InputError('Unexpected or missing catalog fields')

def _boolean(v):
    if type(v) is not bool:
        raise InputError('Expected a catalog boolean')

def _list(v, limit=MAX_ITEMS):
    if not isinstance(v, list) or len(v) > limit:
        raise InputError('Invalid or oversized catalog list')

def validate_snapshot(data):
    _keys(data, ('schemaVersion', 'source', 'relations', 'functions', 'roles', 'limits'))
    if data['schemaVersion'] != 1 or type(data['schemaVersion']) is not int or data['source'] != 'pg_catalog':
        raise InputError('Unsupported catalog schema version')
    _keys(data['limits'], ('relations', 'functions'))
    _list(data['relations']); _list(data['functions']); _list(data['roles'], 32)
    for name, limit in (('relations', len(data['relations'])), ('functions', len(data['functions']))):
        v = data['limits'][name]
        if type(v) is not int or v != limit or v > MAX_ITEMS:
            raise InputError('Catalog limit reached or metadata incomplete')
    relations = set()
    for rel in data['relations']:
        _keys(rel, ('schema', 'name', 'kind', 'rls', 'force_rls', 'security_invoker', 'grants', 'policies'))
        key = (_name(rel['schema']), _name(rel['name']))
        if key in relations or rel['kind'] not in VALID_KINDS:
            raise InputError('Duplicate relation or unexpected kind')
        relations.add(key)
        for field in ('rls', 'force_rls', 'security_invoker'):
            _boolean(rel[field])
        _keys(rel['grants'], ('anon','authenticated'))
        for access in rel['grants'].values():
            _keys(access, ('usage','select','insert','update','delete'))
            for v in access.values(): _boolean(v)
        _list(rel['policies'], 1000)
        seen = set()
        for policy in rel['policies']:
            _keys(policy, ('name','cmd','permissive','roles','using_true','check_true'))
            pname = _name(policy['name'])
            if pname in seen or policy['cmd'] not in VALID_COMMANDS:
                raise InputError('Invalid or duplicate policy')
            seen.add(pname)
            _boolean(policy['permissive']); _boolean(policy['using_true']); _boolean(policy['check_true'])
            _list(policy['roles'], 64)
            if len(policy['roles']) != len(set(_name(x) for x in policy['roles'])):
                raise InputError('Duplicate policy roles')
    functions = set()
    for fun in data['functions']:
        _keys(fun, ('schema','name','identity_args','security_definer','search_path_set','grants'))
        key = (_name(fun['schema']),_name(fun['name']), fun['identity_args'])
        _name(fun['identity_args'] if fun['identity_args'] else '(empty)', 4096)
        if key in functions:
            raise InputError('Duplicate function')
        functions.add(key)
        _boolean(fun['security_definer']); _boolean(fun['search_path_set'])
        _keys(fun['grants'], ('anon','authenticated'))
        for v in fun['grants'].values(): _boolean(v)
    seen_roles = set()
    for role in data['roles']:
        _keys(role, ('name', 'bypassrls', 'superuser'))
        name = _name(role['name'])
        if name not in ('anon', 'authenticated') or name in seen_roles:
            raise InputError('Unexpected database role')
        seen_roles.add(name)
        _boolean(role['bypassrls']); _boolean(role['superuser'])
    return data

def read_snapshot(filename: str | Path):
    """Reject symbolic links and duplicates before auditing user-supplied JSON."""
    p = Path(filename)
    try:
        before = p.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SNAPSHOT_BYTES:
            raise InputError('Expected bounded regular snapshot file')
        flags = os.O_RDONLY | (getattr(os, 'O_NOFOLLOW', 0) if os.name != 'nt' else 0)
        fd = os.open(p, flags)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev,opened.st_ino) != (before.st_dev,before.st_ino):
                raise InputError('Snapshot changed during opening')
            raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) > MAX_SNAPSHOT_BYTES or opened.st_size != after.st_size or
                opened.st_mtime_ns != after.st_mtime_ns):
            raise InputError('Snapshot changed or exceeded size limit')
        data = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_unique)
        return validate_snapshot(data)
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise InputError('Could not read complete snapshot') from exc

def canonical(data):
    validate_snapshot(data)
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',',':'))

def write_new(filename: str | Path, payload: str):
    if len(payload.encode('utf-8')) > MAX_SNAPSHOT_BYTES:
        raise InputError('Report exceeds output limit')
    target = Path(filename)
    created = False
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as output:
            output.write(payload + '\n')
    except (OSError, UnicodeError) as exc:
        if created:
            target.unlink(missing_ok=True)
        raise InputError('Could not exclusively create output file') from exc
