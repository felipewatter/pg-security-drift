"""Read-only PostgreSQL catalog ingestion through psql, without SQL interpolation."""
from __future__ import annotations
from importlib.resources import files
from pathlib import Path
import json
import os
import subprocess
import tempfile

from .errors import CaptureError
from .model import MAX_SNAPSHOT_BYTES, validate_snapshot

COMMAND_TIMEOUT_SECONDS = 30


def capture(psql_binary='psql', timeout=COMMAND_TIMEOUT_SECONDS) -> dict:
    if not isinstance(psql_binary,str) or not psql_binary or '\x00' in psql_binary:
        raise CaptureError('Invalid psql executable')
    if type(timeout) is not int or not (1 <= timeout <= 90):
        raise CaptureError('Invalid catalog timeout')
    query = files('pg_security_drift').joinpath('sql/catalog.sql')
    env = os.environ.copy()
    # psql/libpq connection variables remain operator-controlled; no DSNs in argv or output.
    env['PGCLIENTENCODING'] = 'UTF8'
    env['PGAPPNAME'] = 'pg-security-drift'
    env['PGOPTIONS'] = '-c default_transaction_read_only=on -c statement_timeout=20000 -c lock_timeout=2000'
    with tempfile.TemporaryDirectory(prefix='pg-security-drift-') as tmp:
        output=Path(tmp)/'catalog.json'
        try:
            with output.open('wb') as stream:
                subprocess.run([psql_binary,'-X','-w','-q','-A','-t',
                                '-v','ON_ERROR_STOP=1','-f',str(query)],
                               env=env,stdin=subprocess.DEVNULL,stdout=stream,
                               stderr=subprocess.DEVNULL,check=True,timeout=timeout)
            if output.stat().st_size > MAX_SNAPSHOT_BYTES:
                raise CaptureError('Catalog export exceeded size budget')
            raw=output.read_text(encoding='utf-8').strip()
            if not raw or '\n' in raw:
                raise CaptureError('Unexpected psql catalog output')
            def pairs(v):
                obj={}
                for k, value in v:
                    if k in obj: raise CaptureError('Duplicate catalog response key')
                    obj[k]=value
                return obj
            result=json.loads(raw,object_pairs_hook=pairs)
            return validate_snapshot(result)
        except (subprocess.SubprocessError,FileNotFoundError,PermissionError,
                OSError,ValueError,UnicodeError) as e:
            raise CaptureError('Unable to safely capture complete PostgreSQL metadata') from e
