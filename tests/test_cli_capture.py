import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout,redirect_stderr
from pg_security_drift import capture as capture_module
from pg_security_drift.cli import main,_severity_fails
from pg_security_drift.errors import CaptureError
from pg_security_drift.model import canonical
from pg_security_drift.checks import posture,changes
from tests.helpers import snapshot,relation

class CaptureTests(unittest.TestCase):
    def test_static_sql_is_read_only(self):
        from importlib.resources import files
        sql=files('pg_security_drift').joinpath('sql/catalog.sql').read_text()
        self.assertIn('READ ONLY',sql)
        self.assertNotIn('INSERT INTO ',sql.upper())
        self.assertNotIn('UPDATE ',sql.upper())
        self.assertNotIn('DELETE FROM ',sql.upper())
        self.assertNotIn('SELECT * FROM public.',sql)
        self.assertIn('pg_catalog.pg_class',sql)
    def test_capture_executes_psql_noninteractive_without_secrets_in_argv(self):
        db=snapshot()
        def fake_run(args,**kwargs):
            self.assertIn('-w',args);self.assertIn('ON_ERROR_STOP=1',args)
            self.assertIn('READ ONLY',__import__('pathlib').Path(args[-1]).read_text(encoding='utf-8'))
            self.assertEqual(kwargs['stderr'],-3)  # subprocess.DEVNULL
            self.assertIn('default_transaction_read_only=on',kwargs['env']['PGOPTIONS'])
            self.assertNotIn('PGPASSWORD',str(args))
            kwargs['stdout'].write((canonical(db)+'\n').encode())
        with patch('subprocess.run',side_effect=fake_run):
            self.assertEqual(capture_module.capture(),db)
    def test_psql_failure_never_becomes_empty_snapshot(self):
        import subprocess
        with patch('subprocess.run',side_effect=subprocess.CalledProcessError(1,'psql')):
            with self.assertRaises(CaptureError):capture_module.capture()
    def test_psql_timeout_fail_closed(self):
        import subprocess
        with patch('subprocess.run',side_effect=subprocess.TimeoutExpired('psql',30)):
            with self.assertRaises(CaptureError):capture_module.capture()
    def test_missing_psql_fail_closed(self):
        with patch('subprocess.run',side_effect=FileNotFoundError()):
            with self.assertRaises(CaptureError):capture_module.capture()
    def test_psql_output_many_lines_fails(self):
        def wrong(args,**kwargs):kwargs['stdout'].write(b'{}\n{}\n')
        with patch('subprocess.run',side_effect=wrong):
            with self.assertRaises(CaptureError):capture_module.capture()
    def test_cli_audit_threshold_and_no_secret_echo(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'base.json';p.write_text(canonical(snapshot(relations=[relation(rls=False,anon=True)])))
            with redirect_stdout(io.StringIO()) as out:
                status=main(['audit','--input',str(p),'--format','json'])
            self.assertEqual(status,1);self.assertEqual(json.loads(out.getvalue())['total'],1)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['audit','--input',str(p),'--fail-on','none']),0)
    def test_cli_comparison_new_finding(self):
        with tempfile.TemporaryDirectory() as d:
            old=Path(d)/'base.json';new=Path(d)/'cur.json'
            old.write_text(canonical(snapshot()))
            new.write_text(canonical(snapshot(relations=[relation(rls=False,anon=True)])))
            with redirect_stdout(io.StringIO()) as out:
                status=main(['compare','--baseline',str(old),'--current',str(new),'--format','json'])
            self.assertEqual(status,1)
            self.assertEqual(json.loads(out.getvalue())['summary']['new'],1)
    def test_cli_compare_ignores_existing_findings(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'same.json';p.write_text(canonical(snapshot(relations=[relation(rls=False,anon=True)])))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['compare','--baseline',str(p),'--current',str(p)]),0)
    def test_cli_failure_has_no_path_or_secret(self):
        with redirect_stderr(io.StringIO()) as err,redirect_stdout(io.StringIO()) as out:
            code=main(['audit','--input','/path/SECRET_PASSWORD'])
        self.assertEqual(code,2)
        self.assertNotIn('SECRET_PASSWORD',err.getvalue());self.assertEqual(out.getvalue(),'')
    def test_cli_snapshot_exclusive(self):
        db=snapshot()
        with tempfile.TemporaryDirectory() as d,patch('pg_security_drift.cli.capture',return_value=db):
            out=Path(d)/'baseline.json'
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(['snapshot','--output',str(out)]),0)
                self.assertEqual(main(['snapshot','--output',str(out)]),2)
    def test_cli_output_sarif(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'snapshot.json';p.write_text(canonical(snapshot()))
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(['audit','--input',str(p),'--format','sarif']),0)
            self.assertEqual(json.loads(out.getvalue())['version'],'2.1.0')
    def test_severity_fails(self):
        data=posture(snapshot(relations=[relation(rls=False,anon=True)]))
        self.assertFalse(_severity_fails(data,'none'))
        self.assertTrue(_severity_fails(data,'critical'))

if __name__=='__main__':unittest.main()
