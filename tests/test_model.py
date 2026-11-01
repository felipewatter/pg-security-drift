import json
import tempfile
import unittest
from pathlib import Path
from pg_security_drift.model import validate_snapshot,read_snapshot,canonical,write_new
from pg_security_drift.errors import InputError
from tests.helpers import relation,policy,function,snapshot

class SnapshotTests(unittest.TestCase):
    def test_valid_basic_snapshot(self):self.assertEqual(validate_snapshot(snapshot())['schemaVersion'],1)
    def test_valid_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'meta.json';write_new(path,canonical(snapshot()))
            self.assertEqual(read_snapshot(path),snapshot())
    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'dup.json';p.write_text('{"schemaVersion":1,"schemaVersion":2}')
            with self.assertRaises(InputError):read_snapshot(p)
    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'base.json';p.write_text(canonical(snapshot()))
            s=Path(d)/'link.json'
            try:s.symlink_to(p)
            except OSError:return
            with self.assertRaises(InputError):read_snapshot(s)
    def test_oversized_input_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'big.json';p.write_bytes(b'A'*(8*1024*1024+1))
            with self.assertRaises(InputError):read_snapshot(p)
    def test_invalid_json_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'broken.json';p.write_text('{bad json')
            with self.assertRaises(InputError):read_snapshot(p)
    def test_exclusive_write(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'out.json';write_new(p,'{}')
            with self.assertRaises(InputError):write_new(p,'{}')
    def test_unsupported_schema_version(self):
        x=snapshot();x['schemaVersion']=2
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_incomplete_snapshot_fails(self):
        x=snapshot();x['limits']['relations']=5001
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_missing_field_fails(self):
        x=snapshot();del x['relations']
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_unknown_field_fails(self):
        x=snapshot();x['secrets']='do not include'
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_duplicate_relation_fails(self):
        x=snapshot(relations=[relation(),relation()])
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_invalid_grant_type_fails(self):
        x=snapshot();x['relations'][0]['grants']['anon']['select']='false'
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_duplicate_policy_names_fail(self):
        x=snapshot(relations=[relation(policies=[policy(),policy()])])
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_duplicate_function_fails(self):
        x=snapshot(functions=[function(),function()])
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_control_chars_in_identifiers_fail(self):
        x=snapshot();x['relations'][0]['name']='\x1b[31m'
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_disallow_additional_policy_source_code(self):
        x=snapshot(relations=[relation(policies=[policy()])]);x['relations'][0]['policies'][0]['source']='SECRET SQL'
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_validate_role_names(self):
        x=snapshot(roles=[dict(name='postgres',bypassrls=True,superuser=True)])
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_invalid_limit_bool(self):
        x=snapshot();x['limits']['relations']=True
        with self.assertRaises(InputError):validate_snapshot(x)
    def test_invalid_policy_cmd(self):
        x=snapshot(relations=[relation(policies=[policy(cmd='bad')])])
        with self.assertRaises(InputError):validate_snapshot(x)

if __name__=='__main__':unittest.main()
