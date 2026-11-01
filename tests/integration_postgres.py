"""Execute against ephemeral PostgreSQL only, never automatically against user DBs."""
import os
import unittest
from pg_security_drift.capture import capture
from pg_security_drift.checks import analyze

@unittest.skipUnless(os.getenv('PG_SECURITY_DRIFT_INTEGRATION') == '1',
                     'Live database tests are opt-in and require disposable fixture database')
class LiveCatalogTests(unittest.TestCase):
    def test_read_only_query_actual_catalogs(self):
        data=capture()
        names={(r['schema'],r['name']) for r in data['relations']}
        self.assertIn(('public','pg_drift_example'),names)
        self.assertIn(('public','pg_drift_example_view'),names)
        self.assertIn(('public','pg_drift_definer'),{(f['schema'],f['name']) for f in data['functions']})
        rules={f.rule for f in analyze(data)}
        for expected in ('EXPOSED_TABLE_NO_RLS','VIEW_OWNER_CONTEXT',
                         'DEFINER_MUTABLE_SEARCH_PATH','DEFINER_CALLABLE_BY_API_ROLE'):
            self.assertIn(expected,rules)

if __name__=='__main__':unittest.main()
