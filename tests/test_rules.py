import unittest
from pg_security_drift.checks import analyze,posture,changes,sarif,text_report
from tests.helpers import relation,policy,function,snapshot

class RulesTests(unittest.TestCase):
    def ids(self, db, schemas=('public',)):
        return [f.rule for f in analyze(db,schemas)]

    def test_clean_table_no_findings(self):self.assertEqual(self.ids(snapshot()),[])
    def test_disabled_rls_anon_is_critical(self):
        f=analyze(snapshot(relations=[relation(rls=False,anon=True)]))
        self.assertEqual(len(f),1);self.assertEqual(f[0].severity,'critical')
        self.assertEqual(f[0].rule,'EXPOSED_TABLE_NO_RLS')
    def test_disabled_rls_authenticated_is_high(self):
        f=analyze(snapshot(relations=[relation(rls=False,authenticated=True)]))
        self.assertEqual(f[0].severity,'high')
    def test_disabled_rls_no_effective_grant_is_not_reported(self):
        self.assertEqual(self.ids(snapshot(relations=[relation(rls=False)])),[])
    def test_no_schema_usage_no_exposure(self):
        x=relation(rls=False,anon=True);x['grants']['anon']['usage']=False
        self.assertEqual(self.ids(snapshot(relations=[x])),[])
    def test_policies_defined_but_rls_disabled(self):
        self.assertIn('POLICY_RLS_DISABLED',self.ids(snapshot(relations=[relation(rls=False,policies=[policy()])])))
    def test_rls_without_policies_is_availability_only(self):
        f=analyze(snapshot(relations=[relation(anon=True)]))
        self.assertEqual([x.severity for x in f],['low'])
    def test_broad_permissive_public_policy(self):
        r=relation(rls=True,anon=True,authenticated=True,policies=[policy(roles=['public'],using_true=True)])
        f=analyze(snapshot(relations=[r]));self.assertEqual(len(f),2)
        self.assertTrue(all(x.rule=='BROAD_PERMISSIVE_POLICY' for x in f))
    def test_restrictive_true_policy_does_not_trigger(self):
        self.assertNotIn('BROAD_PERMISSIVE_POLICY',self.ids(snapshot(relations=[relation(rls=True,anon=True,policies=[policy(roles=['anon'],using_true=True,permissive=False)])])))
    def test_unrelated_policy_role_not_reported(self):
        self.assertNotIn('BROAD_PERMISSIVE_POLICY',self.ids(snapshot(relations=[relation(rls=True,anon=True,policies=[policy(roles=['authenticated'],using_true=True)])])))
    def test_insert_check_true_can_trigger(self):
        r=relation(anon=True,policies=[policy(roles=['anon'],cmd='a',check_true=True)])
        r['grants']['anon']['insert']=True
        self.assertIn('BROAD_PERMISSIVE_POLICY',self.ids(snapshot(relations=[r])))
    def test_owner_context_view(self):
        x=relation(kind='v',anon=True,security_invoker=False)
        self.assertIn('VIEW_OWNER_CONTEXT',self.ids(snapshot(relations=[x])))
    def test_invoker_view_not_flagged(self):
        x=relation(kind='v',anon=True,security_invoker=True)
        self.assertEqual(self.ids(snapshot(relations=[x])),[])
    def test_exposed_materialized_view(self):
        x=relation(kind='m',anon=True)
        self.assertIn('EXPOSED_MATERIALIZED_VIEW',self.ids(snapshot(relations=[x])))
    def test_definer_search_path_not_set(self):
        f=analyze(snapshot(functions=[function(search_path=False)]))
        self.assertEqual(f[0].rule,'DEFINER_MUTABLE_SEARCH_PATH')
    def test_definer_callable_via_anon(self):
        f=analyze(snapshot(functions=[function(anon=True)]))
        self.assertEqual(f[0].severity,'high')
    def test_definer_callable_via_authenticated(self):
        f=analyze(snapshot(functions=[function(authenticated=True)]))
        self.assertEqual(f[0].severity,'medium')
    def test_normal_function_exposed_is_not_flagged(self):
        self.assertEqual(self.ids(snapshot(functions=[function(definer=False,anon=True)])),[])
    def test_role_bypassrls(self):
        result=self.ids(snapshot(roles=[dict(name='anon',bypassrls=True,superuser=False)]))
        self.assertIn('ROLE_BYPASS_RLS',result)
    def test_role_superuser(self):
        result=self.ids(snapshot(roles=[dict(name='authenticated',bypassrls=False,superuser=True)]))
        self.assertIn('ROLE_BYPASS_RLS',result)
    def test_only_explicit_schema(self):
        s=snapshot(relations=[relation(schema='private',anon=True,rls=False)])
        self.assertEqual(self.ids(s),[])
        self.assertIn('EXPOSED_TABLE_NO_RLS',self.ids(s,('private',)))
    def test_posture_counts_are_consistent(self):
        a=posture(snapshot(relations=[relation(rls=False,anon=True)]))
        self.assertEqual(a['total'],1);self.assertEqual(a['counts']['critical'],1)
    def test_finding_ids_stable_and_deterministic(self):
        a=snapshot(relations=[relation(name='b',rls=False,anon=True),relation(name='a',rls=False,anon=True)])
        self.assertEqual(analyze(a),analyze(a))
        self.assertEqual(analyze(a)[0].object,'public.a')
    def test_baseline_new_and_resolved(self):
        old=snapshot(relations=[relation(rls=True,policies=[policy()])])
        new=snapshot(relations=[relation(rls=False,anon=True)])
        ch=changes(old,new)
        self.assertEqual(ch['summary']['new'],1)
        self.assertEqual(ch['new'][0]['rule'],'EXPOSED_TABLE_NO_RLS')
    def test_baseline_unchanged(self):
        db=snapshot()
        self.assertEqual(changes(db,db)['summary'],{'new':0,'resolved':0,'changed':0})
    def test_resolved_finding(self):
        bad=snapshot(relations=[relation(rls=False,anon=True)])
        good=snapshot(relations=[relation(rls=True,anon=False)])
        ch=changes(bad,good)
        self.assertEqual(ch['summary']['resolved'],1)
    def test_sarif_avoids_sql_expression_bodies(self):
        rep=posture(snapshot(relations=[relation(rls=False,anon=True)]))
        data=sarif(rep)
        self.assertEqual(data['version'],'2.1.0')
        self.assertEqual(data['runs'][0]['results'][0]['ruleId'],'EXPOSED_TABLE_NO_RLS')
    def test_text_output(self):
        t=text_report(posture(snapshot(relations=[relation(rls=False,anon=True)])))
        self.assertIn('CRITICAL',t)
    def test_two_roles_different_severity(self):
        rel=relation(rls=False,anon=True,authenticated=True)
        f=analyze(snapshot(relations=[rel]))
        self.assertEqual([x.severity for x in f],['critical','high'])

if __name__=='__main__':unittest.main()
