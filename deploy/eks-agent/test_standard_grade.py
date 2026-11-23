import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from lifecycle import Failure, Journal
from runner import Runner, HOSTNAME


class StandardGradeTests(unittest.TestCase):
    def test_same_pod_task_failure_is_saved_and_graded_before_stop(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, 'a'*16, create=True)
            r = Runner(j)
            events = []
            raw = '{"workload":"reported_failed"}'
            r.wait_workload = lambda *args: events.append(('workload', args)) or raw
            r.verify_task_pod = lambda *args: events.append(('verify', args))
            r.verify_frozen_workload_contract = Mock()
            def grade(*args):
                self.assertEqual(j.data['guest'], raw)
                events.append(('grade', args))
            r.standard_grade = grade
            r.delete_job = Mock()
            self.assertEqual(r.collect_task_and_grade('model-task-original', 'job-uid', 'f'*64), raw)
            self.assertEqual([e[0] for e in events], ['workload','verify','grade'])
            self.assertEqual(events[-1][1], ('model-task-original','job-uid','f'*64))
            r.delete_job.assert_not_called()
            j.close()

    def test_bridge_failure_is_not_retried_and_does_not_hide_workload(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r=Runner(j)
            r.wait_workload=Mock(return_value='reported workload')
            r.verify_task_pod=Mock();r.verify_frozen_workload_contract=Mock()
            r.standard_grade=Mock(side_effect=Failure('command_failed'))
            with self.assertRaises(Failure):r.collect_task_and_grade('model-task-one','original-job','b'*64)
            self.assertEqual(j.data['guest'],'reported workload')
            self.assertNotIn('standard_assessment',j.data)
            r.standard_grade.assert_called_once()
            j.close()

    def test_standard_report_preserves_grade_and_original_binding(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r=Runner(j)
            r.kubeconfig=j.folder/'eks.kubeconfig';r.cluster='sandprobe-12345678';r.image='recorded-image'
            j.data.update(context={'pod_uid':'original-uid'},task_container_id='original-container',workload_contract={'frozen':'before-release'})
            r.delegated_state=lambda:{'endpoint':'https://recorded-endpoint'}
            grade={'letter':'F','valid':True,'complete':False,'unknown':['EGR-1']}
            report={'schema':'sandprobe/1','run':{'box':{'provider_id':'original-uid'},'provider':'aws-nitro','id':'standard-run'},'grade':grade}
            r.ops.call=Mock(return_value=json.dumps({'report':report,'html':'<html>standard</html>','input':{},'evidence':{},'observations':'{}'}).encode())
            r.upload_hosts=[HOSTNAME]
            j.data['endpoint_resolution']={'ipv4':['1.1.1.1','8.8.8.8']}
            r.standard_grade('model-task-original','original-job','b'*64)
            args,kw=r.ops.call.call_args
            self.assertEqual(json.loads(kw['payload'])['upload_addresses'],{HOSTNAME:'1.1.1.1'})
            binding=json.loads(kw['payload'])['pod']
            self.assertEqual(binding['uid'],'original-uid');self.assertEqual(binding['job_uid'],'original-job')
            self.assertEqual(binding['namespace'],r.ns);self.assertEqual(binding['container_id'],'original-container')
            self.assertEqual(j.data['standard_assessment']['grade'],grade)
            self.assertEqual(json.loads((j.folder/'legacy-standard-report.json').read_text())['grade'],grade)
            self.assertEqual((j.folder/'legacy-standard-report.json').stat().st_mode & 0o777,0o600)
            j.close()

    def test_canary_domain_and_state_are_per_run_and_cleanup_is_independent(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r=Runner(j)
            r.ops=Mock();r.canary('status',1200)
            env=r.ops.call.call_args.kwargs['env']
            self.assertEqual(env['DOMAIN'],'agent-'+r.run_id+'.probe.ac0.dev')
            self.assertEqual(env['STATE'],str(j.folder/'canary.state'));self.assertEqual(env['DURABLE_STATE'],'1')
            self.assertEqual(env['SANDPROBE_CANARY_NAME'],'sandprobe-canary') # legacy cleanup compatibility
            j.data['resources']['canary']={'status':'creating'}
            (j.folder/'canary.state').write_text('did=original')
            r.account=Mock();r.canary=Mock(side_effect=Failure('command_failed'))
            self.assertFalse(r.cleanup())
            self.assertIn('canary_cleanup_unconfirmed',j.data['cleanup_failures'])
            r.canary.assert_called_once_with('down',timeout=900)
            j.close()

    def test_canary_is_retained_if_probe_cluster_stop_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r=Runner(j)
            j.data['resources'].update(canary={'status':'created'},cluster={'status':'creating'})
            (j.folder/'canary.state').write_text('did=original')
            r.account=Mock();r.canary=Mock()
            self.assertFalse(r.cleanup());r.canary.assert_not_called()
            self.assertIn('canary_cleanup_unconfirmed',j.data['cleanup_failures'])
            j.close()

    def test_standard_grade_gets_the_selected_profile(self):
        # The run's --profile, not the environment's default, reaches the grade's canary-profile check.
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r=Runner(j,profile='second-profile')
            r.kubeconfig=j.folder/'eks.kubeconfig';r.cluster='sandprobe-12345678';r.image='recorded-image'
            j.data.update(context={'pod_uid':'original-uid'},task_container_id='original-container',workload_contract={'frozen':'before-release'})
            r.delegated_state=lambda:{'endpoint':'https://recorded-endpoint'}
            report={'schema':'sandprobe/1','run':{'box':{'provider_id':'original-uid'},'provider':'aws-nitro','id':'standard-run'},'grade':{'letter':'F','valid':True,'complete':False,'unknown':[]}}
            r.ops.call=Mock(return_value=json.dumps({'report':report,'html':'<html>standard</html>','input':{},'evidence':{},'observations':'{}'}).encode())
            try:
                r.standard_grade('model-task-original','original-job','b'*64)
            except Failure:
                pass  # only the call's environment matters here
            env=r.ops.call.call_args.kwargs['env']
            self.assertEqual(env['SANDPROBE_AWS_PROFILE'],'second-profile')
            self.assertEqual(env['SANDPROBE_AWS_ACCOUNT'],os.environ['SANDPROBE_AWS_ACCOUNT'])
            j.close()

    def test_profile_given_only_by_flag_reaches_every_child(self):
        # With SANDPROBE_AWS_PROFILE unset in the environment, the run's --profile is what every child gets.
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ):
            os.environ.pop('SANDPROBE_AWS_PROFILE', None)
            j=Journal(root,'a'*16,create=True);r=Runner(j,profile='only-flag')
            self.assertEqual(r.env['SANDPROBE_AWS_PROFILE'],'only-flag')
            self.assertEqual(r.env['SANDPROBE_AWS_ACCOUNT'],os.environ['SANDPROBE_AWS_ACCOUNT'])
            j.close()
