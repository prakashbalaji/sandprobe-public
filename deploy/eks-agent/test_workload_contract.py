import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import hashlib
import json
import tempfile
import unittest
from unittest.mock import Mock

from lifecycle import Failure, Journal
from render_profile import render
from runner import Runner, ACCOUNT, encoded

class WorkloadContractTests(unittest.TestCase):
    def fixture(self,j):
        r=Runner(j);r.image=f'{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com/{r.name}@sha256:'+('b'*64)
        j.data.update(model='mistral.ministral-3-3b-instruct',endpoint_resolution={'ipv4':['52.94.0.1']},dns_address='172.20.0.10')
        j.data['resources']['role']={'role_id':'original-role-id'}
        expected=render(r.run_id,r.image,ACCOUNT,j.data['model'],['52.94.0.1'],'172.20.0.10')['iam_policy']
        return r,expected

    def test_exact_role_and_only_scoped_inline_policy_are_required(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r,policy=self.fixture(j)
            r.aws=Mock(side_effect=['original-role-id',[r.name],[],policy])
            self.assertEqual(r.identity_configuration_hash(),hashlib.sha256(encoded(policy)).hexdigest())
            for answers in [['different-role-id'],['original-role-id',[r.name,'extra']],
                            ['original-role-id',[r.name],[{'PolicyArn':'unexpected'}]],
                            ['original-role-id',[r.name],[],{'Statement':[{'Action':'*','Resource':'*'}]}]]:
                r.aws=Mock(side_effect=answers)
                with self.assertRaises(Failure):r.identity_configuration_hash()
            j.close()

    def test_contract_is_durable_immutable_and_token_rotation_is_not_allowlisted(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r=Runner(j)
            original={'token_canonical':'exact-alias','token_inode':1,'identity_policy_sha256':'fixed'}
            original.update(box_id='original-pod',config_sha256='c'*64,private_container_verified=True)
            r.image='repo/image@sha256:'+'b'*64
            j.data['runtime_image_id']='containerd://sha256:'+'b'*64
            r.workload_contract=Mock(return_value=original)
            r.freeze_workload_contract('original-pod')
            self.assertEqual(json.loads(j.path.read_text())['workload_contract'],original)
            evidence=json.loads((j.folder/'configuration-evidence.json').read_text())
            self.assertEqual(evidence['box_id'],original['box_id'])
            self.assertEqual(evidence['config_sha256'],original['config_sha256'])
            self.assertEqual((j.folder/'configuration-evidence.json').stat().st_mode&0o777,0o600)
            original['token_inode']=2
            self.assertEqual(j.data['workload_contract']['token_inode'],1)
            with self.assertRaisesRegex(Failure,'pre_workload_contract_changed'):r.verify_frozen_workload_contract('original-pod')
            self.assertEqual(j.data['workload_contract']['token_inode'],1)
            with self.assertRaisesRegex(Failure,'already_frozen'):r.freeze_workload_contract('original-pod')
            j.close()

    def test_finalize_uses_bound_raw_data_and_final_receipts_not_saved_grade(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,'a'*16,create=True);r=Runner(j)
            j.data.update(context={'pod_uid':'original-pod','receiver_uid':'receiver-uid'},nonces=['1'*48,'2'*48,'3'*48],
                          receipts={'receiver_uid':'receiver-uid','nonces':['1'*48,'3'*48]})
            (j.folder/'standard-evidence.json').write_text(json.dumps({'report':{'manifest':{'BoxID':'original-pod','RunID':'original-run'},'grade':{'letter':'F'}},'observations':'original observations','evidence':{'Live':True}}))
            assessment={'schema':'sandprobe.workload-assessment/1','box_id':'original-pod','security_assurance':'not_established_against_active_guest_tampering','configuration_grade':'B','benchmark_requirements_met':True,'valid':True,'complete':True,'contract_bound':True,'profile':'networked-coding-v1','run_id':'original-run','workload':'reported_passed','input_verification':'retrospective_recomputation_unauthenticated_input'}
            r.ops.call=Mock(return_value=json.dumps({'assessment':assessment,'html':'<html>conditional</html>'}).encode())
            with self.assertRaisesRegex(Failure,'coverage_binding_mismatch'):r.finalize_workload_grade('reported_passed')
            coverage={'schema':'sandprobe.evidence-coverage/1','run_id':'original-run','valid':True,'unknown_controls':0}
            exposure={'schema':'sandprobe.workload-exposure/1','run_id':'original-run','box_id':'original-pod','input_verification':'proof_recomputation_unauthenticated_input','valid':True,'score':2,'of':6,'rows':[{'name':name,'green':i<2} for i,name in enumerate(['Secrets','Exfiltration','Containment','Privilege','Cloud access','Persistence'])]}
            r.ops.call=Mock(return_value=json.dumps({'assessment':assessment,'html':'<html>conditional</html>','evidence_coverage':coverage,'exposure_scorecard':exposure}).encode())
            self.assertEqual(r.finalize_workload_grade('reported_passed'),assessment)
            self.assertEqual(json.loads((j.folder/'exposure-scorecard.json').read_text()),exposure)
            for field,value in [('run_id','different-run'),('score',6),('valid',False),('rows',[]),('score',True)]:
                wrong=dict(exposure);wrong[field]=value
                r.ops.call=Mock(return_value=json.dumps({'assessment':assessment,'html':'fixture','evidence_coverage':coverage,'exposure_scorecard':wrong}).encode())
                with self.assertRaisesRegex(Failure,'exposure_binding_mismatch'):r.finalize_workload_grade('reported_passed')
            request=json.loads(r.ops.call.call_args.kwargs['payload'])
            self.assertNotIn('grade',request);self.assertEqual(request['observations'],'original observations')
            self.assertEqual(request['private_receiver']['received_nonces'],['1'*48,'3'*48])
            self.assertEqual(request['manifest']['BoxID'],'original-pod')
            self.assertEqual((j.folder/'workload-report.json').stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads((j.folder/'evidence-coverage.json').read_text()),coverage)
            self.assertIn('--include-coverage',r.ops.call.call_args.args[0])
            self.assertIn('conditional',(j.folder/'workload-report.html').read_text())
            j.close()
