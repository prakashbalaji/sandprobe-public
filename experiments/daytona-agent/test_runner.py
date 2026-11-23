import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import argparse
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys,time
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('daytona_runner',Path(__file__).with_name('run.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class RunnerTests(unittest.TestCase):
 def completed_run(self,storage_profile='ephemeral'):
  with tempfile.TemporaryDirectory() as d:
   home=Path(d);(home/'.config/sandprobe').mkdir(parents=True)
   helper=home/'cf';helper.write_text('fixture')
   key=home/'key';key.write_text('synthetic-not-a-secret');key.chmod(0o600)
   args=argparse.Namespace(cleanup_run='',model_python='/fixture/model-python',go='/fixture/go',sdk_python='/fixture/python',key_file=str(key),cf_helper=str(helper),dns_reference='fixture',storage_profile=storage_profile)
   args.model='mistral.ministral-3-8b-instruct'
   def call(argv,env,timeout=90,data=None):
    if argv[0]=='/fixture/model-python':return b'{"ready":true,"client_version":"1.44.6"}'
    if argv[:2]==['git','rev-parse']:return b'a'*40
    if argv[:2]==['git','status']:return b''
    if argv[:3]==['cf','zones','list']:return b'[{"name":"ac0.dev","id":"zone"}]'
    if argv[0]=='bash' and argv[-1]=='up':Path(env['STATE']).write_text('profile='+r.PROFILE+'\nregion='+r.REGION+'\ninstance=i-fixture\n')
    if argv[0].endswith('/runner'):
     folder=Path(argv[argv.index('--out')+1]);run=argv[argv.index('--run-id')+1]
     self.assertEqual(argv[argv.index('--storage-profile')+1],storage_profile)
     self.assertEqual(argv[argv.index('--model')+1],args.model)
     self.assertEqual(json.loads((folder/'intent.json').read_text())['model'],args.model)
     self.assertEqual(json.loads((folder/'intent.json').read_text())['storage_profile'],storage_profile)
     assessment={'run_id':'rfixture123','box_id':'original-box','configuration_grade':'C','complete':False,'benchmark_requirements_met':False}
     exposure={'schema':'sandprobe.workload-exposure/1','run_id':'rfixture123','box_id':'original-box','valid':True,'score':3,'of':6}
     r.persist(folder/'evaluation.json',{'source_commit':'a'*40,'managed_run_id':run,'primary_assessment':'rc_exposure_scorecard','configuration_assessment':assessment,'exposure_scorecard':exposure,'functional_workload':{'independent_verification':'passed','functional_tests':9,'model_requests':2,'model':args.model}})
    return b''
   output=io.StringIO()
   with patch.object(Path,'home',return_value=home),patch.object(r,'aws',return_value=r.ACCOUNT.encode()),patch.object(r,'sdk',side_effect=[{'available':True},{'id':r.SNAPSHOT}]),patch.object(r,'call',side_effect=call),patch.object(r,'auth_environment',side_effect=lambda a,e:(e,'zone')),patch.object(r.socket,'getaddrinfo',return_value=[(None,None,None,None,('52.94.0.1',443))]),patch.object(r,'cleanup_owned',return_value={'confirmed':True}) as cleanup,patch.object(r.signal,'signal'),contextlib.redirect_stdout(output):
    self.assertEqual(r.main(args),5)
   cleanup.assert_called_once()
   result=json.loads(output.getvalue().splitlines()[-1])
   self.assertEqual(result['primary_assessment'],'rc_exposure_scorecard');self.assertEqual(result['exposure_scorecard']['score'],3)
   self.assertTrue(result['workload_passed']);self.assertFalse(result['complete'])
 def test_completed_run_prints_bound_rc_score_without_waiving_incomplete_exit(self):
  self.completed_run()
 def test_persistent_profile_reaches_same_managed_workload(self):
  self.completed_run('persistent-workspace')
 def test_artifact_profile_reaches_same_managed_workload(self):
  self.completed_run('persistent-artifacts')
 def test_persistent_recovery_keeps_box_and_storage_outcomes_separate(self):
  with tempfile.TemporaryDirectory() as d:
   folder=Path(d);(folder/'workspace-volume.state').write_text('fixture')
   args=argparse.Namespace(key_file='fixture-key-file',sdk_python='/fixture/python')
   result={'box_ids':['12345678-1234-1234-1234-123456789abc'],'boxes_confirmed':True,'storage_confirmed':False,'confirmed':False}
   with patch.object(r,'call',return_value=json.dumps(result).encode()) as call:
    self.assertEqual(r.recover_persistent(folder,args,{}),result)
    self.assertEqual(call.call_args.kwargs['allowed_returncodes'],(0,5))
    self.assertTrue(r.recover_sandbox(folder,args,{}))
   bad=dict(result,boxes_confirmed=False,storage_confirmed=True)
   with patch.object(r,'call',return_value=json.dumps(bad).encode()):
    self.assertFalse(r.recover_persistent(folder,args,{})['boxes_confirmed'])
 def test_unknown_replacement_blocks_receiver_release(self):
  with tempfile.TemporaryDirectory() as d:
   folder=Path(d);(folder/'workspace-volume.state').write_text('fixture')
   state=folder/'canary.state';state.write_text('instance=fixture\n')
   args=argparse.Namespace(key_file='fixture-key-file',sdk_python='/fixture/python')
   pending={'box_ids':[''],'boxes_confirmed':False,'storage_confirmed':False,'confirmed':False}
   with patch.object(r,'recover_persistent',return_value=pending),patch.object(r,'call') as call,patch.object(r.signal,'signal'):
    result=r.cleanup_owned(folder,args,{'STATE':str(state)})
   self.assertFalse(result['confirmed']);self.assertFalse(result['receiver_confirmed'])
   call.assert_not_called()
 def test_timeout_kills_provisioning_descendants(self):
  with tempfile.TemporaryDirectory() as d:
   marker=Path(d)/'must-not-appear'
   child='import time,pathlib,sys;time.sleep(0.8);pathlib.Path(sys.argv[1]).write_text("orphan")'
   parent='import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]]);time.sleep(30)'
   start=time.monotonic()
   with self.assertRaises(r.Failure):r.call([sys.executable,'-c',parent,child,str(marker)],os.environ.copy(),timeout=0.2)
   self.assertLess(time.monotonic()-start,2)
   time.sleep(1)
   self.assertFalse(marker.exists())
 def test_stale_temporary_record_does_not_block_recovery(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'record.json';path.with_suffix('.json.new').write_text('interrupted')
   r.persist(path,{'confirmed':False});r.persist(path,{'confirmed':True})
   self.assertTrue(json.loads(path.read_text())['confirmed'])
 def test_key_is_owner_only_and_symlinks_refused(self):
  with tempfile.TemporaryDirectory() as d:
   key=Path(d)/'key';key.write_text('synthetic-not-a-secret');key.chmod(0o644)
   with self.assertRaises(r.Failure):r.private_key(key)
   key.chmod(0o600);self.assertEqual(r.private_key(key),'synthetic-not-a-secret')
   link=Path(d)/'link';link.symlink_to(key)
   with self.assertRaises(OSError):r.private_key(link)
 def test_no_intent_does_not_hold_receiver_and_ambiguous_intent_does(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);args=argparse.Namespace(key_file='fixture',sdk_python='python')
   self.assertTrue(r.recover_sandbox(p,args,{}))
   (p/'sandbox-started.json').write_text('{}')
   self.assertFalse(r.recover_sandbox(p,args,{}))
   r.persist(p/'execution-status.json',{'create_attempted':False})
   self.assertTrue(r.recover_sandbox(p,args,{}))
   (p/'daytona-original.state').write_text('{}')
   with patch.object(r,'call',side_effect=r.Failure('unresolved')):
    self.assertFalse(r.recover_sandbox(p,args,{}))
 def test_receiver_release_waits_for_sandbox_confirmation(self):
  for confirmed in (False,True):
   with self.subTest(confirmed=confirmed),tempfile.TemporaryDirectory() as d:
    home=Path(d);(home/'.config/sandprobe').mkdir(parents=True)
    helper=home/'cf';helper.write_text('fixture')
    key=home/'key';key.write_text('synthetic-not-a-secret');key.chmod(0o600)
    args=argparse.Namespace(cleanup_run='',model_python='/fixture/model-python',go='/fixture/go',sdk_python='/fixture/python',key_file=str(key),cf_helper=str(helper),dns_reference='fixture')
    calls=[]
    def call(argv,env,timeout=90,data=None):
     calls.append(argv)
     if argv[0]=='/fixture/model-python':return b'{"ready":true,"client_version":"1.44.6"}'
     if argv[:2]==['git','rev-parse']:return b'a'*40
     if argv[:2]==['git','status']:return b''
     if argv[:3]==['cf','zones','list']:return b'[{"name":"ac0.dev","id":"zone"}]'
     if argv[0]=='bash' and argv[-1]=='up':Path(env['STATE']).write_text('profile='+r.PROFILE+'\nregion='+r.REGION+'\ninstance=i-fixture\n')
     if argv[0].endswith('/runner'):raise r.Failure('execution incomplete')
     return b''
    with patch.object(Path,'home',return_value=home),patch.object(r,'aws',return_value=r.ACCOUNT.encode()),patch.object(r,'sdk',side_effect=[{'available':True},{'id':r.SNAPSHOT}]),patch.object(r,'call',side_effect=call),patch.object(r,'auth_environment',side_effect=lambda a,e:(e,'zone')),patch.object(r.socket,'getaddrinfo',return_value=[(None,None,None,None,('52.94.0.1',443))]),patch.object(r,'recover_sandbox',return_value=confirmed),patch.object(r,'verify_receiver',return_value={'confirmed':True}),patch.object(r.signal,'signal'):
     self.assertEqual(r.main(args),5)
    downs=[x for x in calls if x[0]=='bash' and x[-1]=='down']
    self.assertEqual(bool(downs),confirmed)

if __name__=='__main__':unittest.main()
