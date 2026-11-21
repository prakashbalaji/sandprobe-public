import importlib.util,json,os,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('cfmanage',Path(__file__).with_name('manage.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FakeAPI:
 def __init__(self):self.calls=[];self.base='https://api.cloudflare.com/client/v4/accounts/'+'a'*32
 def call(self,method,path,*args,**kwargs):
  self.calls.append((method,path))
  if path=='/workers/subdomain':return None
  raise AssertionError('unexpected request')
class Tests(unittest.TestCase):
 def test_preflight_missing_setup_never_mutates(self):
  api=FakeAPI()
  with tempfile.TemporaryDirectory() as d:
   bundle=Path(d).resolve()/'worker';bundle.write_text('export default {}');state=Path(d).resolve()/'state'
   with self.assertRaises(m.SafeError):m.up(api,'a'*32,state,bundle)
   self.assertFalse(state.exists());self.assertTrue(all(method=='GET' for method,_ in api.calls))
 def test_key_validation_rejects_symlinks_and_world_readable(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve()/'key';p.write_text('not-a-real-token');p.chmod(0o644)
   with self.assertRaises(m.SafeError):m.token(p)
   p.chmod(0o600);link=Path(d).resolve()/'link';link.symlink_to(p)
   with self.assertRaises(m.SafeError):m.token(link)
 def test_deployment_change_prevents_all_deletion(self):
  class Changed(FakeAPI):
   def call(self,method,path,*args,**kwargs):
    self.calls.append((method,path));return {'deployments':[{'id':'replacement'}]}
  api=Changed();state={'name':'sandprobe-'+'b'*24,'deployment_id':'original'}
  with self.assertRaises(m.SafeError):m.check_identity(api,state)
  self.assertTrue(all(method=='GET' for method,_ in api.calls))
 def test_exclusive_intent_cannot_be_overwritten(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve()/'state';m.write_state(p,{'original':True},True)
   with self.assertRaises(m.SafeError):m.write_state(p,{'original':False},True)
   self.assertTrue(json.loads(p.read_text())['original'])
class CleanupTests(unittest.TestCase):
 def test_missing_worker_cleanup_can_finish_after_recorded_delete(self):
  class Removed(FakeAPI):
   def call(self,method,path,*args,**kwargs):
    self.calls.append((method,path))
    if '/settings' in path:return None
    if '/namespaces?' in path:return []
    if '/containers/applications/' in path:return None
    raise AssertionError('unexpected call')
  api=Removed()
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve()/'state';m.write_state(p,{'account':'a'*32,'name':'sandprobe-'+'b'*24,'deployment_id':'old','namespace_ids':['c'*32],'application_ids':['app-1'],'cleanup_phase':'deleting_worker'},True)
   result=m.down(api,p);self.assertTrue(result['deleted']);self.assertFalse(p.exists());self.assertTrue(all(method=='GET' for method,_ in api.calls))
 def test_atomic_update_failure_preserves_old_state(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve()/'state';m.write_state(p,{'original':True},True)
   with patch.object(m.os,'replace',side_effect=OSError('disk failure')):
    with self.assertRaises(m.SafeError):m.write_state(p,{'original':False})
   self.assertTrue(json.loads(p.read_text())['original'])
if __name__=='__main__':unittest.main()
