import importlib.util,json,unittest,io,sys
sys.dont_write_bytecode=True
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('daytona_runtime',Path(__file__).with_name('daytona_runtime.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SID='12345678-1234-1234-1234-123456789abc'
class Tests(unittest.TestCase):
 def test_origins_and_id_path_are_exact(self):
  self.assertTrue(m.safe_url('https://app.daytona.io/api/sandbox'))
  self.assertTrue(m.safe_url('https://proxy.app.daytona.io/toolbox/'+SID+'/process/execute',SID))
  for url in ['http://app.daytona.io/api','https://app.daytona.io.evil.invalid/api','https://user:pass@app.daytona.io/api','https://proxy.app.daytona.io/toolbox/other/process','https://evil.invalid/toolbox/'+SID+'/process','https://app.daytona.io/not-api']:
   self.assertFalse(m.safe_url(url,SID))
 def test_raw_create_preserves_id_despite_invalid_optional_model(self):
  class Response:
   status=200
   closed=False
   def read(self,amount):return json.dumps({'id':SID,'createdAt':{'bad':'type'},'public':'invalid'}).encode()
   def close(self):self.closed=True
  response=Response();self.assertEqual(m.create_identity(response),{'id':SID});self.assertTrue(response.closed)
 def test_metadata_uses_real_generated_string_timestamp(self):
  from daytona_api_client.models.sandbox import Sandbox
  sandbox=Sandbox.model_construct(id=SID,name='fixture',organization_id='org',created_at='2026-11-13T07:00:00Z',state=__import__('daytona_api_client.models.sandbox_state',fromlist=['SandboxState']).SandboxState.STARTED,desired_state=None,labels={'sandprobe_run':'fixture'},user='daytona',public=False,auto_delete_interval=0,auto_stop_interval=15,auto_pause_interval=0,toolbox_proxy_url=m.PROXY,volumes=[])
  value=m.metadata(sandbox)
  self.assertEqual(value['born'],'2026-11-13T07:00:00Z');self.assertEqual(value['desired_state'],'');self.assertEqual(value['state'],'started')
 def test_native_create_policy_matches_pinned_model(self):
  from daytona_api_client.models.create_sandbox import CreateSandbox
  p=CreateSandbox(name='fixture',target='us',env={},labels={'sandprobe_run':'fixture'},public=False,auto_delete_interval=0,auto_stop_interval=15,auto_pause_interval=0,volumes=[],secrets=[]).to_dict()
  self.assertEqual(p['autoDeleteInterval'],0);self.assertEqual(p['autoStopInterval'],15);self.assertEqual(p['autoPauseInterval'],0);self.assertEqual(p['env'],{});self.assertEqual(p['volumes'],[]);self.assertFalse(p['public'])
 def test_transport_disables_redirects_retries_and_denies_external_host(self):
  import urllib3,httpx
  original_pool=urllib3.PoolManager.request;original_send=httpx.Client.send
  class Response:
   def read(self,amt=None):return b'{}'
   def close(self):pass
  seen=[]
  try:
   urllib3.PoolManager.request=lambda pool,method,url,*a,**kw:(seen.append(kw) or Response())
   m.install_transport_guards(SID)
   response=urllib3.PoolManager().request('POST','https://app.daytona.io/api/sandbox')
   self.assertFalse(seen[0]['redirect']);self.assertFalse(seen[0]['retries']);self.assertEqual(response.read(),b'{}')
   with self.assertRaises(ValueError):urllib3.PoolManager().request('POST','https://evil.invalid')
  finally:urllib3.PoolManager.request=original_pool;httpx.Client.send=original_send
 def test_httpx_compressed_response_is_decoded_once(self):
  import httpx,urllib3,gzip
  original_pool=urllib3.PoolManager.request;original_send=httpx.Client.send
  seen=[]
  try:
   def fake(client,request,*a,**kw):
    seen.append(kw)
    return httpx.Response(200,headers={'content-encoding':'gzip','content-length':'123'},content=gzip.compress(b'{"ok":true}'),request=request)
   httpx.Client.send=fake;m.install_transport_guards(SID)
   with httpx.Client() as client:
    response=client.send(httpx.Request('GET','https://app.daytona.io/api/sandbox'))
    self.assertEqual(response.json(),{'ok':True});self.assertNotIn('content-encoding',response.headers);self.assertFalse(seen[0]['follow_redirects'])
  finally:urllib3.PoolManager.request=original_pool;httpx.Client.send=original_send
 def test_check_only_verifies_sdk_version_without_network(self):
  self.assertEqual(m.dispatch({'op':'check'})['version'],'0.198.0')
 def test_workload_create_has_native_policy_and_no_guest_secrets(self):
  import types,daytona
  seen=[]
  class Response:
   status=201
   def read(self,amount):return json.dumps({'id':SID}).encode()
   def close(self):pass
  class Api:
   def create_sandbox_without_preload_content(self,p,**kw):seen.append(p.to_dict());return Response()
  client=types.SimpleNamespace(_api_client=types.SimpleNamespace(configuration=types.SimpleNamespace()),_sandbox_api=Api())
  request={'op':'create','key':'synthetic-not-a-secret','name':'fixture','nonce':'fixture','workload':True,'snapshot_id':SID,'network_allow_list':'52.94.0.1/32'}
  with patch.object(daytona,'Daytona',return_value=client),patch.object(m,'install_transport_guards'):
   self.assertEqual(m.dispatch(request),{'id':SID})
   request['network_allow_list']='0.0.0.0/0'
   with self.assertRaises(ValueError):m.dispatch(request)
  self.assertEqual(len(seen),1)
  self.assertEqual(seen[0]['snapshot'],SID);self.assertEqual(seen[0]['user'],'root')
  self.assertEqual(seen[0]['env'],{});self.assertEqual(seen[0]['secrets'],[]);self.assertEqual(seen[0]['volumes'],[])
  self.assertEqual(seen[0]['networkAllowList'],'52.94.0.1/32');self.assertFalse(seen[0]['public'])
 def test_workload_files_cross_the_actual_sdk_upload_dispatch(self):
  import types,daytona,base64
  seen=[]
  sandbox=types.SimpleNamespace(id=SID,toolbox_proxy_url=m.PROXY,fs=types.SimpleNamespace(upload_file=lambda data,path,timeout:seen.append(path)))
  client=types.SimpleNamespace(_api_client=types.SimpleNamespace(configuration=types.SimpleNamespace()),get=lambda *a,**k:sandbox)
  with patch.object(daytona,'Daytona',return_value=client),patch.object(m,'install_transport_guards'),patch.object(m,'bound',return_value=(None,{'state':'started','proxy':m.PROXY})):
   for name in ('coding.py','project_exec.py','worker.py','solution-s'+'a'*24+'.py'):
    req={'op':'upload','id':SID,'key':'synthetic-not-a-secret','workload':True,'path':'/tmp/.sandprobe-abcdefghijkl/'+name,'data':base64.b64encode(b'fixture').decode()}
    self.assertTrue(m.dispatch(req)['uploaded'])
    req['workload']=False
    with self.assertRaises(ValueError):m.dispatch(req)
  self.assertEqual(len(seen),4)
 def test_nonroot_repair_uses_fresh_readonly_staging(self):
  import os,types,daytona,base64,tempfile
  if os.geteuid()==0:self.skipTest('requires an unprivileged filesystem principal')
  with tempfile.TemporaryDirectory() as directory:
   def upload(data,path,timeout):
    target=Path(directory)/Path(path).name
    target.write_bytes(data)
    target.chmod(0o444)
   sandbox=types.SimpleNamespace(id=SID,toolbox_proxy_url=m.PROXY,fs=types.SimpleNamespace(upload_file=upload))
   client=types.SimpleNamespace(_api_client=types.SimpleNamespace(configuration=types.SimpleNamespace()),get=lambda *a,**k:sandbox)
   req={'op':'upload','id':SID,'key':'synthetic-not-a-secret','workload':True,'data':base64.b64encode(b'fixture').decode()}
   with patch.object(daytona,'Daytona',return_value=client),patch.object(m,'install_transport_guards'),patch.object(m,'bound',return_value=(None,{'state':'started','proxy':m.PROXY})):
    for nonce in ('a'*24,'b'*24):
     req['path']='/tmp/.sandprobe-abcdefghijkl/solution-s'+nonce+'.py'
     self.assertTrue(m.dispatch(req)['uploaded'])
    with self.assertRaises(PermissionError):m.dispatch(req)
    for invalid in ('solution.py','solution-s'+('a'*23)+'.py','../solution-s'+('a'*24)+'.py'):
     req['path']='/tmp/.sandprobe-abcdefghijkl/'+invalid
     with self.assertRaises(ValueError):m.dispatch(req)
   self.assertEqual(len(list(Path(directory).iterdir())),2)
 def test_main_emits_only_fixed_failure_codes(self):
  for error,want in [(ValueError('runtime not ready/approved'),'runtime_proxy_guard'),(ValueError('synthetic-sensitive-detail'),'unclassified_sdk_failure')]:
   output=io.StringIO()
   with patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(b'{}'))),patch.object(sys,'stdout',output),patch.object(m,'dispatch',side_effect=error):
    self.assertEqual(m.main(),1)
   value=json.loads(output.getvalue());self.assertEqual(value['failure_code'],want)
   self.assertNotIn('sensitive',output.getvalue())
if __name__=='__main__':unittest.main()
