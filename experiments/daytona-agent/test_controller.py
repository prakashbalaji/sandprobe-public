import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import io,json,sys,runpy,types,contextlib
spec=importlib.util.spec_from_file_location('controller',Path(__file__).with_name('controller.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class ControllerTests(unittest.TestCase):
 def invoke(self,mode,value,model=None):
  stdin=io.TextIOWrapper(io.BytesIO(json.dumps(value).encode()))
  with patch.object(sys,'argv',['controller',mode]+([model] if model else [])),patch.object(sys,'stdin',stdin):return c.main()
 def test_shared_prompt_and_bounded_request(self):
  out=self.invoke('request',{})
  self.assertEqual(out['messages'][0]['content'][0]['text'],c.coding.PROMPT)
  self.assertEqual(out['modelId'],'mistral.ministral-3-3b-instruct')
  self.assertEqual(out['inferenceConfig']['maxTokens'],2048)
 def test_explicit_8b_keeps_same_prompt_schema_and_limits(self):
  request=self.invoke('request',{},'mistral.ministral-3-8b-instruct')
  default=self.invoke('request',{})
  self.assertEqual(request['modelId'],'mistral.ministral-3-8b-instruct')
  request['modelId']=default['modelId']
  self.assertEqual(request,default)
  with self.assertRaises(ValueError):self.invoke('request',{},'other-model')
 def test_parser_preserves_source_as_data(self):
  source='raise RuntimeError("must not execute on host")'
  out=self.invoke('parse',{'output':{'message':{'content':[{'text':json.dumps({'solution.py':source})}]}}})
  self.assertEqual(out['source'],source)
 def test_malformed_source_rejected(self):
  with self.assertRaises(Exception):self.invoke('parse',{'output':{'message':{'content':[{'text':'{}'}]}}})
 def test_shared_diagnostic_refuses_contradictory_success(self):
  value={"functional_tests":9,"independent_verification":"passed","artifact_sha256":"a"*64,"diagnostics":{
   "schema":"sandprobe.functional-diagnostic/1","failure_kind":"passed","outputs_complete":True,"matched_cases":9,"expected_cases":9,"failed_case_ids":[]}}
  self.assertEqual(self.invoke('diagnostic',value),value['diagnostics'])
  value['independent_verification']='failed'
  with self.assertRaises(ValueError):self.invoke('diagnostic',value)
 def test_repair_gets_only_validated_public_failure_examples(self):
  verification={"functional_tests":9,"independent_verification":"failed","artifact_sha256":"a"*64,"diagnostics":{
   "schema":"sandprobe.functional-diagnostic/1","failure_kind":"case_mismatch","outputs_complete":True,"matched_cases":6,"expected_cases":9,"failed_case_ids":[1,3,4]}}
  value={"previous":json.dumps({"solution.py":"pass"}),"verification":verification}
  result=self.invoke('request',value)
  self.assertEqual(len(result['messages']),3)
  self.assertEqual(result['messages'][0]['content'][0]['text'],c.coding.PROMPT)
  feedback=result['messages'][2]['content'][0]['text']
  for i in [1,3,4]:
   self.assertIn(json.dumps(c.coding.CASES[i-1][0]),feedback)
  self.assertIn('"returns":{"apple":7,"pear":3}',feedback)
  self.assertNotIn('"ok":',feedback)
  self.assertNotIn(json.dumps(c.coding.CASES[8][0]),feedback)
  self.assertEqual(result['inferenceConfig'],{'maxTokens':2048,'temperature':0})
  verification['diagnostics']['candidate_stdout']='synthetic-untrusted-detail'
  with self.assertRaises(ValueError):self.invoke('request',value)
 def test_repair_rejects_missing_or_contradictory_feedback(self):
  with self.assertRaises(ValueError):self.invoke('request',{'previous':'{}'})
  verification={"functional_tests":9,"independent_verification":"passed","artifact_sha256":"a"*64,"diagnostics":{
   "schema":"sandprobe.functional-diagnostic/1","failure_kind":"passed","outputs_complete":True,"matched_cases":9,"expected_cases":9,"failed_case_ids":[]}}
  with self.assertRaises(ValueError):self.invoke('request',{'previous':'{}','verification':verification})
 def test_guest_tls_keeps_frozen_ip_and_hostname(self):
  class Stream:
   def __enter__(self):return self
   def __exit__(self,*args):pass
   def version(self):return 'TLSv1.3'
  calls=[]
  context=types.SimpleNamespace(wrap_socket=lambda conn,server_hostname:(calls.append(server_hostname) or Stream()))
  def connect(addr,timeout):calls.append(addr);return Stream()
  with patch.dict(sys.modules,{'coding':c.coding}),patch.object(sys,'argv',['worker','network','52.94.0.1']),patch('socket.create_connection',side_effect=connect),patch('ssl.create_default_context',return_value=context),contextlib.redirect_stdout(io.StringIO()):
   runpy.run_path(str(Path(__file__).resolve().parents[1]/'eks-agent/worker.py'),run_name='__main__')
  self.assertEqual(calls,[('52.94.0.1',443),'bedrock-runtime.us-west-2.amazonaws.com'])
if __name__=='__main__':unittest.main()
