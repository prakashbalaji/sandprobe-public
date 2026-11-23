import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('daytona_model',Path(__file__).with_name('model.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ModelTests(unittest.TestCase):
 def request_value(self):return {'modelId':m.MODEL,'messages':[{'role':'user','content':[{'text':'fixed synthetic task'}]}],'inferenceConfig':{'maxTokens':2048,'temperature':0},'outputConfig':{}}
 def test_wrong_account_never_invokes_model(self):
  called=[]
  class Client:
   def get_caller_identity(self):return {'Account':'different'}
   def converse(self,**kwargs):called.append(kwargs);return {}
  current=types.SimpleNamespace(client=lambda *a,**k:Client())
  with patch.object(m,'session',return_value=(current,object())):out=m.request(self.request_value())
  self.assertFalse(out['converse_attempted']);self.assertEqual(called,[])
 def test_success_counts_exactly_one_converse(self):
  calls=[]
  class Client:
   def get_caller_identity(self):return {'Account':m.ACCOUNT}
   def converse(self,**kwargs):calls.append(kwargs);return {'output':{'message':{'content':[{'text':'{}'}]}}}
  current=types.SimpleNamespace(client=lambda *a,**k:Client())
  value=self.request_value();value['modelId']='mistral.ministral-3-8b-instruct'
  with patch.object(m,'session',return_value=(current,object())):out=m.request(value)
  self.assertTrue(out['converse_attempted']);self.assertEqual(len(calls),1)
  self.assertEqual(calls[0]['modelId'],'mistral.ministral-3-8b-instruct')
 def test_invalid_model_never_loads_credentials(self):
  value=self.request_value();value['modelId']='other-model'
  with patch.object(m,'session',side_effect=AssertionError('credentials loaded')):out=m.request(value)
  self.assertFalse(out['converse_attempted'])
 def test_client_pins_region_profile_deadlines_and_no_retries(self):
  seen={}
  boto=types.ModuleType('boto3');boto.Session=lambda **kw:(seen.update(session=kw) or 'session')
  config=types.ModuleType('botocore.config');config.Config=lambda **kw:(seen.update(config=kw) or 'config')
  parent=types.ModuleType('botocore');parent.__path__=[];parent.config=config
  with patch.dict(sys.modules,{'boto3':boto,'botocore':parent,'botocore.config':config}):self.assertEqual(m.session(),('session','config'))
  self.assertEqual(seen['session'],{'profile_name':m.PROFILE,'region_name':m.REGION})
  self.assertEqual(seen['config']['retries']['total_max_attempts'],1)
  self.assertEqual(seen['config']['connect_timeout'],5)
  self.assertEqual(seen['config']['read_timeout'],130)
  self.assertTrue(seen['config']['ignore_configured_endpoint_urls'])
if __name__=='__main__':unittest.main()
