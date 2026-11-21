import copy
import hashlib
import json
from pathlib import Path
import runpy
import unittest

guard=runpy.run_path(str(Path(__file__).resolve().parents[2]/'internal/host/workload_home_guard.py'),run_name='sandprobe_owned_home_guard')

def context():
    return {'schema':'sandprobe.workload-home/1','home':guard['HOME'],
            'nodes':[{'path':p,'device':1,'inode':i+1,'uid':0,'mode':0o555 if p==guard['HOME'] else 0o755,'directory':True} for i,p in enumerate(guard['PATHS'])]}

class HomeGuardTests(unittest.TestCase):
    def test_shared_canonical_wire_fixture(self):
        raw=(Path(__file__).resolve().parents[2]/'internal/host/testdata/workload-home.json').read_bytes().strip()
        value=guard['validate'](json.loads(raw))
        self.assertEqual(value,context())
        self.assertEqual(raw,json.dumps(value,sort_keys=True,separators=(',',':')).encode())

    def test_unsafe_ancestors_and_replacement_identity(self):
        original=context();guard['validate'](original)
        for key,value in [('mode',0o777),('uid',10001),('directory',False),('inode',True),('mode',0o700)]:
            wrong=copy.deepcopy(original);wrong['nodes'][2][key]=value
            with self.assertRaises(ValueError):guard['validate'](wrong)
        wrong=copy.deepcopy(original);wrong['nodes'][3]['inode']+=1
        guard['validate'](wrong)
        encoded=lambda d:json.dumps(d,sort_keys=True,separators=(',',':')).encode()
        self.assertNotEqual(hashlib.sha256(encoded(original)).hexdigest(),hashlib.sha256(encoded(wrong)).hexdigest())
