import json
from pathlib import Path
import unittest
from configuration_evidence import runtime_image_digest,runtime_image_matches,verified_configuration_evidence

class ConfigurationEvidenceTests(unittest.TestCase):
    def test_shared_runtime_identity_fixtures(self):
        path=Path(__file__).resolve().parents[2]/'internal/obs/testdata/image-identities.json'
        for case in json.loads(path.read_text()):
            with self.subTest(identity=case['identity']):
                self.assertEqual(runtime_image_digest(case['identity']),case['digest'])
                self.assertEqual(runtime_image_matches('repo/image@sha256:'+'a'*64,case['identity']),bool(case['digest']))

    def test_evidence_requires_exact_running_digest(self):
        image='repo/image@sha256:'+'a'*64
        observed='containerd://sha256:'+'a'*64
        e=verified_configuration_evidence('b'*16,'owned-box','c'*64,image,observed,True)
        self.assertEqual(e['image']['observed'],observed)
        self.assertEqual(e['assurance'],'configuration_readback_not_attestation')
        for wrong in [observed+'suffix','prefix'+observed,'containerd://sha256:'+'f'*64,None]:
            with self.assertRaises(ValueError):verified_configuration_evidence('b'*16,'owned-box','c'*64,image,wrong,True)
        unknown=verified_configuration_evidence('b'*16,'owned-box','c'*64,image,observed,False)
        self.assertEqual(unknown['process']['result'],'unknown')
        for wrong in [None,1,'true']:
            with self.assertRaises(ValueError):verified_configuration_evidence('b'*16,'owned-box','c'*64,image,observed,wrong)
