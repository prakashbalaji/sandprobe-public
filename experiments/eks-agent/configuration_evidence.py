"""EVD-5 provider-independent configuration evidence wire format.

Mirrors internal/obs/configuration_evidence.go; shared fixtures pin the protocol.
Input is trusted host/control-plane readback, never a guest-supplied assertion.
"""
import re

HEX = r'[a-f0-9]{64}'
IMAGE = re.compile(r'[a-z0-9][a-z0-9._:/-]{1,380}@sha256:' + HEX)

def runtime_image_digest(value):
    if not isinstance(value,str):return ''
    for prefix in ('docker-pullable://','containerd://','docker://'):
        if value.startswith(prefix):
            value=value[len(prefix):]
            break
    if '://' in value:return ''
    if re.fullmatch('sha256:'+HEX,value):return value
    if IMAGE.fullmatch(value):return value.split('@',1)[1]
    return ''

def runtime_image_matches(requested, observed):
    return (isinstance(requested,str) and '://' not in requested and IMAGE.fullmatch(requested) is not None
            and runtime_image_digest(observed) != ''
            and runtime_image_digest(requested) == runtime_image_digest(observed))

def verified_configuration_evidence(run, box, config_hash, requested, observed, private_container_verified):
    if (not re.fullmatch(r'[a-f0-9]{16}',run) or not isinstance(box,str) or not 1<=len(box)<=128
            or not re.fullmatch(HEX,config_hash) or not runtime_image_matches(requested,observed)
            or type(private_container_verified) is not bool):
        raise ValueError('invalid configuration evidence')
    return {'schema':'sandprobe.configuration-evidence/1','managed_run_id':run,'box_id':box,
            'config_sha256':config_hash,'assurance':'configuration_readback_not_attestation',
            'image':{'result':'verified','source':'control_plane_runtime_status','reason':'exact_digest_match',
                     'requested':requested,'observed':observed},
            'process':({'result':'verified','source':'control_plane_spec','reason':'private_container_guards_passed'}
                       if private_container_verified else {'result':'unknown','source':'not_available','reason':'isolation_readback_unavailable'})}
