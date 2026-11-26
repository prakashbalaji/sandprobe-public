"""PRV-12 pinned SDK bridge. One request; fixed origins; never raw SDK errors."""
import base64,contextlib,importlib.metadata,io,json,logging,re,sys
from urllib.parse import urlsplit
API='https://app.daytona.io/api'
PROXY='https://proxy.app.daytona.io/toolbox'
UUID=re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
def safe_url(url,sandbox_id=None):
    parsed=urlsplit(str(url))
    if parsed.scheme!='https' or parsed.username or parsed.password or parsed.port not in (None,443) or parsed.fragment:return False
    if parsed.hostname=='app.daytona.io' and (parsed.path=='/api' or parsed.path.startswith('/api/')):return True
    return bool(sandbox_id and parsed.hostname=='proxy.app.daytona.io' and parsed.path.startswith('/toolbox/'+sandbox_id+'/'))
def install_transport_guards(sandbox_id=None):
    import urllib3,httpx
    original=urllib3.PoolManager.request
    def request(pool,method,url,*args,**kwargs):
        if not safe_url(url,sandbox_id):raise ValueError('unapproved SDK origin')
        kwargs['redirect']=False;kwargs['retries']=False;kwargs['preload_content']=False
        response=original(pool,method,url,*args,**kwargs)
        read=response.read;total=0
        def bounded_read(amt=None,*a,**kw):
            nonlocal total
            remaining=8*1024*1024-total
            data=read(min(remaining+1,amt) if amt is not None else remaining+1,*a,**kw);total+=len(data)
            if total>8*1024*1024:response.close();raise ValueError('response limit')
            return data
        response.read=bounded_read
        return response
    urllib3.PoolManager.request=request
    original_httpx=httpx.Client.send
    def send(client,request,*args,**kwargs):
        if not safe_url(request.url,sandbox_id):raise ValueError('unapproved SDK origin')
        kwargs['follow_redirects']=False;kwargs['stream']=True
        response=original_httpx(client,request,*args,**kwargs)
        chunks=[];total=0
        try:
            for chunk in response.iter_bytes():
                total+=len(chunk)
                if total>8*1024*1024:raise ValueError('response limit')
                chunks.append(chunk)
            headers={k:v for k,v in response.headers.items() if k.lower() not in ('content-encoding','content-length')}
            return httpx.Response(response.status_code,headers=headers,content=b''.join(chunks),request=response.request)
        finally:response.close()
    httpx.Client.send=send

def timestamp(value):
    from datetime import datetime
    text=value if isinstance(value,str) else value.isoformat()
    parsed=datetime.fromisoformat(text.replace("Z","+00:00"))
    if parsed.tzinfo is None:raise ValueError("creation timezone missing")
    return text
def metadata(s):
    mounts=[{'id':v.volume_id,'mount_path':v.mount_path,'subpath':v.subpath or ''} for v in (s.volumes or [])]
    return {'id':s.id,'name':s.name,'organization':s.organization_id,'born':timestamp(s.created_at),'state':str(s.state.value),'desired_state':str(s.desired_state.value) if s.desired_state is not None else '','labels':s.labels or {},'user':s.user,'public':s.public,'auto_delete':s.auto_delete_interval,'auto_stop':s.auto_stop_interval,'auto_pause':s.auto_pause_interval,'proxy':s.toolbox_proxy_url,'volumes':len(mounts),'volume_bindings':mounts,'snapshot':getattr(s,'snapshot',None),'network_allow_list':getattr(s,'network_allow_list',None),'network_block_all':getattr(s,'network_block_all',None),'domain_allow_list':getattr(s,'domain_allow_list',None)}
def workload_volume(req):
    value=req.get('volume_binding')
    if value is None:return None
    if not isinstance(value,dict) or set(value)!=set(('id','mount_path','subpath')) or not isinstance(value['id'],str) or not UUID.fullmatch(value['id']) or value['mount_path'] not in ('/workspace','/persist') or value['subpath']!='':
        raise ValueError('invalid workspace volume binding')
    return dict(value)
def volumes_match(meta,req):
    expected=workload_volume(req)
    return (meta['volumes']==1 and meta['volume_bindings']==[expected]) if expected else (meta['volumes']==0 and meta['volume_bindings']==[])
def bound(client,req):
    s=client._sandbox_api.get_sandbox(req['id'],_request_timeout=25)
    m=metadata(s)
    if m['id']!=req['id'] or m['labels'].get('sandprobe_run')!=req['nonce'] or m['born']!=req['born'] or m['organization']!=req['organization'] or m['public'] or m['auto_delete']!=0 or m['auto_stop']!=15 or m['auto_pause']!=0 or not volumes_match(m,req):raise ValueError('identity/policy mismatch')
    return s,m

def organization_policy_failure(error):
    """EVD-14: fixed labels only; never serialize the exception or its response."""
    from pydantic import ValidationError
    from httpx import TimeoutException,TransportError
    from urllib3.exceptions import TimeoutError as HTTPTimeout, HTTPError
    from daytona_api_client.exceptions import ApiException
    if isinstance(error,ValidationError):return 'response_schema_invalid'
    if isinstance(error,(TimeoutError,HTTPTimeout,TimeoutException)):return 'request_timeout'
    if isinstance(error,ApiException):
        status=error.status
        if type(status) is int:
            if status==401:return 'authentication_failed'
            if status==403:return 'permission_denied'
            if status==404:return 'endpoint_unavailable'
            if status==429:return 'rate_limited'
            if 400<=status<500:return 'request_rejected'
            if 500<=status<600:return 'service_unavailable'
    if isinstance(error,(HTTPError,TransportError)):return 'transport_unavailable'
    return 'readback_unavailable'

def native_sdk_failure_label(error):
    """EVD-21: exception types only; raw SDK details never become diagnostics."""
    category=organization_policy_failure(error)
    if category in ('request_timeout','transport_unavailable','response_schema_invalid'):
        return 'sdk_'+category
    return None

def organization_network_policy(client,req):
    """EVD-19: one verified sandbox-ID organization read; never a denial verdict."""
    unknown=lambda reason:{'result':'unknown','reason':reason}
    try:
        _,meta=bound(client,req)
        organization=meta['organization']
        if not isinstance(organization,str) or not UUID.fullmatch(organization):
            return unknown('binding_unverified')
    except Exception:
        return unknown('binding_unverified')
    try:
        value=client._sandbox_api.get_organization_by_sandbox_id(meta['id'],_request_timeout=15)
    except Exception as error:
        return unknown(organization_policy_failure(error))
    if (getattr(value,'id',None)!=organization
            or type(getattr(value,'sandbox_limited_network_egress',None)) is not bool):
        return unknown('response_mismatch')
    return {'result':'observed','reason':'matching_organization_readback',
            'limited_network_egress':value.sandbox_limited_network_egress}

def create_identity(response):
    try:
        if response.status not in (200,201):raise ValueError('create refused')
        raw=response.read(8*1024*1024+1)
        if len(raw)>8*1024*1024:raise ValueError('create response limit')
        value=json.loads(raw)
        if not isinstance(value,dict) or not isinstance(value.get('id'),str) or not UUID.fullmatch(value['id']):raise ValueError('create ID unavailable')
        return {'id':value['id']}
    finally:response.close()

def volume_metadata(volume):
    # RUN-23: select ownership fields only; no error_reason or provider options.
    if not UUID.fullmatch(volume.id):raise ValueError('volume identity unavailable')
    return {'id':volume.id,'name':volume.name,'organization':volume.organization_id,
            'born':timestamp(volume.created_at),'state':str(volume.state.value)}

def volume_operation(client,req):
    # The trusted host must journal the create-returned ID before lookup/mount.
    # Never get-or-create, adopt by name, enumerate or delete a guessed ID.
    from daytona_api_client import VolumesApi,CreateVolume
    api=VolumesApi(client._api_client)
    if req['op']=='volume_create':
        if not re.fullmatch(r'sandprobe-volume-[a-f0-9]{24}',req.get('name','')):
            raise ValueError('invalid volume name')
        return create_identity(api.create_volume_without_preload_content(CreateVolume(name=req['name']),_request_timeout=60))
    volume_id=req.get('volume_id','')
    if not UUID.fullmatch(volume_id):raise ValueError('invalid volume ID')
    try:volume=api.get_volume(volume_id,_request_timeout=25)
    except Exception as e:
        if getattr(e,'status',None)==404:return {'id':volume_id,'absent':True}
        raise
    value=volume_metadata(volume)
    if value['id']!=volume_id:raise ValueError('volume identity changed')
    if req['op']=='volume_lookup':return value
    if req['op']!='volume_delete':raise ValueError('unsupported volume operation')
    if not re.fullmatch(r'sandprobe-volume-[a-f0-9]{24}',req.get('name','')):
        raise ValueError('invalid volume name')
    for key in ('name','organization','born'):
        if not req.get(key) or value[key]!=req[key]:raise ValueError('volume cleanup ownership mismatch')
    api.delete_volume(volume_id,_request_timeout=60)
    return {'id':volume_id,'deleted_request':True}

def rejected_create(client,req):
    """RUN-24: control-plane refusal + independent absence, never name adoption."""
    import hashlib
    from datetime import datetime,timedelta,timezone
    from daytona_api_client.api.audit_api import AuditApi
    volume=workload_volume(req)
    if (not volume or not re.fullmatch(r'sandprobe-[a-f0-9]{24}',req.get('name',''))
            or not re.fullmatch(r'n[a-f0-9]{24}',req.get('nonce',''))
            or not UUID.fullmatch(req.get('snapshot_id','')) or not req.get('organization')):
        raise ValueError('refusal binding invalid')
    start=datetime.fromisoformat(req['requested'].replace('Z','+00:00'))
    now=datetime.now(timezone.utc)
    if start.tzinfo is None or now<start+timedelta(seconds=120):
        raise ValueError('create may still be in flight')
    expected={'name':req['name'],'target':'us','env':{},'labels':{'sandprobe_run':req['nonce']},
        'public':False,'autoDeleteInterval':0,'autoStopInterval':15,'autoPauseInterval':0,
        'volumes':[{'volumeId':volume['id'],'mountPath':volume['mount_path']}],
        'snapshot':req['snapshot_id'],'user':'root','networkAllowList':req['network_allow_list']}
    logs=AuditApi(client._api_client).get_organization_audit_logs(req['organization'],limit=50,
        var_from=start-timedelta(seconds=1),to=start+timedelta(seconds=110),_request_timeout=25)
    if logs.next_token or logs.total_pages is None or logs.total_pages>1:
        raise ValueError('audit incomplete')
    matches=[]
    for event in logs.items:
        body=(event.metadata or {}).get('body')
        if not isinstance(body,dict):continue
        labels=body.get('labels')
        nonce=labels.get('sandprobe_run') if isinstance(labels,dict) else None
        if body.get('name')!=req['name'] and nonce!=req['nonce']:continue
        at=datetime.fromisoformat(timestamp(event.created_at).replace('Z','+00:00'))
        if (event.organization_id!=req['organization'] or event.action!='create'
                or event.target_type!='sandbox' or event.status_code!=400 or event.target_id
                or not start-timedelta(seconds=1)<=at<=start+timedelta(seconds=110)
                or body!=expected or not event.id):
            raise ValueError('create refusal unproven')
        matches.append({'id':event.id,'at':timestamp(event.created_at),'organization':event.organization_id,'body':body,'status':400})
    if len(matches)!=1:raise ValueError('create refusal ambiguous')
    listing=client._sandbox_api.list_sandboxes(x_daytona_organization_id=req['organization'],name=req['name'],limit=10,
        include_errored_deleted=True,_request_timeout=25)
    if listing.items or listing.next_cursor:raise ValueError('create absence unproven')
    digest=hashlib.sha256(json.dumps(matches[0],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'refused':True,'evidence_sha256':digest}

def dispatch(req):
    if importlib.metadata.version('daytona')!='0.198.0':raise ValueError('unsupported SDK')
    if req['op']=='check':return {'version':'0.198.0'}
    sandbox_id=req.get('id')
    if sandbox_id and not UUID.fullmatch(sandbox_id):raise ValueError('invalid ID')
    install_transport_guards(sandbox_id)
    from daytona import Daytona,DaytonaConfig
    from daytona_api_client.models.create_sandbox import CreateSandbox
    client=Daytona(DaytonaConfig(api_key=req['key'],api_url=API,target='us'))
    # Disable SDK retries, with origin/redirect guards also enforced at transport.
    client._api_client.configuration.retries=0
    if req['op']=='organization_network_policy':return organization_network_policy(client,req)
    if req['op']=='rejected_create':return rejected_create(client,req)
    if req['op'] in ('volume_create','volume_lookup','volume_delete'):
        return volume_operation(client,req)
    if req['op']=='available':
        client._sandbox_api.list_sandboxes(limit=1,_request_timeout=25)
        return {'available':True}
    if req['op']=='snapshot':
        from daytona_api_client.api.snapshots_api import SnapshotsApi
        snapshot=SnapshotsApi(client._api_client).get_snapshot(req['snapshot_id'],_request_timeout=25)
        if snapshot.id!=req['snapshot_id'] or str(snapshot.state.value)!='active' or snapshot.gpu not in (None,0):raise ValueError('snapshot identity/state/CPU mismatch')
        return {'id':snapshot.id,'name':snapshot.name,'image_name':snapshot.image_name,'ref':snapshot.ref,'cpu':snapshot.cpu,'memory':snapshot.mem}
    if req['op']=='create':
        extra={}
        mounts=[]
        volume=workload_volume(req)
        if volume:
            if req.get('workload') is not True:raise ValueError('persistent workspace requires workload mode')
            from daytona_api_client.models.sandbox_volume import SandboxVolume
            mounts=[SandboxVolume(volume_id=volume['id'],mount_path=volume['mount_path'])]
        if req.get('workload'):
            import ipaddress
            if not UUID.fullmatch(req['snapshot_id']):raise ValueError('invalid snapshot')
            nets=req['network_allow_list'].split(',')
            if not 1<=len(nets)<=16 or any(not ipaddress.ip_network(n).is_global or ipaddress.ip_network(n).prefixlen!=32 for n in nets):raise ValueError('invalid workload network')
            extra={'snapshot':req['snapshot_id'],'user':'root','network_allow_list':req['network_allow_list']}
        response=client._sandbox_api.create_sandbox_without_preload_content(CreateSandbox(name=req['name'],target='us',env={},labels={'sandprobe_run':req['nonce']},public=False,auto_delete_interval=0,auto_stop_interval=15,auto_pause_interval=0,volumes=mounts,secrets=[],**extra),_request_timeout=60)
        # No generated optional model parsing before the host journals ID.
        return create_identity(response)
    if req['op']=='lookup':
        try:s=client._sandbox_api.get_sandbox(sandbox_id,_request_timeout=25)
        except Exception as e:
            if getattr(e,'status',None)==404:return {'absent':True}
            raise
        value=metadata(s)
        if req.get('workload'):
            from daytona_api_client.api.snapshots_api import SnapshotsApi
            snapshot=SnapshotsApi(client._api_client).get_snapshot(s.snapshot,_request_timeout=25)
            value['snapshot_id']=snapshot.id
            value['snapshot_ref']=snapshot.ref
        return value
    if req['op']=='delete':
        s=client._sandbox_api.get_sandbox(sandbox_id,_request_timeout=25)
        if s.id!=sandbox_id or (s.labels or {}).get('sandprobe_run')!=req['nonce'] or (req.get('born') and timestamp(s.created_at)!=req['born']):raise ValueError('cleanup ownership mismatch')
        client._sandbox_api.delete_sandbox(sandbox_id,_request_timeout=60)
        return {'deleted_request':True,'id':sandbox_id}
    _,m=bound(client,req)
    if m['state']!='started' or m['proxy']!=PROXY:raise ValueError('runtime not ready/approved')
    sandbox=client.get(sandbox_id,request_timeout=25)
    if sandbox.id!=sandbox_id or sandbox.toolbox_proxy_url!=PROXY:raise ValueError('runtime identity changed')
    def command(script):
        result=sandbox.process.exec(script,env={'SANDPROBE_TWIN':'1'},timeout=95)
        output=result.artifacts.stdout if result.artifacts else result.result
        if result.exit_code!=0 or not isinstance(output,str) or len(output.encode())>1024*1024:raise ValueError('execution failed/limit')
        return output
    if req.get('boot'):
        if command('cat /proc/sys/kernel/random/boot_id').strip()!=req['boot']:raise ValueError('boot changed')
    if req['op']=='exec':return {'stdout':command(req['command']),'id':sandbox_id,'exit_code':0}
    if req['op']=='upload':
        names=r'(?:probe|input-i[a-f0-9]{24})'
        if req.get('workload'):names=r'(?:probe|input-i[a-f0-9]{24}|coding\.py|project_exec\.py|worker\.py|solution-s[a-f0-9]{24}\.py)'
        if not re.fullmatch(r'/tmp/\.sandprobe-[A-Za-z0-9]{12}/'+names,req['path']):raise ValueError('private path invalid')
        data=base64.b64decode(req['data'],validate=True)
        if len(data)>16*1024*1024:raise ValueError('upload limit')
        sandbox.fs.upload_file(data,req['path'],timeout=95)
        return {'uploaded':True,'id':sandbox_id}
    raise ValueError('unsupported operation')
def main():
    logging.disable(logging.CRITICAL)
    try:
        raw=sys.stdin.buffer.read(24*1024*1024+1)
        if len(raw)>24*1024*1024:raise ValueError('request limit')
        req=json.loads(raw)
        # Providers can log request headers/bodies in exceptions; silence both channels.
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):result=dispatch(req)
        sys.stdout.write(json.dumps(result))
    except Exception as e:
        code=getattr(e,'status',None)
        suffix=' HTTP '+str(code) if isinstance(code,int) and 100<=code<=599 else ''
        labels={'runtime not ready/approved':'runtime_proxy_guard','runtime identity changed':'runtime_identity_guard','identity/policy mismatch':'identity_policy_guard','execution failed/limit':'command_failed_or_output_limit','boot changed':'boot_guard','private path invalid':'upload_path_guard'}
        label=native_sdk_failure_label(e) or (labels.get(str(e),'unclassified_sdk_failure') if isinstance(e,ValueError) else 'unclassified_sdk_failure')
        sys.stdout.write(json.dumps({'error':'sdk_failure','failure_code':label,'http_status':code if isinstance(code,int) and 100<=code<=599 else 0}));return 1
    return 0
if __name__=='__main__':sys.exit(main())
