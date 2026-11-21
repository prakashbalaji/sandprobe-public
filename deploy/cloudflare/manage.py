#!/usr/bin/env python3
"""PRV-10: native, single-request deployment; Wrangler only bundles offline."""
import argparse, hashlib, json, os, re, secrets, stat, sys, tempfile, urllib.error, urllib.request
from pathlib import Path

HEX = re.compile(r'^[a-f0-9]{32}$')
NAME = re.compile(r'^sandprobe-[a-f0-9]{24}$')
class SafeError(Exception): pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None

def private_read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise SafeError('file must be regular and owner-only')
            data = f.read(65537)
            if len(data) > 65536: raise SafeError('private file too large')
            return data
    except OSError: raise SafeError('private file unavailable') from None

def token(path):
    key = private_read(path).decode().strip()
    if not key or len(key)>8192 or any(ord(c)<=32 or ord(c)>=127 for c in key):
        raise SafeError('token malformed')
    return key

class API:
    def __init__(self, key, account):
        if not HEX.fullmatch(account): raise SafeError('explicit account invalid')
        self.base='https://api.cloudflare.com/client/v4/accounts/'+account
        self.key=key
        self.opener=urllib.request.build_opener(NoRedirect())
    def call(self, method, path, body=None, content_type='application/json', absent=False):
        request=urllib.request.Request(self.base+path,data=body,method=method,
            headers={'Authorization':'Bearer '+self.key,'Content-Type':content_type})
        try:
            with self.opener.open(request,timeout=120) as response:
                raw=response.read(4*1024*1024+1)
                if len(raw)>4*1024*1024: raise SafeError('API response too large')
                data=json.loads(raw)
                if not data.get('success'): raise SafeError('API refused request')
                return data.get('result')
        except urllib.error.HTTPError as e:
            if absent and e.code==404: return None
            raise SafeError(f'Cloudflare API {method} HTTP {e.code}') from None
        except (OSError,ValueError): raise SafeError('Cloudflare API transport/format failure') from None

def private_parent(path):
    parent=Path(path).parent
    try:
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o022:
            raise SafeError('state directory must be owned and not writable by others')
        if parent.resolve()!=parent.absolute():raise SafeError('state directory must not contain symlinks')
    except OSError:raise SafeError('state directory unavailable') from None

def write_state(path, data, exclusive=False):
    private_parent(path)
    temporary=None
    try:
        if exclusive:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        else:
            private_read(path)  # refuse a changed owner, mode, symlink or invalid type
            fd,temporary=tempfile.mkstemp(prefix='.cloudflare-state-',dir=Path(path).parent)
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(data,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        if temporary:
            os.replace(temporary,path);temporary=None
        directory=os.open(Path(path).parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    except OSError:raise SafeError('state write failed; preserve private journal') from None
    finally:
        if temporary:
            try:os.unlink(temporary)
            except OSError:pass

def deployment_identity(api,name):
    d=api.call('GET','/workers/scripts/'+name+'/deployments')
    values=d.get('deployments',[]) if isinstance(d,dict) else []
    if not values or not values[0].get('id'): raise SafeError('deployment identity unavailable')
    return values[0]['id']

def multipart(metadata, code):
    boundary='sandprobe-'+secrets.token_hex(16)
    body=(f'--{boundary}\r\nContent-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n'.encode()+json.dumps(metadata).encode()+
        f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="worker.mjs"; filename="worker.mjs"\r\nContent-Type: application/javascript+module\r\n\r\n'.encode()+code+f'\r\n--{boundary}--\r\n'.encode())
    return body,'multipart/form-data; boundary='+boundary

def preflight(api):
    sub=api.call('GET','/workers/subdomain')
    if not isinstance(sub,dict) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}',sub.get('subdomain','')):
        raise SafeError('existing workers.dev subdomain required; no account setup performed')
    settings=api.call('GET','/workers/account-settings')
    if settings.get('default_usage_model')!='standard':
        raise SafeError('Workers Standard entitlement unverified; no plan change performed')
    apps=api.call('GET','/containers/applications?per_page=100')
    if not isinstance(apps,list): raise SafeError('Containers access unavailable')
    return sub['subdomain']

def up(api, account, state_path, bundle):
    # Token and all local inputs validated before intent or remote mutation.
    code=Path(bundle).read_bytes()
    if not code or len(code)>1024*1024:raise SafeError('offline bundle invalid')
    subdomain=preflight(api)
    nonce=secrets.token_hex(16);name='sandprobe-'+secrets.token_hex(12);cap=secrets.token_hex(32)
    if api.call('GET','/workers/scripts/'+name+'/settings',absent=True) is not None:
        raise SafeError('random name already exists')
    state={'account':account,'name':name,'nonce':nonce,'capability':cap,'origin':f'https://{name}.{subdomain}.workers.dev','phase':'intent','namespace_ids':[],'application_ids':[],'bundle_sha256':hashlib.sha256(code).hexdigest()}
    write_state(state_path,state,exclusive=True)
    metadata={'main_module':'worker.mjs','compatibility_date':'2026-11-13','observability':{'enabled':False},
        'bindings':[{'name':'BOX','type':'durable_object_namespace','class_name':'SandprobeBox'},
            {'name':'AUTH_SHA256','type':'plain_text','text':hashlib.sha256(cap.encode()).hexdigest()},
            {'name':'RUN_NONCE','type':'plain_text','text':nonce}],
        'containers':[{'class_name':'SandprobeBox'}],
        'exports':{'SandprobeBox':{'type':'durable-object','storage':'sqlite'}}}
    body,ctype=multipart(metadata,code)
    uploaded=api.call('PUT','/workers/scripts/'+name,body,ctype)
    state['upload_id']=uploaded.get('id');state['phase']='worker_uploaded';write_state(state_path,state)
    state['deployment_id']=deployment_identity(api,name);write_state(state_path,state)
    settings=api.call('GET','/workers/scripts/'+name+'/settings')
    namespaces=[b.get('namespace_id') for b in settings.get('bindings',[]) if b.get('name')=='BOX' and b.get('type')=='durable_object_namespace']
    if len(namespaces)!=1 or not HEX.fullmatch(namespaces[0] or ''):raise SafeError('created namespace identity unavailable')
    state['namespace_ids']=namespaces;write_state(state_path,state)
    app=api.call('POST','/containers/applications',json.dumps({'name':name+'-box','scheduling_policy':'durable_object','durable_objects':{'namespace_id':namespaces[0]},'observability':{'logs':{'enabled':False}}}).encode())
    app_id=app.get('id')
    if not isinstance(app_id,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}',app_id):raise SafeError('created application identity unavailable')
    state['application_ids']=[app_id];state['phase']='application_created';write_state(state_path,state)
    api.call('POST','/workers/scripts/'+name+'/subdomain',json.dumps({'enabled':True,'previews_enabled':False}).encode())
    state['phase']='ready';write_state(state_path,state)
    return {'name':name,'origin':state['origin'],'phase':'ready','state_file':str(state_path)}

def check_identity(api,state):
    if not NAME.fullmatch(state.get('name','')) or not state.get('deployment_id'):
        raise SafeError('unresolved creation; retain journal for manual reconciliation')
    name=state['name']
    if deployment_identity(api,name)!=state['deployment_id']:raise SafeError('Worker deployment changed; refusing deletion')
    settings=api.call('GET','/workers/scripts/'+name+'/settings')
    bindings=settings.get('bindings',[])
    vals={b['name']:b.get('text') for b in bindings if b.get('type')=='plain_text'}
    if vals.get('RUN_NONCE')!=state['nonce'] or vals.get('AUTH_SHA256')!=hashlib.sha256(state['capability'].encode()).hexdigest():
        raise SafeError('Worker ownership changed; refusing deletion')
    found=[b.get('namespace_id') for b in bindings if b.get('name')=='BOX']
    if found!=state['namespace_ids']:raise SafeError('namespace identity changed')

def down(api,state_path):
    private_parent(state_path)
    state=json.loads(private_read(state_path))
    if state.get('account')!=api.base.rsplit('/',1)[1]:raise SafeError('cleanup account mismatch')
    if not NAME.fullmatch(state.get('name','')) or not state.get('deployment_id'):
        raise SafeError('unresolved creation; retain journal for manual reconciliation')
    if not state.get('namespace_ids') or any(not HEX.fullmatch(v or '') for v in state['namespace_ids']):raise SafeError('recorded namespace IDs invalid')
    if any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}',v or '') for v in state.get('application_ids',[])):raise SafeError('recorded application IDs invalid')
    settings=api.call('GET','/workers/scripts/'+state['name']+'/settings',absent=True)
    if settings is not None:check_identity(api,state)
    elif state.get('cleanup_phase') not in ['deleting_worker','worker_deleted']:
        raise SafeError('Worker missing outside recorded cleanup; retain journal')
    for app_id in state['application_ids']:
        path='/containers/applications/'+app_id
        app=api.call('GET',path,absent=True)
        if app is not None:
            if app.get('id')!=app_id or app.get('durable_objects',{}).get('namespace_id') not in state['namespace_ids']:
                raise SafeError('container application identity changed')
            api.call('DELETE',path)
            if api.call('GET',path,absent=True) is not None:raise SafeError('application deletion unconfirmed')
    if settings is not None:
        check_identity(api,state)
        state['cleanup_phase']='deleting_worker';write_state(state_path,state)
        api.call('DELETE','/workers/scripts/'+state['name'])
        if api.call('GET','/workers/scripts/'+state['name']+'/settings',absent=True) is not None:raise SafeError('Worker deletion unconfirmed')
    state['cleanup_phase']='worker_deleted';write_state(state_path,state)
    remaining=[]
    for page in range(1,101):
        values=api.call('GET',f'/workers/durable_objects/namespaces?per_page=100&page={page}')
        if not isinstance(values,list):raise SafeError('namespace inventory unverified')
        remaining.extend(v.get('id') for v in values)
        if len(values)<100:break
    else:raise SafeError('namespace inventory pagination incomplete')
    if any(v in remaining for v in state['namespace_ids']):raise SafeError('namespace deletion unconfirmed; preserve journal')
    state['phase']='deleted';write_state(state_path,state)
    os.rename(state_path,str(state_path)+'.deleted')
    return {'deleted':True,'name':state['name'],'application_ids':state['application_ids'],'namespace_ids':state['namespace_ids']}

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['preflight','up','down']);p.add_argument('--key-file',required=True);p.add_argument('--account',required=True);p.add_argument('--state');p.add_argument('--bundle');a=p.parse_args()
    try:
        api=API(token(a.key_file),a.account)
        if a.action=='preflight':result={'subdomain':preflight(api),'account':a.account,'mutations':0}
        elif not a.state:raise SafeError('explicit private state path required')
        elif a.action=='up':result=up(api,a.account,Path(a.state),a.bundle)
        else:result=down(api,Path(a.state))
        print(json.dumps(result))
    except SafeError as e:
        print(str(e)+"; preserve lifecycle journal; no mutation retried.",file=sys.stderr);return 1
    except (OSError,ValueError,TypeError,KeyError):
        # No exception body/URL/local secret material can reach logs.
        print('Cloudflare operation stopped; preserve lifecycle journal and inspect fixed operation diagnostics.',file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
