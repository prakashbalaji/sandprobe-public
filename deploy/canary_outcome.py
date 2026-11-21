"""RUN-16 durable, nonce-bound phase barrier. No cloud operations live here."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

SCHEMA='sandprobe.canary-outcome/1'
FIELDS={'schema','run_id','nonce','delegate_sha256','state_file','phase','terminal','outcome','quiescence_verified'}

def _object(pairs):
    out={};seen=set()
    for key,value in pairs:
        if key.lower() in seen:raise ValueError()
        seen.add(key.lower());out[key]=value
    return out

def _private(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()

def _load(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        _private(os.fstat(source.fileno()));raw=source.read(8193)
    if len(raw)>8192:raise ValueError()
    d=json.loads(raw,object_pairs_hook=_object)
    if (not isinstance(d,dict) or set(d)!=FIELDS or d['schema']!=SCHEMA or not re.fullmatch('[a-f0-9]{16}',d['run_id'])
            or not re.fullmatch('[a-f0-9]{48}',d['nonce']) or not re.fullmatch('[a-f0-9]{64}',d['delegate_sha256'])
            or not isinstance(d['state_file'],str) or Path(d['state_file']).parent!=Path(path).parent or Path(d['state_file']).name!='canary.state'
            or d['phase'] not in ['precreate','mutation_possible'] or type(d['terminal']) is not bool
            or type(d['quiescence_verified']) is not bool or d['outcome'] not in ['running','completed','failed','interrupted']):raise ValueError()
    return d

@contextlib.contextmanager
def _lock(path):
    path=Path(path);p=os.lstat(path.parent)
    if not stat.S_ISDIR(p.st_mode) or p.st_uid!=os.getuid() or stat.S_IMODE(p.st_mode)&0o077:raise ValueError()
    fd=os.open(str(path)+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        _private(os.fstat(fd));fcntl.flock(fd,fcntl.LOCK_EX);yield
    finally:os.close(fd)

def _store(path,data,exclusive=False):
    path=Path(path)
    if exclusive and os.path.lexists(path):raise ValueError()
    fd,name=tempfile.mkstemp(prefix='.canary-outcome-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as output:
            json.dump(data,output,sort_keys=True,separators=(',',':'));output.flush();os.fsync(output.fileno())
        os.replace(name,path)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        if os.path.exists(name):os.unlink(name)

def begin(path,run,nonce,state,delegate):
    d={'schema':SCHEMA,'run_id':run,'nonce':nonce,'state_file':str(state),
       'delegate_sha256':hashlib.sha256(Path(delegate).read_bytes()).hexdigest(),
       'phase':'precreate','terminal':False,'outcome':'running','quiescence_verified':False}
    with _lock(path):
        _store(path,d,exclusive=True)
        _load(path)
    return d

def mutation(path,nonce,state,delegate):
    with _lock(path):
        d=_load(path)
        if d['nonce']!=nonce or d['state_file']!=str(state) or d['delegate_sha256']!=hashlib.sha256(Path(delegate).read_bytes()).hexdigest() or d['terminal']:raise ValueError()
        d['phase']='mutation_possible';_store(path,d)

def finish(path,nonce,outcome,quiescent):
    if quiescent is not True or outcome not in ['completed','failed','interrupted']:raise ValueError()
    with _lock(path):
        d=_load(path)
        if d['nonce']!=nonce or d['terminal']:raise ValueError()
        d.update(terminal=True,outcome=outcome,quiescence_verified=True);_store(path,d)
    return d

def no_create(path,run,nonce,state,digest):
    try:
        with _lock(path):d=_load(path)
        return (d['run_id']==run and d['nonce']==nonce and d['state_file']==str(state)
                and d['delegate_sha256']==digest and d['terminal'] and d['quiescence_verified']
                and d['phase']=='precreate' and d['outcome'] in ['failed','interrupted'])
    except (OSError,ValueError,TypeError,KeyError):return False

def stopped(path,run,nonce,state,digest):
    try:
        with _lock(path):d=_load(path)
        return (d['run_id']==run and d['nonce']==nonce and d['state_file']==str(state)
                and d['delegate_sha256']==digest and d['terminal'] and d['quiescence_verified']
                and d['outcome'] in ['completed','failed','interrupted'])
    except (OSError,ValueError,TypeError,KeyError):return False

if __name__=='__main__':
    try:
        if len(sys.argv)!=6 or sys.argv[1]!='mutation':raise ValueError()
        mutation(*sys.argv[2:])
    except Exception:
        print('canary phase update failed',file=sys.stderr);raise SystemExit(1)
