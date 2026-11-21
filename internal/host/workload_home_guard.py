"""RUN-15: metadata only for our fixed, owned startup-home fixture."""
import json
import os
import stat

HOME = '/opt/sandprobe/home'
PATHS = ['/', '/opt', '/opt/sandprobe', HOME]

def validate(context):
    if (not isinstance(context,dict) or set(context)!={'schema','home','nodes'}
            or context['schema']!='sandprobe.workload-home/1' or context['home']!=HOME
            or not isinstance(context['nodes'],list) or len(context['nodes'])!=len(PATHS)):
        raise ValueError('invalid owned home context')
    for node,path in zip(context['nodes'],PATHS):
        if (not isinstance(node,dict) or set(node)!={'path','device','inode','uid','mode','directory'}
                or node['path']!=path or node['directory'] is not True
                or any(type(node[k]) is not int for k in ['device','inode','uid','mode'])
                or not 0<node['device']<2**64 or not 0<node['inode']<2**64
                or node['uid']!=0 or not 0<=node['mode']<=0o777
                or node['mode']&0o022 or not node['mode']&1
                or path==HOME and node['mode']!=0o555):
            raise ValueError('invalid owned home context')
    return context

def collect():
    nodes=[]
    for path in PATHS:
        s=os.lstat(path)
        nodes.append({'path':path,'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,
                      'mode':stat.S_IMODE(s.st_mode),'directory':stat.S_ISDIR(s.st_mode)})
    return validate({'schema':'sandprobe.workload-home/1','home':HOME,'nodes':nodes})

if __name__=='__main__':
    print(json.dumps(collect(),sort_keys=True,separators=(',',':')))
