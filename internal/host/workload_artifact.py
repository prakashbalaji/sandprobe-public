# RUN-23: common bounded artifact write/readback, executed only in the owned guest.
import base64,errno,hashlib,json,os,stat,sys
r={"agent_uid":os.getuid(),"agent_gid":os.getgid(),"root_uid":0,"root_gid":0,"root_mode":0,"directory":False,"verified":False,"bytes":0,"sha256":"","failure_kind":"root_unavailable"}
try:
 s=os.stat("/persist",follow_symlinks=False)
 r.update(root_uid=s.st_uid,root_gid=s.st_gid,root_mode=stat.S_IMODE(s.st_mode),directory=stat.S_ISDIR(s.st_mode))
 if not r["directory"]:raise OSError(errno.ENOTDIR,"root")
 d=os.open("/persist",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  r["failure_kind"]="write_unavailable"
  data=base64.b64decode(sys.argv[2],validate=True)
  with os.fdopen(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d),"wb") as f:f.write(data)
  r["failure_kind"]="readback_unavailable"
  with os.fdopen(os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d),"rb") as f:actual=f.read(len(data)+1)
  if actual==data:r.update(verified=True,bytes=len(data),sha256=hashlib.sha256(actual).hexdigest(),failure_kind="passed")
 finally:os.close(d)
except OSError:pass
print(json.dumps(r,separators=(",",":")))
