"""RUN-16: quiesce the trusted, non-detaching delegate/toolchain process group.

This is not containment for arbitrary code that can setsid/double-fork. The
delegate barrier is serialized with terminal sealing and rejects late updates.
"""
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

class QuiescenceError(Exception):
    pass

def _quiescent(group):
    result=subprocess.run(['ps','-axo','pgid=,stat='],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
    if result.returncode or len(result.stdout)>1<<20:raise QuiescenceError()
    for line in result.stdout.decode('ascii').splitlines():
        fields=line.split()
        if len(fields)!=2 or not fields[0].isdigit():raise QuiescenceError()
        if int(fields[0])==group and not fields[1].startswith('Z'):return False
    return True

def run_quiescent(args,env,timeout,output,errors,confirmed):
    read_fd,write_fd=os.pipe()
    process=None
    try:
        process=subprocess.Popen([sys.executable,'-I',str(Path(__file__).resolve()),'--sentinel',str(write_fd),*args],
            stdin=subprocess.DEVNULL,stdout=output,stderr=errors,env=env,start_new_session=True,pass_fds=(write_fd,))
        os.close(write_fd);write_fd=-1
        ready,_,_=select.select([read_fd],[],[],timeout)
        if not ready:raise subprocess.TimeoutExpired(args,timeout)
        result=os.read(read_fd,32)
        if not result.endswith(b'\n') or len(result)>16:raise RuntimeError('supervisor completion unavailable')
        return int(result.strip())
    finally:
        os.close(read_fd)
        if write_fd>=0:os.close(write_fd)
        if process is not None:
            try:
                # The unreaped sentinel retains its original PID/group identity.
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=10)
                deadline=time.monotonic()+3
                while not _quiescent(process.pid):
                    if time.monotonic()>=deadline:raise QuiescenceError()
                    time.sleep(0.05)
            except BaseException:
                raise QuiescenceError() from None
        confirmed()

def _sentinel(fd,args):
    try:
        child=subprocess.Popen(args,stdin=sys.stdin,stdout=sys.stdout,stderr=sys.stderr,close_fds=True)
        code=child.wait()
    except BaseException:
        code=127
    os.write(fd,(str(code)+'\n').encode());os.close(fd)
    # Never relinquish the group leader until the parent tears down the group.
    while True:time.sleep(3600)

if __name__=='__main__':
    if len(sys.argv)<4 or sys.argv[1]!='--sentinel':raise SystemExit(2)
    _sentinel(int(sys.argv[2]),sys.argv[3:])
