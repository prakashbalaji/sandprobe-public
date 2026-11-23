package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// RUN-15: a real non-root offline task, with the same nine cases and protected
// HOME. This is local calibration, never a provider/model measurement.
func TestProtectedHomeWorkloadDocker(t *testing.T) {
	if os.Getenv("SANDPROBE_REFERENCE_WORKLOAD") != "1" {
		t.Skip("opt-in local Docker workload check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const image = "python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
	out, err := exec.CommandContext(ctx, "docker", "create", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--cpus", "1", "--memory", "1g", "--workdir", "/workspace", "-e", "HOME="+WorkloadHome, "-e", "XDG_CACHE_HOME="+WorkloadCache, "--tmpfs", "/tmp:rw,uid=10001,gid=10001,mode=0700,size=64m", "--tmpfs", "/workspace:rw,uid=10001,gid=10001,mode=0700,size=64m", "--tmpfs", WorkloadHome+":ro,uid=0,gid=0,mode=0555,size=1m", image, "python", "-I", "-c", "import time; time.sleep(180)").Output()
	if err != nil {
		t.Fatal("protected-home fixture create failed")
	}
	id := strings.TrimSpace(string(out))
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) {
		t.Fatal("original fixture identity unavailable")
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if exec.CommandContext(c, "docker", "rm", "-f", id).Run() != nil {
			t.Error("fixture cleanup failed")
			return
		}
		raw, e := exec.CommandContext(c, "docker", "inspect", id).CombinedOutput()
		if e == nil || !strings.Contains(string(raw), "No such object: "+id) {
			t.Error("fixture absence unconfirmed")
		}
	})
	if exec.CommandContext(ctx, "docker", "start", id).Run() != nil {
		t.Fatal("fixture start failed")
	}
	root := filepath.Join("..", "..")
	for name, source := range map[string]string{"coding.py": filepath.Join(root, "experiments/eks-agent/coding.py"), "project_exec.py": filepath.Join(root, "experiments/eks-agent/project_exec.py"), "reference.py": filepath.Join(root, "experiments/eks-agent/fixtures/solution.py"), "workload_home_guard.py": "workload_home_guard.py"} {
		data, err := os.ReadFile(source)
		if err != nil || len(data) > 65536 {
			t.Fatal("owned fixture source unavailable", name)
		}
		// Write through the running unprivileged guest into its writable tmpfs;
		// do not rely on daemon archive-copy support for a read-only rootfs.
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", id, "python", "-I", "-c", `import os,sys
data=sys.stdin.buffer.read(65537)
assert len(data)<=65536
fd=os.open('/tmp/'+sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
with os.fdopen(fd,'wb') as f:f.write(data)`, name)
		cmd.Stdin = bytes.NewReader(data)
		if cmd.Run() != nil {
			t.Fatal("owned fixture upload failed", name)
		}
	}
	script := `import errno,json,os,pathlib,runpy,sys
sys.path.insert(0,'/tmp')
import coding
home='/opt/sandprobe/home'
cache=pathlib.Path('/workspace/.cache');cache.mkdir(mode=0o700)
(cache/'writable').write_text('synthetic')
try:
    f=open(home+'/.bashrc','x')
except OSError as e:
    assert e.errno in (errno.EACCES,errno.EPERM,errno.EROFS)
else:
    f.close();raise RuntimeError('startup write succeeded')
reference=pathlib.Path('/tmp/reference.py').read_text()
class ModelStub:
    def converse(self,**kwargs):return {'output':{'message':{'content':[{'text':json.dumps({'solution.py':reference})}]}}}
result=coding.perform(ModelStub(),'mistral.ministral-3-3b-instruct','/workspace',home=home)
assert result['independent_verification']=='passed' and result['functional_tests']==9
context=runpy.run_path('/tmp/workload_home_guard.py',run_name='owned_home_guard')['collect']()
print(json.dumps({'functional_tests':9,'home_context':context,'cache_writable':True,'startup_refused':True}))`
	out, err = exec.CommandContext(ctx, "docker", "exec", id, "python", "-I", "-c", script).Output()
	if err != nil {
		t.Fatal("protected-home task or controls failed")
	}
	var result struct {
		Tests   int             `json:"functional_tests"`
		Home    json.RawMessage `json:"home_context"`
		Cache   bool            `json:"cache_writable"`
		Refused bool            `json:"startup_refused"`
	}
	if json.Unmarshal(out, &result) != nil || result.Tests != 9 || !result.Cache || !result.Refused {
		t.Fatal("task/control evidence unavailable")
	}
	if _, err = workloadHomeHash(result.Home); err != nil {
		t.Fatal(err)
	}
	t.Log("Nine cases passed with writable project/cache and refused startup write; original fixture cleanup verified.")
}
