package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
)

// DockerBox is a local container reached with docker exec as its agent user: the fixtures' box (Tests). With Args,
// it can be reset by recreating it from them (TWN-3's recreate model), keeping the volumes Sandprobe created (Vols).
type DockerBox struct {
	Container string   // the ID docker run returned
	User      string   // the agent's user
	ProbePath string   // where the shipped probe sits in the box
	Args      []string // the docker run arguments that create it; none means it can't be reset
	Vols      []string // names of the volumes Sandprobe created for it
	// VolumeTracker preserves original volume ownership across reset and failure.
	// The CLI finalizes tracked volume cleanup after removing the last container.
	VolumeTracker *DockerVolumeTracker
	// Hook, nil outside the fixtures, runs at each step of a reset ("removed": the old box gone; "created": the new
	// one up), so the reset fixture can inject faults where a real provider's reset could go wrong.
	Hook func(ctx context.Context, stage string, d *DockerBox)
}

func (d *DockerBox) Storage(ctx context.Context) (Storage, error) {
	if len(d.Args) == 0 {
		return Storage{}, nil
	}
	st := Storage{Model: "recreate"}
	for _, name := range d.Vols {
		v, err := d.volume(ctx, name)
		if err != nil {
			return Storage{}, err
		}
		st.Volumes = append(st.Volumes, v)
	}
	return st, nil
}

// volume is one of Sandprobe's volumes as the provider identifies it: its name and creation time, so a volume
// recreated under the same name is another volume, and where this container mounts it.
func (d *DockerBox) volume(ctx context.Context, name string) (obs.Volume, error) {
	created, err := exec.CommandContext(ctx, "docker", "volume", "inspect", "-f", "{{.CreatedAt}}", name).Output()
	if err != nil {
		return obs.Volume{}, fmt.Errorf("volume %s: %w", name, err)
	}
	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{json .Mounts}}", d.Container).Output()
	if err != nil {
		return obs.Volume{}, fmt.Errorf("the box's mounts: %w", err)
	}
	var mounts []struct{ Type, Name, Destination string }
	if err := json.Unmarshal(out, &mounts); err != nil {
		return obs.Volume{}, err
	}
	v := obs.Volume{ID: name + "@" + strings.TrimSpace(string(created))}
	for _, m := range mounts {
		if m.Type == "volume" && m.Name == name {
			v.MountPath = m.Destination
		}
	}
	return v, nil
}

// Reset recreates the box from its arguments: the old container removed, a new one created with the same volumes.
func (d *DockerBox) Reset(ctx context.Context) (Box, *obs.ResetEvidence, error) {
	ev := &obs.ResetEvidence{Model: "recreate", OperationID: token("op"), BoxBefore: d.Container, Volumes: map[string][2]obs.Volume{}}
	before := map[string]obs.Volume{}
	for _, name := range d.Vols {
		v, err := d.volume(ctx, name)
		if err != nil {
			return nil, ev, err
		}
		before[name] = v
	}
	var snapshot *DockerVolumeSnapshot
	if d.VolumeTracker != nil {
		var err error
		if snapshot, err = d.VolumeTracker.Snapshot(ctx); err != nil {
			return nil, ev, err
		}
	}
	if err := exec.CommandContext(ctx, "docker", "rm", "-f", d.Container).Run(); err != nil {
		return nil, ev, fmt.Errorf("removing the old box: %w", err)
	}
	if d.Hook != nil {
		d.Hook(ctx, "removed", d)
	}
	out, err := exec.CommandContext(ctx, "docker", d.Args...).Output()
	if err != nil {
		if d.VolumeTracker != nil {
			d.VolumeTracker.CreateUnconfirmed()
		}
		return nil, ev, fmt.Errorf("recreating the box: %w", err)
	}
	nb := &DockerBox{Container: strings.TrimSpace(string(out)), User: d.User, ProbePath: d.ProbePath, Args: d.Args, Vols: d.Vols, Hook: d.Hook, VolumeTracker: d.VolumeTracker}
	ev.Done, ev.BoxAfter = true, nb.Container
	if nb.VolumeTracker != nil {
		if err := nb.VolumeTracker.Capture(ctx, nb.Container, snapshot); err != nil {
			return nb, ev, err
		}
	}
	if d.Hook != nil {
		d.Hook(ctx, "created", nb)
	}
	for _, name := range d.Vols {
		v, err := nb.volume(ctx, name)
		if err != nil {
			return nb, ev, err
		}
		ev.Volumes[before[name].MountPath] = [2]obs.Volume{before[name], v}
	}
	return nb, ev, nil
}

// Teardown removes the box by its container ID, then each of Sandprobe's volumes, but only if the name still names
// the volume created for the run (name and creation time). Docker deletes volumes by name alone, so a volume made
// again under the name between that check and the deletion could still be removed: a limit of this local fixture
// adapter, stated in the spec. Gone is reported only when Docker says definitively that the resource no longer exists.
func (d *DockerBox) Teardown(ctx context.Context, vols []obs.Volume) map[string]bool {
	gone := map[string]bool{}
	exec.CommandContext(ctx, "docker", "rm", "-f", d.Container).Run()
	gone[""] = absent(ctx, "no such container", "inspect", "--type", "container", "-f", "{{.Id}}", d.Container)
	for _, v := range vols {
		name, _, _ := strings.Cut(v.ID, "@")
		created, err := exec.CommandContext(ctx, "docker", "volume", "inspect", "-f", "{{.CreatedAt}}", name).Output()
		if err != nil || name+"@"+strings.TrimSpace(string(created)) != v.ID {
			continue // gone already, replaced, or unreadable: not deleted by name, and not reported gone
		}
		if exec.CommandContext(ctx, "docker", "volume", "rm", name).Run() == nil {
			gone[v.ID] = absent(ctx, "no such volume", "volume", "inspect", "-f", "{{.Name}}", name)
		}
	}
	return gone
}

// absent: docker answered this inspect with its definitive "doesn't exist", not some other failure.
func absent(ctx context.Context, says string, args ...string) bool {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return err != nil && strings.Contains(strings.ToLower(string(out)), strings.ToLower(says))
}

func (d *DockerBox) ID() string { return d.Container }

func (d *DockerBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", append([]string{"exec", "-i", "-u", d.User, "-e", "SANDPROBE_TWIN=1",
		d.Container, d.ProbePath}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	out := &capped{max: obs.MaxDoc + 1} // one byte over the limit, so the grader sees an oversized document
	errs := &capped{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = out, errs
	if err := cmd.Run(); err != nil {
		why := strings.TrimSpace(errs.String())
		if why == "" { // docker exec reports a runtime failure (noexec, a missing file) on stdout
			why = strings.TrimSpace(string(out.Bytes()[:min(out.Len(), 200)]))
		}
		return out.Bytes(), fmt.Errorf("%w: %s", err, why)
	}
	return out.Bytes(), nil
}

// capped keeps at most max bytes and drops the rest.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// DockerCanary is the canary in a local container on the fixtures' network (Tests). The host reaches its ports
// through ports published on its own loopback, and its log through docker exec, never through the box's network.
type DockerCanary struct {
	Container string
	Addr      string // its address on the fixture network
	Dom       string
	published map[int]string // canary port -> the host's 127.0.0.1:port for it
}

// StartDockerCanary runs the canary binary (built for Linux) in a container at ip on network.
func StartDockerCanary(ctx context.Context, network, ip, image, binary, domain string) (*DockerCanary, error) {
	args := []string{"run", "-d", "--network", network, "--ip", ip, "-v", binary + ":/sandprobe-canary:ro"}
	for _, p := range []int{443, 22, 80, 8080} {
		args = append(args, "-p", fmt.Sprintf("127.0.0.1::%d", p))
	}
	args = append(args, image, "/sandprobe-canary", "-domain", domain)
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("starting the canary: %w", err)
	}
	c := &DockerCanary{Container: strings.TrimSpace(string(out)), Addr: ip, Dom: domain, published: map[int]string{}}
	for _, p := range []int{443, 22, 80, 8080} {
		out, err := exec.CommandContext(ctx, "docker", "port", c.Container, fmt.Sprintf("%d/tcp", p)).Output()
		if err != nil {
			c.Stop()
			return nil, fmt.Errorf("finding the canary's port %d: %w", p, err)
		}
		c.published[p] = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	}
	for i := 0; i < 50; i++ {
		if a, err := c.Ask(ctx, canary.Request{Op: "status"}); err == nil && a.OK {
			return c, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.Stop()
	return nil, fmt.Errorf("the canary never answered its query")
}

func (c *DockerCanary) IP() string     { return c.Addr }
func (c *DockerCanary) Domain() string { return c.Dom }

func (c *DockerCanary) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c.StopContext(ctx)
}

// StopContext removes the canary's container within ctx (PRV-14: cleanup has its own deadline).
func (c *DockerCanary) StopContext(ctx context.Context) {
	exec.CommandContext(ctx, "docker", "rm", "-f", "-v", c.Container).Run()
}

// Health is one connect the canary proves it answered, through the port docker published on the host's loopback.
func (c *DockerCanary) Health(ctx context.Context, port int, k canary.Key) bool {
	addr, ok := c.published[port]
	return ok && healthConnect(ctx, addr, port, c.Dom, k)
}

// Ask runs the canary's own client inside its container, so the control socket never leaves it.
func (c *DockerCanary) Ask(ctx context.Context, q canary.Request) (canary.Answer, error) {
	var a canary.Answer
	out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", c.Container, "/sandprobe-canary"}, CtlArgs(q)...)...).Output()
	if err != nil {
		return a, fmt.Errorf("the canary's control channel: %w", err)
	}
	return a, canary.Decode(bytes.NewReader(out), &a)
}

// CtlArgs is a request as sandprobe-canary's -ctl flags. Every value is a name, a number or nonce/proto/port, which
// the canary checks again.
func CtlArgs(q canary.Request) []string {
	args := []string{"-ctl", q.Op}
	if q.Run != "" {
		args = append(args, "-run", q.Run)
	}
	if q.TTL != 0 {
		args = append(args, "-ttl", fmt.Sprint(q.TTL))
	}
	var ws []string
	for _, w := range q.Wants {
		ws = append(ws, fmt.Sprintf("%s/%s/%d", w.Nonce, w.Proto, w.Port))
	}
	if len(ws) > 0 {
		args = append(args, "-wants", strings.Join(ws, ","))
	}
	return args
}
