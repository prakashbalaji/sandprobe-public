package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

// PRV-14: the canary's image, pinned by digest as test/probe.sh pins it, and where the probe sits in the box. DKR-1:
// the probe's idle mode, the container's entrypoint unless the person names one. DKR-4: Sandprobe's own scratch tmpfs.
const (
	dockerCanaryImage = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	dockerProbePath   = "/opt/sandprobe/sandprobe-probe"
	dockerIdle        = "-idle"
	dockerScratch     = "/opt/sandprobe/scratch"
	dockerScratchSpec = dockerScratch + ":rw,noexec,nosuid,nodev,size=16m,mode=1777"
	dockerResidual    = "Egress is measured to a canary on a network Sandprobe created, with the box's resolver pointed at it: " +
		"a receipt proves the box can send data out to an address it was given, not that it reaches the internet (PRV-14)."
)

// namesNetwork says whether the person's docker run options already choose the box's network.
func namesNetwork(opts []string) bool {
	for _, o := range opts {
		if o == "--network" || o == "--net" || strings.HasPrefix(o, "--network=") || strings.HasPrefix(o, "--net=") {
			return true
		}
	}
	return false
}

// option finds a docker run option the person gave, as "--name value" or "--name=value": its value, and whether it
// was there. A bool option given bare has the value "true".
func option(opts []string, name string, takesValue bool) (string, bool) {
	value, found := "", false
	for i, o := range opts {
		switch {
		case strings.HasPrefix(o, name+"="):
			value, found = strings.TrimPrefix(o, name+"="), true
		case o == name && takesValue && i+1 < len(opts):
			value, found = opts[i+1], true
		case o == name && !takesValue:
			value, found = "true", true
		}
	}
	return value, found
}

// userEntrypoint is the person's own --entrypoint, if they gave one: then it runs, not Sandprobe's idle process (DKR-1).
func userEntrypoint(opts []string) (string, bool) { return option(opts, "--entrypoint", true) }

// namesHealth: the person's options set the container's health check, which is then theirs to keep (DKR-1).
func namesHealth(opts []string) bool {
	for _, o := range opts {
		if o == "--no-healthcheck" || strings.HasPrefix(o, "--no-healthcheck=") || strings.HasPrefix(o, "--health-") {
			return true
		}
	}
	return false
}

// readOnlyRoot: the person's options make the root read-only, so the probe gets Sandprobe's own scratch (DKR-4).
func readOnlyRoot(opts []string) bool {
	v, ok := option(opts, "--read-only", false)
	on, err := strconv.ParseBool(v)
	return ok && err == nil && on
}

// boxArgs is the docker run command for the box: Sandprobe's network and resolver only when the person named no
// network, then their options unchanged, then Sandprobe's own idle entrypoint unless they named one (DKR-1), with no
// init of Docker's ahead of it unless they named --init and no image health check unless they named a health option,
// its scratch on a read-only root (DKR-4), the probe, read-only, and the image, with the idle process's one argument.
func boxArgs(network, canaryIP, probe, image string, opts []string) []string {
	args := []string{"run", "-d"}
	if !namesNetwork(opts) {
		args = append(args, "--network", network, "--dns", canaryIP)
	}
	args = append(args, opts...)
	_, theirs := userEntrypoint(opts)
	if !theirs {
		args = append(args, "--entrypoint", dockerProbePath)
		if _, init := option(opts, "--init", false); !init {
			args = append(args, "--init=false")
		}
		if !namesHealth(opts) {
			args = append(args, "--no-healthcheck")
		}
	}
	if readOnlyRoot(opts) {
		args = append(args, "--tmpfs", dockerScratchSpec)
	}
	args = append(args, "-v", probe+":"+dockerProbePath+":ro", image)
	if !theirs {
		args = append(args, dockerIdle)
	}
	return args
}

func dockerPlan(image, user string, opts []string) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	net := "a network Sandprobe creates, with the box's resolver pointed at the canary"
	if namesNetwork(opts) {
		net = "the network your options name"
	}
	given := "none"
	if len(opts) > 0 {
		given = strings.Join(opts, " ")
	}
	creates := []string{"a bridge network on a free 172.30.N.0/24", "a canary container on it (" + dockerCanaryImage[:18] + ", pinned)",
		"a throwaway container from " + image + " on " + net + "; your docker run options: " + given}
	if readOnlyRoot(opts) { // DKR-4
		creates = append(creates, "Sandprobe's own addition: a 16 MB tmpfs at "+dockerScratch+" for the probe's scratch, since the root is read-only; no check counts it")
	}
	idle := "nothing but the probe, and Sandprobe's own idle process (the probe in its idle mode) as the container's entrypoint: "
	counted := ", and SEC-2 and SEC-5 don't count the idle process once Docker's record confirms it is PID 1 (DKR-1, DKR-2)"
	ep, theirs := userEntrypoint(opts)
	health := theirs || namesHealth(opts) // the image's health check is left on
	var runs []string
	switch {
	case theirs:
		runs = []string{"the probe, and your --entrypoint " + ep + " as the container's main process, with no arguments: " +
			"it runs, and SEC-2 and SEC-5 count it like any other process (DKR-1)"}
	case health:
		runs = []string{idle + "your image's entrypoint and command don't run" + counted}
	default:
		runs = []string{idle + "your image's entrypoint, command and health check don't run (--no-healthcheck)" + counted}
	}
	if health {
		runs = append(runs, "the image's health check, if it has one, as Docker schedules it with your options: "+
			"SEC-2 and SEC-5 count it if it runs during the probe (DKR-1)")
	}
	return planDoc{Provider: "docker",
		Creates:    creates,
		LaunchPath: "docker exec, as " + user,
		Probe:      "bind-mounted read-only at " + dockerProbePath,
		Markers:    "none: PER-5 is skipped, since run docker creates no volume a marker could outlive the container in (DKR-5)",
		Contacts: append(append([]string{"the local canary: DNS, HTTPS 443, TCP 22, 80 and 8080, UDP 53"}, metadataContacts()...),
			"a Kubernetes API, only if the box's environment names one: a handshake, no request"),
		OpensReadOnly: append([]string{}, sec3.Targets...),
		Runs:          runs,
		Reset:         "none: with PER-5 skipped, the container is never reset (DKR-5)",
		Deletes:       "the container, only its run-created anonymous volumes, the canary and the network, by their recorded IDs, then confirms each is gone; user volumes are preserved",
		LocalProxy:    "no",
		Time:          "about 10 seconds",
		Residual:      dockerResidual,
	}
}

// dockerRunTimeout bounds a whole run, from the network's create to the probe's last answer; cleanup has its own.
var dockerRunTimeout = 5 * time.Minute

// dockerOut runs one docker command within ctx: a hung daemon or a stuck start-up is killed at the deadline or on
// Ctrl-C, and its output pipes are let go soon after, so control always reaches the cleanup (PRV-14).
func dockerOut(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.WaitDelay = 2 * time.Second
	b, err := cmd.Output()
	return strings.TrimSpace(string(b)), err
}

// probeUser is who the probe runs as: -as when given, else the created container's own user (the person's --user
// option, else the image's), else root, Docker's default. It's read from the container, never the image, so an option
// that overrides the image's user is the user graded (PRV-14).
func probeUser(as, container string) string {
	switch {
	case as != "":
		return as
	case container != "":
		return container
	}
	return "root"
}

func automaticRemoval(opts []string) bool {
	for _, option := range opts {
		if option == "--rm" || strings.HasPrefix(option, "--rm=") && option != "--rm=false" {
			return true
		}
	}
	return false
}

// Select without mutation; a lost create response never triggers another create.
func dockerSubnet(ctx context.Context) (int, error) {
	out, err := dockerOut(ctx, "network", "ls", "-q")
	if err != nil {
		return 0, fmt.Errorf("Docker network inventory unavailable")
	}
	var prefixes []netip.Prefix
	if ids := strings.Fields(out); len(ids) > 0 {
		args := append([]string{"network", "inspect", "--format", "{{range .IPAM.Config}}{{println .Subnet}}{{end}}"}, ids...)
		out, err = dockerOut(ctx, args...)
		if err != nil {
			return 0, fmt.Errorf("Docker subnet inventory unavailable")
		}
		for _, raw := range strings.Fields(out) {
			p, e := netip.ParsePrefix(raw)
			if e != nil {
				return 0, fmt.Errorf("Docker subnet inventory invalid")
			}
			prefixes = append(prefixes, p)
		}
	}
	for n := 100; n < 200; n++ {
		candidate := netip.MustParsePrefix(fmt.Sprintf("172.30.%d.0/24", n))
		free := true
		for _, p := range prefixes {
			if p.Overlaps(candidate) {
				free = false
				break
			}
		}
		if free {
			return n, nil
		}
	}
	return 0, fmt.Errorf("no free 172.30.N.0/24 in Docker's network inventory")
}

// runDocker is PRV-14: plan, approval, then the run on a throwaway container and the confirmed teardown.
func runDocker(o opts, r runFlags, image string, planOnly bool, stderr io.Writer) (int, error) {
	if r.canaryFlags { // HCN-5, PRV-14: its canary is always the local one, so a named canary is refused, never set aside
		return 0, fail("usage", "run docker always uses its own local canary (PRV-14), so it takes no -canary, -canary-url or -canary-pin",
			"drop the canary flag, or probe a running container through run exec with docker exec, which takes them", exitUsage)
	}
	if automaticRemoval(r.dockerOpts) {
		return 0, fail("usage", "--rm bypasses safe volume ownership checks", "omit --rm; Sandprobe manages and verifies teardown", exitUsage)
	}
	pre, preCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer preCancel()
	arch, err := dockerOut(pre, "info", "--format", "{{.Architecture}}")
	if err != nil {
		return 0, fail("needs_login", "Docker isn't answering", "start Docker, then run this again", exitLogin)
	}
	arch = map[string]string{"x86_64": "amd64", "aarch64": "arm64", "amd64": "amd64", "arm64": "arm64"}[arch]
	if arch == "" {
		return 0, fail("usage", "Docker runs an architecture sandprobe carries no probe for", "use Docker on amd64 or arm64", exitUsage)
	}
	if _, err := dockerOut(pre, "image", "inspect", "--format", "{{.Id}}", image); err != nil {
		return 0, fail("usage", "no local image "+image+": nothing is pulled", "docker build or docker pull it first", exitUsage)
	}
	planned := r.as
	if planned == "" {
		planned = "the container's own user: your --user option, else the image's, else root"
	}
	p := dockerPlan(image, planned, r.dockerOpts)
	if planOnly {
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
		}
		return 0, nil
	}
	switch {
	case o.yes:
	case o.tty():
		printPlan(o.stdout, p)
		fmt.Fprint(o.stdout, "\nCreate the container, run the probe and delete it? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return exitApproval, fail("needs_approval", "nothing was created: the plan wasn't approved", "sandprobe run docker "+image+" -y", exitApproval)
		}
	default: // AGT-3
		p.NeedsApproval = true
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
			fmt.Fprintln(stderr, "\nsandprobe: nothing was created. Show your person this plan, then run again with -y.")
		}
		return exitApproval, nil
	}
	probeBin, sum, err := probes.Probe(arch)
	if err != nil {
		return 0, fail("usage", err.Error(), "make", exitUsage)
	}
	canaryBin, err := probes.Canary(arch)
	if err != nil {
		return 0, fail("usage", err.Error(), "make", exitUsage)
	}
	step := func(f string, a ...any) {
		if !o.json() {
			fmt.Fprintf(stderr, "· "+f+"\n", a...)
		}
	}
	work, err := os.MkdirTemp("", "sandprobe-docker-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(work)
	os.Chmod(work, 0o755) // the box's user must reach the bind-mounted probe
	probePath, canaryPath := filepath.Join(work, "sandprobe-probe"), filepath.Join(work, "sandprobe-canary")
	if err := os.WriteFile(probePath, probeBin, 0o755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(canaryPath, canaryBin, 0o755); err != nil {
		return 0, err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, dockerRunTimeout)
	defer cancel()
	start := time.Now()
	runID := fmt.Sprintf("%d", start.UnixNano()%1_000_000_000)

	n, err := dockerSubnet(ctx)
	if err != nil {
		return 0, fail("provider_error", err.Error(), "check Docker's network inventory before retrying", exitPartial)
	}
	if ctx.Err() != nil {
		return 0, fail("provider_error", "cancelled before network creation", "retry when ready", exitPartial)
	}
	name, subnet, canaryIP := "sandprobe-"+runID, fmt.Sprintf("172.30.%d.0/24", n), fmt.Sprintf("172.30.%d.10", n)
	network, err := dockerOut(ctx, "network", "create", "--subnet", subnet, name)
	if err != nil || network == "" {
		return 0, fail("cleanup_unconfirmed", "network creation outcome unconfirmed: attempted "+name+" on "+subnet, "inspect Docker for this attempted name; no deletion or retry without the original returned ID", exitCleanup)
	}
	step("network %s on %s, and a local canary", network[:12], subnet)

	var c *host.DockerCanary
	var run *host.Run
	var boxID, residual string
	volumes := new(host.DockerVolumeTracker)
	left := []string{}
	teardown := func() {
		tctx, tcancel := context.WithTimeout(context.Background(), 2*time.Minute) // even after Ctrl-C
		defer tcancel()
		step("deleting the container, the canary and the network, by ID")
		switch {
		case run != nil:
			if err := host.Teardown(tctx, run); err != nil {
				left = append(left, "container "+run.Box.ID())
			}
		case boxID != "":
			exec.CommandContext(tctx, "docker", "rm", "-f", boxID).Run()
			if !dockerGone(tctx, "container", boxID) {
				left = append(left, "container "+boxID)
			}
		}
		left = append(left, volumes.Cleanup(tctx)...)
		if c != nil {
			c.StopContext(tctx)
			if !dockerGone(tctx, "container", c.Container) {
				left = append(left, "canary container "+c.Container)
			}
		}
		exec.CommandContext(tctx, "docker", "network", "rm", network).Run()
		if !dockerGone(tctx, "network", network) {
			left = append(left, "network "+network)
		}
	}
	c, err = host.StartDockerCanary(ctx, network, canaryIP, dockerCanaryImage, canaryPath, "sandprobe.test")
	if err == nil {
		step("starting a throwaway container from %s", image)
		args := boxArgs(network, canaryIP, probePath, image, r.dockerOpts)
		var out, user string
		baseline, inventoryErr := volumes.Snapshot(ctx)
		if inventoryErr != nil {
			err = inventoryErr
		} else {
			out, err = dockerOut(ctx, args...)
			if err != nil {
				volumes.CreateUnconfirmed()
				if ctx.Err() != nil {
					err = fmt.Errorf("docker didn't start the container from %s in time", image)
				} else {
					err = fmt.Errorf("docker couldn't start the container from %s with those options", image)
				}
			}
		}
		if err == nil {
			boxID = out
			err = volumes.Capture(ctx, boxID, baseline)
		}
		if err == nil {
			select { // a start-up that fails at once
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
			switch running, cause, ok := dockerState(ctx, boxID, r.dockerOpts); {
			case !ok:
				err = fmt.Errorf("Docker couldn't say whether the container from %s is running, so the probe didn't run", image)
			case !running:
				err = dockerStopErr("before the probe ran", cause, image, r.as, r.dockerOpts)
			}
		}
		if err == nil {
			var own string
			if own, err = dockerOut(ctx, "inspect", "--type", "container", "--format", "{{.Config.User}}", boxID); err != nil {
				err = fmt.Errorf("couldn't read the container's user")
			}
			user = probeUser(r.as, own)
		}
		if err == nil {
			scratch := ""
			if readOnlyRoot(r.dockerOpts) {
				scratch = dockerScratch
			}
			step("running the probe as %s", user)
			healthOff := dockerHealthOff(ctx, boxID)
			run, err = host.Execute(ctx, &host.DockerBox{Container: boxID, User: user, ProbePath: dockerProbePath, Args: args, VolumeTracker: volumes}, c,
				host.Options{Mode: "exec", ProbeSHA256: sum, AllowLocalProxy: r.allowLocalProxy, OwnInit: dockerOwnInit(ctx, boxID, r.dockerOpts), Scratch: scratch})
			if err != nil || run.Report.Invalid != "" { // DKR-3: a container that stopped says why, never a bare invalid run
				if running, cause, ok := dockerState(ctx, boxID, r.dockerOpts); ok && !running {
					err = dockerStopErr("while the probe ran", cause, image, r.as, r.dockerOpts)
				}
			}
			if err == nil {
				residual = dockerRunResidual(r.dockerOpts, run.Input.OwnInit, healthOff)
			}
		}
	}
	teardown()
	cleanup, cleaned := "deleted: the container, its run-created anonymous volumes, the canary and the network, each confirmed gone by its ID; user volumes preserved", len(left) == 0
	if !cleaned {
		cleanup = "NOT confirmed deleted: " + strings.Join(left, ", ") + "; remove each by that ID"
		fmt.Fprintf(stderr, "sandprobe: %s\n", cleanup)
	}
	if err != nil {
		var stopped *cliError
		if errors.As(err, &stopped) { // DKR-3: its own message and fix
			stopped.exit = failExit(cleaned)
			return 0, stopped
		}
		return 0, fail("provider_error", err.Error(), "see the message; the cleanup is above", failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "docker", BoxName: image, CreatedBySandprobe: true,
		StartedAt: start, Duration: time.Since(start), Cleanup: cleanup, Residual: residual})
	return finish(o, r, d, cleaned)
}

// dockerGone: Docker answered an inspect of this ID with its definitive "no such", not some other failure.
func dockerGone(ctx context.Context, kind, id string) bool {
	args := []string{"inspect", "--type", kind, "--format", "{{.Id}}", id}
	if kind == "network" {
		args = []string{"network", "inspect", "--format", "{{.Id}}", id}
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	s := strings.ToLower(string(out))
	return err != nil && (strings.Contains(s, "no such") || strings.Contains(s, "not found"))
}

// dockerState is DKR-3: Docker's record of whether the container runs and, if it doesn't, what stopped and how, read
// with a narrow format, never the whole inspect document or the logs. ok is false when Docker didn't answer.
func dockerState(ctx context.Context, id string, opts []string) (running bool, cause string, ok bool) {
	out, err := dockerOut(ctx, "inspect", "--type", "container", "--format", "{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}", id)
	f := strings.Fields(out)
	if err != nil || len(f) != 3 {
		return false, "", false
	}
	if f[0] == "true" {
		return true, "", true
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return false, "", false
	}
	who := "Sandprobe's idle process, the container's entrypoint,"
	if ep, theirs := userEntrypoint(opts); theirs {
		who = "your --entrypoint " + ep
	}
	if f[2] == "true" { // Docker's own record; an exit code alone never names a signal, since a process can exit 137 itself
		return false, fmt.Sprintf("%s was killed by Docker for running out of memory (exit code %d)", who, code), true
	}
	return false, fmt.Sprintf("%s exited with code %d", who, code), true
}

// dockerStopErr is DKR-3's error: what stopped, when and how, and a fix that runs as pasted. The person's own
// --entrypoint is dropped, so Sandprobe keeps the container running itself; if its own idle process stopped, the run
// without the person's docker options shows whether one of them stops it.
func dockerStopErr(when, cause, image, as string, opts []string) error {
	var keep []string
	_, theirs := userEntrypoint(opts)
	for i := 0; theirs && i < len(opts); i++ {
		switch o := opts[i]; {
		case o == "--entrypoint":
			i++ // and its value
		case strings.HasPrefix(o, "--entrypoint="):
		default:
			keep = append(keep, o)
		}
	}
	fix := "sandprobe run docker " + shellWord(image)
	if as != "" {
		fix += " -as " + shellWord(as)
	}
	fix += " -y"
	if len(keep) > 0 {
		fix += " --"
		for _, o := range keep {
			fix += " " + shellWord(o)
		}
	}
	return fail("provider_error", "the container stopped "+when+": "+cause, fix, exitPartial)
}

// shellWord quotes one word for a POSIX shell, only when it needs it.
func shellWord(w string) string {
	if w != "" && strings.Trim(w, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@%+,") == "" {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}

// dockerOwnInit is DKR-2: PID 1 of the box is Sandprobe's idle process, read from Docker's own record of the
// container, never from the box. Docker started its entrypoint with exactly the idle argument, in the container's own
// PID namespace, with no init of Docker's ahead of it, so PID 1 there is that process: no other can take PID 1, and
// the idle process never execs. Anything else, or a record Docker doesn't give, names nothing.
func dockerOwnInit(ctx context.Context, id string, opts []string) bool {
	if _, theirs := userEntrypoint(opts); theirs {
		return false
	}
	out, err := dockerOut(ctx, "inspect", "--type", "container", "--format",
		"{{json .Path}} {{json .Args}} {{json .HostConfig.PidMode}} {{json .HostConfig.Init}}", id)
	return err == nil && out == `"`+dockerProbePath+`" ["`+dockerIdle+`"] "" false`
}

// dockerHealthOff is DKR-1: Docker's own record of the container says no health check runs in it, either because the
// image has none or because it is NONE (--no-healthcheck). Anything else, or no answer, is a health check that may run.
func dockerHealthOff(ctx context.Context, id string) bool {
	out, err := dockerOut(ctx, "inspect", "--type", "container", "--format", "{{json .Config.Healthcheck}}", id)
	return err == nil && healthRecordOff(out)
}

// healthRecordOff reads Docker's JSON record of a container's health check: off only as null or a test of NONE.
func healthRecordOff(record string) bool {
	var hc *struct{ Test []string }
	if json.Unmarshal([]byte(record), &hc) != nil {
		return false
	}
	return hc == nil || len(hc.Test) == 1 && hc.Test[0] == "NONE"
}

// dockerRunResidual is the report's residual (PRV-14), with what Sandprobe ran or added in the box (DKR-1, DKR-2,
// DKR-4), from the host's own facts and Docker's record.
func dockerRunResidual(opts []string, ownInit, healthOff bool) string {
	r := dockerResidual
	switch ep, theirs := userEntrypoint(opts); {
	case theirs:
		r += " Your --entrypoint " + ep + " ran as the container's main process, and SEC-2 and SEC-5 counted it like any other process (DKR-1)."
	case ownInit && healthOff:
		r += " Sandprobe's own idle process was the container's entrypoint and no health check ran, so the image's own entrypoint, " +
			"command and health check never ran and SEC-2 and SEC-5 saw none of their processes; the idle process, PID 1 by Docker's record, " +
			"wasn't counted (DKR-1, DKR-2)."
	case ownInit:
		r += " Sandprobe's own idle process was the container's entrypoint, so the image's own entrypoint and command never ran; " +
			"the idle process, PID 1 by Docker's record, wasn't counted (DKR-1, DKR-2)."
	default:
		r += " Sandprobe's own idle process was the container's entrypoint, so the image's own entrypoint and command never ran; " +
			"Docker's record didn't confirm it is PID 1 of the container's own PID namespace (your --init or --pid, say), " +
			"so SEC-2 and SEC-5 counted it (DKR-1, DKR-2)."
	}
	if !healthOff {
		r += " Docker's record shows a health check in the container, so it may have run during the probe, and SEC-2 and SEC-5 " +
			"counted it if it did (DKR-1)."
	}
	if readOnlyRoot(opts) {
		r += " The root was read-only, so Sandprobe added a 16 MB tmpfs at " + dockerScratch + " for the probe's own scratch; " +
			"no check counts it (DKR-4)."
	}
	return r
}
