package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

// PRV-14: the canary's image, pinned by digest as test/probe.sh pins it, and where the probe sits in the box.
const (
	dockerCanaryImage = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	dockerProbePath   = "/opt/sandprobe/sandprobe-probe"
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

// boxArgs is the docker run command for the box: Sandprobe's network and resolver only when the person named no
// network, then their options unchanged, then the probe, read-only, and the image.
func boxArgs(network, canaryIP, probe, image string, opts []string) []string {
	args := []string{"run", "-d"}
	if !namesNetwork(opts) {
		args = append(args, "--network", network, "--dns", canaryIP)
	}
	args = append(args, opts...)
	return append(args, "-v", probe+":"+dockerProbePath+":ro", image)
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
	return planDoc{Provider: "docker",
		Creates: []string{"a bridge network on a free 172.30.N.0/24", "a canary container on it (" + dockerCanaryImage[:18] + ", pinned)",
			"a throwaway container from " + image + " on " + net + "; your docker run options: " + given},
		LaunchPath: "docker exec, as " + user,
		Probe:      "bind-mounted read-only at " + dockerProbePath,
		Markers:    "the box's home and working directory, removed with the container",
		Contacts: append(append([]string{"the local canary: DNS, HTTPS 443, TCP 22, 80 and 8080, UDP 53"}, metadataContacts()...),
			"a Kubernetes API, only if the box's environment names one: a handshake, no request"),
		OpensReadOnly: append([]string{}, sec3.Targets...),
		Runs:          []string{"nothing but the probe"},
		Reset:         "removes the container and creates it again from the same image and options, then rechecks its markers",
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
		fmt.Fprint(o.stdout, "\nCreate the container, run, reset and delete it? [y/N] ")
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
	var boxID string
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
			select { // the image's own start-up
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
			if state, _ := dockerOut(ctx, "inspect", "--format", "{{.State.Running}}", boxID); state != "true" {
				err = fmt.Errorf("the container exited before the probe ran: give the image a command that keeps running")
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
			step("running the probe as %s, then the reset and recheck", user)
			run, err = host.Execute(ctx, &host.DockerBox{Container: boxID, User: user, ProbePath: dockerProbePath, Args: args, VolumeTracker: volumes}, c,
				host.Options{Mode: "exec", ProbeSHA256: sum, AllowLocalProxy: r.allowLocalProxy})
		}
	}
	teardown()
	cleanup, cleaned := "deleted: the container, its run-created anonymous volumes, the canary and the network, each confirmed gone by its ID; user volumes preserved", len(left) == 0
	if !cleaned {
		cleanup = "NOT confirmed deleted: " + strings.Join(left, ", ") + "; remove each by that ID"
		fmt.Fprintf(stderr, "sandprobe: %s\n", cleanup)
	}
	if err != nil {
		return 0, fail("provider_error", err.Error(), "see the message; the cleanup is above", failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "docker", BoxName: image, CreatedBySandprobe: true,
		StartedAt: start, Duration: time.Since(start), Cleanup: cleanup, Residual: dockerResidual})
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
