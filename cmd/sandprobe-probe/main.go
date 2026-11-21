//go:build linux

// sandprobe-probe is the static binary the host copies into a box and runs as the agent. It reads its input from
// stdin and writes one observation document to stdout. It never grades. With -survey it reads nothing and writes only
// what the host needs to plan (SBX-3, SBX-5); -mark and -recheck are PER-5's steps around the reset (TWN-3). -whoami
// [name] is PRV-15's identity-only preflight, and -expect-uid N, before any mode, refuses at startup unless all four of
// the probe's uids are N.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sandprobe/internal/quick"
	"strconv"
	"strings"
	"time"

	"sandprobe/internal/obs"
	"sandprobe/internal/probe"
	"sandprobe/internal/strictjson"
)

var BuildVersion = "dev"

func main() {
	args := os.Args[1:]
	want, args, bound, err := parseExpect(args)
	if err != nil {
		fail(err)
	}
	if bound { // PRV-15: first, before reading input or running anything
		if err := probe.ExpectUID(want); err != nil {
			fail(err)
		}
	}
	mode, err := parseMode(args)
	if err != nil {
		fail(err)
	}
	var out any
	switch mode {
	case "-whoami":
		name := ""
		if len(args) == 2 {
			name = args[1]
		}
		if out, err = probe.WhoAmI(name); err != nil {
			fail(err)
		}
	case "-quick":
		timer := quickDeadline(5 * time.Second)
		d, err := quick.Observe(args[1:], BuildVersion)
		if err != nil {
			fail(err)
		}
		b, err := json.Marshal(d)
		if err != nil || len(b)+1 > quick.MaxOutput {
			fail(errors.New("quick output unavailable or oversized"))
		}
		defer timer.Stop()
		if _, err := os.Stdout.Write(append(b, '\n')); err != nil {
			fail(errors.New("cannot write quick output"))
		}
		return
	case "-survey":
		out = probe.Survey()
	case "-receiver":
		var in obs.ReceiverProbeInput
		read(&in)
		out, err = probe.ReceiverAttempt(in)
		if err != nil {
			fail(err)
		}
	case "-mark": // PER-5's markers, as the host planned them (TWN-3)
		var in obs.MarkInput
		read(&in)
		out = probe.Mark(in)
	case "-recheck": // after the reset
		var in obs.RecheckInput
		read(&in)
		out = probe.Recheck(in)
	case "":
		var in probe.Input
		read(&in)
		d, err := probe.Run(in)
		if err != nil {
			fail(err)
		}
		out = d
	default:
		fail(errors.New("unsupported probe mode"))
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail(err)
	}
}

// read takes the host's input from stdin: at most 1 MB, one value, no field the probe doesn't know.
func read(v any) {
	if err := readFrom(os.Stdin, v); err != nil {
		fail(err)
	}
}

// JON-2: limit+1 distinguishes an oversized input from a complete document.
func readFrom(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, obs.MaxDoc+1))
	if err != nil {
		return errors.New("cannot read host input")
	}
	return strictjson.Decode(b, obs.MaxDoc, v)
}

// parseExpect takes PRV-15's -expect-uid N off the front of the arguments. It can't bind -whoami, which is what learns
// the uid, or -quick.
func parseExpect(args []string) (int, []string, bool, error) {
	if len(args) == 0 || args[0] != "-expect-uid" {
		return 0, args, false, nil
	}
	if len(args) < 2 || strings.Trim(args[1], "0123456789") != "" || len(args[1]) > 10 {
		return 0, nil, false, errors.New("-expect-uid takes one uid")
	}
	n, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return 0, nil, false, errors.New("-expect-uid takes one uid")
	}
	rest := args[2:]
	if len(rest) > 0 && (rest[0] == "-whoami" || rest[0] == "-quick" || rest[0] == "-expect-uid") {
		return 0, nil, false, errors.New("-expect-uid binds a probe run, not " + rest[0])
	}
	return int(n), rest, true, nil
}

func parseMode(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	if args[0] == "-whoami" && (len(args) == 1 || len(args) == 2 && probe.ValidUserName(args[1])) {
		return "-whoami", nil
	}
	if len(args) > 0 && args[0] == "-quick" {
		if err := quick.ValidatePaths(args[1:]); err != nil {
			return "", err
		}
		return "-quick", nil
	}
	if len(args) == 1 {
		switch args[0] {
		case "-survey", "-mark", "-recheck", "-receiver":
			return args[0], nil
		}
	}
	return "", errors.New("unsupported probe arguments")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sandprobe-probe:", err)
	os.Exit(1)
}

// The watchdog must not block on a diagnostic pipe before terminating.
func quickDeadline(d time.Duration) *time.Timer { return time.AfterFunc(d, func() { os.Exit(5) }) }
