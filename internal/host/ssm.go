package host

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"sandprobe/internal/canary"
)

// SSMCanary is the live canary (SBX-11, deploy/canary.sh): its ports at a fixed public IP, and its control socket
// reached only through SSM Run Command on its own instance, never over the network a box uses.
type SSMCanary struct {
	Profile, Region string // the AWS CLI profile and region of the deployment
	Instance        string
	Addr, Dom       string
	// run calls the AWS CLI; tests replace it.
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// LoadSSMCanary reads the deployment deploy/canary.sh recorded in its state file.
func LoadSSMCanary(state string) (*SSMCanary, error) {
	b, err := os.ReadFile(state)
	if err != nil {
		return nil, err
	}
	kv := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = v
		}
	}
	c := &SSMCanary{Profile: kv["profile"], Region: kv["region"], Instance: kv["instance"], Addr: kv["ip"], Dom: kv["domain"]}
	if c.Profile == "" || c.Region == "" || c.Instance == "" || net.ParseIP(c.Addr) == nil || c.Dom == "" {
		return nil, fmt.Errorf("%s doesn't record a whole canary deployment", state)
	}
	return c, nil
}

func (c *SSMCanary) IP() string     { return c.Addr }
func (c *SSMCanary) Domain() string { return c.Dom }

func (c *SSMCanary) Health(ctx context.Context, port int, k canary.Key) bool {
	return healthConnect(ctx, net.JoinHostPort(c.Addr, fmt.Sprint(port)), port, c.Dom, k)
}

var ctlArg = regexp.MustCompile(`^-?[a-z0-9/,-]+$`)

// Ask runs the canary's own client on its instance through SSM, and reads its answer from the command's output. The
// command is fixed but for the request's arguments, each a name, a number or a nonce/proto/port list, checked before
// it reaches the instance's shell.
func (c *SSMCanary) Ask(ctx context.Context, q canary.Request) (canary.Answer, error) {
	var a canary.Answer
	args := CtlArgs(q)
	for _, x := range args {
		if !ctlArg.MatchString(x) {
			return a, fmt.Errorf("not a canary argument: %q", x)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	params, _ := json.Marshal(map[string][]string{"commands": {
		"/usr/local/bin/sandprobe-canary -control /run/sandprobe-canary/ctl.sock " + strings.Join(args, " ")}})
	out, err := c.aws(ctx, "ssm", "send-command", "--instance-ids", c.Instance, "--document-name", "AWS-RunShellScript",
		"--parameters", string(params), "--query", "Command.CommandId", "--output", "text")
	if err != nil {
		return a, fmt.Errorf("sending the canary command: %w", err)
	}
	id := strings.TrimSpace(string(out))
	for {
		var inv struct {
			Status                string
			StandardOutputContent string
			StandardErrorContent  string
		}
		out, err := c.aws(ctx, "ssm", "get-command-invocation", "--command-id", id, "--instance-id", c.Instance, "--output", "json")
		if err == nil {
			err = json.Unmarshal(out, &inv)
		}
		switch {
		case err != nil && ctx.Err() != nil:
			return a, fmt.Errorf("the canary command didn't finish: %w", err)
		case err != nil, inv.Status == "Pending", inv.Status == "InProgress", inv.Status == "Delayed":
			// not there yet: an invocation doesn't exist for a moment after it was sent
		case inv.Status == "Success":
			return a, canary.Decode(strings.NewReader(inv.StandardOutputContent), &a)
		default:
			return a, fmt.Errorf("the canary command ended %s: %s", inv.Status, strings.TrimSpace(inv.StandardErrorContent))
		}
		select {
		case <-ctx.Done():
			return a, errors.New("the canary command didn't finish in time")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (c *SSMCanary) aws(ctx context.Context, args ...string) ([]byte, error) {
	if c.run != nil {
		return c.run(ctx, args...)
	}
	out, err := exec.CommandContext(ctx, "aws", append([]string{"--profile", c.Profile, "--region", c.Region}, args...)...).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return out, err
}

// healthConnect is one health connect that proves the canary with key k answered it (SBX-11): on 443 a TLS handshake
// under the pinned key; on a plain port, the canary's signature over that port and a fresh challenge. Anything that
// could answer without the canary's key, such as a bare health line, confirms nothing.
func healthConnect(ctx context.Context, addr string, port int, dom string, k canary.Key) bool {
	if k.Pub == nil {
		return false
	}
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if port == 443 {
		tc := tls.Client(conn, &tls.Config{ServerName: "health.canary." + dom, InsecureSkipVerify: true, // the pin is the check
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || canary.PinOf(cs.PeerCertificates[0]) != k.Pin {
					return errors.New("not the canary's key")
				}
				return nil
			}})
		if tc.Handshake() != nil {
			return false
		}
		line, ok := readLine(tc)
		return ok && line == "sandprobe:health"
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	ch := hex.EncodeToString(nonce) // fresh for every connect, so no answer can be replayed
	if _, err := io.WriteString(conn, "health "+ch+"\n"); err != nil {
		return false
	}
	line, ok := readLine(conn)
	sig, signed := strings.CutPrefix(line, "sandprobe:health:")
	return ok && signed && k.Verify(port, ch, sig)
}

// readLine reads one newline-terminated line of at most 256 bytes from an endpoint nothing vouches for yet: a longer
// line, or none, is no answer, whatever it says.
func readLine(r io.Reader) (string, bool) {
	line, err := bufio.NewReader(io.LimitReader(r, 256)).ReadString('\n')
	return strings.TrimSpace(line), err == nil
}
