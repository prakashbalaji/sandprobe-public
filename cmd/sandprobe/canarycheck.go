package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/host"
)

// canaryCheck is `sandprobe canary check`: ask a public canary for its signed status and say what it proves (HCN-1).
// It asks the canary a run would use, by HCN-5's precedence: with nothing named, the hosted canary under this
// release's pin (HCN-7). It reserves and arms nothing. -tls-insecure is for a canary -canary-url names whose
// certificate comes from Let's Encrypt's staging service; trust still rests on the control-key pin, and a status
// carries no secret.
func canaryCheck(o opts, r runFlags, args []string, insecure bool) (int, error) {
	if len(args) != 1 || args[0] != "check" {
		return 0, fail("usage", "canary takes check", "sandprobe canary check", exitUsage)
	}
	choice, err := r.chooseCanary() // HCN-5, with no network call: its refusals stand
	if err != nil {
		return 0, err
	}
	if choice.state != "" {
		return 0, fail("usage", "canary check asks a public canary; the operator canary in "+choice.state+" answers only over SSM, and deploy/canary.sh status checks it", `PROFILE="$AWS_PROFILE" deploy/canary.sh status`, exitUsage)
	}
	hosted := r.canaryURL == ""
	if insecure && hosted {
		return 0, fail("usage", "-tls-insecure needs -canary-url: the hosted canary's certificate is a WebPKI one", "sandprobe canary check", exitUsage)
	}
	who, fix := "the public canary you named at "+choice.url, "check -canary-url and -canary-pin"
	if hosted {
		who, fix = "the hosted canary at "+choice.url, "check that this machine reaches "+choice.url+" over HTTPS, then try again"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var c *host.HTTPSCanary
	if insecure {
		c, err = host.NewHTTPSCanaryWithClient(ctx, choice.url, choice.pins, &http.Client{Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}})
	} else {
		c, err = newPublicCanary(ctx, choice.url, choice.pins)
	}
	if err != nil {
		return exitLogin, fail("needs_login", who+": its signed status isn't proven: "+err.Error(), fix, exitLogin)
	}
	// A second signed status: the client refuses it unless it names the address and domain the first did, so every field
	// printed here comes from this one verified answer.
	st, err := c.Ask(ctx, canary.Request{Op: "status"})
	if err != nil || !st.OK {
		return exitLogin, fail("needs_login", who+": its second signed status didn't match its first", "try again", exitLogin)
	}
	out := map[string]string{"control": c.URL, "address": st.Addr, "domain": st.Domain, "receipt_pin": st.Pin}
	if o.json() {
		o.emit(out)
	} else {
		fmt.Fprintf(o.stdout, "%s, signed by the pinned control key\n  receipt address %s\n  domain %s\n  receipt pin %s\n", who, st.Addr, st.Domain, st.Pin)
	}
	return 0, nil
}
