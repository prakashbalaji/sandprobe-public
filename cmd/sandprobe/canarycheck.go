package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/host"
)

// canaryCheck is `sandprobe canary check`: ask a public canary for its signed status and say what it proves (HCN-1).
// It reserves and arms nothing. -tls-insecure is for a canary whose certificate comes from Let's Encrypt's staging
// service; trust still rests on the control-key pin, and a status carries no secret.
func canaryCheck(o opts, r runFlags, args []string, insecure bool) (int, error) {
	if len(args) != 1 || args[0] != "check" {
		return 0, fail("usage", "canary takes check", "sandprobe canary check -canary-url https://control.<domain> -canary-pin <pin>", exitUsage)
	}
	if r.canaryURL == "" || r.canaryPin == "" {
		return 0, fail("usage", "canary check needs -canary-url and -canary-pin", "sandprobe canary check -canary-url https://control.<domain> -canary-pin <pin>", exitUsage)
	}
	var pins []string
	for _, p := range strings.Split(r.canaryPin, ",") {
		if p = strings.TrimSpace(p); p != "" {
			pins = append(pins, p)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var c *host.HTTPSCanary
	var err error
	if insecure {
		c, err = host.NewHTTPSCanaryWithClient(ctx, r.canaryURL, pins, &http.Client{Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}})
	} else {
		c, err = host.NewHTTPSCanary(ctx, r.canaryURL, pins)
	}
	if err != nil {
		return exitLogin, fail("needs_login", "the canary's signed status isn't proven: "+err.Error(), "check -canary-url and -canary-pin", exitLogin)
	}
	// A second signed status: the client refuses it unless it names the address and domain the first did, so every field
	// printed here comes from this one verified answer.
	st, err := c.Ask(ctx, canary.Request{Op: "status"})
	if err != nil || !st.OK {
		return exitLogin, fail("needs_login", "the canary's second signed status didn't match its first", "try again", exitLogin)
	}
	out := map[string]string{"control": c.URL, "address": st.Addr, "domain": st.Domain, "receipt_pin": st.Pin}
	if o.json() {
		o.emit(out)
	} else {
		fmt.Fprintf(o.stdout, "signed by the pinned control key\n  receipt address %s\n  domain %s\n  receipt pin %s\n", st.Addr, st.Domain, st.Pin)
	}
	return 0, nil
}
