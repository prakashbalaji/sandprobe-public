// Package probes carries the Linux probe builds inside the sandprobe binary (UX-1), and their digests.
package probes

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
)

//go:embed all:bin
var bin embed.FS

// Probe is the probe built for a Linux architecture (amd64 or arm64), and its SHA-256.
func Probe(arch string) ([]byte, string, error) {
	b, err := bin.ReadFile("bin/sandprobe-probe-linux-" + arch)
	if err != nil {
		return nil, "", fmt.Errorf("this sandprobe carries no probe for linux/%s: build it with `make`", arch)
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

// Canary is the canary server built for a Linux architecture, for the local Docker provider's own canary (PRV-14).
func Canary(arch string) ([]byte, error) {
	b, err := bin.ReadFile("bin/sandprobe-canary-linux-" + arch)
	if err != nil {
		return nil, fmt.Errorf("this sandprobe carries no canary for linux/%s: build it with `make`", arch)
	}
	return b, nil
}
