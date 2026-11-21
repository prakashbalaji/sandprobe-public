// Package recipes holds the shipped recipes (RCP-4), embedded in the CLI. Each is a provider adapter with a PRV row
// in SPEC.md and the two reviews.
package recipes

import "embed"

//go:embed *.sh
var files embed.FS

// Shipped names the shipped recipes, each with its PRV row.
var Shipped = map[string]string{"kubernetes": "PRV-16"}

// Get returns a shipped recipe's bytes.
func Get(name string) ([]byte, bool) {
	if _, ok := Shipped[name]; !ok {
		return nil, false
	}
	b, err := files.ReadFile(name + ".sh")
	return b, err == nil
}
