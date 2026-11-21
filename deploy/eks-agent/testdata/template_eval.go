// Test-only rendering of the exact kubectl go-template guards on synthetic Pods.
package main

import (
	"encoding/json"
	"os"
	"text/template"
)

func main() {
	var in struct {
		Source string
		Data   map[string]any
	}
	if json.NewDecoder(os.Stdin).Decode(&in) != nil {
		os.Exit(2)
	}
	t, err := template.New("projection").Parse(in.Source)
	if err != nil || t.Execute(os.Stdout, in.Data) != nil {
		os.Exit(2)
	}
}
