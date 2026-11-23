// Sandprobe TUI prototype: the whole experience on demo data. No box is created or probed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	fs := flag.NewFlagSet("sandprobe-proto", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	theme := fs.String("theme", "modern", "palette: modern or mission")
	out := fs.String("o", "", "plain output for agents, no TUI: json or ndjson")
	speed := fs.Float64("speed", 1, "animation speed")
	still := fs.Bool("still", false, "reduced motion: no animations")
	minGrade := fs.String("min", "", "with -o: exit 6 when the grade is worse than this letter")
	html := fs.String("html", "", "write the web report to this path and exit")
	snap := fs.String("snap", "", "debug: print one frame, e.g. run:6.5 or grade:2")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			fs.SetOutput(os.Stdout)
			fs.PrintDefaults()
			return
		}
		usage(err.Error(), "run sandprobe-proto -h for the flags")
	}
	if g := strings.ToUpper(*minGrade); g != "" && (len(g) != 1 || !strings.Contains("ABCDF", g)) {
		usage("-min must be one of A, B, C, D or F, not "+strconv.Quote(*minGrade), "use -min C, for example")
	}

	switch {
	case *html != "":
		if err := writeHTML(*html, themeIndex(*theme)); err != nil {
			fail(err)
		}
		fmt.Println(*html)
		return
	case *snap != "":
		fmt.Println(snapshot(*snap, themeIndex(*theme)))
		return
	}
	if fi, err := os.Stdout.Stat(); *out == "" && err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		*out = "json" // not a terminal: an agent or a pipe gets JSON, never an animation
	}
	if *out != "" {
		os.Exit(agentOutput(*out, *minGrade))
	}
	if os.Getenv("SANDPROBE_REDUCED_MOTION") != "" {
		*still = true
	}
	if _, err := tea.NewProgram(newModel(themeIndex(*theme), *speed, *still), tea.WithAltScreen()).Run(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sandprobe:", err)
	os.Exit(1)
}

// usage reports a usage error and exits 2: JSON with a fix when piped or when -o asks for JSON, plain text otherwise.
func usage(msg, fix string) {
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 && !wantsJSON(os.Args[1:]) {
		fmt.Fprintf(os.Stderr, "sandprobe: %s\nfix: %s\n", msg, fix)
	} else {
		json.NewEncoder(os.Stderr).Encode(map[string]string{"error": "usage", "message": msg, "fix": fix})
	}
	os.Exit(2)
}

// snapshot renders one frame without a terminal, so layouts can be checked in plain text.
func snapshot(spec string, th int) string {
	kind, s, _ := strings.Cut(spec, ":")
	sec, _ := strconv.ParseFloat(s, 64)
	d := time.Duration(sec * float64(time.Second))
	m := newModel(th, 1, false)
	m.w, m.h = 110, 44
	switch kind {
	case "boot":
		m.ph, m.phStart = phBoot, m.now.Add(-d)
	case "pick":
		m.ph = phPick
	case "mode":
		m.ph = phMode
	case "plan":
		m.ph, m.phStart = phPlan, m.now.Add(-d)
	case "run":
		m = m.startRun()
		m.snapE = sec
	case "grade":
		m = m.startRun()
		m.snapE = m.tl.tGrade + sec
		for i := 0; i < int(sec*30); i++ {
			m = m.stepSpring(float64(i) / 30)
		}
	case "explore":
		m = m.startRun()
		m.ph = phExplore
	}
	return m.View()
}

// wantsJSON spots -o json or -o ndjson in the raw arguments, so usage errors are structured even before parsing ends.
func wantsJSON(args []string) bool {
	for i, a := range args {
		name, val, eq := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "o" {
			continue
		}
		if !eq && i+1 < len(args) {
			val = args[i+1]
		}
		if val == "json" || val == "ndjson" {
			return true
		}
	}
	return false
}
