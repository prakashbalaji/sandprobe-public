package main

import (
	_ "embed"
	"fmt"
	"html"
	"html/template"
	"math"
	"os"
	"strings"
)

//go:embed report.html
var reportTmpl string

type viewCheck struct {
	ID, Title, Cat, SevLabel, SevClass, Gets, Evidence, How, Fix string
}

type group struct {
	Name   string
	Checks []viewCheck
}

type reportView struct {
	Theme, Provider, Box, When, Grade, GradeClass, Lead string
	Demo, Complete                                      bool
	Crit, High, Med, Passed, Unknown                    int
	Map                                                 template.HTML
	Findings, Unknowns                                  []viewCheck
	Passes                                              []group
	Identity, Hosts, Markers                            [][2]string
	Data                                                any
}

// writeHTML writes the web report: one self-contained file, no external scripts, fonts or requests.
func writeHTML(path string, th int) error {
	tpl, err := template.New("report").Parse(reportTmpl)
	if err != nil {
		return err
	}
	var b strings.Builder
	if err := tpl.Execute(&b, buildReportView(th)); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func toView(c Check) viewCheck {
	v := viewCheck{ID: c.ID, Title: c.Title, Cat: catLong[c.Cat], Gets: c.Gets, Evidence: c.Evidence, How: c.How, Fix: c.Fix}
	switch {
	case c.Result == Pass:
		v.SevLabel, v.SevClass = "VERIFIED", "pass"
	case c.Result == Unknown:
		v.SevLabel, v.SevClass = "UNKNOWN", "med"
	case c.Sev == "CRIT":
		v.SevLabel, v.SevClass = "CRITICAL", "crit"
	case c.Sev == "HIGH":
		v.SevLabel, v.SevClass = "HIGH", "crit"
	default:
		v.SevLabel, v.SevClass = "MEDIUM", "med"
	}
	return v
}

func buildReportView(th int) reportView {
	cr, hi, md, ps, un := counts()
	letter := gradeLetter()
	v := reportView{Theme: themes[th].Name, Provider: "sprites", Box: "sandprobe-7f3a", When: nowPT(), Grade: letter,
		GradeClass: map[string]string{"F": "crit", "D": "crit", "C": "med"}[letter], Lead: lead, Demo: true, Complete: un == 0,
		Crit: cr, High: hi, Med: md, Passed: ps, Unknown: un, Map: mapSVG(), Data: reportJSON()}
	if v.GradeClass == "" {
		v.GradeClass = "pass"
	}
	for _, c := range findings() {
		v.Findings = append(v.Findings, toView(c))
	}
	for _, cat := range []Cat{SEC, EGR, PER, AMP} {
		g := group{Name: catLong[cat]}
		for _, c := range checks {
			switch {
			case c.Cat != cat:
			case c.Result == Pass:
				g.Checks = append(g.Checks, toView(c))
			case c.Result == Unknown:
				v.Unknowns = append(v.Unknowns, toView(c))
			}
		}
		if len(g.Checks) > 0 {
			v.Passes = append(v.Passes, g)
		}
	}
	v.Identity = [][2]string{{"User", "agent (uid 1001, gid 1001)"}, {"Launched through", "sprite exec, the agent's own path"},
		{"CapEff", "0000000000000000"}, {"CapBnd", "000001ffffffffff"}, {"NoNewPrivs", "0"}, {"Seccomp", "0 (off)"},
		{"Tools", "curl, sh (sha256 recorded); python3 and socat absent"}, {"Probe", "sandprobe 0.1.0-proto, probe.sh sha256 3f9a…c21e (demo)"}}
	v.Hosts = [][2]string{{"probe.sandprobe.dev:443 · TLS", "reached directly; pinned key matched"}, {"probe.sandprobe.dev:22 · TCP", "reset by the network"},
		{"<unique>.probe.sandprobe.dev · DNS", "no upstream query seen"}, {"169.254.169.254:80", "connection refused"},
		{"169.254.170.2:80", "connection refused"}, {"169.254.170.23:80", "connection refused"}, {"127.0.0.1:8080", "accepted the connection"}}
	v.Markers = [][2]string{{"/home/agent/.sandprobe-7f3a", "survived the reset; removed"}, {"/tmp/.sandprobe-7f3a", "gone after the reset"},
		{"/var/tmp/.sandprobe-7f3a", "gone after the reset"}}
	return v
}

// mapSVG draws the containment map for the web report, animating in the TUI's order.
func mapSVG() template.HTML {
	const x0, x1, y0, y1, ax, ay = 230.0, 590.0, 90.0, 300.0, 410.0, 195.0
	n, idx := map[Cat]int{}, make([]int, len(checks))
	byCat := make([][]int, 4)
	for i, c := range checks {
		idx[i] = n[c.Cat]
		n[c.Cat]++
		byCat[c.Cat] = append(byCat[c.Cat], i)
	}
	pos := func(i int) (float64, float64) {
		c, k := checks[i], float64(idx[i])
		d := math.Max(1, float64(n[c.Cat]-1))
		switch c.Cat {
		case SEC:
			return 330 + k*230/d, y0
		case AMP:
			return 330 + k*230/d, y1
		case PER:
			return x0, 130 + k*140/d
		}
		return x1, 130 + k*140/d
	}
	begin, arrive := make([]float64, len(checks)), make([]float64, len(checks))
	o := 0
	for k, added := 0, true; added; k++ {
		added = false
		for _, cat := range []Cat{SEC, EGR, AMP, PER} {
			if k < len(byCat[cat]) {
				i := byCat[cat][k]
				begin[i] = 1.2 + float64(o)*0.11
				arrive[i] = begin[i] + 0.55
				o++
				added = true
			}
		}
	}
	esc := html.EscapeString
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w(`<svg class="map" viewBox="0 0 820 400" role="img" aria-label="Containment map: the agent in its box, each check on its wall">`)
	w(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" class="arrowhead"/></marker>`)
	w(`<pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M20 0H0V20" class="grid"/></pattern></defs>`)
	w(`<rect width="820" height="400" fill="url(#grid)" class="gridbg"/>`)
	w(`<rect class="wall" x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="8"/>`, x0, y0, x1-x0, y1-y0)
	w(`<rect class="scan" x="%.0f" y="%.0f" width="3" height="%.0f" opacity="0"><animate attributeName="x" from="%.0f" to="%.0f" dur="1.8s" begin="1.2s" repeatCount="2"/>`+
		`<animate attributeName="opacity" values="0;.7;.7;0" dur="3.6s" begin="1.2s" fill="freeze"/></rect>`, x0, y0, y1-y0, x0, x1-3)
	w(`<text class="cat" x="%.0f" y="%.0f">SECRETS</text><text class="cat" x="%.0f" y="%.0f">AMPLIFIERS</text>`, x0+16, y0+24, x0+16, y1-14)
	w(`<text class="cat" x="%.0f" y="%.0f" text-anchor="middle" transform="rotate(-90 %.0f %.0f)">PERSIST</text>`, x0+22, ay, x0+22, ay)
	w(`<text class="cat" x="%.0f" y="%.0f" text-anchor="middle" transform="rotate(90 %.0f %.0f)">EGRESS</text>`, x1-22, ay, x1-22, ay)
	w(`<circle class="agent-ring" cx="%.0f" cy="%.0f" r="18"/><circle class="agent" cx="%.0f" cy="%.0f" r="6"/>`, ax, ay, ax, ay)
	w(`<text class="agent-label" x="%.0f" y="%.0f" text-anchor="middle">agent · uid 1001</text>`, ax, ay+34)

	if s, g := idxOf("SEC-1"), idxOf("EGR-1"); s >= 0 && g >= 0 {
		sx, _ := pos(s)
		_, gy := pos(g)
		w(`<g class="mark" style="animation-delay:%.2fs" data-target="CHN-1"><title>CHN-1 · a secret can leave the box</title>`, math.Max(arrive[s], arrive[g])+0.3)
		w(`<path class="chain" d="M%.1f,%.0fV%.1fH%.0f"/><text class="chain-label" x="%.1f" y="%.1f">chain: a secret can leave</text></g>`, sx, y0, gy, x1, sx+12, gy-9)
	}
	for i, c := range checks {
		x, y := pos(i)
		w(`<circle class="pulse" r="3.5" opacity="0"><animateMotion dur="0.55s" begin="%.2fs" fill="freeze" path="M%.0f,%.0fL%.1f,%.1f"/>`+
			`<animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.1;.85;1" dur="0.55s" begin="%.2fs" fill="freeze"/></circle>`, begin[i], ax, ay, x, y, begin[i])
		target := c.ID
		if c.Result == Find && c.Sev == "" {
			target = "CHN-1" // part of a chain: its card is the chain's
		}
		w(`<g class="mark" style="animation-delay:%.2fs" data-target="%s"><title>%s</title>`, arrive[i], target, esc(c.ID+" · "+c.Title+" · "+resultName(c.Result)))
		switch c.Result {
		case Pass:
			if c.Cat == SEC || c.Cat == AMP {
				w(`<line class="seg" x1="%.1f" y1="%.0f" x2="%.1f" y2="%.0f"/>`, x-11, y, x+11, y)
			} else {
				w(`<line class="seg" x1="%.0f" y1="%.1f" x2="%.0f" y2="%.1f"/>`, x, y-11, x, y+11)
			}
		case Unknown:
			w(`<circle class="unk" cx="%.1f" cy="%.1f" r="10"/><text class="unk-q" x="%.1f" y="%.1f" text-anchor="middle">?</text>`, x, y, x, y+4.5)
		case Find:
			w(`<path class="crack" d="M%.1f,%.1fL%.1f,%.1fM%.1f,%.1fL%.1f,%.1f"/>`, x-7, y-7, x+7, y+7, x-7, y+7, x+7, y-7)
			var d, anchor string
			var lx, ly float64
			switch c.Cat {
			case SEC:
				d, lx, ly, anchor = fmt.Sprintf("M%.1f,%.0fV%.0f", x, y, y-42), x, y-52, "middle"
			case EGR:
				d, lx, ly, anchor = fmt.Sprintf("M%.0f,%.1fH%.0f", x, y, x+62), x+72, y+5, "start"
			case PER:
				d, lx, ly, anchor = fmt.Sprintf("M%.0f,%.1fH%.0f", x, y, x-62), x-72, y+5, "end"
			case AMP: // leftmost breaches drop deepest, so their lines never cross
				drop := 34.0
				for j := range checks {
					if xj, _ := pos(j); checks[j].Cat == AMP && checks[j].Result == Find && xj > x {
						drop += 24
					}
				}
				d, lx, ly, anchor = fmt.Sprintf("M%.1f,%.0fV%.0fH%.1f", x, y, y+drop, x+26), x+34, y+drop+5, "start"
			}
			w(`<path class="breach" d="%s" marker-end="url(#arrow)"/><text class="breach-label" x="%.1f" y="%.1f" text-anchor="%s">%s</text>`, d, lx, ly, anchor, esc(c.Breach))
		}
		w(`<circle class="hit" cx="%.1f" cy="%.1f" r="13"/></g>`, x, y)
	}
	w(`</svg>`)
	return template.HTML(b.String())
}
