package main

import (
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The containment map: the agent sits in a box whose four walls are the four categories.
const (
	mapH     = 14
	bx0, bx1 = 16, 57
	by0, by1 = 2, 9
	agX, agY = 36, 5
	stagger  = 0.36
	travel   = 0.55
)

type event struct {
	at, end   float64
	ci, stage int // ci < 0 marks a step; stage 1 is a persistence check after the reset
	step, txt string
}

type timeline struct {
	events                                   []event
	tProbe, tReset, tRescan, tDelete, tGrade float64
	arrive                                   [][2]float64 // per check: when its pulse reaches the wall, per stage
}

func buildTimeline(p provider) timeline {
	tl := timeline{tProbe: 1.4, arrive: make([][2]float64, len(checks))}
	byCat := make([][]int, 4)
	for i, c := range checks {
		byCat[c.Cat] = append(byCat[c.Cat], i)
	}
	tl.events = append(tl.events, event{at: 0, end: tl.tProbe, ci: -1, step: "CREATE", txt: p.Steps[0]})
	t := tl.tProbe + 0.3
	for k, added := 0, true; added; k++ {
		added = false
		for _, cat := range []Cat{SEC, EGR, AMP, PER} {
			if k < len(byCat[cat]) {
				ci := byCat[cat][k]
				tl.events = append(tl.events, event{at: t, end: t + travel, ci: ci})
				tl.arrive[ci][0] = t + travel
				t += stagger
				added = true
			}
		}
	}
	tl.tReset = t + travel + 0.6
	tl.tRescan = tl.tReset + 2.0
	tl.events = append(tl.events,
		event{at: tl.tReset, end: tl.tRescan, ci: -1, step: "RESET", txt: p.Reset},
		event{at: tl.tRescan, end: tl.tRescan + 1.0, ci: -1, step: "RESCAN", txt: "look again for anything that survived"})
	t = tl.tRescan + 1.1
	for _, ci := range byCat[PER] {
		tl.events = append(tl.events, event{at: t, end: t + travel, ci: ci, stage: 1})
		tl.arrive[ci][1] = t + travel
		t += 0.3
	}
	tl.tDelete = t + travel + 0.7
	tl.tGrade = tl.tDelete + 1.0
	tl.events = append(tl.events, event{at: tl.tDelete, end: tl.tGrade, ci: -1, step: "DELETE", txt: "delete " + p.Box})
	return tl
}

// layout places each check on its wall and plots the pulse's path from the agent to it.
func layout() ([][2]int, [][][2]int) {
	n, idx := make([]int, 4), make([]int, len(checks))
	for i, c := range checks {
		idx[i] = n[c.Cat]
		n[c.Cat]++
	}
	pos, paths := make([][2]int, len(checks)), make([][][2]int, len(checks))
	for i, c := range checks {
		k, d := idx[i], max(1, n[c.Cat]-1)
		var x, y int
		switch c.Cat {
		case SEC:
			x, y = bx0+13+(bx1-3-bx0-13)*k/d, by0
		case AMP:
			x, y = bx0+16+(bx1-3-bx0-16)*k/d, by1
		case PER:
			x, y = bx0, by0+2+k
		case EGR:
			x, y = bx1, by0+2+k
		}
		pos[i], paths[i] = [2]int{x, y}, line(agX, agY, x, y)
	}
	return pos, paths
}

// line is Bresenham's, without its two ends.
func line(x0, y0, x1, y1 int) [][2]int {
	abs := func(v int) int { return max(v, -v) }
	sign := func(v int) int { return max(-1, min(v, 1)) }
	dx, dy, sx, sy := abs(x1-x0), -abs(y1-y0), sign(x1-x0), sign(y1-y0)
	err, x, y := dx+dy, x0, y0
	var pts [][2]int
	for {
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x += sx
		}
		if e2 <= dx {
			err += dx
			y += sy
		}
		if x == x1 && y == y1 {
			return pts
		}
		pts = append(pts, [2]int{x, y})
	}
}

// status: 0 not reached, 1 a persistence marker planted, 2 resolved.
func (m model) status(i int, e float64) int {
	a := m.tl.arrive[i]
	switch {
	case checks[i].Cat == PER && a[1] > 0 && e >= a[1]:
		return 2
	case checks[i].Cat == PER && e >= a[0]:
		return 1
	case checks[i].Cat != PER && e >= a[0]:
		return 2
	}
	return 0
}

func (m model) header(e float64) string {
	t, p := m.theme(), providers[m.pick]
	return t.spread(t.sp(2)+t.b(t.Accent, "SANDPROBE")+t.c(t.Dim, fmt.Sprintf("   %s › %s › agent uid 1001", p.Short, p.Box)),
		t.c(t.Unknown, "DEMO  ")+t.c(t.Text, fmt.Sprintf("%02d:%02d", int(e)/60, int(e)%60))+t.sp(2), W)
}

func (m model) viewRun() string {
	t, e := m.theme(), m.runE()
	ls := []string{m.header(e), m.stepsLine(e), ""}
	ls = append(ls, strings.Split(m.mapCanvas(e).render(t, m.roll()), "\n")...)
	ls = append(ls, "", m.barsLine(e), t.c(t.Faint, strings.Repeat("─", W)))
	ls = append(ls, m.tickerLines(e)...)
	ls = append(ls, "", keys(t, "s", "skip to the grade", "t", "palette", "q", "quit"))
	return t.pad(ls, W)
}

func (m model) stepsLine(e float64) string {
	t, tl := m.theme(), m.tl
	steps := []struct {
		n    string
		a, b float64
	}{{"CREATE", 0, tl.tProbe}, {"PROBE", tl.tProbe, tl.tReset}, {"RESET", tl.tReset, tl.tRescan}, {"RESCAN", tl.tRescan, tl.tDelete}, {"DELETE", tl.tDelete, tl.tGrade}}
	s := t.sp(2)
	for i, st := range steps {
		if i > 0 {
			s += t.c(t.Faint, "  ›  ")
		}
		switch {
		case e >= st.b:
			s += t.c(t.Dim, st.n+" ") + t.b(t.Pass, "✓")
		case e >= st.a:
			s += t.b(t.Text, st.n+" ") + t.c(t.Accent, spinner(m.frame))
		default:
			s += t.c(t.Faint, st.n+" ·")
		}
	}
	return s
}

func (m model) barsLine(e float64) string {
	t := m.theme()
	s := t.sp(2)
	for k, cat := range []Cat{SEC, EGR, PER, AMP} {
		if k > 0 {
			s += t.sp(4)
		}
		done, n, sq := 0, 0, ""
		for i, c := range checks {
			if c.Cat != cat {
				continue
			}
			n++
			switch m.status(i, e) {
			case 2:
				done++
				sq += t.b(t.result(c.Result), "■")
			case 1:
				sq += t.c(t.Dim, "▪")
			default:
				sq += t.c(t.Faint, "□")
			}
		}
		s += t.b(t.Text, catName[cat]+" ") + sq + t.c(t.Dim, fmt.Sprintf(" %d/%d", done, n))
	}
	return s
}

func (m model) tickerLines(e float64) []string {
	t := m.theme()
	var shown []event
	for _, ev := range m.tl.events {
		if ev.at <= e {
			shown = append(shown, ev)
		}
	}
	shown = shown[max(0, len(shown)-4):]
	var ls []string
	for _, ev := range shown {
		live := e < ev.end
		if ev.ci < 0 {
			g := t.b(t.Pass, "✓")
			if live {
				g = t.c(t.Accent, spinner(m.frame))
			}
			ls = append(ls, t.sp(2)+g+t.sp(1)+t.b(t.Accent, fmt.Sprintf("%-7s", ev.step))+t.c(t.Text, trunc(ev.txt, 64)))
			continue
		}
		c := checks[ev.ci]
		var g, res string
		switch {
		case live && ev.stage == 1:
			g, res = t.c(t.Accent, spinner(m.frame)), t.c(t.Faint, "looking again…")
		case live && c.Cat == PER:
			g, res = t.c(t.Accent, spinner(m.frame)), t.c(t.Faint, "planting a marker…")
		case live:
			g, res = t.c(t.Accent, spinner(m.frame)), t.c(t.Faint, "probing…")
		case c.Cat == PER && ev.stage == 0:
			g, res = t.c(t.Dim, "◌"), t.c(t.Dim, "marker planted")
		case c.Result == Pass:
			g, res = t.b(t.Pass, glyph(Pass)), t.c(t.Dim, c.Ticker)
		default:
			g, res = t.b(t.result(c.Result), glyph(c.Result)), t.b(t.result(c.Result), c.Ticker)
		}
		ls = append(ls, t.sp(2)+g+t.sp(1)+t.c(t.Text, fmt.Sprintf("%-7s", c.ID))+t.c(t.Dim, fmt.Sprintf("%-35s", trunc(c.Title, 33)))+res)
	}
	for len(ls) < 4 {
		ls = append(ls, "")
	}
	return ls
}

// roll is the mission palette's CRT refresh band sliding down the map.
func (m model) roll() func(int) lipgloss.Color {
	t := m.theme()
	if t.Roll == "" {
		return nil
	}
	y0 := (m.frame / 2) % (mapH + 12)
	return func(y int) lipgloss.Color {
		if y == y0 || y == y0-1 {
			return t.Roll
		}
		return ""
	}
}

func (m model) mapCanvas(e float64) *canvas {
	t, tl := m.theme(), m.tl
	cv := newCanvas(W, mapH)
	inner := func(fn func(x, y int)) {
		for y := by0 + 1; y < by1; y++ {
			for x := bx0 + 1; x < bx1; x++ {
				fn(x, y)
			}
		}
	}
	if (e >= tl.tProbe && e < tl.tReset) || (e >= tl.tRescan+1 && e < tl.tDelete) { // radar sweep
		x := bx0 + 1 + int(math.Mod(e, 1.8)/1.8*float64(bx1-bx0-1))
		for y := by0 + 1; y < by1; y++ {
			cv.set(x, y, '┊', t.Faint, false)
		}
	}
	if r := e - tl.tReset; r >= 0 && r < 1.05 { // the reset floods the box, then drains it
		ch := []rune("▓▒░")[int(r/0.35)]
		inner(func(x, y int) { cv.set(x, y, ch, t.Dim, false) })
	}
	if r := e - tl.tRescan; r >= 0 && r < 1.0 { // the rescan bar sweeps across
		x := bx0 + 1 + int(r*float64(bx1-bx0-1))
		for y := by0 + 1; y < by1; y++ {
			for d := 1; d <= 3; d++ {
				cv.set(x-d, y, '│', t.Dim, false)
			}
			cv.set(x, y, '┃', t.Accent, true)
		}
	}
	m.walls(cv, e)
	if e < tl.tProbe-0.3 || e >= tl.tDelete+0.2 {
		return cv
	}
	cv.set(agX, agY, '◉', t.Accent, m.frame%16 < 8)
	cv.put(agX-2, agY+1, "agent", t.Dim, false)
	m.chain(cv, e)
	for i := range checks {
		m.drawCheck(cv, i, e)
	}
	for _, ev := range tl.events { // pulses in flight, with a fading trail
		if ev.ci < 0 || e < ev.at || e >= ev.end || len(m.paths[ev.ci]) == 0 {
			continue
		}
		path := m.paths[ev.ci]
		h := min(int((e-ev.at)/travel*float64(len(path))), len(path)-1)
		for d := 3; d >= 1; d-- {
			if j := h - d; j >= 0 {
				col := t.Faint
				if d == 1 {
					col = t.Dim
				}
				cv.set(path[j][0], path[j][1], '∙', col, false)
			}
		}
		cv.set(path[h][0], path[h][1], '●', t.Accent, true)
	}
	return cv
}

type pt struct {
	x, y int
	r    rune
}

func perimeter() []pt {
	var p []pt
	corner := func(x int, l, r rune) rune {
		switch x {
		case bx0:
			return l
		case bx1:
			return r
		}
		return '─'
	}
	for x := bx0; x <= bx1; x++ {
		p = append(p, pt{x, by0, corner(x, '┌', '┐')})
	}
	for y := by0 + 1; y < by1; y++ {
		p = append(p, pt{bx1, y, '│'})
	}
	for x := bx1; x >= bx0; x-- {
		p = append(p, pt{x, by1, corner(x, '└', '┘')})
	}
	for y := by1 - 1; y > by0; y-- {
		p = append(p, pt{bx0, y, '│'})
	}
	return p
}

// walls draw themselves clockwise during CREATE and dissolve during DELETE.
func (m model) walls(cv *canvas, e float64) {
	t, tl := m.theme(), m.tl
	per := perimeter()
	shown := math.Min(e/(tl.tProbe-0.2), 1)
	gone := math.Max(0, (e-tl.tDelete)/0.8)
	col := t.Wall
	if r := e - tl.tReset; r >= 0 && r < 1.05 && m.frame%4 < 2 {
		col = t.Faint
	}
	for i, p := range per {
		f := float64(i) / float64(len(per))
		switch {
		case f > shown || f < gone-0.12:
		case f < gone:
			cv.set(p.x, p.y, []rune("░▒▓")[(i+m.frame)%3], t.Faint, false)
		default:
			cv.set(p.x, p.y, p.r, col, false)
		}
	}
	if shown >= 1 && gone == 0 {
		cv.put(bx0+2, by0, " SECRETS ", t.Text, true)
		cv.put(bx0+2, by1, " AMPLIFIERS ", t.Text, true)
		cv.put(bx0-2-len("PERSIST"), by0+1, "PERSIST", t.Text, true)
		cv.put(bx1+2, by0+1, "EGRESS", t.Text, true)
	}
}

func (m model) drawCheck(cv *canvas, i int, e float64) {
	t, c := m.theme(), checks[i]
	x, y := m.pos[i][0], m.pos[i][1]
	switch m.status(i, e) {
	case 1:
		if e < m.tl.tReset || e >= m.tl.tRescan || m.frame%6 < 3 {
			cv.set(x, y, '◌', t.Dim, false)
		}
	case 2:
		a := m.tl.arrive[i][0]
		if c.Cat == PER {
			a = m.tl.arrive[i][1]
		}
		age := e - a
		switch c.Result {
		case Pass: // the wall hardens where a refusal was verified
			if y == by0 || y == by1 {
				for d := -1; d <= 1; d++ {
					cv.set(x+d, y, '━', t.Pass, true)
				}
			} else {
				cv.set(x, y, '┃', t.Pass, true)
			}
			if age < 0.45 {
				cv.set(x, y, []rune("✦✧∙")[int(age/0.15)], t.Pass, true)
			}
		case Find: // the wall cracks and the line escapes
			cv.set(x, y, '╳', t.Find, true)
			m.breach(cv, i, age)
		case Unknown:
			cv.set(x, y, '?', t.Unknown, true)
		}
	}
}

func (m model) breach(cv *canvas, i int, age float64) {
	c, f := checks[i], m.theme().Find
	x, y := m.pos[i][0], m.pos[i][1]
	n := int(age * 30)
	switch c.Cat {
	case EGR:
		for d := 1; d <= min(3, n); d++ {
			cv.set(x+d, y, '━', f, true)
		}
		if n >= 4 {
			cv.set(x+4, y, '▶', f, true)
		}
		cv.put(x+6, y, typed(c.Breach, n-5), f, true)
	case PER:
		for d := 1; d <= min(3, n); d++ {
			cv.set(x-d, y, '━', f, true)
		}
		if n >= 4 {
			cv.set(x-4, y, '◀', f, true)
		}
		cv.put(x-5-runeLen(c.Breach), y, typed(c.Breach, n-5), f, true)
	case SEC:
		if n >= 1 {
			cv.set(x, y-1, '┃', f, true)
		}
		l := "▲ " + c.Breach
		cv.put(x-runeLen(l)/2, y-2, typed(l, n-2), f, true)
	case AMP: // leftmost breaches drop deepest, so their lines never cross
		row := y + 2
		for j := range checks {
			if checks[j].Cat == AMP && checks[j].Result == Find && m.pos[j][0] > x {
				row++
			}
		}
		for r := y + 1; r < row && r-y <= n; r++ {
			cv.set(x, r, '┃', f, true)
		}
		k := n - (row - y)
		if k >= 0 {
			cv.set(x, row, '┗', f, true)
		}
		if k >= 1 {
			cv.set(x+1, row, '━', f, true)
		}
		if k >= 2 {
			cv.set(x+2, row, '▶', f, true)
		}
		cv.put(x+4, row, typed(c.Breach, k-3), f, true)
	}
}

// chain links a readable secret to a proven way out, with marching ants toward the exit.
func (m model) chain(cv *canvas, e float64) {
	s, g := idxOf("SEC-1"), idxOf("EGR-1")
	if s < 0 || g < 0 || m.status(s, e) < 2 || m.status(g, e) < 2 {
		return
	}
	age := e - math.Max(m.tl.arrive[s][0], m.tl.arrive[g][0]) - 0.3
	if age < 0 {
		return
	}
	f := m.theme().Find
	sx, gy := m.pos[s][0], m.pos[g][1]
	var path [][2]int
	for y := by0 + 1; y <= gy; y++ {
		path = append(path, [2]int{sx, y})
	}
	for x := sx + 1; x < bx1; x++ {
		path = append(path, [2]int{x, gy})
	}
	n := min(len(path), int(age*50))
	for j := 0; j < n; j++ {
		r := '┄'
		switch {
		case path[j] == [2]int{sx, gy}:
			r = '└'
		case path[j][0] == sx:
			r = '┆'
		}
		cv.set(path[j][0], path[j][1], r, f, ((j-m.frame/2)%4+4)%4 == 0)
	}
	if n == len(path) {
		cv.put(sx+2, by0+1, "CHAIN: a secret can leave", f, true)
	}
}

// The grade drops in on a spring, lands with a shake, then the counts tick up.
func (m model) viewGrade() string {
	t, p := m.theme(), providers[m.pick]
	ge := m.runE() - m.tl.tGrade
	letter := gradeLetter()
	col := t.grade(letter)
	cr, hi, md, ps, un := counts()
	cv := newCanvas(W, 13)
	d := -1.0
	if m.impact != -1 {
		d = ge - m.impact
	}
	shake := 0
	if d >= 0 && d < 0.5 {
		shake = int(math.Round(1.8 * math.Sin(d*48) * math.Exp(-d*7)))
	}
	fx0, fy0, fx1, fy1 := 4+shake, 3, 23+shake, 10
	fc := t.Faint
	if d >= 0 {
		fc = col
	}
	boxDouble(cv, fx0, fy0, fx1, fy1, fc)
	rows := bigText(letter, 2)
	lx, ly := fx0+(fx1-fx0+1-runeLen(rows[0]))/2, fy0+2+int(math.Round(m.gy))
	ink := '█'
	if d >= 0 && d < 0.12 {
		ink = '▓'
	}
	for y, row := range rows {
		for x, r := range []rune(row) {
			if r != ' ' {
				cv.set(lx+x, ly+y, ink, col, true)
			}
		}
	}
	if d >= 0 {
		tx, ty := 30, int(d*60)
		cv.put(tx, 4, typed("CONTAINMENT GRADE", ty), t.Text, true)
		cv.put(tx, 5, typed(p.Short+" · default box", ty-4), t.Dim, false)
		cv.put(tx, 6, typed(nowPT(), ty-8), t.Dim, false)
		if d >= 0.25 {
			f := math.Min(1, (d-0.25)/0.6)
			k := func(v int) string { return fmt.Sprint(int(math.Round(float64(v) * f))) }
			x := cv.put(tx, 8, k(cr)+" critical", t.Find, true)
			x = cv.put(x+3, 8, k(hi)+" high", t.Find, false)
			cv.put(x+3, 8, k(md)+" medium", t.Unknown, false)
			x = cv.put(tx, 9, k(ps)+" verified passes", t.Pass, false)
			x = cv.put(x, 9, " · ", t.Dim, false)
			x = cv.put(x, 9, k(un)+" unknown", t.Unknown, false)
			if un > 0 {
				cv.put(x, 9, " · incomplete", t.Dim, false)
			}
		}
	}
	ls := []string{m.header(m.tl.tGrade), m.stepsLine(m.runE()), ""}
	ls = append(ls, strings.Split(cv.render(t, nil), "\n")...)
	if d > 1.0 {
		ls = append(ls, t.sp(2)+t.c(t.Dim, "Web report  ")+t.c(t.Text, trunc(m.htmlPath, W-14)), "",
			keys(t, "o", "open the web report", "⏎", "explore here", "r", "run again", "t", "palette", "q", "quit"))
	} else {
		ls = append(ls, "", "", "")
	}
	ls = append(ls, "", m.toastLine())
	return t.pad(ls, W)
}

// The explorer: findings first, then unknowns, then every verified pass with its evidence.
type item struct {
	head string
	c    Check
}

func buildItems() []item {
	var u, p []Check
	for _, c := range checks {
		switch c.Result {
		case Unknown:
			u = append(u, c)
		case Pass:
			p = append(p, c)
		}
	}
	var it []item
	for _, g := range []struct {
		h  string
		cs []Check
	}{{"FINDINGS", findings()}, {"UNKNOWN", u}, {"VERIFIED PASSES", p}} {
		if len(g.cs) > 0 {
			it = append(it, item{head: fmt.Sprintf("%s (%d)", g.h, len(g.cs))})
			for _, c := range g.cs {
				it = append(it, item{c: c})
			}
		}
	}
	return it
}

func (m model) viewExplore() string {
	t, p := m.theme(), providers[m.pick]
	ew := clampInt(m.w-4, W, 112)
	lw := 40
	rw := ew - lw - 3
	cr, hi, md, ps, un := counts()
	letter := gradeLetter()

	var left []string
	selLine := 0
	for i, it := range m.items {
		if it.head != "" {
			if i > 0 {
				left = append(left, "")
			}
			left = append(left, t.sp(1)+t.b(t.Dim, it.head))
			continue
		}
		c := it.c
		cur, title := t.sp(2), t.st(t.Dim)
		if i == m.sel {
			cur, title, selLine = t.b(t.Accent, "▸ "), t.st(t.Text).Bold(true), len(left)
		}
		tag := c.Sev
		switch c.Result {
		case Pass:
			tag = c.ID
		case Unknown:
			tag = "UNKN"
		}
		left = append(left, cur+t.b(t.result(c.Result), glyph(c.Result))+t.sp(1)+t.c(t.sev(c), fmt.Sprintf("%-6s", tag))+title.Render(trunc(c.Title, lw-11)))
	}
	avail := max(10, m.h-9)
	if len(left) > avail {
		start := clampInt(selLine-avail/2, 0, len(left)-avail)
		left = left[start : start+avail]
	}

	c := m.items[m.sel].c
	label, lcol := "VERIFIED", t.Pass
	switch {
	case c.Result == Unknown:
		label, lcol = "UNKNOWN", t.Unknown
	case c.Sev == "CRIT":
		label, lcol = "CRITICAL", t.Find
	case c.Sev == "HIGH":
		label, lcol = "HIGH", t.Find
	case c.Sev == "MED":
		label, lcol = "MEDIUM", t.Unknown
	}
	right := []string{t.b(lcol, label) + t.c(t.Dim, " · "+c.ID), t.b(t.Text, c.Title), ""}
	sec := func(h, body string) {
		if body == "" {
			return
		}
		right = append(right, t.b(t.Accent, h))
		for _, l := range wrap(body, rw-2) {
			right = append(right, t.sp(2)+t.c(t.Text, l))
		}
		right = append(right, "")
	}
	switch c.Result {
	case Pass:
		sec("Evidence", c.Evidence)
		sec("How we checked", c.How)
	case Unknown:
		sec("Why it's unknown", c.Evidence)
		sec("What that means", c.How)
		sec("Fix", c.Fix)
	default:
		sec("What a hijacked agent gets", c.Gets)
		sec("Evidence", c.Evidence)
		sec("How we checked", c.How)
		sec("Fix", c.Fix)
	}

	rows := []string{
		t.spread(t.b(t.Accent, "SANDPROBE")+t.c(t.Dim, fmt.Sprintf("   %s › %s › %s", p.Short, p.Box, nowPT())), t.b(t.Unknown, "DEMO DATA, NOT A REAL RUN"), ew),
		t.b(t.grade(letter), "GRADE "+letter) + t.c(t.Dim, fmt.Sprintf("   %d critical · %d high · %d medium · %d verified · %d unknown", cr, hi, md, ps, un)),
		t.c(t.Faint, strings.Repeat("─", ew)),
	}
	for i := 0; i < max(len(left), len(right)); i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		rows = append(rows, l+t.sp(lw-lipgloss.Width(l))+t.c(t.Faint, " │ ")+r)
	}
	rows = append(rows, t.c(t.Faint, strings.Repeat("─", ew)),
		t.spread(keys(t, "↑↓", "move", "c", "copy fix", "o", "web report", "esc", "back", "t", "palette", "q", "quit"), m.toastLine(), ew))
	return t.pad(rows, ew)
}
