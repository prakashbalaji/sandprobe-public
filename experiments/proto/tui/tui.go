package main

import (
	"fmt"
	"math"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/harmonica"
	"github.com/charmbracelet/lipgloss"
)

type phase int

const (
	phBoot phase = iota
	phPick
	phMode
	phPlan
	phRun // the live map, then the grade
	phExplore
)

const W = 76 // width of every screen but the explorer

type model struct {
	w, h       int
	th         int
	speed      float64
	still      bool
	ph         phase
	now        time.Time
	phStart    time.Time
	runStart   time.Time
	frame      int
	pick, mode int
	tl         timeline
	pos        [][2]int
	paths      [][][2]int
	gy, gv     float64 // the grade letter's drop, driven by a spring
	impact     float64 // when it landed, in grade seconds; -1 not yet
	spring     harmonica.Spring
	items      []item
	sel        int
	toast      string
	toastUntil time.Time
	snapE      float64 // >= 0: render the run frozen at this time
	htmlPath   string
}

type tickMsg time.Time
type toastMsg string
type reportMsg string

func tick() tea.Cmd {
	return tea.Tick(time.Second/30, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func newModel(th int, speed float64, still bool) model {
	now := time.Now()
	m := model{th: th, speed: speed, still: still, now: now, phStart: now, snapE: -1, impact: -1,
		spring: harmonica.NewSpring(harmonica.FPS(30), 7.0, 0.42)}
	if still {
		m.ph = phPick
	}
	m.pos, m.paths = layout()
	m.items = buildItems()
	m.sel = 1
	return m
}

func (m model) Init() tea.Cmd { return tick() }

func (m model) theme() Theme { return themes[m.th] }

func (m model) since(t time.Time) float64 { return m.now.Sub(t).Seconds() * m.speed }

func (m model) runE() float64 {
	switch {
	case m.snapE >= 0:
		return m.snapE
	case m.still:
		return 1e6
	}
	return m.since(m.runStart)
}

func (m model) startRun() model {
	m.ph, m.runStart = phRun, m.now
	m.tl = buildTimeline(providers[m.pick])
	m.gy, m.gv, m.impact = -9, 0, -1
	if m.still {
		m.gy, m.impact = 0, -10
	}
	m.htmlPath = ""
	return m
}

func (m model) stepSpring(ge float64) model {
	m.gy, m.gv = m.spring.Update(m.gy, m.gv, 0)
	if m.impact == -1 && m.gy > -0.5 {
		m.impact = ge
	}
	return m
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tickMsg:
		m.now, m.frame = time.Time(msg), m.frame+1
		if m.ph == phBoot && m.since(m.phStart) > bootDone(m.theme()) {
			m.ph = phPick
		}
		var write tea.Cmd
		if m.ph == phRun {
			if ge := m.runE() - m.tl.tGrade; ge >= 0 {
				m = m.stepSpring(ge)
				if m.htmlPath == "" {
					m.htmlPath = "writing…"
					write = writeReportCmd(m.th)
				}
			}
		}
		return m, tea.Batch(tick(), write)
	case reportMsg:
		m.htmlPath = string(msg)
	case toastMsg:
		m.toast, m.toastUntil = string(msg), m.now.Add(2500*time.Millisecond)
	case tea.KeyMsg:
		return m.key(msg.String())
	}
	return m, nil
}

func (m model) key(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "t":
		m.th = (m.th + 1) % len(themes)
		return m, nil
	}
	switch m.ph {
	case phBoot:
		m.ph = phPick
	case phPick:
		switch k {
		case "up", "k":
			m.pick = (m.pick + len(providers) - 1) % len(providers)
		case "down", "j":
			m.pick = (m.pick + 1) % len(providers)
		case "enter":
			m.ph, m.mode = phMode, 0
		}
	case phMode:
		switch k {
		case "up", "k", "down", "j":
			m.mode = 1 - m.mode
		case "enter":
			m.ph, m.phStart = phPlan, m.now
		case "esc":
			m.ph = phPick
		}
	case phPlan:
		switch k {
		case "y", "Y", "enter":
			m = m.startRun()
		case "n", "N", "esc":
			m.ph = phPick
		}
	case phRun:
		graded := m.runE() >= m.tl.tGrade
		switch {
		case k == "s" && !graded:
			m.runStart = m.now.Add(-time.Duration((m.tl.tGrade + 3) / m.speed * float64(time.Second)))
			m.gy, m.gv, m.impact = 0, 0, -10
		case k == "enter" && graded:
			m.ph = phExplore
		case k == "o" && graded:
			return m, openCmd(m.htmlPath)
		case k == "r" && graded:
			m = m.startRun()
		}
	case phExplore:
		switch k {
		case "up", "k":
			m.sel = m.step(-1)
		case "down", "j":
			m.sel = m.step(1)
		case "c":
			return m, copyCmd(m.items[m.sel].c.Fix)
		case "o":
			return m, openCmd(m.htmlPath)
		case "r":
			m = m.startRun()
		case "esc":
			m.ph = phRun
		}
	}
	return m, nil
}

func (m model) step(d int) int {
	for i := m.sel + d; i >= 0 && i < len(m.items); i += d {
		if m.items[i].head == "" {
			return i
		}
	}
	return m.sel
}

func writeReportCmd(th int) tea.Cmd {
	return func() tea.Msg {
		path, _ := filepath.Abs(fmt.Sprintf("sandprobe-%s-7f3a.html", "sprites"))
		if err := writeHTML(path, th); err != nil {
			return toastMsg("couldn't write the web report: " + err.Error())
		}
		return reportMsg(path)
	}
}

func openCmd(path string) tea.Cmd {
	return func() tea.Msg {
		if !strings.HasSuffix(path, ".html") {
			return toastMsg("the web report isn't written yet")
		}
		name := "open"
		if runtime.GOOS == "linux" {
			name = "xdg-open"
		}
		if exec.Command(name, path).Start() != nil {
			return toastMsg("couldn't open " + path)
		}
		return toastMsg("opened the web report in your browser")
	}
}

func copyCmd(s string) tea.Cmd {
	return func() tea.Msg {
		if s == "" {
			return toastMsg("a verified pass has no fix to copy")
		}
		name, args := "pbcopy", []string{}
		if runtime.GOOS == "linux" {
			name, args = "xclip", []string{"-selection", "clipboard"}
		}
		cmd := exec.Command(name, args...)
		cmd.Stdin = strings.NewReader(s)
		if cmd.Run() != nil {
			return toastMsg("couldn't reach the clipboard")
		}
		return toastMsg("fix copied to the clipboard")
	}
}

func (m model) View() string {
	if m.w == 0 {
		return ""
	}
	t := m.theme()
	var body string
	switch {
	case m.w < W+2 || m.h < 27:
		body = t.c(t.Text, fmt.Sprintf("Sandprobe needs a window of at least %d×27 (this one is %d×%d).", W+2, m.w, m.h))
	case m.ph <= phMode:
		body = m.viewBoot()
	case m.ph == phPlan:
		body = m.viewPlan()
	case m.ph == phRun && m.runE() < m.tl.tGrade:
		body = m.viewRun()
	case m.ph == phRun:
		body = m.viewGrade()
	default:
		body = m.viewExplore()
	}
	var opts []lipgloss.WhitespaceOption
	if t.BG != "" {
		opts = append(opts, lipgloss.WithWhitespaceBackground(t.BG))
	}
	return lipgloss.Place(m.w, m.h, lipgloss.Center, lipgloss.Center, body, opts...)
}

func (m model) toastLine() string {
	t := m.theme()
	if m.toast == "" || m.now.After(m.toastUntil) {
		return ""
	}
	return t.sp(2) + t.b(t.Accent, "› ") + t.c(t.Text, m.toast)
}

func keys(t Theme, pairs ...string) string {
	s := t.sp(2)
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			s += t.c(t.Faint, "   ")
		}
		s += t.b(t.Accent, pairs[i]) + t.c(t.Dim, " "+pairs[i+1])
	}
	return s
}

// Boot: the wordmark decodes out of noise (after a CRT power-on in the mission palette), then the tagline types.

const tagline = "what could a hijacked agent reach in your sandbox?"

func powerOn(t Theme) float64 {
	if t.Name == "mission" {
		return 0.45
	}
	return 0
}

func bootDone(t Theme) float64 { return powerOn(t) + 1.35 + float64(len(tagline))/45 + 0.25 }

func (m model) viewBoot() string {
	t := m.theme()
	e := m.since(m.phStart)
	if m.ph != phBoot {
		e = 1e6
	}
	off := powerOn(t)
	cv := newCanvas(W, 7)
	logo := bigText("SANDPROBE", 1)
	lw := runeLen(logo[0])
	ox := (W - lw) / 2
	if e < off {
		half := int(math.Min(e/0.25, 1) * float64(W/2-4))
		col := t.Accent
		if e > 0.3 {
			col = t.Dim
		}
		for x := W/2 - half; x < W/2+half; x++ {
			cv.set(x, 3, '━', col, true)
		}
	} else {
		noise := []rune("░▒▓█<>/\\|#%&@$*+=?!")
		at := func(x, y int) float64 { return off + 0.1 + float64(x)/float64(lw)*0.9 + hash01(x, y)*0.3 }
		for y, row := range logo {
			for x, r := range []rune(row) {
				if r != ' ' && e >= at(x, y) {
					cv.set(ox+x+1, y+1, '░', t.Faint, false) // drop shadow
				}
			}
		}
		for y, row := range logo {
			for x, r := range []rune(row) {
				if r == ' ' {
					continue
				}
				switch a := at(x, y); {
				case e >= a:
					cv.set(ox+x, y, '█', t.Accent, true)
				case e >= a-0.45:
					cv.set(ox+x, y, noise[(x*7+y*13+m.frame*3)%len(noise)], t.Dim, false)
				}
			}
		}
	}
	ls := strings.Split(cv.render(t, nil), "\n")
	n := clampInt(int((e-off-1.35)*45), 0, len(tagline))
	tag := t.c(t.Text, tagline[:n])
	if n < len(tagline) && e > off+1.3 && m.frame%10 < 5 {
		tag += t.c(t.Accent, "▌")
	}
	ls = append(ls, t.center(tag, W), t.center(t.c(t.Faint, "prototype · demo data · palette "+t.Name), W), "", "")
	switch m.ph {
	case phPick:
		ls = append(ls, t.sp(2)+t.b(t.Accent, "?")+t.b(t.Text, " Where does your agent run?"), "")
		for i, p := range providers {
			cur, name, desc := t.sp(2), t.st(t.Dim), t.st(t.Faint)
			if i == m.pick {
				cur, name, desc = t.b(t.Accent, "❯ "), t.st(t.Text).Bold(true), t.st(t.Dim)
			}
			ls = append(ls, t.sp(4)+cur+name.Render(fmt.Sprintf("%-28s", p.Name))+desc.Render(p.Desc))
		}
	case phMode:
		ls = append(ls, t.sp(2)+t.b(t.Accent, "?")+t.b(t.Text, " What should we probe?")+t.c(t.Dim, "   "+providers[m.pick].Name), "")
		opts := [][2]string{{"A new throwaway box, default settings", "we create it, then delete it"}, {"A box I already have", "we never change or delete it"}}
		for i, o := range opts {
			cur, name, desc := t.sp(2), t.st(t.Dim), t.st(t.Faint)
			if i == m.mode {
				cur, name, desc = t.b(t.Accent, "❯ "), t.st(t.Text).Bold(true), t.st(t.Dim)
			}
			ls = append(ls, t.sp(4)+cur+name.Render(fmt.Sprintf("%-40s", o[0]))+desc.Render(o[1]))
		}
	}
	for len(ls) < 20 {
		ls = append(ls, "")
	}
	switch m.ph {
	case phBoot:
		ls = append(ls, t.center(t.c(t.Faint, "any key to skip"), W))
	case phPick:
		ls = append(ls, keys(t, "↑↓", "choose", "⏎", "select", "t", "palette", "q", "quit"))
	default:
		ls = append(ls, keys(t, "↑↓", "choose", "⏎", "select", "esc", "back", "t", "palette", "q", "quit"))
	}
	return t.pad(ls, W)
}

// Plan: check access, say exactly what will happen, ask once.
func (m model) viewPlan() string {
	t, p, e := m.theme(), providers[m.pick], m.since(m.phStart)
	ls := []string{t.spread(t.sp(2)+t.b(t.Accent, "SANDPROBE")+t.c(t.Dim, "   "+p.Name), t.b(t.Unknown, "DEMO DATA")+t.sp(2), W), "", t.sp(2) + t.b(t.Text, "Checking access")}
	for i, a := range p.Access {
		at := 0.25 + float64(i)*0.45
		switch {
		case e >= at+0.4:
			ls = append(ls, t.sp(2)+t.b(t.Pass, "✓ ")+t.c(t.Text, a))
		case e >= at:
			ls = append(ls, t.sp(2)+t.c(t.Accent, spinner(m.frame)+" ")+t.c(t.Dim, a))
		}
	}
	if e >= 1.4 {
		ls = append(ls, "", t.sp(2)+t.b(t.Text, "This will"))
		steps := p.Steps
		if m.mode == 1 {
			steps = p.Existing
		}
		for i, s := range steps {
			if e >= 1.5+float64(i)*0.12 {
				ls = append(ls, t.sp(4)+t.c(t.Accent, "• ")+t.c(t.Text, s))
			}
		}
	}
	if e >= 2.1 {
		ls = append(ls, "", t.sp(2)+t.c(t.Dim, "The probe never reads a secret's value, only that it's readable."),
			t.sp(2)+t.c(t.Dim, "It contacts only probe.sandprobe.dev; the report lists every host."))
		if m.mode == 1 {
			ls = append(ls, t.sp(2)+t.c(t.Faint, "demo: the run below replays the throwaway flow"))
		}
	}
	if e >= 2.4 {
		cur := " "
		if m.frame%16 < 8 {
			cur = "▌"
		}
		ls = append(ls, "", t.sp(2)+t.b(t.Accent, "?")+t.b(t.Text, " Go ahead? ")+t.c(t.Dim, "(Y/n) ")+t.c(t.Accent, cur))
	}
	for len(ls) < 20 {
		ls = append(ls, "")
	}
	ls = append(ls, keys(t, "y", "go", "n", "back", "t", "palette", "q", "quit"))
	return t.pad(ls, W)
}
