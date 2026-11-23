package main

import (
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type Theme struct {
	Name                           string
	BG, Roll                       lipgloss.Color // Roll: the mission palette's CRT refresh band
	Text, Dim, Faint, Accent, Wall lipgloss.Color
	Pass, Find, Unknown            lipgloss.Color
}

var themes = []Theme{
	{Name: "modern", Text: "#E6EDF3", Dim: "#7D8590", Faint: "#3B4450", Accent: "#22D3EE", Wall: "#8B98A9",
		Pass: "#3FB950", Find: "#FF4D6D", Unknown: "#F2CC60"},
	{Name: "mission", BG: "#0B0800", Roll: "#191200", Text: "#FFB000", Dim: "#A87400", Faint: "#4D3500", Accent: "#FFD27A",
		Wall: "#CC8C00", Pass: "#FFC940", Find: "#FF3D1F", Unknown: "#FFF06A"},
}

func themeIndex(name string) int {
	for i, t := range themes {
		if t.Name == name {
			return i
		}
	}
	return 0
}

// Every piece of text goes through st, so the mission palette's background covers the whole screen.
func (t Theme) st(fg lipgloss.Color) lipgloss.Style {
	s := lipgloss.NewStyle()
	if fg != "" {
		s = s.Foreground(fg)
	}
	if t.BG != "" {
		s = s.Background(t.BG)
	}
	return s
}

func (t Theme) c(fg lipgloss.Color, s string) string { return t.st(fg).Render(s) }
func (t Theme) b(fg lipgloss.Color, s string) string { return t.st(fg).Bold(true).Render(s) }

func (t Theme) sp(n int) string {
	if n <= 0 {
		return ""
	}
	return t.st("").Render(strings.Repeat(" ", n))
}

// pad makes every line exactly w cells wide, so the block centres as one piece.
func (t Theme) pad(lines []string, w int) string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			l = ansi.Truncate(l, w, "…")
		}
		out[i] = l + t.sp(w-lipgloss.Width(l))
	}
	return strings.Join(out, "\n")
}

func (t Theme) center(s string, w int) string { return t.sp((w-lipgloss.Width(s))/2) + s }

func (t Theme) spread(l, r string, w int) string {
	return l + t.sp(w-lipgloss.Width(l)-lipgloss.Width(r)) + r
}

func (t Theme) result(r Result) lipgloss.Color {
	switch r {
	case Pass:
		return t.Pass
	case Find:
		return t.Find
	}
	return t.Unknown
}

func (t Theme) sev(c Check) lipgloss.Color {
	switch {
	case c.Result == Pass:
		return t.Dim
	case c.Result == Unknown || c.Sev == "MED":
		return t.Unknown
	}
	return t.Find
}

func (t Theme) grade(letter string) lipgloss.Color {
	switch letter {
	case "F", "D":
		return t.Find
	case "C":
		return t.Unknown
	}
	return t.Pass
}

func glyph(r Result) string { return map[Result]string{Pass: "✓", Find: "✗", Unknown: "?"}[r] }

// canvas is a grid of styled cells for the animated screens.
type cell struct {
	r    rune
	fg   lipgloss.Color
	bold bool
}

type canvas struct {
	w, h int
	c    [][]cell
}

func newCanvas(w, h int) *canvas {
	cv := &canvas{w: w, h: h, c: make([][]cell, h)}
	for y := range cv.c {
		cv.c[y] = make([]cell, w)
		for x := range cv.c[y] {
			cv.c[y][x].r = ' '
		}
	}
	return cv
}

func (cv *canvas) set(x, y int, r rune, fg lipgloss.Color, bold bool) {
	if x >= 0 && y >= 0 && x < cv.w && y < cv.h {
		cv.c[y][x] = cell{r, fg, bold}
	}
}

// put writes s from x and returns the column after it.
func (cv *canvas) put(x, y int, s string, fg lipgloss.Color, bold bool) int {
	for _, r := range s {
		cv.set(x, y, r, fg, bold)
		x++
	}
	return x
}

func (cv *canvas) render(t Theme, rowBG func(int) lipgloss.Color) string {
	var b strings.Builder
	for y, row := range cv.c {
		bg := t.BG
		if rowBG != nil {
			if c := rowBG(y); c != "" {
				bg = c
			}
		}
		for i := 0; i < len(row); {
			j := i
			var seg strings.Builder
			for j < len(row) && row[j].fg == row[i].fg && row[j].bold == row[i].bold {
				seg.WriteRune(row[j].r)
				j++
			}
			s := lipgloss.NewStyle().Bold(row[i].bold)
			if row[i].fg != "" {
				s = s.Foreground(row[i].fg)
			}
			if bg != "" {
				s = s.Background(bg)
			}
			b.WriteString(s.Render(seg.String()))
			i = j
		}
		if y < len(cv.c)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func boxDouble(cv *canvas, x0, y0, x1, y1 int, col lipgloss.Color) {
	for x := x0 + 1; x < x1; x++ {
		cv.set(x, y0, '═', col, true)
		cv.set(x, y1, '═', col, true)
	}
	for y := y0 + 1; y < y1; y++ {
		cv.set(x0, y, '║', col, true)
		cv.set(x1, y, '║', col, true)
	}
	cv.set(x0, y0, '╔', col, true)
	cv.set(x1, y0, '╗', col, true)
	cv.set(x0, y1, '╚', col, true)
	cv.set(x1, y1, '╝', col, true)
}

// A five-row block font for the wordmark and the grade.
var font = map[rune][5]string{
	'S': {" ████", "██   ", " ███ ", "   ██", "████ "},
	'A': {" ███ ", "██ ██", "█████", "██ ██", "██ ██"},
	'N': {"██  ██", "███ ██", "██████", "██ ███", "██  ██"},
	'D': {"████ ", "██ ██", "██ ██", "██ ██", "████ "},
	'P': {"████ ", "██ ██", "████ ", "██   ", "██   "},
	'R': {"████ ", "██ ██", "████ ", "██ ██", "██ ██"},
	'O': {" ███ ", "██ ██", "██ ██", "██ ██", " ███ "},
	'B': {"████ ", "██ ██", "████ ", "██ ██", "████ "},
	'E': {"█████", "██   ", "████ ", "██   ", "█████"},
	'C': {" ████", "██   ", "██   ", "██   ", " ████"},
	'F': {"█████", "██   ", "████ ", "██   ", "██   "},
}

// bigText lays s out in the block font, sx cells per pixel across.
func bigText(s string, sx int) []string {
	rows := make([]string, 5)
	for i, ch := range s {
		g := font[ch]
		for y := range rows {
			if i > 0 {
				rows[y] += strings.Repeat(" ", sx)
			}
			for _, r := range g[y] {
				rows[y] += strings.Repeat(string(r), sx)
			}
		}
	}
	return rows
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func typed(s string, n int) string {
	r := []rune(s)
	return string(r[:clampInt(n, 0, len(r))])
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func wrap(s string, w int) []string {
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case runeLen(line)+1+runeLen(word) > w:
			out = append(out, line)
			line = word
		default:
			line += " " + word
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

func clampInt(v, lo, hi int) int { return max(lo, min(v, hi)) }

func spinner(frame int) string { return string([]rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")[frame/2%10]) }

func hash01(x, y int) float64 {
	h := uint32(x)*374761393 + uint32(y)*668265263
	h = (h ^ (h >> 13)) * 1274126177
	return float64(h%1000) / 1000
}
