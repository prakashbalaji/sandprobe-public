package report

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// themes are -theme's values (UX-8): every page test that covers the palettes runs over all four.
var themes = []string{"auto", "light", "graphite", "mission"}

// paletteAt names each palette's token block in the page's stylesheet by the text that opens it (UX-8). autoDark is
// graphite again, behind the system's dark scheme.
var paletteAt = map[string]string{
	"light":    "\n:root, [data-theme=\"light\"] {",
	"autoDark": "\n@media (prefers-color-scheme: dark) {\n  [data-theme=\"auto\"] {",
	"graphite": "\n[data-theme=\"graphite\"] {",
	"mission":  "\n[data-theme=\"mission\"] {",
}

var tokenRE = regexp.MustCompile(`--([a-z0-9-]+):\s*([^;]+);`)

// stylesheet is the page's one style block.
func stylesheet(t *testing.T) string {
	t.Helper()
	b, err := HTML(Build(run(), meta()), "")
	if err != nil {
		t.Fatal(err)
	}
	m := styleRE.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("no style block")
	}
	return m[1]
}

// tokens reads one palette's custom properties from the stylesheet.
func tokens(t *testing.T, css, name string) map[string]string {
	t.Helper()
	open := paletteAt[name]
	i := strings.Index(css, open)
	if i < 0 || strings.Count(css, open) != 1 {
		t.Fatalf("%s: want exactly one block opened by %q", name, open)
	}
	block := css[i+len(open):]
	block = block[:strings.Index(block, "}")]
	out := map[string]string{}
	for _, m := range tokenRE.FindAllStringSubmatch(block, -1) {
		out[m[1]] = strings.TrimSpace(m[2])
	}
	return out
}

type rgba struct{ r, g, b, a float64 }

var (
	hexRE = regexp.MustCompile(`^#([0-9a-f]{6}|[0-9a-f]{3})$`)
	rgbRE = regexp.MustCompile(`^rgb\((\d+) (\d+) (\d+)(?: / ([0-9.]+))?\)$`)
	varRE = regexp.MustCompile(`^var\(--([a-z0-9-]+)\)$`)
)

// color resolves a token to a color: #rgb, #rrggbb, rgb(r g b / a), or var() of another token.
func color(t *testing.T, pal map[string]string, name string) rgba {
	t.Helper()
	v, ok := pal[name]
	for depth := 0; ok && depth < 4; depth++ {
		m := varRE.FindStringSubmatch(v)
		if m == nil {
			break
		}
		v, ok = pal[m[1]]
	}
	if !ok {
		t.Fatalf("no token --%s", name)
	}
	if m := hexRE.FindStringSubmatch(v); m != nil {
		h := m[1]
		if len(h) == 3 {
			h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
		}
		n, _ := strconv.ParseUint(h, 16, 32)
		return rgba{float64(n >> 16), float64(n >> 8 & 255), float64(n & 255), 1}
	}
	if m := rgbRE.FindStringSubmatch(v); m != nil {
		c := rgba{a: 1}
		c.r, _ = strconv.ParseFloat(m[1], 64)
		c.g, _ = strconv.ParseFloat(m[2], 64)
		c.b, _ = strconv.ParseFloat(m[3], 64)
		if m[4] != "" {
			c.a, _ = strconv.ParseFloat(m[4], 64)
		}
		return c
	}
	t.Fatalf("--%s: %q isn't a color this test reads", name, v)
	return rgba{}
}

// over draws c on an opaque color.
func (c rgba) over(on rgba) rgba {
	return rgba{c.r*c.a + on.r*(1-c.a), c.g*c.a + on.g*(1-c.a), c.b*c.a + on.b*(1-c.a), 1}
}

// luminance is WCAG 2's relative luminance of an opaque sRGB color.
func (c rgba) luminance() float64 {
	lin := func(v float64) float64 {
		if v /= 255; v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.r) + 0.7152*lin(c.g) + 0.0722*lin(c.b)
}

// contrast is WCAG 2's contrast ratio of two opaque colors.
func contrast(a, b rgba) float64 {
	hi, lo := a.luminance(), b.luminance()
	if hi < lo {
		hi, lo = lo, hi
	}
	return (hi + 0.05) / (lo + 0.05)
}

func TestContrastMath(t *testing.T) {
	white, black := rgba{255, 255, 255, 1}, rgba{0, 0, 0, 1}
	if r := contrast(white, black); math.Abs(r-21) > 0.001 {
		t.Errorf("white on black: want 21, got %.3f", r)
	}
	if r := contrast(rgba{0x76, 0x76, 0x76, 1}, white); math.Abs(r-4.54) > 0.01 { // WCAG's own 4.5:1 grey
		t.Errorf("#767676 on white: want 4.54, got %.3f", r)
	}
	if c := (rgba{0, 0, 0, .5}).over(white); math.Abs(c.r-127.5) > 0.001 {
		t.Errorf("half black over white: got %v", c)
	}
}

// The three floors of UX-9: text, a mark that carries a result, and a hairline, which only has to stay visible.
const (
	aaText   = 4.5
	aaMark   = 3.0
	hairline = 1.2
)

// pairs is every foreground token on every surface the page draws it on (UX-9). A surface is a stack, drawn bottom
// up: a tint or a hover wash sits on the page or on a panel. dim is the opacity token of a severity dot.
var pairs = []struct {
	fg   string
	on   []string
	dim  string
	min  float64
	what string
}{
	{"text", []string{"bg"}, "", aaText, "body text"},
	{"text", []string{"raise"}, "", aaText, "text in a panel"},
	{"text", []string{"inset"}, "", aaText, "a banner"},
	{"text", []string{"bg", "sel"}, "", aaText, "the contents rail's current entry"},
	{"text", []string{"bg", "hover"}, "", aaText, "a hovered rail entry or button"},
	{"text", []string{"raise", "hover"}, "", aaText, "a hovered test link in a category row"},
	{"muted", []string{"bg"}, "", aaText, "secondary text: what was seen, a fix, the statements"},
	{"muted", []string{"raise"}, "", aaText, "secondary text in a panel, table captions"},
	{"faint", []string{"bg"}, "", aaText, "labels: a test's ID, the strip, the footer"},
	{"faint", []string{"raise"}, "", aaText, "labels in a panel, a neutral test link, the map's wall and words"},
	{"faint", []string{"bg", "sel"}, "", aaText, "a count in the rail's current entry"},
	{"faint", []string{"bg", "hover"}, "", aaText, "a count in a hovered rail entry"},
	{"red", []string{"bg"}, "", aaText, "the score, a failing count"},
	{"red", []string{"raise"}, "", aaText, "the map's finding labels, a row's red dot"},
	{"red", []string{"raise", "red-tint"}, "", aaText, "a red pill in a panel: the chain's severity, RED, a failing test link"},
	{"on-fail", []string{"bg", "fail-bg"}, "", aaText, "the Fail pill"},
	{"green", []string{"bg"}, "", aaText, "the Pass pill, the score, Fix"},
	{"green", []string{"raise"}, "", aaText, "GREEN, a passing test link, the map's verified walls"},
	{"unk", []string{"bg"}, "", aaText, "the Unknown pill, an incomplete run's status"},
	{"unk", []string{"raise"}, "", aaText, "an unknown test link, the map's unknown mark"},
	{"on-pill", []string{"pill"}, "", aaText, "the JSON button"},
	{"on-pill", []string{"pill-hover"}, "", aaText, "the JSON button, hovered"},

	{"red-edge", []string{"bg"}, "", aaMark, "the Fail pill's outline"},
	{"red-edge", []string{"raise"}, "", aaMark, "a red pill's outline in a panel"},
	{"green-edge", []string{"bg"}, "", aaMark, "the Pass pill's outline"},
	{"green-edge", []string{"raise"}, "", aaMark, "a green pill's outline in a panel"},
	{"unk-edge", []string{"bg"}, "", aaMark, "a dashed unknown outline"},
	{"unk-edge", []string{"raise"}, "", aaMark, "a dashed unknown outline in a panel"},
	{"unk-edge", []string{"inset"}, "", aaMark, "a banner's dashed mark"},
	{"unk-edge", []string{"bg", "sel"}, "", aaMark, "the unknown group's dashed dot in the rail's current entry"},
	{"edge", []string{"bg"}, "", aaMark, "a neutral pill's outline"},
	{"edge", []string{"raise"}, "", aaMark, "a neutral pill's outline in a panel"},
	{"red", []string{"bg", "sel"}, "", aaMark, "the critical group's dot in the rail's current entry"},
	{"red", []string{"bg"}, "dim-high", aaMark, "the high group's dot"},
	{"red", []string{"bg", "sel"}, "dim-high", aaMark, "the high group's dot in the rail's current entry"},
	{"red", []string{"bg"}, "dim-medium", aaMark, "the medium group's dot"},
	{"red", []string{"bg", "sel"}, "dim-medium", aaMark, "the medium group's dot in the rail's current entry"},
	{"red", []string{"bg"}, "dim-low", aaMark, "the low group's dot"},
	{"red", []string{"bg", "sel"}, "dim-low", aaMark, "the low group's dot in the rail's current entry"},

	{"line", []string{"bg"}, "", hairline, "a hairline on the page"},
	{"line", []string{"raise"}, "", hairline, "a hairline in a panel"},
	{"line2", []string{"bg"}, "", hairline, "a banner's edge"},
}

// UX-9: in every palette, each text token meets WCAG AA (4.5:1) on every surface it is drawn on, and each mark that
// carries a result (a pill's outline, a dot, a dashed unknown mark) meets 3:1. The ratios are computed from the
// tokens the page ships, so a palette edit that costs readability fails here.
func TestContrast(t *testing.T) {
	css := stylesheet(t)
	for _, name := range []string{"light", "graphite", "mission"} {
		pal := tokens(t, css, name)
		for _, p := range pairs {
			surface := color(t, pal, p.on[0])
			if surface.a != 1 {
				t.Fatalf("%s: --%s is a surface and must be opaque", name, p.on[0])
			}
			for _, layer := range p.on[1:] {
				surface = color(t, pal, layer).over(surface)
			}
			fg := color(t, pal, p.fg)
			label := "--" + p.fg
			if p.dim != "" {
				dim, err := strconv.ParseFloat(pal[p.dim], 64)
				if err != nil || dim <= 0 || dim > 1 {
					t.Fatalf("%s: --%s is %q, want an opacity", name, p.dim, pal[p.dim])
				}
				fg.a *= dim
				label += " at --" + p.dim
			}
			got := contrast(fg.over(surface), surface)
			if testing.Verbose() { // go test -v -run TestContrast lists every ratio
				t.Logf("%-8s %5.2f:1 (floor %.1f)  %s on %s", name, got, p.min, label, strings.Join(p.on, " + "))
			}
			if got < p.min {
				t.Errorf("%s: %s on %s is %.2f:1, want %.1f:1 (%s)", name, label, strings.Join(p.on, " + "), got, p.min, p.what)
			}
		}
		// UX-8: an unknown is never green, in any mark
		if color(t, pal, "unk") == color(t, pal, "green") || color(t, pal, "unk-edge") == color(t, pal, "green-edge") {
			t.Errorf("%s: an unknown mark has the color of a pass", name)
		}
	}
}

var (
	ruleRE   = regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)
	sizeRE   = regexp.MustCompile(`font(?:-size)?:[^;]*?([0-9.]+)px`)
	mapBoxRE = regexp.MustCompile(`\n\.map \{ display: block; width: 100%; min-width: (\d+)px; height: auto; max-height: (\d+)px; \}`)
)

// UX-9: body text is 14px on a line height of 1.55, and nothing is set under 12px; mission keeps its own type. The
// map's text is in its own units, so its floor is checked at the smallest size the map is ever drawn.
func TestTypeSizes(t *testing.T) {
	css := stylesheet(t)
	if !strings.Contains(css, "font: 400 14px/1.55 var(--sans);") {
		t.Error("body text isn't 14px on a line height of 1.55")
	}
	m := mapBoxRE.FindStringSubmatch(css)
	if m == nil {
		t.Fatal("the map has no smallest width and height")
	}
	w, _ := strconv.ParseFloat(m[1], 64)
	h, _ := strconv.ParseFloat(m[2], 64)
	mapScale := math.Min(w/820, h/420) // mapSVG's viewBox is 820 by 420
	sizes := 0
	for _, r := range ruleRE.FindAllStringSubmatch(css, -1) {
		sel := strings.TrimSpace(r[1])
		if strings.Contains(sel, `[data-theme="mission"]`) {
			continue
		}
		for _, s := range sizeRE.FindAllStringSubmatch(r[2], -1) {
			px, err := strconv.ParseFloat(s[1], 64)
			if err != nil {
				t.Fatalf("%s: %q", sel, s[0])
			}
			if sizes++; strings.HasPrefix(sel, ".map ") {
				px *= mapScale
			}
			if px < 12 {
				t.Errorf("%s: text at %.1fpx, under 12px (%s)", sel, px, s[0])
			}
		}
	}
	if sizes < 40 {
		t.Fatalf("read only %d font sizes: the stylesheet's shape changed", sizes)
	}
}
