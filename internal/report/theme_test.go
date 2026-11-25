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
