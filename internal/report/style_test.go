package report

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// cssRule is one style rule of the page, as its stylesheet writes it.
type cssRule struct {
	media string      // the @media it sits in, "" at the top level
	sel   string      // the selector list, its spaces collapsed
	decls [][2]string // each property and its value
}

var commentRE = regexp.MustCompile(`(?s)/\*.*?\*/`)

// parseCSS reads the page's stylesheet: plain rules, and @media blocks of plain rules. It leaves @keyframes out,
// since a frame is a moment of an animation and never the state a reader is left with, and stops at anything else.
func parseCSS(t *testing.T, css string) []cssRule {
	t.Helper()
	var out []cssRule
	var walk func(s, media string)
	walk = func(s, media string) {
		for {
			open := strings.Index(s, "{")
			if open < 0 {
				if rest := strings.TrimSpace(s); rest != "" {
					t.Fatalf("stylesheet: text outside a rule: %q", rest)
				}
				return
			}
			depth, end := 1, open+1
			for ; end < len(s) && depth > 0; end++ {
				switch s[end] {
				case '{':
					depth++
				case '}':
					depth--
				}
			}
			if depth != 0 {
				t.Fatalf("stylesheet: a block that never closes: %q", s[:open])
			}
			head, body := strings.Join(strings.Fields(s[:open]), " "), s[open+1:end-1]
			switch {
			case strings.HasPrefix(head, "@media") && media == "":
				walk(body, head)
			case strings.HasPrefix(head, "@keyframes"):
			case strings.HasPrefix(head, "@"):
				t.Fatalf("stylesheet: an at-rule this test doesn't read: %s", head)
			default:
				r := cssRule{media: media, sel: head}
				for _, d := range strings.Split(body, ";") {
					if d = strings.TrimSpace(d); d == "" {
						continue
					}
					prop, value, ok := strings.Cut(d, ":")
					if !ok || strings.Contains(d, "{") {
						t.Fatalf("stylesheet: %s: not a declaration: %q", head, d)
					}
					r.decls = append(r.decls, [2]string{strings.TrimSpace(prop), strings.Join(strings.Fields(value), " ")})
				}
				out = append(out, r)
			}
			s = s[end:]
		}
	}
	walk(commentRE.ReplaceAllString(css, ""), "")
	return out
}

// paletteRules are the rules that set the palettes' tokens (UX-8). They paint nothing themselves.
var paletteRules = []string{":root", `:root, [data-theme="light"]`, `[data-theme="auto"]`, `[data-theme="graphite"]`, `[data-theme="mission"]`}

// screenRules are the rules a screen draws with: every rule but the palettes' own and print's. Print has its own
// palette on white (UX-11) and UX-9's floors are for a screen.
func screenRules(t *testing.T, css string) []cssRule {
	t.Helper()
	var out []cssRule
	for _, r := range parseCSS(t, css) {
		if r.media != "@media print" && !slices.Contains(paletteRules, r.sel) {
			out = append(out, r)
		}
	}
	if len(out) < 150 {
		t.Fatalf("read only %d rules: the stylesheet's shape changed", len(out))
	}
	return out
}

// role is what a color is for where a rule uses it, which sets the contrast it owes (UX-9).
type role int

const (
	text       role = iota // words: 4.5:1. The score's large numerals are held to it too, so no large-text class exists to misuse
	mark                   // a mark that carries a result or marks a control: an outline, a dot, an underline: 3:1
	decoration             // a hairline that only has to stay visible: 1.2:1
	ground                 // a surface that text and marks are drawn on: no floor of its own
)

var (
	roleName = map[role]string{text: "text", mark: "mark", decoration: "decoration", ground: "ground"}
	floors   = map[role]float64{text: 4.5, mark: 3.0, decoration: 1.2, ground: 0}
)

// kindOf sorts the properties that can carry a color into the kinds the roles are checked against.
func kindOf(prop string) string {
	switch {
	case prop == "color":
		return "ink"
	case prop == "fill":
		return "fill"
	case prop == "background" || prop == "background-color":
		return "fill-area"
	case prop == "stroke" || prop == "text-decoration-color" || prop == "outline" || prop == "outline-color":
		return "line"
	case prop == "opacity":
		return "opacity"
	case prop == "text-shadow" || prop == "box-shadow" || prop == "caret-color" || prop == "accent-color" || prop == "-webkit-text-fill-color":
		return "other"
	}
	if m := borderRE.FindStringSubmatch(prop); m != nil {
		return "line"
	}
	return ""
}

var borderRE = regexp.MustCompile(`^border(-(top|right|bottom|left|block|inline|block-start|block-end|inline-start|inline-end))?(-color)?$`)

// roleKinds is which kinds of property each role may sit on. Words are only ever colored by color or, in the map, by
// fill, and neither may be a decoration: that is what keeps text out of the one class allowed under 3:1.
var roleKinds = map[role][]string{
	text:       {"ink", "fill"},
	mark:       {"fill", "fill-area", "line", "opacity"},
	decoration: {"line"},
	ground:     {"fill-area", "fill"},
}

// use is one audited use of a palette token: the rule and property that use it, what the color is for there, and the
// surfaces it is drawn on. The token itself is never written here: TestContrast reads it from the stylesheet, so a
// rule moved to another token is measured as what it now is.
type use struct {
	sel, prop string
	role      role
	// on lists the surfaces, space separated. A surface is a stack of tokens drawn bottom up and joined by "+":
	// "raise+red-tint" is a red tint on a panel. For a ground it is what lies beneath it, and "" for one that is a
	// base: opaque, with nothing showing through.
	on string
}

// audit is every use of a palette token in the page's stylesheet, in the stylesheet's order (UX-9). TestContrast
// fails when the stylesheet uses a token this list doesn't name, when the list names a use the stylesheet no longer
// has, and when a use falls under its role's floor on any surface in any palette.
//
// What the test can't see, so the list states it: where an element sits (a count is inside a rail entry, the
// breadcrumbs inside the translucent bar), and what two rules make together (a green test link is also a hovered
// one, so it lists the hover wash). An element with no color of its own inherits one this list holds: a link and an
// icon take their parent's (color: inherit, currentColor). The flash behind a row a link lands on is a keyframe and
// fades in under two seconds. The test reads the style block alone: a color set in the markup (a style or an SVG
// fill attribute) or on a property kindOf doesn't name (a filter, a background image) is outside it.
var audit = []use{
	{"html", "background", ground, ""},
	{"body", "background", ground, ""},
	{"body", "color", text, "bg raise inset bg+nav"},
	{"::selection", "background", ground, ""},
	{"::selection", "color", text, "text"},
	{":focus-visible", "outline", mark, "bg raise"},

	{".nav", "border-bottom", decoration, "bg"},
	{".nav", "background", ground, "bg"},
	{".crumbs", "color", text, "bg+nav"},
	{".pill", "background", ground, ""},
	{".pill", "color", text, "pill pill-hover"},
	{".pill:hover", "background", ground, ""},
	{".ghost", "border", mark, "bg+nav"},
	{".ghost", "color", text, "bg+nav"},
	{".ghost:hover", "color", text, "bg+nav+hover"},
	{".ghost:hover", "background", ground, "bg+nav"},

	{".toc p", "color", text, "bg"},
	{".toc a", "color", text, "bg"},
	{".toc a:hover", "color", text, "bg+hover"},
	{".toc a:hover", "background", ground, "bg"},
	{".toc a.on", "color", text, "bg+sel"},
	{".toc a.on", "background", ground, "bg"},
	{".toc .n", "color", text, "bg bg+hover bg+sel"},

	{".saved", "border", decoration, "bg"},
	{".saved", "background", ground, ""},
	{".saved::before", "border", mark, "inset"},
	{".head", "border", decoration, "bg"},
	{".head", "background", ground, ""},
	{".tag", "border", mark, "raise"},
	{".tag", "color", text, "raise"},
	{".lede", "color", text, "raise"},
	{".lede.chain", "color", text, "raise"},
	{".sevtag", "border", mark, "raise"},
	{".sevtag", "background", ground, "raise"},
	{".sevtag", "color", text, "raise+red-tint"},
	{".facts div", "border-left", decoration, "raise"},
	{".facts dt", "color", text, "raise"},

	{".kicker", "color", text, "bg"},
	{".kicker em", "color", text, "bg"},
	{".score .kicker em", "border", mark, "bg"},
	{".scorebig", "color", text, "bg"},
	{".scorebig.green", "color", text, "bg"},
	{".scorebig span", "color", text, "bg"},
	{".status", "border", mark, "bg"},
	{".status", "color", text, "bg"},
	{".stats", "border-block", decoration, "bg"},
	{".stats li", "border-left", decoration, "bg"},
	{".stats b.red", "color", text, "bg"},
	{".stats b.green", "color", text, "bg"},
	{".stats b.unk", "border", mark, "bg"},
	{".stats b.unk", "color", text, "bg"},
	{".stats span", "color", text, "bg"},
	{".statement", "color", text, "bg"},
	{".cov", "color", text, "bg"},

	{".cats .cat", "border", decoration, "bg"},
	{".cats .cat", "background", ground, ""},
	{".cats .dot", "background", mark, "raise"},
	{".cats .green .dot", "background", mark, "raise"},
	{".cats .green.gnp .dot", "border", mark, "raise"},
	{".cats .na .dot", "border", mark, "raise"},
	{".cats .q", "color", text, "raise"},
	{".cats .why", "color", text, "raise"},
	{".cats .why.np, .cats .why.cv", "color", text, "raise"},
	{".cats .why.np::before", "border", mark, "raise"},
	{".tl .ran", "color", text, "raise"},
	{"a.t", "border", mark, "raise"},
	{"a.t", "color", text, "raise"},
	{"a.t:hover", "color", text, "raise+hover"},
	{"a.t:hover", "background", ground, "raise"},
	{"a.t.red", "color", text, "raise+red-tint"},
	{"a.t.red", "border-color", mark, "raise"},
	{"a.t.red", "background", ground, "raise"},
	{"a.t.green", "color", text, "raise raise+hover"}, // hovered, it keeps its green and takes a.t:hover's wash
	{"a.t.green", "border-color", mark, "raise"},
	{"a.t.amber", "color", text, "raise raise+hover"}, // as a.t.green
	{"a.t.amber", "border", mark, "raise"},
	{".verdict", "border", mark, "raise"},
	{".verdict", "background", ground, "raise"},
	{".verdict", "color", text, "raise+red-tint"},
	{".cat.green .verdict", "color", text, "raise"},
	{".cat.green .verdict", "border-color", mark, "raise"},
	{".cat.na .verdict", "color", text, "raise"},
	{".cat.na .verdict", "border-color", mark, "raise"},

	{".sec-h span, h2.appendix span", "color", text, "bg"},
	{".none", "color", text, "bg"},
	{".grp-h .q", "color", text, "bg"},
	{".sevdot", "background", mark, "bg bg+hover bg+sel"}, // a group's heading, and its entry in the rail
	{".sevdot.high", "opacity", mark, "bg bg+hover bg+sel"},
	{".sevdot.medium, .sevdot.unrated", "opacity", mark, "bg bg+hover bg+sel"},
	{".sevdot.low", "opacity", mark, "bg bg+hover bg+sel"},
	{".sevdot.unknown", "border", mark, "bg bg+hover bg+sel"},
	{".box", "border", decoration, "bg"},
	{".row", "border-top", decoration, "bg"},
	{".key", "border", mark, "bg"},
	{".key", "color", text, "bg"},
	{".row.red .key", "color", text, "bg+fail-bg"},
	{".row.red .key", "background", ground, "bg"},
	{".row.red .key", "border-color", mark, "bg"},
	{".row.green .key", "color", text, "bg"},
	{".row.green .key", "border-color", mark, "bg"},
	{".row.amber .key", "color", text, "bg"},
	{".row.amber .key", "border", mark, "bg"},
	{".row.grey .key", "color", text, "bg"},
	{".seen", "color", text, "bg"},
	{".seen a", "text-decoration-color", mark, "bg"}, // the underline is all that marks a link in this line
	{".seen a:hover", "color", text, "bg"},
	{".fixit", "color", text, "bg"},
	{".fixit b", "color", text, "bg"},
	{".cid", "color", text, "bg"},
	{".ctag", "border", mark, "bg"},
	{".ctag", "color", text, "bg"},
	{".would", "color", text, "bg"},
	{"details.more > summary", "background", ground, ""},
	{"details.more > summary", "color", text, "raise"},
	{"details.more > summary:hover", "color", text, "raise"},
	{"details.more[open] > summary", "border-bottom", decoration, "raise"},

	{"h2.appendix", "border-top", decoration, "bg"},
	{".banner", "border", decoration, "bg"},
	{".banner", "background", ground, ""},
	{".banner.unk", "border", mark, "bg inset"},
	{"h2.ap-h b", "border", decoration, "bg"}, // a box round a section's letter; the letter is the text
	{"h2.ap-h b", "color", text, "bg"},
	{".note", "color", text, "bg"},
	{".legend", "color", text, "bg"},
	{".legend span::before", "border-top", mark, "bg"}, // drawn in --c, which each kind of legend line sets
	{".mapbox", "background", ground, ""},
	{".map .grid", "stroke", decoration, "raise"},
	{".map .wall", "stroke", mark, "raise"},
	{".map .cat", "fill", text, "raise"},
	{".map .agent", "fill", mark, "raise"},
	{".map .agent-ring", "stroke", mark, "raise"},
	{".map .agent-label", "fill", text, "raise"},
	{".map .seg", "stroke", mark, "raise"},
	{".map .crack", "stroke", mark, "raise"},
	{".map .breach", "stroke", mark, "raise"},
	{".map .arrowhead", "fill", mark, "raise"},
	{".map .breach-label", "fill", text, "raise"},
	{".map .unk", "fill", ground, ""},
	{".map .unk", "stroke", mark, "raise"},
	{".map .unk-q", "fill", text, "raise"},
	{".panel", "border", decoration, "bg"},
	{".panel h3", "border-bottom", decoration, "raise"},
	{".panel h3", "background", ground, ""},
	{".panel h3", "color", text, "raise"},
	{".panel table + h3, .panel ul + h3", "border-top", decoration, "raise"},
	{".panel td", "border-top", decoration, "bg"},
	{".grid2 td:last-child", "color", text, "bg"},
	{".panel .note + .note", "border-top", decoration, "bg"},
	{"ul.plain", "color", text, "bg"},
	{"ul.plain li", "border-top", decoration, "bg"},
	{"details.passes > summary", "border", decoration, "bg"},
	{"details.passes > summary", "background", ground, ""},
	{"details.passes > summary span", "color", text, "raise"},
	{"footer", "border-top", decoration, "bg"},
	{"footer p", "color", text, "bg"},
}

// dims names, for each opacity the audit lists, the "selector | property" whose color it dims.
var dims = map[string]string{
	".sevdot.high | opacity":                    ".sevdot | background",
	".sevdot.medium, .sevdot.unrated | opacity": ".sevdot | background",
	".sevdot.low | opacity":                     ".sevdot | background",
}

// fixed is every color or opacity the stylesheet writes out instead of taking from a palette, as "selector |
// property: value", with why it may. The value is part of the entry, so a changed one has to be looked at again. No
// ratio is computed for these, so a text color can't be one: TestContrast refuses color and -webkit-text-fill-color.
var fixed = map[string]string{
	".map .wall | fill: rgb(255 255 255 / .015)":                              "a white wash of 1.5% inside the box's wall, too thin to change what the map's words sit on",
	".map .mark | opacity: 0":                                                 "where a mark's entry animation starts; it ends at 1",
	".map .mark | opacity: 1":                                                 "reduced motion: the mark as the animation leaves it",
	`[data-theme="mission"] body | text-shadow: 0 0 6px rgb(255 176 0 / .28)`: "mission's glow, the text's own color at 28%: not computed",
	`[data-theme="mission"] body::after | background: repeating-linear-gradient(to bottom, transparent 0 2px, rgb(0 0 0 / .22) 2px 3px)`: "mission's scan lines, a fixed overlay over the whole page: not computed",
	`[data-theme="mission"] .map .gridbg | opacity: .55`: "mission's grid behind the map: decoration",
}

// plain are the values that bring no color of their own.
var plain = []string{"none", "transparent", "inherit", "currentColor", "0"}

var (
	varUseRE = regexp.MustCompile(`var\(--([a-z0-9-]+)\)`)
	funcRE   = regexp.MustCompile(`[a-zA-Z-]+\(`)
)

// tokenUse is a palette token as one declaration uses it.
type tokenUse struct {
	rule  cssRule
	token string   // the palette token, or the local custom property the color comes through
	inks  []string // the palette tokens it can be: the token itself, or every token a rule sets the local property to
}

// paints reads every use of a palette token from the screen's rules, keyed "selector | property", and checks every
// other color the rules write: a plain value, or one fixed lists. A local custom property (the legend's --c) may only
// be set to one palette token, and a declaration that draws with it is a use like any other, measured as every token
// the property is set to. It knows the properties kindOf names; a color written out on any other is beyond it.
func paints(t *testing.T, rules []cssRule, palette map[string]string) map[string]tokenUse {
	t.Helper()
	locals := map[string][]string{}
	for _, r := range rules {
		for _, d := range r.decls {
			if !strings.HasPrefix(d[0], "--") {
				continue
			}
			m := varUseRE.FindStringSubmatch(d[1])
			if m == nil || m[0] != d[1] || palette[m[1]] == "" {
				t.Errorf("%s | %s: %s: a local property may only be set to one palette token", r.sel, d[0], d[1])
				continue
			}
			locals[d[0][2:]] = append(locals[d[0][2:]], m[1])
		}
	}
	out, seenFixed := map[string]tokenUse{}, map[string]bool{}
	for _, r := range rules {
		for _, d := range r.decls {
			key, kind := r.sel+" | "+d[0], kindOf(d[0])
			var tokens, local []string
			for _, m := range varUseRE.FindAllStringSubmatch(d[1], -1) {
				if _, ok := palette[m[1]]; ok {
					tokens = append(tokens, m[1])
				} else if locals[m[1]] != nil {
					local = append(local, m[1])
				}
			}
			switch {
			case len(tokens)+len(local) > 0 && funcRE.MatchString(varUseRE.ReplaceAllString(d[1], "")):
				// color-mix(), rgb(from ...), calc(): the color drawn isn't the token's, and this test can't work it out
				t.Errorf("%s: %s puts a palette color through a function this test can't measure", key, d[1])
			case strings.HasPrefix(d[0], "--"): // a local property's source, read above
			case len(tokens)+len(local) > 1:
				t.Errorf("%s: two colors in one declaration: %s", key, d[1])
			case len(tokens)+len(local) == 1:
				use := tokenUse{r, strings.Join(append(tokens, local...), ""), tokens}
				if len(local) == 1 {
					use.inks = locals[local[0]]
				}
				if kind == "" || kind == "other" {
					t.Errorf("%s uses --%s: a property this test has no rule for", key, use.token)
				}
				if _, dup := out[key]; dup {
					t.Errorf("%s is set twice: the audit can't tell the two apart", key)
				}
				out[key] = use
			case kind == "" || kind != "opacity" && slices.Contains(plain, d[1]):
			case fixed[key+": "+d[1]] != "" && kind != "ink" && d[0] != "-webkit-text-fill-color":
				seenFixed[key+": "+d[1]] = true
			default:
				t.Errorf("%s: %s is a color no palette sets and fixed doesn't list", key, d[1])
			}
		}
	}
	for key := range fixed {
		if !seenFixed[key] {
			t.Errorf("fixed lists %s, which the stylesheet no longer writes", key)
		}
	}
	return out
}

// surface draws a stack of tokens bottom up in one palette.
func surface(t *testing.T, pal map[string]string, stack string) rgba {
	t.Helper()
	layers := strings.Split(stack, "+")
	s := color(t, pal, layers[0])
	for _, l := range layers[1:] {
		s = color(t, pal, l).over(s)
	}
	return s
}

// UX-9: every color the stylesheet uses is accounted for, and meets its floor. For each rule that uses a palette
// token, audit says what the color is for there and what it is drawn on; the token is read from the rule. Text owes
// 4.5:1 and a mark 3:1 on every surface listed, in every palette; a hairline owes only 1.2:1, and only a border, a
// stroke or an underline can be one. A surface must be one the stylesheet makes: a base is an opaque background some
// rule sets, and each layer above it a background some rule sets on what is beneath.
func TestContrast(t *testing.T) {
	css := stylesheet(t)
	rules := screenRules(t, css)
	palettes := map[string]map[string]string{}
	for _, name := range []string{"light", "graphite", "mission"} {
		palettes[name] = tokens(t, css, name)
	}
	used := paints(t, rules, palettes["light"])

	// every use is audited once, and every audit entry is a use
	entries := map[string]use{}
	for _, u := range audit {
		key := u.sel + " | " + u.prop
		if _, dup := entries[key]; dup {
			t.Errorf("audit lists %s twice", key)
		}
		entries[key] = u
		if _, ok := used[key]; !ok {
			t.Errorf("audit lists %s, which the stylesheet no longer sets from a palette token", key)
		}
		if !slices.Contains(roleKinds[u.role], kindOf(u.prop)) {
			t.Errorf("audit: %s can't be %s: only %v can", key, roleName[u.role], roleKinds[u.role])
		}
	}
	for key, p := range used {
		if _, ok := entries[key]; !ok {
			t.Errorf("%s uses --%s and audit doesn't say what for, or on what", key, p.token)
		}
	}
	for key := range dims {
		if u, ok := entries[key]; !ok || u.prop != "opacity" {
			t.Errorf("dims names %s, which isn't an audited opacity", key)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	// the surfaces the stylesheet makes
	bases, layers := map[string]bool{}, map[string]bool{} // a base token; "beneath+token"
	for key, u := range entries {
		if u.role != ground {
			continue
		}
		tok := used[key].token
		if !slices.Equal(used[key].inks, []string{tok}) {
			t.Errorf("%s: a surface can't take its color through a local property", key)
			continue
		}
		if u.on == "" {
			bases[tok] = true
			for name, pal := range palettes {
				if color(t, pal, tok).a != 1 {
					t.Errorf("%s: --%s is a base and %s lets what is beneath it show through", key, tok, name)
				}
			}
		}
		for _, beneath := range strings.Fields(u.on) {
			layers[beneath+"+"+tok] = true
		}
	}
	made := func(stack string) bool {
		parts := strings.Split(stack, "+")
		if !bases[parts[0]] {
			return false
		}
		for i := 1; i < len(parts); i++ {
			if !layers[strings.Join(parts[:i+1], "+")] {
				return false
			}
		}
		return true
	}

	for _, u := range audit {
		key := u.sel + " | " + u.prop
		p := used[key]
		stacks := strings.Fields(u.on)
		for _, s := range stacks {
			if !made(s) {
				t.Errorf("%s: no rule makes the surface %s", key, s)
			}
		}
		if u.role == ground {
			continue
		}
		if len(stacks) == 0 {
			t.Errorf("%s: audit names no surface", key)
		}
		if own, ok := used[u.sel+" | background"]; ok && u.role == text && entries[u.sel+" | background"].role == ground &&
			!slices.ContainsFunc(stacks, func(s string) bool { return s == own.token || strings.HasSuffix(s, "+"+own.token) }) {
			t.Errorf("%s: the rule sets its own background, --%s, and audit lists no surface ending in it", key, own.token)
		}
		inks, dimmed := p.inks, ""
		if kindOf(u.prop) == "opacity" {
			of, ok := used[dims[key]]
			if !ok {
				t.Errorf("%s: dims doesn't name the color this opacity dims", key)
				continue
			}
			inks, dimmed = of.inks, " at --"+p.token
		}
		for _, name := range []string{"light", "graphite", "mission"} {
			pal := palettes[name]
			for _, ink := range inks { // one, or every token a local property is set to
				fg, label := color(t, pal, ink), "--"+ink+dimmed
				if dimmed != "" {
					dim, err := strconv.ParseFloat(pal[p.token], 64)
					if err != nil || dim <= 0 || dim > 1 {
						t.Errorf("%s: %s: --%s is %q, want an opacity", name, key, p.token, pal[p.token])
						continue
					}
					fg.a *= dim
				}
				for _, s := range stacks {
					if !made(s) {
						continue
					}
					on, where := surface(t, pal, s), strings.ReplaceAll(s, "+", " + ")
					got := contrast(fg.over(on), on)
					if testing.Verbose() { // go test -v -run 'TestContrast$' lists every ratio
						t.Logf("%-8s %5.2f:1 (floor %.1f) %s on %s  [%s]", name, got, floors[u.role], label, where, key)
					}
					if got < floors[u.role] {
						t.Errorf("%s: %s: %s on %s is %.2f:1, and %s owes %.1f:1", name, key, label, where, got, roleName[u.role], floors[u.role])
					}
				}
			}
		}
	}

	// the map's words: every class the map puts on a <text> element is audited as text, and nothing else in the map
	// is. An HTML rule's color is always text; whether a border or a stroke is the only thing that tells a reader
	// something is a judgment the audit records and this test can't check.
	page, err := HTML(Build(run(), meta()), "")
	if err != nil {
		t.Fatal(err)
	}
	words := map[string]bool{}
	for _, m := range regexp.MustCompile(`<text class="([a-z-]+)"`).FindAllStringSubmatch(string(page), -1) {
		words[".map ."+m[1]+" | fill"] = true
	}
	if len(words) < 4 {
		t.Fatalf("the map has only %d classes of text: its markup changed", len(words))
	}
	for key, u := range entries {
		if strings.HasPrefix(key, ".map ") && u.prop == "fill" && words[key] != (u.role == text) {
			t.Errorf("%s: audited as %s, and the map's <text> elements say otherwise", key, roleName[u.role])
		}
	}
	for key := range words {
		if _, ok := entries[key]; !ok {
			t.Errorf("%s: the map's text has no audited fill", key)
		}
	}

	// UX-8: an unknown is never green, in any mark
	for name, pal := range palettes {
		if color(t, pal, "unk") == color(t, pal, "green") || color(t, pal, "unk-edge") == color(t, pal, "green-edge") {
			t.Errorf("%s: an unknown mark has the color of a pass", name)
		}
	}
}

// keyframeColors is every color a keyframe may set, as "animation | property" and the one token allowed there: the
// flash behind a row a link lands on washes it with the selection token, for 1.4s.
var keyframeColors = map[string]string{"flash | background": "sel"}

var (
	keyframesRE = regexp.MustCompile(`@keyframes ([a-z-]+) \{((?:[^{}]*\{[^{}]*\})*)\s*\}`)
	frameDeclRE = regexp.MustCompile(`([a-z-]+):\s*([^;{}]+)[;}]`) // a frame's last declaration may end at its brace
)

// UX-9: TestContrast's audit leaves keyframes out, so a keyframe's colors are held here. One may set only the token
// keyframeColors lists for it, and a row's words keep 4.5:1 on the flash at its strongest. Fades of opacity and
// moves are not colors and pass.
func TestKeyframeColors(t *testing.T) {
	css := commentRE.ReplaceAllString(stylesheet(t), "")
	blocks := keyframesRE.FindAllStringSubmatch(css, -1)
	if len(blocks) < 4 || len(blocks) != strings.Count(css, "@keyframes") {
		t.Fatalf("read %d of %d @keyframes blocks", len(blocks), strings.Count(css, "@keyframes"))
	}
	seen := map[string]bool{}
	for _, b := range blocks {
		for _, d := range frameDeclRE.FindAllStringSubmatch(b[2], -1) {
			key, value, kind := b[1]+" | "+d[1], strings.TrimSpace(d[2]), kindOf(d[1])
			colored := kind != "" && kind != "opacity" && !slices.Contains(plain, value)
			if !colored && !strings.Contains(value, "var(--") {
				continue
			}
			if tok, ok := keyframeColors[key]; !ok || value != "var(--"+tok+")" {
				t.Errorf("@keyframes %s: %s is a color keyframeColors doesn't allow there", key, value)
			}
			seen[key] = true
		}
	}
	for key := range keyframeColors {
		if !seen[key] {
			t.Errorf("keyframeColors lists %s, which no keyframe sets", key)
		}
	}
	wash := "bg+" + keyframeColors["flash | background"] // a row sits on the page
	for _, name := range []string{"light", "graphite", "mission"} {
		pal := tokens(t, css, name)
		for ink, on := range map[string]string{"text": wash, "muted": wash, "faint": wash, "green": wash, "unk": wash, "on-fail": wash + "+fail-bg"} {
			if got := contrast(color(t, pal, ink).over(surface(t, pal, on)), surface(t, pal, on)); got < floors[text] {
				t.Errorf("%s: --%s on %s, a flashed row, is %.2f:1, and text owes %.1f:1", name, ink, strings.ReplaceAll(on, "+", " + "), got, floors[text])
			}
		}
	}
}

// span is the least and the greatest a CSS length can come to, in px.
type span struct{ lo, hi float64 }

var lengthTokRE = regexp.MustCompile(`[0-9]*\.?[0-9]+[a-z%]*|[a-z]+|[(),+*/-]`)

// lengthParser works out a CSS length: a number with a unit, or clamp(), min(), max() and calc() of lengths. em and %
// are of the parent's size. rem is of the root's, which the page doesn't set, so the browser's 16px unless a reader
// has changed it. A viewport unit can come to nothing, so it counts as 0 at the least.
type lengthParser struct {
	toks     []string
	i        int
	parent   span
	relative bool // an em or a % was read
}

func (p *lengthParser) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return ""
}

func (p *lengthParser) next() string { s := p.peek(); p.i++; return s }

func (p *lengthParser) sum() (span, error) {
	a, err := p.product()
	for err == nil && (p.peek() == "+" || p.peek() == "-") {
		op := p.next()
		var b span
		if b, err = p.product(); op == "+" {
			a = span{a.lo + b.lo, a.hi + b.hi}
		} else {
			a = span{a.lo - b.hi, a.hi - b.lo}
		}
	}
	return a, err
}

func (p *lengthParser) product() (span, error) {
	a, err := p.factor()
	for err == nil && (p.peek() == "*" || p.peek() == "/") {
		op := p.next()
		var b span
		if b, err = p.factor(); err != nil {
			break
		}
		if op == "/" {
			if b.lo != b.hi || b.lo <= 0 {
				return a, fmt.Errorf("a division this test doesn't work out")
			}
			b = span{1 / b.lo, 1 / b.lo}
		}
		times := func(x, y float64) float64 {
			if x == 0 || y == 0 { // nothing times anything, however large, is nothing
				return 0
			}
			return x * y
		}
		c := []float64{times(a.lo, b.lo), times(a.lo, b.hi), times(a.hi, b.lo), times(a.hi, b.hi)}
		a = span{slices.Min(c), slices.Max(c)}
	}
	return a, err
}

var lengthRE = regexp.MustCompile(`^([0-9]*\.?[0-9]+)([a-z%]*)$`)

func (p *lengthParser) factor() (span, error) {
	tok := p.next()
	switch tok {
	case "-":
		a, err := p.factor()
		return span{-a.hi, -a.lo}, err
	case "(":
		a, err := p.sum()
		if err == nil && p.next() != ")" {
			err = fmt.Errorf("a bracket that never closes")
		}
		return a, err
	case "clamp", "min", "max", "calc":
		if p.next() != "(" {
			return span{}, fmt.Errorf("%s without its bracket", tok)
		}
		var args []span
		for {
			a, err := p.sum()
			if err != nil {
				return span{}, err
			}
			args = append(args, a)
			if sep := p.next(); sep == ")" {
				break
			} else if sep != "," {
				return span{}, fmt.Errorf("%s(): want a comma or a bracket, got %q", tok, sep)
			}
		}
		least := func(a, b span) span { return span{math.Min(a.lo, b.lo), math.Min(a.hi, b.hi)} }
		most := func(a, b span) span { return span{math.Max(a.lo, b.lo), math.Max(a.hi, b.hi)} }
		switch {
		case tok == "calc" && len(args) == 1:
			return args[0], nil
		case tok == "clamp" && len(args) == 3:
			return most(args[0], least(args[1], args[2])), nil
		case tok == "min" && len(args) > 0:
			return foldSpans(args, least), nil
		case tok == "max" && len(args) > 0:
			return foldSpans(args, most), nil
		}
		return span{}, fmt.Errorf("%s() with %d values", tok, len(args))
	}
	m := lengthRE.FindStringSubmatch(tok)
	if m == nil {
		return span{}, fmt.Errorf("%q isn't a length this test reads", tok)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	switch m[2] {
	case "", "px":
		return span{v, v}, nil
	case "em":
		p.relative = true
		return span{v * p.parent.lo, v * p.parent.hi}, nil
	case "%":
		p.relative = true
		return span{v / 100 * p.parent.lo, v / 100 * p.parent.hi}, nil
	case "rem":
		return span{v * 16, v * 16}, nil
	case "vw", "vh", "vmin", "vmax", "svw", "svh", "lvw", "lvh", "dvw", "dvh", "vi", "vb":
		return span{0, math.Inf(1)}, nil
	}
	return span{}, fmt.Errorf("%q: a unit this test doesn't read", tok)
}

func foldSpans(args []span, f func(a, b span) span) span {
	out := args[0]
	for _, a := range args[1:] {
		out = f(out, a)
	}
	return out
}

// length works out a font size against its parent's.
func length(expr string, parent span) (size span, relative bool, err error) {
	p := &lengthParser{toks: lengthTokRE.FindAllString(expr, -1), parent: parent}
	if strings.Join(p.toks, "") != strings.ReplaceAll(expr, " ", "") {
		return span{}, false, fmt.Errorf("%q isn't a length this test reads", expr)
	}
	size, err = p.sum()
	if err == nil && p.i != len(p.toks) {
		err = fmt.Errorf("%q: read only part of it", expr)
	}
	return size, p.relative, err
}

var fontWordRE = regexp.MustCompile(`^(normal|bold|bolder|lighter|italic|oblique|small-caps|[0-9]+)$`)

// fontSize is the size a declaration sets, as written: font-size's value, or the size in a font shorthand, which
// comes after any style and weight and before the line height.
func fontSize(prop, value string) (string, bool) {
	if prop == "font-size" {
		return value, true
	}
	if prop != "font" {
		return "", false
	}
	depth, start := 0, 0
	for i := 0; i <= len(value); i++ {
		switch {
		case i < len(value) && value[i] == '(':
			depth++
		case i < len(value) && value[i] == ')':
			depth--
		case i == len(value) || depth == 0 && (value[i] == ' ' || value[i] == '/'):
			if word := value[start:i]; word != "" && !fontWordRE.MatchString(word) {
				return word, true
			}
			start = i + 1
		}
	}
	return "", false
}

// sizeParents says what a relative font size is relative to: the rule that sizes the element's parent. The
// stylesheet can't say, so this does, and TestTypeSizes fails on a relative size with no entry here.
var sizeParents = map[string]string{
	".scorebig span": ".scorebig", // the "/6" beside the score
}

var mapBoxRE = regexp.MustCompile(`\n\.map \{ display: block; width: 100%; min-width: (\d+)px; height: auto; max-height: (\d+)px; \}`)

// missionCapitals is the one rule allowed under 12px: mission's capitals, 10.5px and no smaller (UX-9).
const missionCapitals = `[data-theme="mission"] .kicker, [data-theme="mission"] .panel h3, [data-theme="mission"] .stats span, ` +
	`[data-theme="mission"] .facts dt, [data-theme="mission"] .toc p, [data-theme="mission"] .ctag, [data-theme="mission"] .key`

// UX-9: on a screen, body text is 14px on a line height of 1.55 and no font size the stylesheet sets can come to
// under 12px. mission keeps its own type, held the same way: a 13px body, and its capitals alone under the floor. Every size is worked out to the least it can be: a clamp() to its floor,
// an em against the least its parent can be. The map's text is in the map's own units, so it is measured at the
// smallest the map is drawn. An element with no size of its own takes its parent's, which this test also holds.
func TestTypeSizes(t *testing.T) {
	css := stylesheet(t)
	m := mapBoxRE.FindStringSubmatch(css)
	if m == nil {
		t.Fatal("the map has no smallest width and height")
	}
	w, _ := strconv.ParseFloat(m[1], 64)
	h, _ := strconv.ParseFloat(m[2], 64)
	mapScale := math.Min(w/820, h/420) // mapSVG's viewBox is 820 by 420

	type sized struct{ sel, expr string }
	var all []sized
	bySel := map[string]string{}
	for _, r := range screenRules(t, css) {
		for _, d := range r.decls {
			if d[0] != "font" && d[0] != "font-size" {
				continue
			}
			expr, ok := fontSize(d[0], d[1])
			if !ok {
				t.Errorf("%s: no size in %s: %s", r.sel, d[0], d[1])
				continue
			}
			all = append(all, sized{r.sel, expr})
			if r.media == "" {
				if _, dup := bySel[r.sel]; dup {
					t.Errorf("%s sets its size twice", r.sel)
				}
				bySel[r.sel] = expr
			}
		}
	}
	if len(all) < 40 {
		t.Fatalf("read only %d font sizes: the stylesheet's shape changed", len(all))
	}
	var resolve func(sel, expr string, depth int) (span, error)
	resolve = func(sel, expr string, depth int) (span, error) {
		if depth > 8 {
			return span{}, fmt.Errorf("its parents go round in a circle")
		}
		if size, relative, err := length(expr, span{}); err != nil || !relative {
			if _, stated := sizeParents[sel]; stated && err == nil {
				err = fmt.Errorf("sizeParents names it, and its size isn't relative")
			}
			return size, err
		}
		parent, ok := sizeParents[sel]
		if !ok {
			return span{}, fmt.Errorf("a relative size, and sizeParents doesn't say of what")
		}
		pexpr, ok := bySel[parent]
		if !ok {
			return span{}, fmt.Errorf("its parent, %s, sets no size", parent)
		}
		psize, err := resolve(parent, pexpr, depth+1)
		if err != nil {
			return span{}, fmt.Errorf("its parent, %s: %v", parent, err)
		}
		size, _, err := length(expr, psize)
		return size, err
	}
	for sel := range sizeParents {
		if _, ok := bySel[sel]; !ok {
			t.Errorf("sizeParents names %s, which sets no size", sel)
		}
	}
	for _, s := range all {
		size, err := resolve(s.sel, s.expr, 0)
		if err != nil {
			t.Errorf("%s: font size %s: %v", s.sel, s.expr, err)
			continue
		}
		least, unit := size.lo, ""
		if strings.HasPrefix(s.sel, ".map ") {
			least, unit = least*mapScale, " at the map's smallest"
		}
		if testing.Verbose() {
			t.Logf("%6.2fpx at the least  %s { %s }%s", least, s.sel, s.expr, unit)
		}
		floor := 12.0
		if s.sel == missionCapitals { // held at exactly 10.5px (UX-8), not only kept from going under it
			floor = 10.5
			if size != (span{10.5, 10.5}) {
				t.Errorf("%s: font size %s isn't mission's 10.5px capitals", s.sel, s.expr)
			}
		}
		if least < floor {
			t.Errorf("%s: font size %s can come to %.2fpx%s, under %gpx", s.sel, s.expr, least, unit, floor)
		}
	}
	if _, ok := bySel[missionCapitals]; !ok {
		t.Error("mission's capitals rule, the one allowed under 12px, is gone or renamed")
	}
	if got, err := resolve("mission", bySel[`[data-theme="mission"] body`], 0); err != nil || got != (span{13, 13}) {
		t.Errorf("mission's body text isn't 13px: %v %v", got, err)
	}
	body, err := resolve("body", bySel["body"], 0)
	if err != nil || body != (span{14, 14}) || !strings.Contains(css, "font: 400 14px/1.55 var(--sans);") {
		t.Errorf("body text isn't 14px on a line height of 1.55: %v %v", body, err)
	}
}

// The length parser against known values, the reviewer's two among them.
func TestLength(t *testing.T) {
	for _, tc := range []struct {
		expr     string
		parent   span
		lo       float64
		relative bool
	}{
		{"14px", span{}, 14, false},
		{"clamp(120px, 14vw, 176px)", span{}, 120, false},
		{".36em", span{120, 176}, 43.2, true},
		{".01em", span{120, 176}, 1.2, true},
		{"80%", span{14, 14}, 11.2, true},
		{".7rem", span{}, 11.2, false},
		{"min(14px, 2vw)", span{}, 0, false},
		{"max(12px, 1vw)", span{}, 12, false},
		{"calc(10px + .25em)", span{12, 12}, 13, true},
		{"calc(1rem - 2px * 3)", span{}, 10, false},
	} {
		got, relative, err := length(tc.expr, tc.parent)
		if err != nil || math.Abs(got.lo-tc.lo) > 0.001 || relative != tc.relative {
			t.Errorf("%s: want %.2f, relative %v; got %.2f, relative %v, %v", tc.expr, tc.lo, tc.relative, got.lo, relative, err)
		}
	}
	for _, bad := range []string{"12pt", "calc(12px", "large", "clamp(1px, 2px)", "12px 13px"} {
		if got, _, err := length(bad, span{}); err == nil {
			t.Errorf("%s: want an error, got %v", bad, got)
		}
	}
	for prop, want := range map[string]string{"400 14px/1.55 var(--sans)": "14px", "12px var(--mono)": "12px",
		"300 clamp(120px, 14vw, 176px)/.84 var(--sans)": "clamp(120px, 14vw, 176px)", "italic bold .8em/1.2 serif": ".8em"} {
		if got, ok := fontSize("font", prop); !ok || got != want {
			t.Errorf("font: %s: want the size %s, got %q", prop, want, got)
		}
	}
}
