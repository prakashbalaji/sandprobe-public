package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/report"
)

// noLetter is a saved older report as a run writes it now: sandprobe/6, with no letter (AGT-6).
func noLetter(d report.Doc) report.Doc {
	d.Schema, d.Grade.Letter = report.SchemaNoLetter, nil
	return d
}

// A letter grade in any output: the word beside a letter, the old field names, or a bare letter as a JSON value.
var letterShown = regexp.MustCompile(`(?i)\bgrade\s+"?[ABCDF]\b|"letter"|reported_grade|saved grade|"[ABCDF]"`)

var reportData = regexp.MustCompile(`(?s)<script id="report-data" type="application/json">(.*?)</script>`)

// GRD-1, ANL-1, ANL-2, CAL-3, CMP-1 and FBK-3: no offline command prints or copies a saved report's letter, in text,
// in JSON, in feedback's preview or in the page -out re-renders. Each older report (sandprobe/1, with its letter)
// gives byte for byte the output of the same report as a run writes it now (sandprobe/6, no letter), so the letter
// decides nothing; and one against the other compares as unchanged.
func TestNoLetterInOfflineOutput(t *testing.T) {
	pinGH(t, "absent") // feedback previews only: no gh, nothing sent
	body := writeBody(t, plainBody)
	files, _ := filepath.Glob("../../demo/reports/*.json")
	more, _ := filepath.Glob("../../test/reports/*.json")
	files = append(files, more...)
	if len(files) < 6 {
		t.Fatalf("saved reports: %v", files)
	}
	letters := map[string]bool{}
	for _, old := range files {
		b, err := os.ReadFile(old)
		if err != nil {
			t.Fatal(err)
		}
		var d report.Doc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		if d.Schema != report.Schema || d.Grade.Letter == nil || len(*d.Grade.Letter) != 1 {
			t.Fatalf("%s isn't an older report with a letter: %s", old, d.Schema)
		}
		letters[*d.Grade.Letter] = true
		now := writeDoc(t, noLetter(d))
		if b, _ := os.ReadFile(now); bytes.Contains(b, []byte(`"letter"`)) || !bytes.Contains(b, []byte(`"schema":"sandprobe/6"`)) {
			t.Fatalf("%s as sandprobe/6 still carries a letter", old)
		}
		for _, args := range [][]string{{"scorecard", "%"}, {"scorecard", "%", "-o", "json"}, {"profile", "%"}, {"profile", "%", "-o", "json"},
			{"assess", "%", "canary-egress-deny-v1"}, {"assess", "%", "canary-egress-deny-v1", "-o", "json"},
			{"compare", "%", "%"}, {"compare", "%", "%", "-o", "json"}, {"fix", "%"}, {"fix", "%", "-o", "json"}} {
			var outs [2]string
			var codes [2]int
			for i, path := range []string{old, now} {
				var out, errs bytes.Buffer
				codes[i] = run([]string(strings.Split(strings.ReplaceAll(strings.Join(args, "\x00"), "%", path), "\x00")), &out, &errs)
				outs[i] = strings.ReplaceAll(out.String()+errs.String(), path, "%")
				if codes[i] == exitUsage || out.Len() == 0 {
					t.Fatalf("%s %q: exit %d\n%s", path, args, codes[i], outs[i])
				}
				if m := letterShown.FindString(outs[i]); m != "" {
					t.Errorf("%s %q shows a letter grade (%q):\n%s", path, args, m, outs[i])
				}
			}
			if outs[0] != outs[1] || codes[0] != codes[1] {
				t.Errorf("%s %q: the older report and its sandprobe/6 form differ (exit %d, %d):\n%s\n---\n%s", old, args, codes[0], codes[1], outs[0], outs[1])
			}
		}
		// CMP-1: the version and the letter are not compared.
		var same, mixed, errs bytes.Buffer
		want := run([]string{"compare", old, old, "-o", "json"}, &same, &errs)
		if code := run([]string{"compare", old, now, "-o", "json"}, &mixed, &errs); code != want || mixed.String() != same.String() ||
			strings.Contains(mixed.String(), `"declared_configuration"`) {
			t.Errorf("%s against its sandprobe/6 form: exit %d, want %d:\n%s", old, code, want, mixed.String())
		}
		// FBK-3: feedback's preview of a report's summary, which is all it would send.
		var previews [2]fbRun
		for i, path := range []string{old, now} {
			previews[i] = fbIn(t, "", nil, "bug", "-title", "a summary", "-report", path, "-body-file", body, "-o", "json")
			if s := previews[i].stdout + previews[i].stderr; previews[i].code != exitApproval || !strings.Contains(s, "### Report summary") || letterShown.MatchString(s) {
				t.Errorf("%s: feedback's preview: exit %d, a letter %q:\n%s", path, previews[i].code, letterShown.FindString(s), s)
			}
		}
		if previews[0] != previews[1] {
			t.Errorf("%s: feedback previews the older report and its sandprobe/6 form differently", old)
		}
		// SCR-3 and AGT-6: the page -out re-renders embeds the report as sandprobe/6 without its letter, whichever
		// form it was saved in, and scorecard reads that embedded report back to the same card.
		var card bytes.Buffer
		run([]string{"scorecard", old, "-o", "json"}, &card, &errs)
		for _, path := range []string{old, now} {
			dir := t.TempDir()
			var out, errs bytes.Buffer
			run([]string{"scorecard", path, "-out", dir}, &out, &errs)
			pages, _ := filepath.Glob(filepath.Join(dir, "*.html"))
			if len(pages) != 1 {
				t.Fatalf("%s: pages %v: %s", path, pages, errs.String())
			}
			page, _ := os.ReadFile(pages[0])
			data := reportData.FindSubmatch(page)
			if data == nil || !bytes.Contains(data[1], []byte(`"schema":"sandprobe/6"`)) || !bytes.Contains(data[1], []byte(`"grade":{`)) || bytes.Contains(page, []byte(`"letter"`)) {
				t.Fatalf("%s: the re-rendered page's JSON carries a letter, an older version, or no grade", path)
			}
			embedded := filepath.Join(dir, "embedded.json")
			if err := os.WriteFile(embedded, data[1], 0o644); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if code := run([]string{"scorecard", embedded, "-o", "json"}, &out, &errs); code == exitUsage || out.String() != card.String() {
				t.Errorf("%s: the page's embedded report doesn't read back to the same card: exit %d\n%s%s", path, code, out.String(), errs.String())
			}
		}
	}
	if !letters["F"] || !letters["A"] || len(letters) < 3 {
		t.Fatalf("want saved reports with different letters to ignore, an A and an F among them; got %v", letters)
	}
	// ANL-2 and CAL-3: the outputs that lost a field say so in their version.
	var out, errs bytes.Buffer
	run([]string{"profile", files[0], "-o", "json"}, &out, &errs)
	if !strings.Contains(out.String(), `"schema": "sandprobe.profile/2"`) {
		t.Errorf("profile: %s", out.String())
	}
	out.Reset()
	run([]string{"assess", files[0], "canary-egress-deny-v1", "-o", "json"}, &out, &errs)
	if s := out.String(); !strings.Contains(s, `"schema": "sandprobe.assessment/2"`) || !strings.Contains(s, `"schema": "sandprobe.profile/2"`) ||
		!strings.Contains(s, `"highest_severity_finding_ids_unverified": [`) || strings.Contains(s, "driver") {
		t.Errorf("assess: %s", s)
	}
}

// GRD-1 and AGT-6: no generic writer writes a letter. BuildLegacy's only callers are the two managed-workload
// evaluations, whose legacy standard report keeps its version and letter (WGR-4, RUN-17, EVD-10); every runner here
// writes its report with Build.
func TestOnlyWorkloadEvaluationsWriteALetter(t *testing.T) {
	files, _ := filepath.Glob("../*/*.go")
	legacy, built := []string{}, 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("report.BuildLegacy(")) {
			legacy = append(legacy, f)
		}
		if strings.HasPrefix(f, "../sandprobe/") {
			built += bytes.Count(b, []byte("report.Build("))
		}
	}
	if want := []string{"../sandprobe-agent-grade/main.go", "../sandprobe-daytona-workload/main.go"}; !slices.Equal(legacy, want) {
		t.Errorf("BuildLegacy is called from %v, want only %v", legacy, want)
	}
	if built < 12 { // the twelve runners (UX-5), the PoC's render among them
		t.Errorf("found %d reports written with Build", built)
	}
}
