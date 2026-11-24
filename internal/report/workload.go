package report

import (
	"bytes"
	"html/template"

	"sandprobe/internal/grade"
)

// WorkloadHTML makes WGR's conditional configuration grade the headline, with
// the measurement assumption beside it. The legacy generic letter is diagnostic.
func WorkloadHTML(r grade.WorkloadReport) ([]byte, error) {
	return workloadHTML(r, nil, nil)
}

// WorkloadEvidenceHTML opts into EVD-1 without rewriting historical renderings.
func WorkloadEvidenceHTML(r grade.WorkloadReport, coverage grade.EvidenceCoverage) ([]byte, error) {
	return workloadHTML(r, &coverage, nil)
}

func workloadHTML(r grade.WorkloadReport, coverage *grade.EvidenceCoverage, exposure *WorkloadExposure) ([]byte, error) {
	// The evidence-coverage text renders recorded evidence byte for byte as it was first written, so its wording,
	// "RC's exposure score" included, stays as recorded; the exposure page's own heading isn't recorded.
	const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>{{if .Exposure}}Sandprobe workload exposure scorecard{{else}}Sandprobe workload configuration assessment{{end}}</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 20px;line-height:1.5;color:#17212b}h1{font-size:30px}strong.grade{font-size:48px}aside{padding:16px;background:#fff3ce;border:1px solid #b58a20}table{border-collapse:collapse;width:100%;margin:24px 0}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}code{overflow-wrap:anywhere}</style><main>
{{with .Exposure}}<h1>Exposure score: <strong class="grade">{{if .Valid}}{{.Score}}/{{.Of}}{{else}}Unassessed{{end}}</strong></h1>{{range .NotCounted}}<p>{{.}}</p>{{end}}<p>Exposure categories only; not a security certification or provider-wide ranking. Unknown and not-proven observations remain missing proof.</p>{{with .Coverage}}<p>{{.Description}}</p>{{else}}<p>Coverage unavailable for this historical scorecard.</p>{{end}}<table><thead><tr><th>Category</th><th>Exposure result</th><th>Unknown checks</th><th>Not proven</th><th>Measurement coverage</th></tr></thead><tbody>{{range .Rows}}<tr><td>{{.Name}}</td><td>{{if .Green}}{{if .GreenNotProven}}Green · not proven{{else}}Green{{end}}{{else}}{{.Why}}{{end}}</td><td>{{range .Unknown}}<code>{{.}}</code> {{end}}</td><td>{{range .Unproven}}<code>{{.}}</code> {{end}}</td><td>{{with .Coverage}}{{.Description}}{{else}}Unavailable{{end}}</td></tr>{{end}}</tbody></table>{{end}}{{if .Exposure}}<h2>Workload configuration grade: <strong class="grade">{{if .ConfigurationGrade}}{{.ConfigurationGrade}}{{else}}Unassessed{{end}}</strong></h2>{{else}}<h1>Workload configuration grade: <strong class="grade">{{if .ConfigurationGrade}}{{.ConfigurationGrade}}{{else}}Unassessed{{end}}</strong></h1>{{end}}
<p>Profile: <code>{{.Profile}}</code> · workload: {{.Workload}} · valid: {{.Valid}} · complete: {{.Complete}}</p>
<aside><strong>Conditional configuration benchmark.</strong> Assumption: <code>{{.MeasurementAssumption}}</code>.<br>Input verification: <code>{{.InputVerification}}</code>.<br>Security assurance: <code>{{.SecurityAssurance}}</code>. This grade is not a deployment-safety verdict or provider-wide certification.</aside>
<h2>Residual exposure</h2><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>
{{with .EvidenceCoverage}}<h2>Evidence coverage</h2><p>This six-category workload-context view is separate from RC's exposure score and the configuration grade. Unknowns are missing proof; unassessed controls are not passes. Grouped gaps may affect several controls.</p>
<table><thead><tr><th>Missing measurement</th><th>Evidence source</th><th>Affected controls</th><th>Next measurement</th></tr></thead><tbody>{{range .Gaps}}<tr><td>{{.ID}}</td><td>{{.Source}}</td><td>{{range .Controls}}<code>{{.}}</code> {{end}}</td><td>{{.NextMeasurement}}</td></tr>{{end}}</tbody></table>
{{range .Categories}}<h3>{{.Name}}</h3><ul>{{range .Controls}}<li><code>{{.ID}}</code>: {{.Result}} ({{.Coverage}})</li>{{else}}<li>No controls assessed in this category.</li>{{end}}</ul>{{end}}
<h3>Connection diagnostics</h3><p>Diagnostic guest observations only. A completed exchange is not a host receipt; silence or an exchange error is not proof of blocking.</p><table><thead><tr><th>Check</th><th>TCP outcome</th><th>Exchange stage</th><th>Exchange outcome</th></tr></thead><tbody>{{range .Exchanges}}<tr><td>{{.Check}}</td><td>{{.Transport}}</td><td>{{.Stage}}</td><td>{{.Result}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>Controls and scope</h2><table><thead><tr><th>Control</th><th>Coverage</th><th>Result</th><th>Basis</th></tr></thead><tbody>{{range .Controls}}<tr><td><code>{{.ID}}</code></td><td>{{.Coverage}}</td><td>{{.Result}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody></table>
<h2>Missing evidence</h2><ul>{{range .Unknown}}<li>{{.}}</li>{{else}}<li>No missing evidence within this fixed configuration profile.</li>{{end}}</ul>
<h2>Limits</h2><ul>{{range .Limits}}<li>{{.}}</li>{{end}}</ul>
<p>Legacy generic grade: {{.LegacyGrade}} (diagnostic; not the workload configuration grade). Run: <code>{{.RunID}}</code> · box: <code>{{.BoxID}}</code>.</p></main></html>`
	t, err := template.New("workload").Parse(page)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	view := struct {
		grade.WorkloadReport
		EvidenceCoverage *grade.EvidenceCoverage
		Exposure         *WorkloadExposure
	}{r, coverage, exposure}
	if err = t.Execute(&out, view); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
