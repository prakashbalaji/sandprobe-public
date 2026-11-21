package host

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"sandprobe/internal/obs"
)

// REF-1: public Amazon Linux 2023 multi-arch index, resolved 18 November 2026.
// Updating the pin is an explicit benchmark configuration change.
const ReferenceImage = obs.BoundaryReferenceImage

// REF-2: a deterministic file-work task, not an LLM/coding-agent evaluation.
// Only nonsecret text is written, only inside the run-owned emptyDir.
const referenceTask = `set -eu
umask 077
export HOME=/workspace
mkdir -p /workspace/task
printf '%s\n' 'sandprobe reference task v1' > /workspace/task/input.txt
tr '[:lower:]' '[:upper:]' < /workspace/task/input.txt > /workspace/task/output.txt
IFS= read -r reference_result < /workspace/task/output.txt
[ "$reference_result" = 'SANDPROBE REFERENCE TASK V1' ]
sha256sum /workspace/task/output.txt > /workspace/task/output.sha256
touch /workspace/.sandprobe-reference-ready
exec sleep infinity
`

func referenceManifest(pod map[string]any) {
	spec := pod["spec"].(map[string]any)
	spec["automountServiceAccountToken"] = false
	spec["enableServiceLinks"] = false
	spec["hostNetwork"], spec["hostPID"], spec["hostIPC"] = false, false, false
	spec["securityContext"] = map[string]any{"runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001, "runAsNonRoot": true,
		"seccompProfile": map[string]string{"type": "RuntimeDefault"}}
	spec["volumes"] = []map[string]any{
		{"name": "scratch", "emptyDir": map[string]string{"sizeLimit": "64Mi"}},
		{"name": "workspace", "emptyDir": map[string]string{"sizeLimit": "64Mi"}},
	}
	c := spec["containers"].([]map[string]any)[0]
	c["command"] = []string{"sh", "-c", referenceTask}
	c["workingDir"] = "/workspace"
	c["securityContext"] = map[string]any{"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
		"capabilities": map[string]any{"drop": []string{"ALL"}}}
	c["volumeMounts"] = []map[string]string{{"name": "scratch", "mountPath": "/tmp"}, {"name": "workspace", "mountPath": "/workspace"}}
	c["readinessProbe"] = map[string]any{"exec": map[string]any{"command": []string{"test", "-f", "/workspace/.sandprobe-reference-ready"}},
		"periodSeconds": 1, "timeoutSeconds": 1, "failureThreshold": 120}
}

// Each projection emits only nonsecret scalar configuration or presence flags.
// Never retrieve Pod JSON or env/envFrom values (REF-3).
type referenceField struct{ expression, expected string }

func absentContainerKey(key string) referenceField {
	return referenceField{`{{with index .spec.containers 0}}{{range $key, $_ := .securityContext}}{{if eq $key ` + strconv.Quote(key) + `}}present{{end}}{{end}}{{end}}`, ""}
}

func matchesCommand(path string, command []string) referenceField {
	conditions := []string{"(eq (len " + path + ") " + strconv.Itoa(len(command)) + ")"}
	for i, arg := range command {
		conditions = append(conditions, "(eq (index "+path+" "+strconv.Itoa(i)+") "+strconv.Quote(arg)+")")
	}
	return referenceField{`{{with index .spec.containers 0}}{{if and ` + strings.Join(conditions, " ") + `}}match{{else}}mismatch{{end}}{{end}}`, "match"}
}

func referenceFields(uid string, s PodSpec) []referenceField {
	network := ""
	if s.NetworkIsolated {
		network = "true"
	}
	fields := []referenceField{
		{"{{.metadata.uid}}", uid},
		{"{{.spec.runtimeClassName}}", "isolated-sandbox"},
		{`{{with .metadata.annotations}}{{with index . "sandbox.amazonaws.com/network-isolated"}}{{.}}{{end}}{{end}}`, network},
		{"{{range .spec.containers}}{{.name}} {{end}}", "agent "},
		{"{{if .spec.initContainers}}present{{else}}absent{{end}}", "absent"},
		{"{{if .spec.ephemeralContainers}}present{{else}}absent{{end}}", "absent"},
		{"{{.spec.automountServiceAccountToken}}", "false"},
		{"{{.spec.enableServiceLinks}}", "false"},
		{"{{if .spec.hostNetwork}}true{{else}}false{{end}}", "false"},
		{"{{if .spec.hostPID}}true{{else}}false{{end}}", "false"},
		{"{{if .spec.hostIPC}}true{{else}}false{{end}}", "false"},
		{"{{.spec.securityContext.runAsUser}}", "10001"},
		{"{{.spec.securityContext.runAsGroup}}", "10001"},
		{"{{.spec.securityContext.fsGroup}}", "10001"},
		{"{{.spec.securityContext.runAsNonRoot}}", "true"},
		{"{{.spec.securityContext.seccompProfile.type}}", "RuntimeDefault"},
		{"{{range .spec.securityContext.supplementalGroups}}{{.}} {{end}}", ""},
		{"{{if .spec.securityContext.sysctls}}present{{else}}absent{{end}}", "absent"},
		{`{{with index .spec.containers 0}}{{.image}}{{end}}`, s.Image},
		{`{{with index .spec.containers 0}}{{.workingDir}}{{end}}`, "/workspace"},
		{`{{with index .spec.containers 0}}{{if .env}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{if .envFrom}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{if .securityContext.privileged}}true{{else}}false{{end}}{{end}}`, "false"},
		{`{{with index .spec.containers 0}}{{.securityContext.allowPrivilegeEscalation}}{{end}}`, "false"},
		{`{{with index .spec.containers 0}}{{.securityContext.readOnlyRootFilesystem}}{{end}}`, "true"},
		{`{{with index .spec.containers 0}}{{range .securityContext.capabilities.drop}}{{.}} {{end}}{{end}}`, "ALL "},
		{`{{with index .spec.containers 0}}{{if .securityContext.capabilities.add}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{if .args}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{if .lifecycle}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{if .startupProbe}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{if .livenessProbe}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{if .volumeDevices}}present{{else}}absent{{end}}{{end}}`, "absent"},
		{`{{with index .spec.containers 0}}{{range .volumeMounts}}{{.name}}={{.mountPath}} {{end}}{{end}}`, "scratch=/tmp workspace=/workspace "},
		{`{{with index .spec.containers 0}}{{range .volumeMounts}}{{if or .readOnly .subPath .subPathExpr .mountPropagation .recursiveReadOnly}}changed{{else}}plain{{end}} {{end}}{{end}}`, "plain plain "},
		{"{{range .spec.volumes}}{{.name}}={{.emptyDir.sizeLimit}} {{end}}", "scratch=64Mi workspace=64Mi "},
		{"{{range .spec.volumes}}{{if .emptyDir.medium}}changed{{else}}disk{{end}} {{end}}", "disk disk "},
		{`{{with index .spec.containers 0}}{{.resources.limits.cpu}}/{{.resources.limits.memory}}{{end}}`, "1/1Gi"},
	}
	for _, key := range []string{"runAsUser", "runAsGroup", "runAsNonRoot", "seccompProfile", "procMount"} {
		fields = append(fields, absentContainerKey(key))
	}
	return append(fields, matchesCommand(".command", []string{"sh", "-c", referenceTask}),
		matchesCommand(".readinessProbe.exec.command", []string{"test", "-f", "/workspace/.sandprobe-reference-ready"}))
}

var referenceImageID = regexp.MustCompile(`^[a-zA-Z0-9._/:@-]*sha256:[0-9a-f]{64}$`)

func (p *PodBox) verifyReference(ctx context.Context, s PodSpec) error {
	fields := referenceFields(p.UID, s)
	expressions := make([]string, 0, len(fields)+1)
	for _, f := range fields {
		expressions = append(expressions, f.expression)
	}
	expressions = append(expressions, "{{range .status.containerStatuses}}{{.imageID}}{{end}}")
	out, err := p.run(ctx, nil, "get", "pod", p.Name, "-o", "go-template="+strings.Join(expressions, "\n"))
	if err != nil {
		return errors.New("reference pod configuration could not be verified")
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) != len(fields)+1 || p.UID == "" {
		return errors.New("reference pod configuration did not match the declared profile")
	}
	for i, f := range fields {
		if lines[i] != f.expected {
			return errors.New("reference pod configuration did not match the declared profile")
		}
	}
	imageID := lines[len(fields)]
	if len(imageID) > 256 || !referenceImageID.MatchString(imageID) {
		return errors.New("reference pod immutable image ID was not reported")
	}
	p.ReferenceImageID = imageID
	return nil
}

// ReferenceBoundary declares BND-1's fixed context after REF-3 verification,
// before the full probe. The caller passes that pod's verified imageID.
func ReferenceBoundary(s PodSpec, imageID string) (*obs.BoundaryContract, error) {
	if !s.Reference {
		return nil, nil
	}
	if s.RuntimeClass != "isolated-sandbox" {
		return nil, errors.New("unsupported reference boundary configuration")
	}
	c := &obs.BoundaryContract{Schema: "sandprobe.boundary-contract/1", Workload: "aws-reference-file-v1",
		RequestedImage: s.Image, ReportedImageID: imageID, AgentUID: 10001, AgentGID: 10001,
		NetworkExpectation: "unrestricted", ResetModel: "none", ProtectedResourceAttribution: "unestablished"}
	if s.NetworkIsolated {
		c.NetworkExpectation = "deny-canary-six-routes"
	}
	if err := obs.ValidateBoundaryContract(c); err != nil {
		return nil, err
	}
	return c, nil
}
