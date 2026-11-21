package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"
)

func TestDockerVolumeMetadataProjectionExcludesCredentials(t *testing.T) {
	const secret = "synthetic-private-value"
	metadata := map[string]any{"Env": []string{"KEY=" + secret}, "Mounts": []map[string]string{{"Type": "volume", "Name": "owned", "Destination": "/data", "Driver": "local"}}, "HostConfig": map[string]any{
		"Binds": []string{}, "VolumesFrom": []string{}, "Mounts": []map[string]any{{"Type": "volume", "Source": "named", "Target": "/data", "VolumeOptions": map[string]string{"password": secret}}}}}
	tmpl, err := template.New("projection").Funcs(template.FuncMap{"json": func(v any) (string, error) { b, e := json.Marshal(v); return string(b), e }}).Parse(dockerMountOrigins)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = tmpl.Execute(&out, metadata); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), secret) || !json.Valid(out.Bytes()) {
		t.Fatal("projection leaked values or invalid JSON")
	}
}

// CI enables this after the pinned image has been loaded by test/quick.sh. It
// creates only its own image/containers/empty volumes, with networking disabled.
func TestDockerVolumeNative(t *testing.T) {
	if os.Getenv("SANDPROBE_DOCKER_VOLUME_TESTS") != "1" {
		t.Skip("native Docker volume lifecycle test is enabled explicitly in CI")
	}
	const baseImage = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	docker := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.WaitDelay = 2 * time.Second
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("native Docker fixture command %s failed: %v", args[0], err)
		}
		return strings.TrimSpace(string(b))
	}
	docker("image", "inspect", "--format", "{{.Id}}", baseImage) // no implicit pull
	dir := t.TempDir()
	file := "FROM " + baseImage + "\nLABEL io.sandprobe.volume-test=" + token("v") + "\nVOLUME /data\nCMD [\"true\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(file), 0600); err != nil {
		t.Fatal(err)
	}
	image := docker("build", "--network", "none", "--pull=false", "-q", dir)
	defer exec.Command("docker", "image", "rm", image).Run() // exact new image ID; unique test label
	for _, mode := range []string{"explicit", "inherited", "fresh-reset"} {
		t.Run(mode, func(t *testing.T) {
			fixture := new(DockerVolumeTracker)
			before, err := fixture.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			owner := &DockerBox{Container: docker("create", "--network", "none", image)}
			defer func() {
				owner.Teardown(context.Background(), nil)
				if left := fixture.Cleanup(context.Background()); len(left) > 0 {
					t.Errorf("fixture cleanup: %v", left)
				}
			}()
			if err = fixture.Capture(ctx, owner.Container, before); err != nil || len(fixture.owned) != 1 {
				t.Fatal("fixture volume ownership", err)
			}
			var prior, birth string
			for name, created := range fixture.owned {
				prior, birth = name, created
			}
			tracker := new(DockerVolumeTracker)
			baseline, err := tracker.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"run", "-d", "--network", "none"}
			switch mode {
			case "explicit":
				args = append(args, "-v", prior+":/data")
			case "inherited":
				args = append(args, "--volumes-from", owner.Container)
			case "fresh-reset":
				args = append(args, "-v", "/extra")
			}
			args = append(args, image)
			box := &DockerBox{Container: docker(args...), Args: args, VolumeTracker: tracker}
			defer func() {
				box.Teardown(context.Background(), nil)
				if left := tracker.Cleanup(context.Background()); len(left) > 0 {
					t.Errorf("tested-box cleanup: %v", left)
				}
			}()
			if err = tracker.Capture(ctx, box.Container, baseline); err != nil {
				t.Fatal(err)
			}
			owner.Teardown(ctx, nil) // inherited source is gone: no other reference protects its volume
			if mode == "fresh-reset" {
				if len(tracker.owned) != 2 {
					t.Fatal("implicit image/bare volumes not tracked")
				}
				after, _, err := box.Reset(ctx)
				if err != nil {
					t.Fatal(err)
				}
				box = after.(*DockerBox)
				if len(tracker.owned) != 4 {
					t.Fatal("reset lost volume identities")
				}
			} else if len(tracker.owned) != 0 {
				t.Fatal("operator storage was claimed as owned")
			}
			box.Teardown(ctx, nil)
			if left := tracker.Cleanup(ctx); len(left) > 0 {
				t.Fatal(left)
			}
			if now, err := dockerVolumeBirth(ctx, prior); err != nil || now != birth {
				t.Fatal("pre-existing anonymous volume was deleted or replaced")
			}
		})
	}
}
