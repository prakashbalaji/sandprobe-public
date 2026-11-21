package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type dockerVolumeFixture struct {
	Birth    map[string]string
	Metadata map[string]map[string]any
	Fail     string
	Calls    [][]string
	Removed  []string
	RunID    string
	RunBirth map[string]string
}

// This subprocess replaces only the Docker CLI; it never contacts a daemon.
func TestDockerVolumeCommandHelper(t *testing.T) {
	if os.Getenv("SANDPROBE_VOLUME_HELPER") != "1" {
		return
	}
	path := os.Getenv("SANDPROBE_VOLUME_STATE")
	var f dockerVolumeFixture
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &f)
	var args []string
	for i, s := range os.Args {
		if s == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	f.Calls = append(f.Calls, args)
	out, code := "", 0
	switch {
	case len(args) >= 3 && args[0] == "volume" && args[1] == "ls":
		if f.Fail == "list" {
			code = 1
			break
		}
		for name := range f.Birth {
			out += name + "\n"
		}
	case len(args) > 3 && args[0] == "inspect" && slices.Contains(args, dockerMountOrigins):
		if f.Fail == "mounts" {
			code = 1
			break
		}
		b, _ := json.Marshal(f.Metadata[args[len(args)-1]])
		out = string(b)
	case len(args) >= 3 && args[0] == "volume" && args[1] == "inspect":
		name := args[len(args)-1]
		birth, ok := f.Birth[name]
		if !ok {
			out = "Error: No such volume: " + name
			code = 1
			break
		}
		if f.Fail == "birth" {
			code = 1
			break
		}
		if slices.Contains(args, "{{.CreatedAt}}") {
			out = birth
		} else {
			out = name
		}
	case len(args) == 3 && args[0] == "volume" && args[1] == "rm":
		f.Removed = append(f.Removed, args[2])
		delete(f.Birth, args[2])
	case len(args) >= 3 && args[0] == "rm":
		delete(f.Metadata, args[len(args)-1])
	case len(args) >= 2 && args[0] == "run":
		for name, birth := range f.RunBirth {
			f.Birth[name] = birth
		}
		out = f.RunID
	case len(args) >= 4 && args[0] == "inspect":
		if _, ok := f.Metadata[args[len(args)-1]]; !ok {
			out = "Error: No such container"
			code = 1
		}
	default:
		code = 1
	}
	b, _ = json.Marshal(f)
	os.WriteFile(path, b, 0600)
	fmt.Print(out)
	os.Exit(code)
}

func fakeDockerVolumes(t *testing.T, f dockerVolumeFixture) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	writeDockerVolumeFixture(t, path, f)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quoted := "'" + strings.ReplaceAll(exe, "'", "'\"'\"'") + "'"
	script := "#!/bin/sh\nexec " + quoted + " -test.run '^TestDockerVolumeCommandHelper$' -- \"$@\"\n"
	if err = os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SANDPROBE_VOLUME_HELPER", "1")
	t.Setenv("SANDPROBE_VOLUME_STATE", path)
	return path
}
func writeDockerVolumeFixture(t *testing.T, path string, f dockerVolumeFixture) {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func readDockerVolumeFixture(t *testing.T, path string) dockerVolumeFixture {
	t.Helper()
	var f dockerVolumeFixture
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}
func volumeMount(name, target string) map[string]string {
	return map[string]string{"type": "volume", "name": name, "target": target, "driver": "local"}
}
func volumeOrigins(mounts ...map[string]string) map[string]any {
	return map[string]any{"mounts": mounts, "binds": []string{}, "declared": []map[string]string{}, "volumes_from": []string{}}
}

func TestDockerVolumeOwnershipPreservesExplicitAndInheritedStorage(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, name := range []string{"implicit", "explicit-bind", "explicit-mount", "inherited-existing", "ambiguous-inherited", "bare-with-inheritance"} {
		t.Run(name, func(t *testing.T) {
			f := dockerVolumeFixture{Birth: map[string]string{a: "2026-11-20T01:00:00Z"}, Metadata: map[string]map[string]any{}}
			path := fakeDockerVolumes(t, f)
			tracker := new(DockerVolumeTracker)
			before, err := tracker.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			f = readDockerVolumeFixture(t, path)
			meta := volumeOrigins(volumeMount(a, "/old"))
			if name != "inherited-existing" {
				f.Birth[b] = "2026-11-20T02:00:00Z"
				meta = volumeOrigins(volumeMount(a, "/old"), volumeMount(b, "/new"))
			}
			switch name {
			case "explicit-bind":
				meta["binds"] = []string{a + ":/old:ro", b + ":/new"}
			case "explicit-mount":
				meta["declared"] = []map[string]string{{"type": "volume", "source": b, "target": "/new"}}
			case "inherited-existing", "ambiguous-inherited", "bare-with-inheritance":
				meta["volumes_from"] = []string{"source-container"}
			}
			if name == "bare-with-inheritance" {
				meta["binds"] = []string{"/new:ro"}
			}
			f.Metadata["box"] = meta
			writeDockerVolumeFixture(t, path, f)
			err = tracker.Capture(context.Background(), "box", before)
			if (err != nil) != (name == "ambiguous-inherited") {
				t.Fatalf("capture: %v", err)
			}
			left := tracker.Cleanup(context.Background())
			f = readDockerVolumeFixture(t, path)
			if _, ok := f.Birth[a]; !ok {
				t.Fatal("pre-existing storage deleted")
			}
			owns := name == "implicit" || name == "bare-with-inheritance"
			if slices.Contains(f.Removed, b) != owns {
				t.Fatalf("wrong ownership deletion: %+v", f.Removed)
			}
			if (len(left) > 0) != (name == "ambiguous-inherited") {
				t.Fatal("ambiguous ownership falsely confirmed", left)
			}
		})
	}
}

func TestDockerVolumeFailuresAndReplacementNeverAuthorizeDeletion(t *testing.T) {
	b := strings.Repeat("b", 64)
	for _, failure := range []string{"list", "mounts", "birth", "replacement", "incomplete"} {
		t.Run(failure, func(t *testing.T) {
			path := fakeDockerVolumes(t, dockerVolumeFixture{Birth: map[string]string{}, Metadata: map[string]map[string]any{}})
			tracker := new(DockerVolumeTracker)
			if failure == "list" {
				f := readDockerVolumeFixture(t, path)
				f.Fail = "list"
				writeDockerVolumeFixture(t, path, f)
			}
			before, err := tracker.Snapshot(context.Background())
			if failure == "list" {
				if err == nil || len(tracker.Cleanup(context.Background())) == 0 {
					t.Fatal("failed inventory treated as empty")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f := readDockerVolumeFixture(t, path)
			f.Birth[b] = "2026-11-20T02:00:00Z"
			f.Metadata["box"] = volumeOrigins(volumeMount(b, "/data"))
			if failure == "mounts" || failure == "birth" {
				f.Fail = failure
			}
			if failure == "incomplete" {
				delete(f.Metadata["box"], "volumes_from")
			}
			writeDockerVolumeFixture(t, path, f)
			err = tracker.Capture(context.Background(), "box", before)
			if failure == "replacement" {
				if err != nil {
					t.Fatal(err)
				}
				f = readDockerVolumeFixture(t, path)
				f.Birth[b] = "2026-11-20T03:00:00Z"
				writeDockerVolumeFixture(t, path, f)
			} else if err == nil {
				t.Fatal("inventory failure hidden")
			}
			if len(tracker.Cleanup(context.Background())) == 0 {
				t.Fatal("unverified inventory reported clean")
			}
			if f = readDockerVolumeFixture(t, path); len(f.Removed) != 0 {
				t.Fatal("unowned/replaced volume removed")
			}
		})
	}
}

func TestDockerVolumeTrackingSurvivesReset(t *testing.T) {
	b, c := strings.Repeat("b", 64), strings.Repeat("c", 64)
	path := fakeDockerVolumes(t, dockerVolumeFixture{Birth: map[string]string{}, Metadata: map[string]map[string]any{}})
	tracker := new(DockerVolumeTracker)
	before, err := tracker.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f := readDockerVolumeFixture(t, path)
	f.Birth[b] = "2026-11-20T02:00:00Z"
	f.Metadata["old"] = volumeOrigins(volumeMount(b, "/data"))
	f.Metadata["new"] = volumeOrigins(volumeMount(c, "/data"))
	f.RunID = "new"
	f.RunBirth = map[string]string{c: "2026-11-20T03:00:00Z"}
	writeDockerVolumeFixture(t, path, f)
	if err = tracker.Capture(context.Background(), "old", before); err != nil {
		t.Fatal(err)
	}
	d := &DockerBox{Container: "old", Args: []string{"run", "-d", "fixture"}, VolumeTracker: tracker}
	after, _, err := d.Reset(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	box := after.(*DockerBox)
	box.Teardown(context.Background(), nil)
	if left := tracker.Cleanup(context.Background()); len(left) != 0 {
		t.Fatal(left)
	}
	f = readDockerVolumeFixture(t, path)
	if !slices.Contains(f.Removed, b) || !slices.Contains(f.Removed, c) {
		t.Fatal("reset lost original ownership")
	}
	for _, call := range f.Calls {
		if len(call) > 0 && call[0] == "rm" && slices.Contains(call, "-v") {
			t.Fatal("unguarded rm -v")
		}
		if len(call) > 1 && call[0] == "volume" && call[1] == "inspect" && !slices.Contains(call, "-f") {
			t.Fatal("full volume metadata was requested")
		}
	}
}
