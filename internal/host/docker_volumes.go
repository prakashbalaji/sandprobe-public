package host

// PRV-14: volume labels describe a volume, never who created it.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type DockerVolumeSnapshot struct{ names map[string]bool }
type DockerVolumeTracker struct {
	owned         map[string]string // original create-time mount name -> creation identity
	uncertain     bool
	unknownCreate bool
}

var anonymousDockerName = regexp.MustCompile(`^[a-f0-9]{64}$`)

type dockerVolumeBuffer struct{ buffer bytes.Buffer }

func (b *dockerVolumeBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 1<<20 {
		return 0, errors.New("Docker volume metadata limit")
	}
	return b.buffer.Write(p)
}

func dockerVolumeMetadata(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.WaitDelay = 2 * time.Second
	var b dockerVolumeBuffer
	cmd.Stdout = &b
	if cmd.Run() != nil {
		return nil, errors.New("Docker volume metadata unavailable")
	}
	return b.buffer.Bytes(), nil
}

func (t *DockerVolumeTracker) Snapshot(ctx context.Context) (*DockerVolumeSnapshot, error) {
	b, err := dockerVolumeMetadata(ctx, "volume", "ls", "-q")
	if err != nil {
		t.uncertain = true
		return nil, err
	}
	s := &DockerVolumeSnapshot{names: map[string]bool{}}
	for _, name := range strings.Fields(string(b)) {
		s.names[name] = true
	}
	return s, nil
}

// Only selected mount metadata is requested: never Env or volume driver options,
// which can contain credentials. Source-less mounts are Docker-created; explicit
// sources and pre-existing/inherited storage remain outside our ownership.
const dockerMountOrigins = `{"mounts":[{{range $i,$m:=.Mounts}}{{if $i}},{{end}}{"type":{{json $m.Type}},"name":{{json $m.Name}},"target":{{json $m.Destination}},"driver":{{json $m.Driver}}}{{end}}],"binds":{{json .HostConfig.Binds}},"declared":[{{range $i,$m:=.HostConfig.Mounts}}{{if $i}},{{end}}{"type":{{json $m.Type}},"source":{{json $m.Source}},"target":{{json $m.Target}}}{{end}}],"volumes_from":{{json .HostConfig.VolumesFrom}}}`

func (t *DockerVolumeTracker) Capture(ctx context.Context, id string, before *DockerVolumeSnapshot) error {
	if before == nil || before.names == nil {
		t.uncertain = true
		return errors.New("Docker volume baseline unavailable")
	}
	b, err := dockerVolumeMetadata(ctx, "inspect", "--type", "container", "-f", dockerMountOrigins, id)
	if err != nil {
		t.uncertain = true
		return err
	}
	var fields map[string]json.RawMessage
	var meta struct {
		Mounts      []struct{ Type, Name, Target, Driver string }
		Binds       []string
		Declared    []struct{ Type, Source, Target string }
		VolumesFrom []string `json:"volumes_from"`
	}
	if json.Unmarshal(b, &fields) != nil || json.Unmarshal(b, &meta) != nil || meta.Mounts == nil || meta.Declared == nil {
		t.uncertain = true
		return errors.New("Docker volume inventory invalid")
	}
	for _, key := range []string{"mounts", "binds", "declared", "volumes_from"} {
		if _, ok := fields[key]; !ok {
			t.uncertain = true
			return errors.New("Docker volume origins incomplete")
		}
	}
	explicit, bare := map[string]bool{}, map[string]bool{}
	for _, bind := range meta.Binds {
		parts := strings.Split(bind, ":")
		switch {
		case len(parts) == 1:
			bare[parts[0]] = true
		case parts[0] == "":
			bare[parts[1]] = true
		case strings.HasPrefix(parts[0], "/") && !strings.HasPrefix(parts[1], "/"):
			bare[parts[0]] = true
		default:
			explicit[parts[1]] = true
		}
	}
	for _, mount := range meta.Declared {
		if mount.Source != "" {
			explicit[mount.Target] = true
		} else if mount.Type == "volume" {
			bare[mount.Target] = true
		}
	}
	for _, mount := range meta.Mounts {
		if mount.Type != "volume" || before.names[mount.Name] || explicit[mount.Target] {
			continue
		}
		if (len(meta.VolumesFrom) > 0 && !bare[mount.Target]) || mount.Driver != "local" || !anonymousDockerName.MatchString(mount.Name) || !strings.HasPrefix(mount.Target, "/") {
			t.uncertain = true
			continue // cannot prove this new mount was created by this container
		}
		birth, e := dockerVolumeBirth(ctx, mount.Name)
		if e != nil {
			t.uncertain = true
			continue
		}
		if t.owned == nil {
			t.owned = map[string]string{}
		}
		if old, ok := t.owned[mount.Name]; ok && old != birth {
			t.uncertain = true
			continue
		}
		t.owned[mount.Name] = birth
	}
	if t.uncertain {
		return errors.New("Docker volume ownership unconfirmed")
	}
	return nil
}

func dockerVolumeBirth(ctx context.Context, name string) (string, error) {
	b, err := dockerVolumeMetadata(ctx, "volume", "inspect", "-f", "{{.CreatedAt}}", name)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if _, err = time.Parse(time.RFC3339Nano, s); err != nil {
		return "", errors.New("Docker volume creation identity unavailable")
	}
	return s, nil
}

func (t *DockerVolumeTracker) CreateUnconfirmed() { t.uncertain = true; t.unknownCreate = true }

// Cleanup never removes by an anonymous label or an unguarded name. Docker has
// no conditional name+birth DELETE; the local check-to-delete race is disclosed.
func (t *DockerVolumeTracker) Cleanup(ctx context.Context) []string {
	var left []string
	names := make([]string, 0, len(t.owned))
	for name := range t.owned {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		birth, err := dockerVolumeBirth(ctx, name)
		if err != nil && absent(ctx, "no such volume", "volume", "inspect", "-f", "{{.Name}}", name) {
			continue
		}
		if err != nil || birth != t.owned[name] {
			left = append(left, "volume "+name+"@"+t.owned[name])
			continue
		}
		cmd := exec.CommandContext(ctx, "docker", "volume", "rm", name)
		cmd.WaitDelay = 2 * time.Second
		if cmd.Run() != nil || !absent(ctx, "no such volume", "volume", "inspect", "-f", "{{.Name}}", name) {
			left = append(left, "volume "+name+"@"+birth)
		}
	}
	if t.uncertain {
		left = append(left, "anonymous volume inventory/ownership unconfirmed")
	}
	if t.unknownCreate {
		left = append(left, "container creation outcome unconfirmed (no returned ID)")
	}
	return left
}
