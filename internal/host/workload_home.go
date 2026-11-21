package host

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"

	"sandprobe/internal/strictjson"
)

const WorkloadHome = "/opt/sandprobe/home"
const WorkloadCache = "/workspace/.cache"

//go:embed workload_home_guard.py
var workloadHomeGuard string

type workloadHomeNode struct {
	Path      string `json:"path"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	UID       uint32 `json:"uid"`
	Mode      uint32 `json:"mode"`
	Directory bool   `json:"directory"`
}
type workloadHomeContext struct {
	Schema string             `json:"schema"`
	Home   string             `json:"home"`
	Nodes  []workloadHomeNode `json:"nodes"`
}

func workloadHomeHash(raw []byte) (string, error) {
	var h workloadHomeContext
	bad := errors.New("owned workload home invalid")
	if strictjson.Decode(raw, 8192, &h) != nil || h.Schema != "sandprobe.workload-home/1" || h.Home != WorkloadHome || len(h.Nodes) != 4 {
		return "", bad
	}
	for i, path := range []string{"/", "/opt", "/opt/sandprobe", WorkloadHome} {
		n := h.Nodes[i]
		if n.Path != path || n.Device == 0 || n.Inode == 0 || n.UID != 0 || !n.Directory || n.Mode > 0777 || n.Mode&0022 != 0 || n.Mode&1 == 0 || path == WorkloadHome && n.Mode != 0555 {
			return "", bad
		}
	}
	nodes := make([]map[string]any, 0, len(h.Nodes))
	for _, n := range h.Nodes {
		nodes = append(nodes, map[string]any{"path": n.Path, "device": n.Device, "inode": n.Inode, "uid": n.UID, "mode": n.Mode, "directory": n.Directory})
	}
	canonical, _ := json.Marshal(map[string]any{"schema": h.Schema, "home": h.Home, "nodes": nodes})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
