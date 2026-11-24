package catalog

import (
	"fmt"
	"path"
	"strings"
)

// ValidateBlockDevicePaths bounds host-declared Linux metadata targets (EVD-13).
// Never resolve these paths on the host: they belong to the sandbox namespace.
func ValidateBlockDevicePaths(paths []string) error {
	if len(paths) > 32 {
		return fmt.Errorf("block-device paths: at most 32 targets allowed")
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if len(p) > 4095 || p == "/" || !strings.HasPrefix(p, "/") || path.Clean(p) != p || seen[p] {
			return fmt.Errorf("block-device paths must be distinct canonical absolute Linux paths")
		}
		for _, c := range []byte(p) {
			if c < 32 || c > 126 {
				return fmt.Errorf("block-device paths must contain only printable ASCII")
			}
		}
		seen[p] = true
	}
	return nil
}
