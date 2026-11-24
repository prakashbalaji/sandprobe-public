package catalog

import (
	"fmt"
	"strings"
	"testing"
)

func TestBlockDevicePaths(t *testing.T) {
	for _, paths := range [][]string{nil, {"/dev/workload/disk", "/mounted-device"}, {"/" + strings.Repeat("a", 4094)}} {
		if err := ValidateBlockDevicePaths(paths); err != nil {
			t.Fatal(err)
		}
	}
	for _, paths := range [][]string{{""}, {"relative"}, {"/"}, {"/dev/../disk"}, {"/dev//disk"}, {"/dev/disk/"}, {"/dev/disk", "/dev/disk"}, {"/dev/line\nbreak"}, {"/dev/\x00disk"}, {"/dev/\x7fdisk"}, {"/dev/é"}, {"/" + strings.Repeat("a", 4095)}} {
		if err := ValidateBlockDevicePaths(paths); err == nil {
			t.Fatalf("accepted invalid paths %q", paths)
		}
	}
	var paths []string
	for i := 0; i < 33; i++ {
		paths = append(paths, fmt.Sprintf("/dev/disk%d", i))
	}
	if err := ValidateBlockDevicePaths(paths[:32]); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBlockDevicePaths(paths); err == nil {
		t.Fatal("accepted more than 32 paths")
	}
}
