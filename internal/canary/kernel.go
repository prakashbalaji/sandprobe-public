package canary

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// readKernelDrops sums the kernel's counts of what it dropped before the canary could see it: TcpExt ListenOverflows
// and ListenDrops (a full accept queue) in /proc/net/netstat, and Udp InErrors and RcvbufErrors in /proc/net/snmp.
// Any file or field it can't read is an error, which marks every armed run overloaded: a count that can't be read
// never reads as no overload.
func readKernelDrops() (uint64, error) {
	var sum uint64
	for _, f := range []struct {
		path, prefix string
		fields       []string
	}{
		{"/proc/net/netstat", "TcpExt:", []string{"ListenOverflows", "ListenDrops"}},
		{"/proc/net/snmp", "Udp:", []string{"InErrors", "RcvbufErrors"}},
	} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			return 0, err
		}
		v, err := counters(string(b), f.prefix, f.fields)
		if err != nil {
			return 0, err
		}
		sum += v
	}
	return sum, nil
}

// counters sums the named fields from the first pair of header and value lines that start with prefix, the way
// /proc/net/netstat and /proc/net/snmp lay them out.
func counters(text, prefix string, fields []string) (uint64, error) {
	var head []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		f := strings.Fields(line)[1:]
		if head == nil {
			head = f
			continue
		}
		if len(f) != len(head) {
			return 0, fmt.Errorf("%s counters don't match their header", prefix)
		}
		var sum uint64
		for _, name := range fields {
			i := slices.Index(head, name)
			if i < 0 {
				return 0, fmt.Errorf("no %s%s counter", prefix, name)
			}
			v, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("%s%s: %w", prefix, name, err)
			}
			sum += v
		}
		return sum, nil
	}
	return 0, errors.New("no " + prefix + " counters")
}
