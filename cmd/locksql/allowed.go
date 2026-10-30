package main

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

// parseAllowedUIDs reads `console --allowed-uids`: comma-separated decimal
// uids, as the image's ALLOWED_UIDS build argument takes them. Root (0),
// 65534 (nobody) and leading zeros are refused here; the console's own uid
// is refused by the isolation checks (the separation would be void).
func parseAllowedUIDs(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var uids []int
	for _, f := range strings.Split(s, ",") {
		if f == "" || strings.Trim(f, "0123456789") != "" {
			return nil, fmt.Errorf("--allowed-uids: comma-separated uids, got %q", s)
		}
		if f[0] == '0' {
			return nil, fmt.Errorf("--allowed-uids: %s is root or has a leading zero", f)
		}
		// 2^32-1 is (uid_t)-1, no account's.
		v, err := strconv.ParseUint(f, 10, 32)
		if err != nil || v == math.MaxUint32 {
			return nil, fmt.Errorf("--allowed-uids: %s is not a uid", f)
		}
		n := int(v)
		if n == 65534 {
			// The overflow uid: any peer of a user namespace with no
			// mapping for its uid, never one agent.
			return nil, errors.New("--allowed-uids: 65534 is nobody, the kernel's overflow uid")
		}
		if !slices.Contains(uids, n) {
			uids = append(uids, n)
		}
	}
	return uids, nil
}

// onceFlag is a string flag given at most once: a second --allowed-uids
// (one a wrapper prepends, say) would otherwise replace the first.
type onceFlag struct {
	v   string
	set bool
}

func (f *onceFlag) String() string { return f.v }

func (f *onceFlag) Set(s string) error {
	if f.set {
		return errors.New("given twice: list every uid in one --allowed-uids")
	}
	f.v, f.set = s, true
	return nil
}

// joinUIDs prints uids as the flag takes them.
func joinUIDs(uids []int) string {
	s := make([]string, len(uids))
	for i, u := range uids {
		s[i] = strconv.Itoa(u)
	}
	return strings.Join(s, ",")
}
