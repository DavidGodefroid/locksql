//go:build unix

package main

import (
	"bytes"
	"slices"
	"testing"
)

func TestParseAllowedUIDs(t *testing.T) {
	for in, want := range map[string][]int{
		"":               nil,
		"1000":           {1000},
		"1000,1001":      {1000, 1001},
		"1001,1001":      {1001},
		"2147483647":     {2147483647},
		"10002,1000,999": {10002, 1000, 999},
	} {
		got, err := parseAllowedUIDs(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("parseAllowedUIDs(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0", "007", "1000,0", "1,,2", ",1", "1,", "-1", "+1", " 1", "1 ", "a", "65534", "4294967295", "99999999999999999999"} {
		if got, err := parseAllowedUIDs(bad); err == nil {
			t.Errorf("parseAllowedUIDs(%q) = %v, want an error", bad, got)
		}
	}
}

// locksql console refuses a bad or repeated --allowed-uids before anything
// else (exit 3), with or without a terminal.
func TestConsoleAllowedUIDsFlag(t *testing.T) {
	for _, args := range [][]string{
		{"console", "--allowed-uids", "0"},
		{"console", "--allowed-uids", "65534"},
		{"console", "--allowed-uids", "007"},
		{"console", "--allowed-uids", "1000", "--allowed-uids", "1001"},
	} {
		for _, tty := range []bool{true, false} {
			var out bytes.Buffer
			e := env{stdout: &out, stderr: &out, cwd: t.TempDir(), tty: tty}
			if code := runEnv(e, args); code != exitUsage {
				t.Errorf("%v (tty %v): exit %d, %s", args, tty, code, out.String())
			}
		}
	}
}
