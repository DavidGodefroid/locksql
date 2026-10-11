package sysconf

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Relays: a session of the console account opened from another account's
// terminal, which then carries every keystroke. loginuid and the terminal
// owner both name the console account there, so the console must look at
// how the session was opened.
const (
	// RelayMachinectl is `machinectl shell locksql@`: machined runs the
	// shell in a container-shell@N.service unit, and the machinectl
	// process that forwards the terminal runs as the caller.
	RelayMachinectl = "machinectl shell"
	// RelaySSHLoopback is an SSH login from this machine: the ssh client
	// runs in an account the console cannot identify.
	RelaySSHLoopback = "ssh from this machine"
)

// sessionsRoot holds the logind session files; tests replace it.
var sessionsRoot = "/run/systemd/sessions"

// SessionRelay reports whether the current process runs in a session
// opened through a relay (RelayMachinectl, RelaySSHLoopback), or "".
func SessionRelay() string {
	if b, err := os.ReadFile(procRoot + "/self/cgroup"); err == nil && bytes.Contains(b, []byte("/container-shell@")) {
		return RelayMachinectl
	}
	id, err := os.ReadFile(procRoot + "/self/sessionid")
	if err != nil {
		return ""
	}
	sid := strings.TrimSpace(string(id))
	if sid == "" || sid == "4294967295" || strings.ContainsAny(sid, "/.") {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(sessionsRoot, sid))
	if err != nil {
		return ""
	}
	vars := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vars[k] = v
		}
	}
	if vars["REMOTE"] == "1" && loopbackHost(vars["REMOTE_HOST"]) {
		return RelaySSHLoopback
	}
	return ""
}

// loopbackHost reports whether h names this machine.
func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.TrimPrefix(h, "::ffff:"))
	return ip != nil && ip.IsLoopback()
}

// MachinectlShellUIDs returns the real uids of the running `machinectl
// shell` processes (those forwarding a terminal into a machinectl session),
// and false when /proc cannot be listed.
func MachinectlShellUIDs() ([]int, bool) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, false
	}
	var uids []int
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		cmd, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmd), "\x00"), "\x00")
		if len(args) < 2 || filepath.Base(args[0]) != "machinectl" || !hasArg(args[1:], "shell", "login") {
			continue
		}
		if uid, ok := realUID(filepath.Join(dir, "status")); ok {
			uids = append(uids, uid)
		}
	}
	return uids, true
}

func hasArg(args []string, want ...string) bool {
	for _, a := range args {
		for _, w := range want {
			if a == w {
				return true
			}
		}
	}
	return false
}

// realUID reads the real uid from a /proc/<pid>/status file.
func realUID(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(rest)
			if len(f) == 0 {
				return 0, false
			}
			n, err := strconv.Atoi(f[0])
			return n, err == nil
		}
	}
	return 0, false
}
