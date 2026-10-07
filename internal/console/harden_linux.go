//go:build linux

package console

import "golang.org/x/sys/unix"

// harden keeps the secret out of core dumps and away from same-user
// ptrace and /proc/<pid>/mem readers: RLIMIT_CORE=0 and PR_SET_DUMPABLE=0.
func harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
