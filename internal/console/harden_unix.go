//go:build unix && !linux

package console

import "golang.org/x/sys/unix"

// harden disables core dumps (RLIMIT_CORE=0).
func harden() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}
