//go:build windows

package sysconf

import "os"

// TerminalOwner is not available on Windows.
func TerminalOwner(*os.File) (int, bool) { return 0, false }
