package sysconf

import "os"

// TerminalOwner is unknown on Windows.
func TerminalOwner(*os.File) (int, bool) { return 0, false }
