//go:build windows

package sysconf

import "io/fs"

// checkRootOwned is a no-op on Windows, which has no system setup.
func checkRootOwned(string, fs.FileInfo) error { return nil }
