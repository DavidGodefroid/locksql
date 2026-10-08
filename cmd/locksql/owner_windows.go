//go:build windows

package main

import "os"

// fileOwner is not available on Windows.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
