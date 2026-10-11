package main

import "os"

// fileOwner is unknown on Windows.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
