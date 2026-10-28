package main

import "os"

// fileOwner is unknown on Windows.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

// fileDevIno is unknown on Windows.
func fileDevIno(os.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }
