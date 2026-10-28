package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// expectDirEnv carries the device and inode ("DEV:INO") of the project's
// .locksql that the launcher checked (LOCKSQL_READONLY_PROJECT, Linux):
// the console refuses to start on another directory, one swapped in
// between that check and Docker's mount. Once the console runs, its mount
// no longer moves.
const expectDirEnv = "LOCKSQL_EXPECT_DIR"

// checkConsoleDir checks that project/.locksql is a directory, not a
// symbolic link, with the device and inode want ("DEV:INO"); an empty want
// checks nothing.
func checkConsoleDir(project, want string) error {
	if want == "" {
		return nil
	}
	d, i, ok := strings.Cut(want, ":")
	dev, err1 := strconv.ParseUint(d, 10, 64)
	ino, err2 := strconv.ParseUint(i, 10, 64)
	if !ok || err1 != nil || err2 != nil {
		return fmt.Errorf("%s=%q: not DEV:INO", expectDirEnv, want)
	}
	dir := filepath.Join(project, ".locksql")
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if gd, gi, ok := fileDevIno(fi); !ok || gd != dev || gi != ino {
		return fmt.Errorf("%s is not the directory the launcher checked (%s): it was replaced; start the console again", dir, want)
	}
	return nil
}
