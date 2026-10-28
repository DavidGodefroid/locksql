package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// expectDirInodeEnv carries the inode of the project's .locksql that the
// launcher checked (LOCKSQL_READONLY_PROJECT, Linux): the console refuses
// to start on another directory, one swapped in between that check and
// Docker's mount. Once the console runs, its mount no longer moves.
const expectDirInodeEnv = "LOCKSQL_EXPECT_DIR_INODE"

// checkConsoleDir checks that project/.locksql is a directory, not a
// symbolic link, with the inode want; an empty want checks nothing.
func checkConsoleDir(project, want string) error {
	if want == "" {
		return nil
	}
	n, err := strconv.ParseUint(want, 10, 64)
	if err != nil {
		return fmt.Errorf("%s=%q: not an inode number", expectDirInodeEnv, want)
	}
	dir := filepath.Join(project, ".locksql")
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if ino, ok := fileInode(fi); !ok || ino != n {
		return fmt.Errorf("%s is not the directory the launcher checked (inode %d): it was replaced; start the console again", dir, n)
	}
	return nil
}
