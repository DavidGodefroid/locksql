//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The console refuses a .locksql that is not the directory the launcher
// checked (LOCKSQL_EXPECT_DIR_INODE): one swapped in before Docker mounted it.
func TestConsoleDirExpected(t *testing.T) {
	project := t.TempDir()
	dir := filepath.Join(project, ".locksql")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	ino := strconv.FormatUint(uint64(st.Ino), 10)
	if err := checkConsoleDir(project, ""); err != nil {
		t.Errorf("nothing expected: %v", err)
	}
	if err := checkConsoleDir(project, ino); err != nil {
		t.Errorf("the checked one: %v", err)
	}
	if err := checkConsoleDir(project, ino+"0"); err == nil || !strings.Contains(err.Error(), "not the directory the launcher checked") {
		t.Errorf("another inode: %v", err)
	}
	if err := checkConsoleDir(project, "x"); err == nil {
		t.Error("a bad value is accepted")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	if err := checkConsoleDir(project, ino); err == nil {
		t.Error("a symbolic link is accepted")
	}
}
