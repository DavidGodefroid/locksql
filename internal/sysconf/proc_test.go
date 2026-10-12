//go:build linux

package sysconf

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// ParentChain walks /proc/<pid>/status from the parent up to pid 1,
// excluded, with the real uid and the comm of each ancestor.
func TestParentChain(t *testing.T) {
	proc := t.TempDir()
	oldP, oldG := procRoot, getppid
	procRoot, getppid = proc, func() int { return 7 }
	t.Cleanup(func() { procRoot, getppid = oldP, oldG })
	status := func(pid, body string) {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "status"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	status("42", "Name:\tlocksql\nPPid:\t7\nUid:\t900\t900\t900\t900\n")
	status("7", "Name:\tbash\nUmask:\t0022\nPPid:\t3\nUid:\t900\t900\t900\t900\n")
	status("3", "Name:\tfoot\nPPid:\t1\nUid:\t900\t0\t900\t900\n")
	status("1", "Name:\tsystemd\nPPid:\t0\nUid:\t0\t0\t0\t0\n")

	got, err := ParentChain()
	if err != nil {
		t.Fatal(err)
	}
	want := []Proc{{PID: 7, UID: 900, Comm: "bash"}, {PID: 3, UID: 900, Comm: "foot"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParentChain() = %+v, want %+v", got, want)
	}

	if err := os.Remove(filepath.Join(proc, "3", "status")); err != nil {
		t.Fatal(err)
	}
	if got, err := ParentChain(); err == nil || len(got) != 1 {
		t.Fatalf("missing ancestor: %+v, %v", got, err)
	}
}

// The kernel shows gnome-terminal-server as "gnome-terminal-" (15 bytes).
func TestParentChainTruncatedComm(t *testing.T) {
	proc := t.TempDir()
	oldP, oldG := procRoot, getppid
	procRoot, getppid = proc, func() int { return 5 }
	t.Cleanup(func() { procRoot, getppid = oldP, oldG })
	if err := os.MkdirAll(filepath.Join(proc, "5"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "Name:\tgnome-terminal-\nUmask:\t0002\nState:\tS (sleeping)\nPPid:\t1\nUid:\t900\t900\t900\t900\n"
	if err := os.WriteFile(filepath.Join(proc, "5", "status"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ParentChain()
	if err != nil {
		t.Fatal(err)
	}
	want := []Proc{{PID: 5, UID: 900, Comm: "gnome-terminal-"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParentChain() = %+v, want %+v", got, want)
	}
	if len("gnome-terminal-server") <= CommLen || "gnome-terminal-server"[:CommLen] != got[0].Comm {
		t.Fatalf("CommLen %d does not truncate gnome-terminal-server to %q", CommLen, got[0].Comm)
	}
}
