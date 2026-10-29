//go:build unix

package proxycmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// alive reports whether pid runs; a zombie no reaper has collected yet
// does not.
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	i := bytes.LastIndexByte(stat, ')')
	return i < 0 || i+2 >= len(stat) || stat[i+2] != 'Z'
}

func TestCloseKillsCommand(t *testing.T) {
	c := dial(t, New(helperArgv("pid")))
	pid := readPid(t, c)
	c.Close()
	waitGone(t, pid)
}

// A process that leaves the command's group holding its stderr does not
// keep the connection from ending: Wait gives up on the pipe after
// WaitDelay.
func TestOrphanHoldingStderr(t *testing.T) {
	p := New(helperArgv("orphan"))
	c := dial(t, p)
	orphan := readPid(t, c)
	t.Cleanup(func() { syscall.Kill(orphan, syscall.SIGKILL) })
	c.Close()
	deadline := time.Now().Add(waitDelay + 5*time.Second)
	for !strings.Contains(p.Stderr(), "orphaned") {
		if time.Now().After(deadline) {
			t.Fatal("the command's end waits for its orphan")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNoControllingTerminal(t *testing.T) {
	c := dial(t, New(helperArgv("tty")))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "no tty\n" {
		t.Errorf("read %q, %v", line, err)
	}
}
