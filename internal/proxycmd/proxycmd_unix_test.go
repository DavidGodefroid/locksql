//go:build unix

package proxycmd

import (
	"bufio"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCloseKillsCommand(t *testing.T) {
	c := dial(t, New(helperArgv("pid")))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("command %d still runs after Close", pid)
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
