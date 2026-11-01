//go:build firstquery && linux

package firstquery

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A console that prints its last line and exits at once: the prompt is
// found though done closes before the reader has copied that line.
func TestWaitForReadsTheOutputBeforeTheExit(t *testing.T) {
	s := &screen{done: make(chan struct{}), drained: make(chan struct{})}
	close(s.done)
	go func() {
		time.Sleep(200 * time.Millisecond)
		s.mu.Lock()
		s.buf.WriteString("refused: may also connect as a client\n")
		s.mu.Unlock()
		close(s.drained)
	}()
	got, at := s.waitFor(t, 0, time.Minute, "may also connect as a client")
	if got != "may also connect as a client" || at != len("refused: may also connect as a client") {
		t.Fatalf("waitFor = %q, %d", got, at)
	}
}

// A console that exits without the prompt still fails, naming the exit.
func TestWaitForFailsAnExitWithoutThePrompt(t *testing.T) {
	if os.Getenv("LOCKSQL_WAITFOR_CHILD") == "1" {
		s := &screen{done: make(chan struct{}), drained: make(chan struct{})}
		s.buf.WriteString("something else\n")
		close(s.done)
		close(s.drained)
		s.waitFor(t, 0, time.Minute, "may also connect as a client")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestWaitForFailsAnExitWithoutThePrompt$", "-test.v")
	cmd.Env = append(os.Environ(), "LOCKSQL_WAITFOR_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "exited (<nil>) before") {
		t.Fatalf("want a failure naming the exit: %v\n%s", err, out)
	}
}

// The prompt that comes first wins, and from skips what was already seen.
func TestFind(t *testing.T) {
	out := "a Listening… b Apply these changes? [y/N] "
	if got, at := find(out, 0, []string{"Apply these changes? [y/N] ", "Listening…"}); got != "Listening…" || at != strings.Index(out, " b") {
		t.Errorf("find = %q, %d", got, at)
	}
	if got, at := find(out, strings.Index(out, " b"), []string{"Listening…", "Apply these changes? [y/N] "}); got != "Apply these changes? [y/N] " || at != len(out) {
		t.Errorf("find from = %q, %d", got, at)
	}
	if got, at := find(out, 0, []string{"nope"}); got != "" || at != -1 {
		t.Errorf("find none = %q, %d", got, at)
	}
}
