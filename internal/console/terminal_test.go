package console

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// pipeTerminal is a Terminal fed through a pipe: not a tty, so no termios
// call, but the same line editor and key decoding. echo is turned on to
// check what the editor writes.
func pipeTerminal(t *testing.T) (*Terminal, *os.File, *lockedBuffer) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close(); r.Close() })
	out := &lockedBuffer{}
	term := NewTerminal(r, out)
	term.echo = true
	return term, w, out
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestTerminalEditsLines(t *testing.T) {
	term, w, out := pipeTerminal(t)
	lines := term.Lines()
	// "abc", backspace, "d", Ctrl-W removes "abd", "héllo wörld", Enter.
	w.WriteString("abc\x7fd\x17héllo wörld\r")
	select {
	case l := <-lines:
		if l != "héllo wörld" {
			t.Errorf("line %q", l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no line")
	}
	// Ctrl-U clears the line; Tab and arrows are ignored.
	w.WriteString("junk\x15\t\x1b[A:status\n")
	if l := <-lines; l != ":status" {
		t.Errorf("line %q", l)
	}
	if o := out.String(); !strings.Contains(o, "abc\b \bd\b \b\b \b\b \bhéllo wörld\n") {
		t.Errorf("echo %q", o)
	}
	// Ctrl-D on an empty line ends the input.
	w.WriteString("\x04")
	if _, ok := <-lines; ok {
		t.Error("input not closed")
	}
}

func TestTerminalKeys(t *testing.T) {
	term, w, _ := pipeTerminal(t)
	keys := term.Keys()
	w.WriteString("\x1b[Z\x0f\x1bOP")
	for _, want := range []Key{KeyShiftTab, KeyCtrlO} {
		select {
		case k := <-keys:
			if k != want {
				t.Errorf("key %v, want %v", k, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no key")
		}
	}
	select {
	case k := <-keys:
		t.Errorf("SS3 sequence delivered a key: %v", k)
	case <-time.After(50 * time.Millisecond):
	}
}

// A key pressed while a prompt waits goes to the handler; the prompt then
// takes the line.
func TestTerminalAskDispatchesKeys(t *testing.T) {
	term, w, out := pipeTerminal(t)
	var got []Key
	term.SetKeyHandler(func(k Key) { got = append(got, k) })
	done := make(chan string, 1)
	go func() {
		l, ok := term.Ask(context.Background(), "Approve? ", 5*time.Second)
		if !ok {
			l = "(none)"
		}
		done <- l
	}()
	time.Sleep(50 * time.Millisecond) // past discard's flush delay
	w.WriteString("\x1b[Zy\n")
	if l := <-done; l != "y" {
		t.Errorf("answer %q", l)
	}
	if len(got) != 1 || got[0] != KeyShiftTab {
		t.Errorf("keys %v", got)
	}
	if !strings.Contains(out.String(), "Approve? y\n") {
		t.Errorf("output %q", out.String())
	}
}

func TestTerminalAskTimeoutAndCancel(t *testing.T) {
	term, _, out := pipeTerminal(t)
	if _, ok := term.Ask(context.Background(), "p: ", 30*time.Millisecond); ok {
		t.Error("answered")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := term.Ask(ctx, "q: ", time.Second); ok {
		t.Error("answered")
	}
	if o := out.String(); !strings.Contains(o, "(no answer)") || !strings.Contains(o, "(cancelled)") {
		t.Errorf("output %q", o)
	}
}

// AskSecret on a started, non-tty terminal reads the line without echo.
func TestTerminalAskSecretNoEcho(t *testing.T) {
	term, w, out := pipeTerminal(t)
	term.Lines() // started
	go func() {
		time.Sleep(50 * time.Millisecond)
		w.WriteString("s3cret\n")
	}()
	term.restore = func() {} // as in cbreak mode: the editor's echo is off
	b, err := term.AskSecret(context.Background(), "Password: ")
	if err != nil || string(b) != "s3cret" {
		t.Fatalf("%q, %v", b, err)
	}
	if o := out.String(); strings.Contains(o, "s3cret") || !strings.HasSuffix(o, "Password: \n") {
		t.Errorf("output %q", o)
	}
}

func TestTerminalStatusNeedsInteractive(t *testing.T) {
	term, _, out := pipeTerminal(t)
	term.SetStatus("x")
	if out.String() != "" {
		t.Errorf("status drawn without a terminal: %q", out.String())
	}
	if term.Width() != 80 {
		t.Errorf("width %d", term.Width())
	}
}

func TestTerminalStatusSequences(t *testing.T) {
	term, _, out := pipeTerminal(t)
	term.restore = func() {}
	term.rows, term.cols = 10, 12
	term.SetStatus("\x1b[1mmode\x1b[0m manual results")
	want := "\n\x1b7\x1b[1;9r\x1b8\x1b[1A" + // region: one row freed, cursor kept
		"\x1b7\x1b[10;1H\x1b[2K\x1b[1mmode\x1b[0m manual\x1b[0m\x1b8" // cut at 11 columns
	if got := out.String(); got != want {
		t.Errorf("status:\n%q\nwant\n%q", got, want)
	}
	term.SetStatus("")
	if got := out.String(); !strings.HasSuffix(got, "\x1b7\x1b[10;1H\x1b[2K\x1b[r\x1b8") {
		t.Errorf("close: %q", got)
	}
}

func TestCutVisible(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		n        int
	}{
		{"abc", "abc\x1b[0m", 5},
		{"abcdef", "abc\x1b[0m", 3},
		{"\x1b[31mabc\x1b[0mdef", "\x1b[31mabc\x1b[0md\x1b[0m", 4},
		{"héllo", "hé\x1b[0m", 2},
	} {
		if got := cutVisible(tc.in, tc.n); got != tc.want {
			t.Errorf("cutVisible(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
