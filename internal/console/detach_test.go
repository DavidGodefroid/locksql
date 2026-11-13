package console

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// The detach line is lox's, word for word (lockhub cmd/lox/attach.go
// detachLine): `lox attach` prints it once, the console repeats it.
func TestDetachLineIsLoxs(t *testing.T) {
	const lox = "Ctrl-P Ctrl-Q detaches (the console keeps running) · Ctrl-C stops it · closing this terminal only detaches"
	if DetachLine != lox {
		t.Fatalf("DetachLine = %q, want lox's %q", DetachLine, lox)
	}
}

// The Ready box shows the detach keys first, before any Ctrl-C, and no
// longer says that Ctrl-C ends the session.
func TestReadyLinesShowDetachFirst(t *testing.T) {
	r := strings.Join(readyLines("/run/x.sock", "", false), "\n")
	d := strings.Index(r, "Ctrl-P Ctrl-Q detaches")
	if d < 0 {
		t.Fatalf("Ready block lacks the detach line: %q", r)
	}
	if c := strings.Index(r, "Ctrl-C"); c < d {
		t.Errorf("Ctrl-C shown before the detach keys: %q", r)
	}
	if strings.Contains(r, "Ctrl-C ends the session") {
		t.Errorf("Ready block still says Ctrl-C ends the session: %q", r)
	}
	if !strings.Contains(r, DetachLine) {
		t.Errorf("detach line not lox's wording: %q", r)
	}
}

// askOnce asks one question on io, its input already closed: the prompt is
// printed, no answer comes.
func askOnce(t *testing.T, io IO, secret bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if secret {
		_, _ = io.AskSecret(ctx, "Password for u@h: ")
		return
	}
	io.Ask(ctx, "Apply these changes? [y/N] ", time.Second)
}

func closedTerminal(t *testing.T, out *bytes.Buffer) *Terminal {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	term := NewTerminal(r, out)
	// The reader runs, as once the console serves.
	term.Lines()
	return term
}

// Before the console served, a question is asked as it is: the detach line
// is only for the questions that come after (a reconnect, a loosened
// policy), once lox attach's own line has scrolled away.
func TestDetachHintOnlyAfterServed(t *testing.T) {
	for _, secret := range []bool{false, true} {
		var out bytes.Buffer
		h := withDetachHint(closedTerminal(t, &out))
		askOnce(t, h, secret)
		if strings.Contains(out.String(), "Ctrl-P Ctrl-Q") {
			t.Errorf("secret=%v: hint before the console served: %q", secret, out.String())
		}
		out.Reset()
		h.(*detachHintIO).served()
		askOnce(t, h, secret)
		s := out.String()
		d, p := strings.Index(s, DetachLine), strings.Index(s, "[y/N]")
		if secret {
			p = strings.Index(s, "Password for")
		}
		if d < 0 || p < 0 || d > p {
			t.Errorf("secret=%v: later question not preceded by the detach line: %q", secret, s)
		}
	}
}

// Only the real Terminal is wrapped; it keeps its other faces (status line,
// keys, the question file) behind the wrapper.
func TestDetachHintKeepsTerminalFaces(t *testing.T) {
	var out bytes.Buffer
	h := withDetachHint(closedTerminal(t, &out))
	for name, ok := range map[string]bool{
		"LineSource":       is[LineSource](h),
		"StatusLine":       is[interface{ SetStatus(string) }](h),
		"Sized":            is[Sized](h),
		"QuestionRecorder": is[interface{ SetQuestionFile(string) }](h),
		"ContextPrinter":   is[interface{ PrintContext(string) }](h),
		"Beller":           is[interface{ Bell() }](h),
		"KeySource":        is[interface{ SetKeyHandler(func(Key)) }](h),
	} {
		if !ok {
			t.Errorf("wrapped Terminal lost %s", name)
		}
	}
	var other IO = &detachHintIO{}
	if withDetachHint(other) != other {
		t.Error("an IO that is not a Terminal is wrapped")
	}
}

func is[T any](v any) bool { _, ok := v.(T); return ok }
