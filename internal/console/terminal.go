package console

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DavidGodefroid/locksql/internal/secrets"
)

// Terminal is the IO of a real console: prompts and messages go to out,
// answers and console commands are read line by line from in, which must
// be the controlling terminal.
//
// One goroutine reads in from the first prompt on, so that the console can
// wait for a request and for a typed command at the same time. Before each
// prompt the kernel's pending input is flushed and the lines already read
// are dropped: type-ahead never answers a prompt.
type Terminal struct {
	in  *os.File
	out io.Writer

	once    sync.Once
	started atomic.Bool
	lines   chan string
}

// NewTerminal returns the IO over in and out (normally os.Stdin and
// os.Stdout).
func NewTerminal(in *os.File, out io.Writer) *Terminal {
	return &Terminal{in: in, out: out, lines: make(chan string, 16)}
}

func (t *Terminal) start() {
	t.once.Do(func() {
		t.started.Store(true)
		go func() {
			r := bufio.NewReader(t.in)
			for {
				line, err := r.ReadString('\n')
				if line != "" {
					t.lines <- strings.TrimRight(line, "\r\n")
				}
				if err != nil {
					close(t.lines)
					return
				}
			}
		}()
	})
}

// Println writes one line.
func (t *Terminal) Println(s string) { fmt.Fprintln(t.out, s) }

// Bell rings the terminal bell.
func (t *Terminal) Bell() { fmt.Fprint(t.out, "\a") }

// Lines delivers the lines typed while no prompt is active.
func (t *Terminal) Lines() <-chan string {
	t.start()
	return t.lines
}

// discard drops pending input: what the terminal holds and what the reader
// already took from it.
func (t *Terminal) discard() {
	drain := func() {
		for {
			select {
			case _, ok := <-t.lines:
				if !ok {
					return
				}
			default:
				return
			}
		}
	}
	drain()
	_ = flushInput(t.in)
	// A line the reader had read just before the flush is not in the
	// channel yet: give it a moment, then drop it too.
	time.Sleep(20 * time.Millisecond)
	drain()
}

// Ask flushes pending input, prints prompt and waits for one line.
func (t *Terminal) Ask(ctx context.Context, prompt string, timeout time.Duration) (string, bool) {
	t.start()
	t.discard()
	fmt.Fprint(t.out, prompt)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case line, ok := <-t.lines:
		if !ok {
			fmt.Fprintln(t.out)
			return "", false
		}
		return line, true
	case <-timer.C:
		fmt.Fprintln(t.out, "(no answer)")
		return "", false
	case <-ctx.Done():
		fmt.Fprintln(t.out, "(cancelled)")
		return "", false
	}
}

// errSecretTimeout is AskSecret's error when no answer comes within
// ApprovalTimeout.
var errSecretTimeout = errors.New("console: no password entered")

// AskSecret reads a line with echo off. Before the reader goroutine runs it
// uses secrets.PromptPassword; afterwards it turns echo off on in itself.
func (t *Terminal) AskSecret(ctx context.Context, prompt string) ([]byte, error) {
	if !t.started.Load() {
		return secrets.PromptPassword(prompt)
	}
	restore, err := echoOff(t.in)
	if err != nil {
		return nil, fmt.Errorf("console: cannot turn the terminal echo off: %w", err)
	}
	defer restore()
	t.discard()
	fmt.Fprint(t.out, prompt)
	defer fmt.Fprintln(t.out)
	timer := time.NewTimer(ApprovalTimeout)
	defer timer.Stop()
	select {
	case line, ok := <-t.lines:
		if !ok {
			return nil, secrets.ErrNoTerminal
		}
		return []byte(line), nil
	case <-timer.C:
		return nil, errSecretTimeout
	case <-ctx.Done():
		return nil, secrets.ErrInterrupted
	}
}
