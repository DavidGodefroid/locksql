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
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockkit/secrets"
)

// Key is a control key the human pressed, outside a line. Keys reach the
// console only from its own terminal: no client can send one.
type Key int

const (
	// KeyShiftTab is back-tab (ESC [ Z, the same on Linux and macOS): it
	// cycles the approval mode.
	KeyShiftTab Key = iota + 1
	// KeyCtrlO toggles the clear results.
	KeyCtrlO
)

// Terminal is the IO of a real console: prompts and messages go to out,
// answers and console commands are read from in, which must be the
// controlling terminal.
//
// Interactive puts the terminal in cbreak mode: the Terminal does the line
// editing itself, so that it also sees the control keys (Shift+Tab, Ctrl-O)
// and can keep a status line on the bottom row, above which the output
// scrolls. One goroutine reads in from the first prompt on, so that the
// console can wait for a request and for a typed command at the same time.
// Before each prompt the kernel's pending input is flushed and the lines
// already read are dropped: type-ahead never answers a prompt.
type Terminal struct {
	in  *os.File
	out io.Writer
	fd  int // -1 when in is not a terminal

	once    sync.Once
	started atomic.Bool
	lines   chan string
	keys    chan Key
	// onKey handles a key pressed while a prompt waits; it runs on the
	// goroutine that asked.
	onKey func(Key)

	// mu guards the output, the line being typed and the screen state.
	mu      sync.Mutex
	buf     []rune
	echo    bool   // echo the typed runes (cbreak mode, no secret prompt)
	restore func() // puts the terminal back in its previous mode
	status  string
	rows    int
	cols    int
	region  bool // the scroll region keeps the bottom row for the status
}

// NewTerminal returns the IO over in and out (normally os.Stdin and
// os.Stdout).
func NewTerminal(in *os.File, out io.Writer) *Terminal {
	t := &Terminal{in: in, out: out, fd: -1, lines: make(chan string, 16), keys: make(chan Key, 16), rows: 24, cols: 80}
	if in != nil && term.IsTerminal(int(in.Fd())) {
		t.fd = int(in.Fd())
	}
	return t
}

// Interactive puts the terminal in cbreak mode (no line discipline, no
// kernel echo; signals and output post-processing kept) and starts
// reading it. Restore undoes it. An input that is not a terminal (a test
// pipe) stays as it is: lines are read, keys and the status line are off.
func (t *Terminal) Interactive() error {
	if t.fd < 0 {
		t.start()
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.restore != nil {
		return nil
	}
	restore, err := cbreak(t.fd)
	if err != nil {
		return fmt.Errorf("console: terminal mode: %w", err)
	}
	t.restore = restore
	t.echo = true
	t.size()
	go t.watchSize()
	t.start()
	return nil
}

// Restore ends the status line and puts the terminal back in the mode it
// had before Interactive.
func (t *Terminal) Restore() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.region {
		t.closeRegion()
	}
	if t.restore != nil {
		t.restore()
		t.restore = nil
		t.echo = false
	}
}

// size reads the terminal size; mu held.
func (t *Terminal) size() {
	if w, h, err := term.GetSize(t.fd); err == nil && w > 0 && h > 1 {
		t.cols, t.rows = w, h
	}
}

// watchSize re-applies the scroll region and redraws the status when the
// terminal is resized.
func (t *Terminal) watchSize() {
	sig := make(chan os.Signal, 1)
	stop := notifyResize(sig)
	defer stop()
	for range sig {
		t.mu.Lock()
		if t.restore == nil {
			t.mu.Unlock()
			return
		}
		if t.region {
			t.closeRegion()
		}
		t.size()
		if t.status != "" {
			t.openRegion()
			t.drawStatus()
		}
		t.mu.Unlock()
	}
}

func (t *Terminal) start() {
	t.once.Do(func() {
		t.started.Store(true)
		go t.read()
	})
}

// read is the reader goroutine: it edits the line being typed and
// delivers complete lines and control keys.
func (t *Terminal) read() {
	r := bufio.NewReader(t.in)
	for {
		b, err := r.ReadByte()
		if err != nil {
			close(t.lines)
			return
		}
		if !t.handle(b, r) {
			close(t.lines)
			return
		}
	}
}

// handle processes one input byte (reading the rest of a sequence from
// r) and reports whether reading goes on.
func (t *Terminal) handle(b byte, r *bufio.Reader) bool {
	switch {
	case b == '\n' || b == '\r':
		t.mu.Lock()
		line := string(t.buf)
		t.buf = t.buf[:0]
		if t.echo {
			fmt.Fprint(t.out, "\n")
		}
		t.mu.Unlock()
		t.lines <- line
	case b == 0x7f || b == 0x08: // backspace
		t.erase(1)
	case b == 0x15: // Ctrl-U: the whole line
		t.erase(-1)
	case b == 0x17: // Ctrl-W: the last word
		t.mu.Lock()
		n := 0
		for i := len(t.buf) - 1; i >= 0 && t.buf[i] == ' '; i-- {
			n++
		}
		for i := len(t.buf) - 1 - n; i >= 0 && t.buf[i] != ' '; i-- {
			n++
		}
		t.mu.Unlock()
		t.erase(n)
	case b == 0x04: // Ctrl-D on an empty line: end of input
		t.mu.Lock()
		empty := len(t.buf) == 0
		t.mu.Unlock()
		if empty {
			return false
		}
	case b == 0x0f:
		t.key(KeyCtrlO)
	case b == 0x1b:
		t.escape(r)
	case b < 0x20:
		// Other control bytes (Tab, Ctrl-C arrives as a signal) are ignored.
	default:
		t.insert(b, r)
	}
	return true
}

// escape reads the rest of an escape sequence and delivers the keys the
// console knows; other sequences (arrows, function keys) are dropped.
func (t *Terminal) escape(r *bufio.Reader) {
	next, err := r.ReadByte()
	if err != nil {
		return
	}
	switch next {
	case '[':
		var params []byte
		for {
			c, err := r.ReadByte()
			if err != nil {
				return
			}
			if c >= 0x40 && c <= 0x7e {
				if c == 'Z' && len(params) == 0 {
					t.key(KeyShiftTab)
				}
				return
			}
			params = append(params, c)
		}
	case 'O': // SS3: one final byte
		_, _ = r.ReadByte()
	}
}

// insert decodes one UTF-8 rune starting with b, appends it to the line
// and echoes it.
func (t *Terminal) insert(b byte, r *bufio.Reader) {
	seq := []byte{b}
	for !utf8.FullRune(seq) && len(seq) < utf8.UTFMax {
		c, err := r.ReadByte()
		if err != nil {
			return
		}
		seq = append(seq, c)
	}
	ru, _ := utf8.DecodeRune(seq)
	if ru == utf8.RuneError {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, ru)
	if t.echo {
		fmt.Fprint(t.out, string(ru))
	}
}

// erase removes the last n runes of the line (all of them for n < 0) and
// their echo.
func (t *Terminal) erase(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n < 0 || n > len(t.buf) {
		n = len(t.buf)
	}
	t.buf = t.buf[:len(t.buf)-n]
	if t.echo && n > 0 {
		fmt.Fprint(t.out, strings.Repeat("\b \b", n))
	}
}

// key delivers a control key; keys nobody collects are dropped.
func (t *Terminal) key(k Key) {
	select {
	case t.keys <- k:
	default:
	}
}

// Println writes one line.
func (t *Terminal) Println(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintln(t.out, s)
}

// print writes a prompt, without a newline.
func (t *Terminal) print(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprint(t.out, s)
}

// Bell rings the terminal bell.
func (t *Terminal) Bell() { t.print("\a") }

// Width is the terminal width in columns (80 when unknown).
func (t *Terminal) Width() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cols
}

// Lines delivers the lines typed while no prompt is active.
func (t *Terminal) Lines() <-chan string {
	t.start()
	return t.lines
}

// Keys delivers the control keys pressed while no prompt is active.
func (t *Terminal) Keys() <-chan Key {
	t.start()
	return t.keys
}

// SetKeyHandler sets the function that handles a control key pressed while
// a prompt waits. It runs on the goroutine that asked.
func (t *Terminal) SetKeyHandler(f func(Key)) { t.onKey = f }

// SetStatus shows s on the bottom row of the terminal, above which the
// output scrolls; "" removes the row. Nothing happens before Interactive.
func (t *Terminal) SetStatus(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s == t.status {
		return
	}
	t.status = s
	if t.restore == nil {
		return
	}
	switch {
	case s == "" && t.region:
		t.closeRegion()
	case s != "":
		if !t.region {
			t.openRegion()
		}
		t.drawStatus()
	}
}

// openRegion frees the bottom row and confines scrolling to the rows
// above it: one newline makes room (the cursor keeps its line), then the
// scroll region (DECSTBM, which homes the cursor: it is saved and restored
// around it) excludes the last row. mu held.
func (t *Terminal) openRegion() {
	fmt.Fprintf(t.out, "\n\x1b7\x1b[1;%dr\x1b8\x1b[1A", t.rows-1)
	t.region = true
}

// closeRegion clears the status row and lets the whole screen scroll
// again. mu held.
func (t *Terminal) closeRegion() {
	fmt.Fprintf(t.out, "\x1b7\x1b[%d;1H\x1b[2K\x1b[r\x1b8", t.rows)
	t.region = false
}

// drawStatus paints the status row and puts the cursor back. The text is
// cut before the last column, where a wrap would scroll. mu held.
func (t *Terminal) drawStatus() {
	fmt.Fprintf(t.out, "\x1b7\x1b[%d;1H\x1b[2K%s\x1b8", t.rows, cutVisible(t.status, t.cols-1))
}

// cutVisible cuts s to n visible columns, ANSI escapes not counted, and
// ends it with a reset.
func cutVisible(s string, n int) string {
	var b strings.Builder
	width := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
					j++
				}
				if j < len(s) {
					j++
				}
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if width+1 > n {
			break
		}
		b.WriteRune(r)
		width++
		i += size
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

// discard drops pending input: what the terminal holds, what the reader
// already took from it and the line being typed.
func (t *Terminal) discard() {
	drain := func() {
		for {
			select {
			case _, ok := <-t.lines:
				if !ok {
					return
				}
			case <-t.keys:
			default:
				return
			}
		}
	}
	drain()
	if t.fd >= 0 {
		_ = flushInput(t.in)
	}
	// A line the reader had read just before the flush is not in the
	// channel yet: give it a moment, then drop it too.
	time.Sleep(20 * time.Millisecond)
	drain()
	t.erase(-1)
}

// wait waits for one line, dispatching the control keys pressed meanwhile.
// It returns false when no line came within timeout, when ctx ended or
// when the input is closed.
func (t *Terminal) wait(ctx context.Context, timeout time.Duration) (string, bool, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-t.lines:
			if !ok {
				return "", false, io.EOF
			}
			return line, true, nil
		case k := <-t.keys:
			if t.onKey != nil {
				t.onKey(k)
			}
		case <-timer.C:
			return "", false, errTimeout
		case <-ctx.Done():
			return "", false, ctx.Err()
		}
	}
}

var errTimeout = errors.New("timeout")

// Ask flushes pending input, prints prompt and waits for one line.
func (t *Terminal) Ask(ctx context.Context, prompt string, timeout time.Duration) (string, bool) {
	t.start()
	t.discard()
	t.print(prompt)
	line, ok, err := t.wait(ctx, timeout)
	switch {
	case ok:
		return line, true
	case errors.Is(err, io.EOF):
		t.Println("")
	case errors.Is(err, errTimeout):
		t.Println("(no answer)")
	default:
		t.Println("(cancelled)")
	}
	return "", false
}

// errSecretTimeout is AskSecret's error when no answer comes within
// ApprovalTimeout.
var errSecretTimeout = errors.New("console: no password entered")

// AskSecret reads a line with echo off. Before the reader goroutine runs it
// uses secrets.PromptPassword; in cbreak mode it stops echoing itself;
// otherwise it turns the kernel echo off on in.
func (t *Terminal) AskSecret(ctx context.Context, prompt string) ([]byte, error) {
	if !t.started.Load() {
		return secrets.PromptPassword(prompt)
	}
	t.mu.Lock()
	interactive := t.restore != nil
	if interactive {
		t.echo = false
	}
	t.mu.Unlock()
	if interactive {
		defer func() {
			t.mu.Lock()
			t.echo = true
			t.mu.Unlock()
		}()
	} else if t.fd >= 0 {
		restore, err := echoOff(t.in)
		if err != nil {
			return nil, fmt.Errorf("console: cannot turn the terminal echo off: %w", err)
		}
		defer restore()
	}
	t.discard()
	t.print(prompt)
	defer t.Println("")
	line, ok, err := t.wait(ctx, ApprovalTimeout)
	switch {
	case ok:
		return []byte(line), nil
	case errors.Is(err, io.EOF):
		return nil, secrets.ErrNoTerminal
	case errors.Is(err, errTimeout):
		return nil, errSecretTimeout
	default:
		return nil, secrets.ErrInterrupted
	}
}
