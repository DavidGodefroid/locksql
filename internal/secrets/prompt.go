package secrets

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"golang.org/x/term"
)

// ErrNoTerminal means there is no controlling terminal to prompt on.
var ErrNoTerminal = errors.New("secrets: no terminal to prompt for the password")

// ErrInterrupted means the human pressed Ctrl-C at the prompt.
var ErrInterrupted = errors.New("secrets: password prompt interrupted")

// openTerminal opens the controlling terminal: /dev/tty on Unix, the
// console input and output buffers on Windows. Using the terminal rather
// than stdin/stdout keeps the prompt on the human's screen even when the
// standard streams are redirected.
func openTerminal() (in, out *os.File, err error) {
	if runtime.GOOS == "windows" {
		in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, nil, ErrNoTerminal
		}
		out, err = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			in.Close()
			return nil, nil, ErrNoTerminal
		}
	} else {
		in, err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return nil, nil, ErrNoTerminal
		}
		out = in
	}
	if !term.IsTerminal(int(in.Fd())) {
		closeTerminal(in, out)
		return nil, nil, ErrNoTerminal
	}
	return in, out, nil
}

func closeTerminal(in, out *os.File) {
	if out != in {
		out.Close()
	}
	in.Close()
}

func hasTerminal() bool {
	in, out, err := openTerminal()
	if err != nil {
		return false
	}
	closeTerminal(in, out)
	return true
}

// PromptPassword prints prompt on the controlling terminal and reads a line
// with echo off. Ctrl-C restores the terminal and returns ErrInterrupted.
func PromptPassword(prompt string) ([]byte, error) {
	in, out, err := openTerminal()
	if err != nil {
		return nil, err
	}
	fd := int(in.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		closeTerminal(in, out)
		return nil, ErrNoTerminal
	}
	if _, err := fmt.Fprint(out, prompt); err != nil {
		closeTerminal(in, out)
		return nil, ErrNoTerminal
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := term.ReadPassword(fd)
		done <- result{b, err}
	}()
	select {
	case r := <-done:
		fmt.Fprintln(out)
		closeTerminal(in, out)
		if r.err != nil {
			Wipe(r.b)
			return nil, fmt.Errorf("secrets: reading the password: %w", r.err)
		}
		return trimLineEnd(r.b), nil
	case <-sig:
		// The read goroutine stays blocked on the terminal; the terminal is
		// restored and the files are left open for it.
		_ = term.Restore(fd, state)
		fmt.Fprintln(out)
		return nil, ErrInterrupted
	}
}

// trimLineEnd drops a trailing CR and/or LF that some terminals leave.
func trimLineEnd(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
