package console

import (
	"context"
	"sync/atomic"
	"time"
)

// DetachLine is how the human leaves the console's terminal without ending
// it, word for word lox's (lockhub cmd/lox/attach.go detachLine): the
// console runs under `lox run` and is reached with `lox attach`, which
// detaches on Ctrl-P Ctrl-Q.
const DetachLine = "Ctrl-P Ctrl-Q detaches (the console keeps running) · Ctrl-C stops it · closing this terminal only detaches"

// detachHintIO is the console's Terminal that, once the console served,
// prints the detach line before each question it asks: `lox attach` shows
// it once, before the start-up questions, and a later question (a
// reconnect, a loosened policy) comes after it scrolled away (#199). The
// embedded Terminal keeps its other faces (keys, status line, the question
// file).
type detachHintIO struct {
	*Terminal
	on atomic.Bool
}

// withDetachHint wraps io when it is the real Terminal; any other IO (a
// test's) is returned as it is.
func withDetachHint(io IO) IO {
	if t, ok := io.(*Terminal); ok {
		return &detachHintIO{Terminal: t}
	}
	return io
}

// servedOnce turns the hint on for io when withDetachHint wrapped it.
func servedOnce(io IO) {
	if h, ok := io.(*detachHintIO); ok {
		h.served()
	}
}

// served turns the hint on: the console serves.
func (h *detachHintIO) served() { h.on.Store(true) }

func (h *detachHintIO) hint() {
	if h.on.Load() {
		h.Println(paint.Dim(DetachLine))
	}
}

// Ask prints the detach line, once the console served, then asks.
func (h *detachHintIO) Ask(ctx context.Context, prompt string, timeout time.Duration) (string, bool) {
	h.hint()
	return h.Terminal.Ask(ctx, prompt, timeout)
}

// AskSecret prints the detach line, once the console served, then asks.
func (h *detachHintIO) AskSecret(ctx context.Context, prompt string) ([]byte, error) {
	h.hint()
	return h.Terminal.AskSecret(ctx, prompt)
}
