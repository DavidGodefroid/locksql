package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ProtocolMajor is exchanged in the hello handshake. A client and a console
// with different majors refuse to talk.
const ProtocolMajor = 1

// MaxMessage is the largest message, excluding the newline, in bytes.
const MaxMessage = 1 << 20

// ErrTooLarge means a message is over MaxMessage. After a read error the
// stream is out of step and the connection must be closed.
var ErrTooLarge = errors.New("ipc: message larger than 1 MiB")

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// Response is a JSON-RPC 2.0 response: Result or Error, never both.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object. Message must never carry a
// secret; the console sanitises it.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }

// Compatible reports whether a peer's protocol major can talk to this one.
func Compatible(major int) bool { return major == ProtocolMajor }

// WriteMsg writes v as one line of JSON. Nothing is written when v encodes
// to more than MaxMessage bytes.
func WriteMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ipc: encode: %w", err)
	}
	if len(b) > MaxMessage {
		return ErrTooLarge
	}
	// json.Marshal escapes control characters, so b holds no newline.
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("ipc: write: %w", err)
	}
	return nil
}

// ReadMsg reads one line of at most MaxMessage bytes (a trailing CR is
// dropped) and decodes it into v. It returns io.EOF at a clean end of
// stream and ErrTooLarge as soon as the line passes the cap, without
// buffering the rest.
func ReadMsg(r *bufio.Reader, v any) error {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > MaxMessage+2 { // content + "\r\n"
			return ErrTooLarge
		}
		line = append(line, chunk...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return io.EOF
			}
			return io.ErrUnexpectedEOF
		}
		return fmt.Errorf("ipc: read: %w", err)
	}
	line = line[:len(line)-1]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	if len(line) > MaxMessage {
		return ErrTooLarge
	}
	if len(line) == 0 {
		return errors.New("ipc: empty message")
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("ipc: decode: %w", err)
	}
	return nil
}
