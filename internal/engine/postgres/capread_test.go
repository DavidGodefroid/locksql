package postgres

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// trickle hands out at most n bytes per Read, as a network does.
type trickle struct {
	r io.Reader
	n int
}

func (t *trickle) Read(p []byte) (int, error) {
	if len(p) > t.n {
		p = p[:t.n]
	}
	return t.r.Read(p)
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func encode(t *testing.T, msgs ...pgproto3.BackendMessage) []byte {
	t.Helper()
	var out []byte
	for _, m := range msgs {
		b, err := m.Encode(nil)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return out
}

// TestCapReader checks that a DataRow column longer than the cap reaches
// the driver as its first MaxCellBytes+1 bytes, read in pieces, while the
// other messages and columns pass unchanged.
func TestCapReader(t *testing.T) {
	huge := bytes.Repeat([]byte("9"), 10<<20)
	stream := encode(t,
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("a")}, {Name: []byte("b")}, {Name: []byte("c")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("small"), huge, nil}},
		&pgproto3.DataRow{Values: [][]byte{{}, []byte("x"), bytes.Repeat([]byte("y"), engine.MaxCellBytes+1)}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	for _, chunk := range []int{1, 7, 4096, 1 << 20} {
		f := pgproto3.NewFrontend(newCapReader(&trickle{bytes.NewReader(stream), chunk}), io.Discard)
		var rows [][][]byte
		for {
			m, err := f.Receive()
			if err != nil {
				t.Fatalf("chunk %d: %v", chunk, err)
			}
			if dr, ok := m.(*pgproto3.DataRow); ok {
				var vals [][]byte
				for _, v := range dr.Values {
					if v == nil {
						vals = append(vals, nil)
					} else {
						vals = append(vals, append([]byte{}, v...))
					}
				}
				rows = append(rows, vals)
			}
			if _, ok := m.(*pgproto3.ReadyForQuery); ok {
				break
			}
		}
		if len(rows) != 2 {
			t.Fatalf("chunk %d: %d rows", chunk, len(rows))
		}
		if string(rows[0][0]) != "small" || rows[0][2] != nil || len(rows[1][0]) != 0 || rows[1][0] == nil || string(rows[1][1]) != "x" {
			t.Errorf("chunk %d: short values changed: %q", chunk, rows)
		}
		if len(rows[0][1]) != engine.MaxCellBytes+1 || !bytes.Equal(rows[0][1], huge[:engine.MaxCellBytes+1]) {
			t.Errorf("chunk %d: huge value = %d bytes, want its first %d", chunk, len(rows[0][1]), engine.MaxCellBytes+1)
		}
		if len(rows[1][2]) != engine.MaxCellBytes+1 {
			t.Errorf("chunk %d: cap+1 value = %d bytes", chunk, len(rows[1][2]))
		}
	}
}

// TestCapReaderBoundsMemory checks that the reader never asks for, nor
// keeps, the whole of a huge column: it hands the driver a bounded message
// while the source is read to the end.
func TestCapReaderBoundsMemory(t *testing.T) {
	huge := make([]byte, 64<<20)
	msg := make([]byte, 0, 11+len(huge))
	msg = append(msg, 'D', 0, 0, 0, 0, 0, 1)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(huge)))
	msg = append(msg, huge...)
	binary.BigEndian.PutUint32(msg[1:], uint32(len(msg)-1))
	src := &countingReader{r: bytes.NewReader(msg)}
	cr := newCapReader(src)
	var got bytes.Buffer
	buf := make([]byte, 32<<10)
	for {
		n, err := cr.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if cr.buffered() > 2*engine.MaxCellBytes {
			t.Fatalf("the reader holds %d bytes", cr.buffered())
		}
	}
	if src.n != len(msg) {
		t.Errorf("read %d of %d source bytes", src.n, len(msg))
	}
	if want := 1 + 4 + 2 + 4 + engine.MaxCellBytes + 1; got.Len() != want {
		t.Errorf("the driver got %d bytes, want %d", got.Len(), want)
	}
}

// timeoutOnce fails one Read with a timeout after `after` bytes, as a
// read deadline set by a cancelled statement does; reads go on after it.
type timeoutOnce struct {
	r     io.Reader
	after int
	done  bool
	n     int
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func (t *timeoutOnce) Read(p []byte) (int, error) {
	if !t.done && t.n >= t.after {
		t.done = true
		return 0, timeoutErr{}
	}
	if !t.done && len(p) > t.after-t.n {
		p = p[:t.after-t.n]
	}
	n, err := t.r.Read(p)
	t.n += n
	return n, err
}

// TestCapReaderResumesAfterTimeout checks that a read error such as a
// timeout is returned once and does not end the stream: pgconn keeps a
// connection whose read timed out, and reads the rest of the reply.
func TestCapReaderResumesAfterTimeout(t *testing.T) {
	stream := encode(t,
		&pgproto3.DataRow{Values: [][]byte{bytes.Repeat([]byte("z"), 100)}},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	cr := newCapReader(&timeoutOnce{r: bytes.NewReader(stream), after: 20})
	var got []byte
	buf := make([]byte, 7)
	timeouts := 0
	for {
		n, err := cr.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			timeouts++
			if timeouts > 1 {
				t.Fatalf("error repeated: %v", err)
			}
		}
	}
	if timeouts != 1 || !bytes.Equal(got, stream) {
		t.Errorf("timeouts %d, got %d of %d bytes", timeouts, len(got), len(stream))
	}
}
