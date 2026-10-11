package postgres

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// keepBytes is what capReader keeps of a DataRow column: one byte more than
// engine.MaxCellBytes, so that value() knows a value of that length was
// cut (every longer value arrives with exactly that length).
const keepBytes = engine.MaxCellBytes + 1

// capReader sits between the connection and pgx's protocol reader (see
// connConfig, BuildFrontend). It passes every backend message through,
// except that each column of a DataRow is cut to keepBytes while it is read:
// the rest of the column is read from the connection and dropped, so a
// value of hundreds of megabytes (a numeric power, jsonb_pretty) never
// reaches memory whole. The connection itself stays the *tls.Conn pgx made,
// which SCRAM channel binding needs.
//
// A DataRow's length comes before its columns, so the cut row is held until
// its last column is read: at most its column count times keepBytes.
// Every other message streams through.
type capReader struct {
	r   io.Reader
	buf []byte // read from r, not yet parsed
	out []byte // parsed, ready for pgx
	err error  // the error of r, returned once out is drained

	hdr  [5]byte // the message header being read
	nhdr int
	left int // bytes of the current message body still to come

	// DataRow state.
	row     []byte  // the cut row body being built
	cols    int     // columns still to read; -1 before the column count
	colHdr  [4]byte // the column length being read
	ncolHdr int
	colLeft int // bytes of the current column still to come
	colKeep int // of which still to keep
	inCol   bool
}

func newCapReader(r io.Reader) *capReader { return &capReader{r: r} }

// buffered is the number of bytes the reader holds, for the tests.
func (c *capReader) buffered() int { return len(c.buf) + len(c.out) + len(c.row) }

func (c *capReader) Read(p []byte) (int, error) {
	for len(c.out) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if cap(c.buf) == 0 {
			c.buf = make([]byte, 0, 32<<10)
		}
		n, err := c.r.Read(c.buf[:cap(c.buf)])
		if perr := c.parse(c.buf[:n]); perr != nil {
			c.err = perr
		} else if err != nil {
			c.err = err
		}
	}
	n := copy(p, c.out)
	c.out = c.out[n:]
	if len(c.out) == 0 {
		c.out = nil // let a large passed-through message go
	}
	return n, nil
}

var errBadMessage = errors.New("postgres: malformed message from the server")

// parse consumes b, appending what pgx must see to out.
func (c *capReader) parse(b []byte) error {
	for len(b) > 0 {
		if c.nhdr < 5 { // the message header: type and length
			k := copy(c.hdr[c.nhdr:], b)
			c.nhdr += k
			b = b[k:]
			if c.nhdr < 5 {
				return nil
			}
			size := int(binary.BigEndian.Uint32(c.hdr[1:]))
			if size < 4 {
				return errBadMessage
			}
			c.left = size - 4
			if c.hdr[0] == 'D' {
				c.row, c.cols, c.ncolHdr, c.inCol = c.row[:0], -1, 0, false
			} else {
				c.out = append(c.out, c.hdr[:]...)
			}
			if c.left == 0 {
				if err := c.endMessage(); err != nil {
					return err
				}
			}
			continue
		}
		if c.hdr[0] != 'D' { // pass through
			k := min(c.left, len(b))
			c.out = append(c.out, b[:k]...)
			b, c.left = b[k:], c.left-k
			if c.left == 0 {
				if err := c.endMessage(); err != nil {
					return err
				}
			}
			continue
		}
		k, err := c.dataRow(b[:min(c.left, len(b))])
		if err != nil {
			return err
		}
		b, c.left = b[k:], c.left-k
		if c.left == 0 {
			if err := c.endMessage(); err != nil {
				return err
			}
		}
	}
	return nil
}

// dataRow consumes the start of b, which lies within a DataRow body, and
// returns how much it used.
func (c *capReader) dataRow(b []byte) (int, error) {
	used := 0
	for len(b) > 0 {
		switch {
		case c.cols < 0: // the column count, 2 bytes, read through colHdr
			k := copy(c.colHdr[c.ncolHdr:2], b)
			c.ncolHdr += k
			b, used = b[k:], used+k
			if c.ncolHdr == 2 {
				c.cols = int(binary.BigEndian.Uint16(c.colHdr[:2]))
				c.row = append(c.row, c.colHdr[:2]...)
				c.ncolHdr = 0
			}
		case c.inCol:
			k := min(c.colLeft, len(b))
			keep := min(k, c.colKeep)
			c.row = append(c.row, b[:keep]...)
			c.colKeep -= keep
			c.colLeft -= k
			b, used = b[k:], used+k
			if c.colLeft == 0 {
				c.inCol = false
				c.cols--
			}
		case c.cols == 0:
			return used, errBadMessage // bytes after the last column
		default: // a column length
			k := copy(c.colHdr[c.ncolHdr:], b)
			c.ncolHdr += k
			b, used = b[k:], used+k
			if c.ncolHdr < 4 {
				continue
			}
			c.ncolHdr = 0
			n := int32(binary.BigEndian.Uint32(c.colHdr[:]))
			if n < 0 { // NULL
				c.row = binary.BigEndian.AppendUint32(c.row, uint32(n))
				c.cols--
				continue
			}
			kept := min(int(n), keepBytes)
			c.row = binary.BigEndian.AppendUint32(c.row, uint32(kept))
			c.colLeft, c.colKeep = int(n), kept
			if n > 0 {
				c.inCol = true
			} else {
				c.cols--
			}
		}
	}
	return used, nil
}

// endMessage finishes the message whose body was read: a DataRow is
// emitted with its new length.
func (c *capReader) endMessage() error {
	c.nhdr = 0
	if c.hdr[0] != 'D' {
		return nil
	}
	if c.cols != 0 || c.inCol || c.ncolHdr != 0 {
		return errBadMessage
	}
	c.out = append(c.out, 'D')
	c.out = binary.BigEndian.AppendUint32(c.out, uint32(len(c.row)+4))
	c.out = append(c.out, c.row...)
	if cap(c.row) > 4*keepBytes {
		c.row = nil // do not keep a wide row's buffer
	}
	return nil
}
