package engine

import (
	"strings"
	"unicode/utf8"
)

// MaxCellBytes is the most an engine keeps of one cell value. The engines
// apply it while reading, before a value is copied or converted (PostgreSQL
// on the wire, see the postgres capReader), so that a value of hundreds of
// megabytes built by the server (a numeric power, jsonb_pretty) never
// costs the console more. It equals the scan limit of the PII detectors:
// what is kept is what they read, and the renderer shows far less
// (max_cell_chars).
const MaxCellBytes = 64 << 10

// CutMark ends a text value that was cut.
const CutMark = "…"

// cutTail is how far back a cut retreats over value-like characters, so that
// a value split by the cut (a partial number or address) is dropped whole.
const cutTail = 64

// valueChars may belong to a value the PII detectors recognise.
const valueChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@._%+-/() "

// CutAt cuts s, which must be longer than n bytes, to at most n bytes
// followed by CutMark: at a rune boundary, then back over up to cutTail
// value-like characters, so that a value the cut splits (a partial e-mail
// address or number, which no detector would recognise) is dropped
// rather than shown in part.
func CutAt(s string, n int) string {
	end := n
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	for back := 0; back < cutTail && end > 0 && strings.IndexByte(valueChars, s[end-1]) >= 0; back++ {
		end--
	}
	return s[:end] + CutMark
}

// CapText is the text of a value: b as is when it fits MaxCellBytes, else
// cut to at most MaxCellBytes bytes, CutMark included, and cut true. It
// copies no more of b than it keeps.
func CapText(b []byte) (s string, cut bool) {
	if len(b) <= MaxCellBytes {
		return string(b), false
	}
	n := MaxCellBytes - len(CutMark)
	return CutAt(string(b[:n+1]), n), true
}

// CapBytes is a copy of a binary value, cut to MaxCellBytes bytes.
func CapBytes(b []byte) (out []byte, cut bool) {
	if len(b) > MaxCellBytes {
		return append([]byte{}, b[:MaxCellBytes]...), true
	}
	return append([]byte{}, b...), false
}

// MarkCut records that the engine cut cell (row, col) at MaxCellBytes.
func (r *Result) MarkCut(row, col int) {
	r.CutCells = append(r.CutCells, [2]int{row, col})
}

// CutSet is CutCells as a set, for lookups over a whole result.
func (r *Result) CutSet() map[[2]int]bool {
	set := make(map[[2]int]bool, len(r.CutCells))
	for _, c := range r.CutCells {
		set[c] = true
	}
	return set
}

// IsCut reports whether the engine cut cell (row, col).
func (r *Result) IsCut(row, col int) bool {
	for _, c := range r.CutCells {
		if c[0] == row && c[1] == col {
			return true
		}
	}
	return false
}
