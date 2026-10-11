package engine

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCapText(t *testing.T) {
	short := []byte("hello")
	if s, cut := CapText(short); s != "hello" || cut {
		t.Errorf("CapText(short) = %q, %v", s, cut)
	}
	exact := bytes.Repeat([]byte("a"), MaxCellBytes)
	if s, cut := CapText(exact); len(s) != MaxCellBytes || cut {
		t.Errorf("a value of MaxCellBytes is cut (%d, %v)", len(s), cut)
	}
	// A huge number: the cut retreats over the digits it splits.
	digits := bytes.Repeat([]byte("1234567890"), 1<<20)
	s, cut := CapText(digits)
	if !cut || len(s) > MaxCellBytes || !strings.HasSuffix(s, "…") {
		t.Fatalf("CapText(10 MB) = %d bytes, cut %v", len(s), cut)
	}
	// Text with separators: the partial word at the cut is dropped.
	words := []byte(strings.Repeat("ab é jean@example.com ", 1<<16))
	s, cut = CapText(words)
	if !cut || len(s) > MaxCellBytes || !utf8.ValidString(s) {
		t.Fatalf("CapText(words) = %d bytes, cut %v, valid %v", len(s), cut, utf8.ValidString(s))
	}
	tail := strings.TrimSuffix(s, "…")
	if !strings.HasSuffix(tail, " ") && !strings.HasSuffix(tail, "é") {
		t.Errorf("the cut keeps a partial value: ...%q", tail[len(tail)-30:])
	}
}

func TestCapBytes(t *testing.T) {
	b := bytes.Repeat([]byte{1}, MaxCellBytes+10)
	got, cut := CapBytes(b)
	if !cut || len(got) != MaxCellBytes {
		t.Fatalf("CapBytes = %d bytes, cut %v", len(got), cut)
	}
	got[0] = 9
	if b[0] != 1 {
		t.Error("CapBytes aliases its input")
	}
	if got, cut := CapBytes([]byte{1, 2}); cut || len(got) != 2 {
		t.Errorf("CapBytes(short) = %v, %v", got, cut)
	}
}

func TestResultCut(t *testing.T) {
	var r Result
	r.MarkCut(2, 1)
	if !r.IsCut(2, 1) || r.IsCut(1, 2) {
		t.Errorf("CutCells = %v", r.CutCells)
	}
}
