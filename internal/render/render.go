// Package render turns a (masked) result into the text an agent sees: TSV
// or JSON, within the profile's row, cell and output caps. It is lockkit's
// table renderer over a locksql result: control and bidirectional
// characters are escaped, invalid UTF-8 is replaced, NULL is "NULL" (null
// in JSON), binary values are "<bytes:N>" and times ISO 8601.
package render

import (
	"fmt"
	"io"

	krender "github.com/DavidGodefroid/lockkit/render"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// Formats.
const (
	FormatTSV  = krender.FormatTSV
	FormatJSON = krender.FormatJSON
)

// Table is the TSV rendering of a result split into cells: the header
// labels, the rows shown and the lines after them (cut marker, row count).
type Table = krender.Cells

// Render writes res to w in format "tsv" (the default when empty) or
// "json". Limits that are zero or negative take the non-production
// defaults. Rows beyond MaxRows are dropped and reported as truncated; rows
// that would push the output past MaxOutputBytes are dropped with a marker.
func Render(w io.Writer, res engine.Result, l config.Limits, format string) error {
	return krender.Render(w, table(res), caps(l), format)
}

// TSVTable is what Render writes in format tsv for a result with columns,
// before the cells are joined.
func TSVTable(res engine.Result, l config.Limits) Table {
	return krender.TSVCells(table(res), caps(l))
}

func table(res engine.Result) krender.Table {
	t := krender.Table{Columns: make([]string, len(res.Columns)), Rows: res.Rows, Truncated: res.Truncated,
		Affected: res.Affected, Cut: res.CutSet()}
	for i, c := range res.Columns {
		t.Columns[i] = c.Label
	}
	return t
}

func caps(l config.Limits) krender.Caps {
	d := config.DefaultLimits(false)
	c := krender.Caps{MaxRows: l.MaxRows, MaxCellChars: l.MaxCellChars, MaxOutputBytes: l.MaxOutputBytes, CutNote: cutCellsNote}
	if c.MaxRows <= 0 {
		c.MaxRows = d.MaxRows
	}
	if c.MaxCellChars <= 0 {
		c.MaxCellChars = d.MaxCellChars
	}
	if c.MaxOutputBytes <= 0 {
		c.MaxOutputBytes = d.MaxOutputBytes
	}
	return c
}

// effective is the limits Render applies (the fuzz test checks the cap).
func effective(l config.Limits) krender.Caps { return caps(l) }

// cutCellsNote tells how many cells were cut: past maxChars characters by
// the renderer, or past engine.MaxCellBytes bytes while they were read.
func cutCellsNote(n, maxChars int) string {
	cells := "cells"
	if n == 1 {
		cells = "cell"
	}
	return fmt.Sprintf("[%d %s cut: a value longer than %d characters (max_cell_chars) or %d bytes ends with …]",
		n, cells, maxChars, engine.MaxCellBytes)
}
