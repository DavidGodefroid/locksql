package console

import (
	"strings"
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/render"
)

// Output layout of the console: results as aligned tables under the
// profile's output caps, the status as aligned key/value lines.

const (
	// maxColWidth bounds one column of a console table.
	maxColWidth = 48
	// defaultWidth is the table width when the IO does not know its own.
	defaultWidth = 100
)

// width is the usable width of the console in columns.
func (s *Server) width() int {
	if w, ok := s.cfg.IO.(Sized); ok {
		if n := w.Width(); n > 20 {
			return n
		}
	}
	return defaultWidth
}

// cell is one cell of a console table: its text, whether the client got
// it masked, and the reference it then carries.
type cell struct {
	text   string
	masked bool
	ref    string
}

// display is the cell's visible text: the value, then its reference.
func (c cell) display() string {
	if c.ref != "" {
		return c.text + " ‹" + c.ref + "›"
	}
	return c.text
}

// showTable prints a result in the console, under the profile's output
// caps, so that the human sees the clear values. With masked, the result
// as the client got it, each cell the client got masked is yellow and
// followed by its reference name when it has one. The audit log never
// holds row data.
func (s *Server) showTable(title string, res engine.Result, masked *engine.Result) {
	t := render.TSVTable(res, s.profile.Limits)
	var m render.Table
	if masked != nil {
		m = render.TSVTable(*masked, s.profile.Limits)
	}
	rows := make([][]cell, len(t.Rows))
	for i, r := range t.Rows {
		rows[i] = make([]cell, len(r))
		for j, v := range r {
			c := cell{text: safeText(v, false)}
			if i < len(m.Rows) && j < len(m.Rows[i]) && m.Rows[i][j] != v {
				c.masked = true
				if mc := m.Rows[i][j]; strings.HasPrefix(mc, "<redacted:") && strings.HasSuffix(mc, ">") {
					c.ref = safeText(strings.TrimSuffix(strings.TrimPrefix(mc, "<redacted:"), ">"), false)
				}
			}
			rows[i][j] = c
		}
	}
	header := make([]string, len(t.Header))
	for j, h := range t.Header {
		header[j] = safeText(h, false)
	}
	s.println(title)
	for _, line := range layoutTable(header, rows, s.width()-2) {
		s.println("  " + line)
	}
	for _, f := range t.Footer {
		s.println("  " + paint.Dim(safeText(f, false)))
	}
}

// layoutTable aligns a table in at most width columns: each column takes
// the width of its widest cell, capped, and the widest columns are
// narrowed first when the table does not fit. A masked column's header is
// yellow, a masked cell yellow with its reference dimmed.
func layoutTable(header []string, rows [][]cell, width int) []string {
	n := len(header)
	widths := make([]int, n)
	maskedCol := make([]bool, n)
	for j, h := range header {
		widths[j] = min(runeLen(h), maxColWidth)
	}
	for _, r := range rows {
		for j, c := range r {
			if j >= n {
				continue
			}
			widths[j] = max(widths[j], min(runeLen(c.display()), maxColWidth))
			if c.masked {
				maskedCol[j] = true
			}
		}
	}
	fit(widths, width-3*(n-1))

	pad := func(text string, painted string, w int) string {
		l := runeLen(text)
		if l > w {
			text = cutRunes(text, w)
			painted = cutRunes(painted, w)
			l = w
		}
		if painted == "" {
			painted = text
		}
		return painted + strings.Repeat(" ", w-l)
	}
	var out []string
	cells := make([]string, n)
	for j, h := range header {
		painted := ""
		if maskedCol[j] {
			painted = paint.Yellow(h)
		}
		cells[j] = pad(h, painted, widths[j])
	}
	out = append(out, strings.TrimRight(strings.Join(cells, " │ "), " "))
	rules := make([]string, n)
	for j, w := range widths {
		rules[j] = strings.Repeat("─", w)
	}
	out = append(out, paint.Dim(strings.Join(rules, "─┼─")))
	for _, r := range rows {
		for j := range cells {
			cells[j] = strings.Repeat(" ", widths[j])
			if j >= len(r) {
				continue
			}
			c := r[j]
			painted := ""
			if c.masked {
				painted = paint.Yellow(c.text)
				if c.ref != "" {
					painted += " " + paint.Dim("‹"+c.ref+"›")
				}
			}
			cells[j] = pad(c.display(), painted, widths[j])
		}
		out = append(out, strings.TrimRight(strings.Join(cells, " │ "), " "))
	}
	return out
}

// fit narrows the widest columns until their sum is at most total, never
// below 4 columns each.
func fit(widths []int, total int) {
	sum := 0
	for _, w := range widths {
		sum += w
	}
	for sum > total {
		widest := -1
		for j, w := range widths {
			if w > 4 && (widest < 0 || w > widths[widest]) {
				widest = j
			}
		}
		if widest < 0 {
			return
		}
		widths[widest]--
		sum--
	}
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

// cutRunes cuts s to w runes, ending it with "…" when it was cut. Escape
// sequences are kept whole and not counted.
func cutRunes(s string, w int) string {
	if runeLen(s) <= w || w < 1 {
		return s
	}
	var b strings.Builder
	count := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			// Escapes are kept, those after the cut included (a reset).
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
		i += size
		switch {
		case count < w-1:
			b.WriteRune(r)
			count++
		case count == w-1:
			b.WriteString("…")
			count++
		}
	}
	return b.String()
}

// keyValues aligns "key  value" lines, keys padded to the longest.
func keyValues(pairs [][2]string) []string {
	w := 0
	for _, p := range pairs {
		w = max(w, runeLen(p[0]))
	}
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = "  " + paint.Dim(p[0]+strings.Repeat(" ", w-runeLen(p[0]))) + "  " + p[1]
	}
	return out
}
