// Package ui holds the look of locksql's human-facing output: the palette
// of the logo, the banner and the status marks. Agent-facing output (the
// client commands, MCP) never goes through it.
package ui

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// ANSI escapes. The brand colours are the 256-colour neighbours of the
// logo's: violet #8B5CF6 (body), lavender #C4B5FD (lid), teal #14B8A6
// (shackle).
const (
	Reset   = "\x1b[0m"
	Bold    = "\x1b[1m"
	Dim     = "\x1b[2m"
	Red     = "\x1b[1;31m"
	Green   = "\x1b[32m"
	Yellow  = "\x1b[33m"
	Violet  = "\x1b[38;5;99m"
	Lilac   = "\x1b[38;5;183m"
	Teal    = "\x1b[38;5;37m"
	Neutral = "\x1b[38;5;245m"
)

// Status marks.
const (
	MarkOK   = "✓"
	MarkWarn = "▲"
	MarkFail = "✗"
	MarkStep = "›"
)

// Tagline is the line under the name.
const Tagline = "Your AI writes the query. You hold the key."

// Painter colours text when On, and returns it unchanged otherwise.
type Painter struct{ On bool }

// For returns a painter that colours output to f when f is a terminal and
// the environment does not opt out (NO_COLOR, TERM=dumb).
func For(f *os.File) Painter {
	return Painter{On: term.IsTerminal(int(f.Fd())) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"}
}

// Paint wraps s in the escape code when the painter is on.
func (p Painter) Paint(code, s string) string {
	if !p.On || code == "" || s == "" {
		return s
	}
	return code + s + Reset
}

func (p Painter) Bold(s string) string   { return p.Paint(Bold, s) }
func (p Painter) Dim(s string) string    { return p.Paint(Dim, s) }
func (p Painter) Red(s string) string    { return p.Paint(Red, s) }
func (p Painter) Green(s string) string  { return p.Paint(Green, s) }
func (p Painter) Yellow(s string) string { return p.Paint(Yellow, s) }
func (p Painter) Brand(s string) string  { return p.Paint(Bold+Violet, s) }
func (p Painter) Accent(s string) string { return p.Paint(Teal, s) }

// OK, Warn and Fail are status lines led by their mark.
func (p Painter) OK(s string) string   { return p.Green(MarkOK) + " " + s }
func (p Painter) Warn(s string) string { return p.Yellow(MarkWarn) + " " + s }
func (p Painter) Fail(s string) string { return p.Red(MarkFail) + " " + s }

// Step is a line that announces what happens next.
func (p Painter) Step(s string) string { return p.Accent(MarkStep) + " " + s }

// Heading is a section title: "── title ───…" padded to width columns.
func (p Painter) Heading(title string, width int) string {
	head := "── " + title + " "
	fill := width - len([]rune(head))
	if fill < 3 {
		fill = 3
	}
	return p.Paint(Neutral, "── ") + p.Bold(title) + " " + p.Paint(Neutral, strings.Repeat("─", fill))
}

// logo is the lock-and-cylinder mark of docs/assets/logo.svg: a shackle
// over a database whose lid is the lock's top, with a keyhole. Each row is
// split in the parts that take a colour: shackle, lid, body, keyhole.
var logo = [][]struct{ code, text string }{
	{{"", "   "}, {Teal, "╭─────╮"}},
	{{"", "   "}, {Teal, "│     │"}},
	{{Lilac, "╭──┴─────┴──╮"}},
	{{Violet, "├───────────┤"}},
	{{Violet, "│     "}, {Bold, "●"}, {Violet, "     │"}},
	{{Violet, "│     "}, {Bold, "▼"}, {Violet, "     │"}},
	{{Violet, "╰───────────╯"}},
}

// logoWidth is the width of every logo row, in columns.
const logoWidth = 13

// Banner is the logo with the name, the version, the tagline and up to
// two lines of context beside it, indented by two columns.
func (p Painter) Banner(version string, context ...string) string {
	side := make([]string, len(logo))
	side[2] = p.Brand("locksql") + "  " + p.Dim(version)
	words := strings.SplitAfter(Tagline, ". ")
	side[3] = strings.TrimSpace(words[0])
	if len(words) > 1 {
		side[4] = strings.TrimSpace(words[1])
	}
	for i, c := range context {
		if 5+i < len(side) {
			side[5+i] = p.Dim(c)
		}
	}
	var b strings.Builder
	b.WriteByte('\n')
	for i, row := range logo {
		b.WriteString("  ")
		n := 0
		for _, part := range row {
			b.WriteString(p.Paint(part.code, part.text))
			n += len([]rune(part.text))
		}
		if side[i] != "" {
			b.WriteString(strings.Repeat(" ", logoWidth-n+5))
			b.WriteString(side[i])
		}
		b.WriteByte('\n')
	}
	return b.String()
}
