package ui

import (
	"strings"
	"testing"
)

func TestPlainPainterWritesNoEscapes(t *testing.T) {
	p := Painter{}
	out := p.Banner("v1.2.3", "profile uat") + p.OK("ok") + p.Heading("Human commands", 40)
	if strings.Contains(out, "\x1b") {
		t.Fatalf("escape in plain output: %q", out)
	}
	for _, want := range []string{"locksql  v1.2.3", "Your AI writes the query.", "You hold the key.", "profile uat", "╰───────────╯", "✓ ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestBannerColumnsLineUp(t *testing.T) {
	lines := strings.Split(strings.Trim(Painter{}.Banner("dev", "a", "b"), "\n"), "\n")
	const col = 2 + logoWidth + 5
	for i, l := range lines {
		r := []rune(l)
		if len([]rune(logo[i][0].text)) == 3 { // shackle rows carry no text
			continue
		}
		if len(r) <= col || r[col-1] != ' ' || r[col] == ' ' {
			t.Errorf("line %d: text does not start at column %d: %q", i, col, l)
		}
	}
}

func TestColouredPainterResets(t *testing.T) {
	if got := (Painter{On: true}).Red("x"); got != Red+"x"+Reset {
		t.Fatalf("Red = %q", got)
	}
	if got := (Painter{On: true}).Red(""); got != "" {
		t.Fatalf("Red(\"\") = %q", got)
	}
}
