package sqlrefusal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestEveryCodeIsDescribed(t *testing.T) {
	codes := Codes()
	if len(codes) < 10 {
		t.Fatalf("only %d codes", len(codes))
	}
	if !slices.IsSorted(codes) {
		t.Error("Codes is not sorted")
	}
	name := regexp.MustCompile(`^E_[A-Z][A-Z_]*[A-Z]$`)
	for _, c := range codes {
		if !name.MatchString(string(c)) {
			t.Errorf("%s: not an E_UPPER_SNAKE name", c)
		}
		if !c.Known() {
			t.Errorf("%s: not known", c)
		}
		switch c.Retry() {
		case RetryRewrite, RetryAskUser, RetryStop:
		default:
			t.Errorf("%s: retry %q", c, c.Retry())
		}
		if c.Title() == "" || c.Hint() == "" {
			t.Errorf("%s: title or hint missing", c)
		}
	}
	if Code("E_NOPE").Known() || Code("").Known() {
		t.Error("unknown codes reported known")
	}
}

func TestIssueCodesExist(t *testing.T) {
	for _, c := range []Code{UnsupportedSyntax, NoLimit, Cost, KAnon, MaskedFilter} {
		if !c.Known() {
			t.Errorf("%s missing", c)
		}
	}
}

// A retired code stays known, for the audit records that carry it, but is
// no longer listed among the codes a refusal may carry.
func TestRetiredCodeStaysKnown(t *testing.T) {
	if !KAnon.Known() || KAnon.Hint() == "" {
		t.Fatal("E_K_ANON is no longer known")
	}
	if slices.Contains(Codes(), KAnon) {
		t.Fatal("E_K_ANON is listed among the codes a refusal may carry")
	}
}

func TestNewAndError(t *testing.T) {
	e := Newf(NoLimit, "a top-level %s is required", "LIMIT")
	if e.Error() != "a top-level LIMIT is required" || e.Code != NoLimit || e.Pos != -1 {
		t.Fatalf("%+v", e)
	}
	var r *Error
	if !errors.As(fmt.Errorf("wrapped: %w", e), &r) || r != e {
		t.Fatal("errors.As")
	}
	if e.WithHint("x").Hint != "x" {
		t.Fatal("hint")
	}
}

func TestInfoLocatesTheSpan(t *testing.T) {
	src := "  SELECT id\n  FROM users\n  ORDER BY émail LIMIT 5"
	pos := strings.Index(src, "émail")
	e := New(MaskedOrder, "x").At(pos-2, "émail") // positions of the trimmed text
	in := e.Info(src, 2)
	if in.Span == nil || in.Span.Line != 3 || in.Span.Col != 12 || in.Span.Token != "émail" {
		t.Fatalf("%+v", in.Span)
	}
	if in.Code != MaskedOrder || in.Retry != MaskedOrder.Retry() || in.Hint != MaskedOrder.Hint() {
		t.Fatalf("%+v", in)
	}
}

// A token folded by the lexer comes back as the agent wrote it.
func TestInfoKeepsTheSpelling(t *testing.T) {
	in := New(Forbidden, "x").At(7, "SLEEP").Info("SELECT sleep(1)", 0)
	if in.Span == nil || in.Span.Token != "sleep" {
		t.Fatalf("%+v", in.Span)
	}
}

func TestInfoWithoutPosition(t *testing.T) {
	in := New(Cost, "weight").Info("SELECT 1", 0)
	if in.Span != nil {
		t.Fatalf("span %+v", in.Span)
	}
	b, _ := json.Marshal(in)
	if strings.Contains(string(b), "span") {
		t.Fatalf("%s", b)
	}
}

// A position outside the text, or inside a character, gives no span:
// a wrong span is worse than none.
func TestInfoDropsABadPosition(t *testing.T) {
	for _, pos := range []int{-5, 100, 1} {
		if in := New(Cost, "x").At(pos, "").Info("é", 0); in.Span != nil {
			t.Errorf("pos %d: %+v", pos, in.Span)
		}
	}
}

// A token is kept only when it is printable and short: it comes from the
// agent's own statement, but it must not carry a whole literal.
func TestTokenIsBounded(t *testing.T) {
	long := strings.Repeat("a", 100)
	in := New(UnsupportedSyntax, "x").At(0, long).Info(long, 0)
	if in.Span == nil || len(in.Span.Token) > MaxToken {
		t.Fatalf("%+v", in.Span)
	}
	in = New(UnsupportedSyntax, "x").At(0, "a\x1bb").Info("a\x1bb", 0)
	if in.Span == nil || in.Span.Token != "" {
		t.Fatalf("control character kept: %+v", in.Span)
	}
}

func TestShift(t *testing.T) {
	e := New(NoLimit, "x").At(3, "LIMIT")
	e.Shift(4)
	if e.Pos != 7 {
		t.Fatal(e.Pos)
	}
	n := New(NoLimit, "x")
	n.Shift(4)
	if n.Pos != -1 {
		t.Fatal("an unknown position moved")
	}
}

func TestFromFallsBackClosed(t *testing.T) {
	if r := From(errors.New("plain")); r.Code != Policy || r.Reason != "plain" {
		t.Fatalf("%+v", r)
	}
	if r := From(&Error{Reason: "no code", Pos: -1}); r.Code != Policy {
		t.Fatalf("%+v", r)
	}
	e := New(NoLimit, "k")
	if From(e) != e {
		t.Fatal("a coded refusal was replaced")
	}
}

// docs/usage.md documents every code with the retry rule clients get.
func TestUsageDocumentsEveryCode(t *testing.T) {
	b, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[Code]string{}
	for _, line := range strings.Split(string(b), "\n") {
		cells := strings.Split(line, " | ")
		if len(cells) < 4 || !strings.HasPrefix(cells[0], "| `E_") {
			continue
		}
		rows[Code(strings.Trim(cells[0], "| `"))] = strings.TrimSpace(cells[2])
	}
	for _, c := range Codes() {
		r, ok := rows[c]
		if !ok {
			t.Errorf("docs/usage.md lacks %s", c)
		} else if r != string(c.Retry()) {
			t.Errorf("docs/usage.md: %s retry %q, want %q", c, r, c.Retry())
		}
	}
	if len(rows) != len(Codes()) {
		t.Errorf("docs/usage.md lists %d codes, want %d", len(rows), len(Codes()))
	}
}
