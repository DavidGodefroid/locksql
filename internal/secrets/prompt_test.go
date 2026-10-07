package secrets

import (
	"bytes"
	"testing"
)

func TestTrimLineEnd(t *testing.T) {
	cases := map[string]string{"pw": "pw", "pw\r": "pw", "pw\n": "pw", "pw\r\n": "pw", " pw ": " pw ", "": ""}
	for in, want := range cases {
		if got := trimLineEnd([]byte(in)); !bytes.Equal(got, []byte(want)) {
			t.Errorf("trimLineEnd(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPromptPasswordNoTerminal(t *testing.T) {
	if hasTerminal() {
		t.Skip("a controlling terminal is present")
	}
	if _, err := PromptPassword("Password: "); err == nil {
		t.Fatal("expected an error without a terminal")
	}
}
