package secrets

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestSanitizeRemovesSecrets(t *testing.T) {
	err := fmt.Errorf("connect: access denied for 'alice' using s3cr3t!pw and again s3cr3t!pw")
	got := Sanitize(err, []byte("s3cr3t!pw"))
	if strings.Contains(got, "s3cr3t") {
		t.Fatalf("secret left in %q", got)
	}
	if !strings.Contains(got, "access denied for 'alice'") {
		t.Fatalf("message lost: %q", got)
	}
	if strings.Count(got, Redacted) != 2 {
		t.Fatalf("want two redactions in %q", got)
	}
}

func TestSanitizeEncodedForms(t *testing.T) {
	s := "p@ss w/rd%"
	for _, form := range []string{url.QueryEscape(s), url.PathEscape(s), url.UserPassword("u", s).String()} {
		got := Sanitize(errors.New("dial "+form+" failed"), []byte(s))
		if strings.Contains(got, "ss w") || strings.Contains(got, "ss+w") || strings.Contains(got, "ss%20w") {
			t.Errorf("encoded secret %q left in %q", form, got)
		}
	}
}

func TestSanitizeSeveralSecretsLongestFirst(t *testing.T) {
	got := Sanitize(errors.New("a=abc b=abcdef"), []byte("abc"), []byte("abcdef"))
	if strings.Contains(got, "def") || strings.Contains(got, "abc") {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeEdgeCases(t *testing.T) {
	if got := Sanitize(nil, []byte("x")); got != "" {
		t.Errorf("nil error: %q", got)
	}
	if got := Sanitize(errors.New("plain"), nil, []byte{}); got != "plain" {
		t.Errorf("no secrets: %q", got)
	}
}

func TestWipe(t *testing.T) {
	b := []byte("secret")
	Wipe(b)
	for _, c := range b {
		if c != 0 {
			t.Fatalf("not wiped: %q", b)
		}
	}
	Wipe(nil)
}
