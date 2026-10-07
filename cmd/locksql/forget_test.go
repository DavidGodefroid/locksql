package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/DavidGodefroid/locksql/internal/secrets"
)

const forgetConfig = `
[profiles.uat]
engine = "mariadb"
host   = "db.uat.example.com"
credentials = "keychain"

[profiles.local]
engine = "sqlite"
path   = "app.db"
`

func forgetEnv(t *testing.T, terminal bool) (env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := project(t, forgetConfig)
	old := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return terminal }
	t.Cleanup(func() { stdinIsTerminal = old })
	var out, errb bytes.Buffer
	return env{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, cwd: dir}, &out, &errb
}

func TestForgetDeletesTheKeychainItem(t *testing.T) {
	keyring.MockInit()
	if err := secrets.KeychainSet("uat", "db.uat.example.com", []byte("s3cret")); err != nil {
		t.Fatal(err)
	}
	e, out, errb := forgetEnv(t, true)
	if code := runEnv(e, []string{"forget", "--profile", "uat"}); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "removed") {
		t.Errorf("stdout = %q", out.String())
	}
	if _, err := secrets.KeychainGet("uat", "db.uat.example.com"); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("item still there: %v", err)
	}
	// A second forget finds nothing and says so; that is not a failure.
	out.Reset()
	if code := runEnv(e, []string{"forget", "--profile", "uat"}); code != exitOK || !strings.Contains(out.String(), "no keychain secret") {
		t.Errorf("second forget: code = %d, stdout = %q, stderr = %q", code, out.String(), errb.String())
	}
}

func TestForgetUsageAndRefusals(t *testing.T) {
	keyring.MockInit()
	cases := []struct {
		name     string
		terminal bool
		args     []string
		code     int
		stderr   string
	}{
		{"no profile", true, []string{"forget"}, exitUsage, "usage: locksql forget"},
		{"extra argument", true, []string{"forget", "--profile", "uat", "x"}, exitUsage, "usage: locksql forget"},
		{"unknown profile", true, []string{"forget", "--profile", "nope"}, exitUsage, "unknown profile"},
		{"not a terminal", false, []string{"forget", "--profile", "uat"}, exitUsage, "terminal"},
		{"sqlite has no secret", true, []string{"forget", "--profile", "local"}, exitFail, "no keychain secret"},
	}
	for _, c := range cases {
		e, _, errb := forgetEnv(t, c.terminal)
		if code := runEnv(e, c.args); code != c.code || !strings.Contains(errb.String(), c.stderr) {
			t.Errorf("%s: code = %d, stderr = %q; want %d and %q", c.name, code, errb.String(), c.code, c.stderr)
		}
	}
}

func TestForgetReportsAnUnavailableKeychain(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	e, _, errb := forgetEnv(t, true)
	if code := runEnv(e, []string{"forget", "--profile", "uat"}); code != exitFail || !strings.Contains(errb.String(), "keychain unavailable") {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
}
