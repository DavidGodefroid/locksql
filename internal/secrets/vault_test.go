package secrets

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeVault replaces the vault CLI for one test: it records the arguments
// and answers with stdout, stderr and err.
func fakeVault(t *testing.T, stdout, stderr string, err error) *[]string {
	t.Helper()
	var got []string
	old := vaultRun
	vaultRun = func(_ context.Context, args ...string) ([]byte, []byte, error) {
		got = append([]string(nil), args...)
		return []byte(stdout), []byte(stderr), err
	}
	t.Cleanup(func() { vaultRun = old })
	return &got
}

// exitErr is a CLI run that exited non-zero, as exec reports it.
var exitErr = &exec.ExitError{}

const dbCreds = `{
  "request_id": "5f1f",
  "lease_id": "database/creds/app-ro/3HXq",
  "lease_duration": 3600,
  "renewable": true,
  "data": {"password": "A1a-pZ9x", "username": "v-token-app-ro-8xq2"},
  "warnings": null
}`

func TestVaultReadDatabaseCreds(t *testing.T) {
	args := fakeVault(t, dbCreds, "", nil)
	c, err := VaultRead(context.Background(), "database/creds/app-ro")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"read", "-format=json", "--", "database/creds/app-ro"}; !slices.Equal(*args, want) {
		t.Errorf("args = %q, want %q", *args, want)
	}
	if c.User != "v-token-app-ro-8xq2" || string(c.Password) != "A1a-pZ9x" {
		t.Errorf("login = %q / %q", c.User, c.Password)
	}
	if c.LeaseID != "database/creds/app-ro/3HXq" || c.LeaseDuration != time.Hour {
		t.Errorf("lease = %q %s", c.LeaseID, c.LeaseDuration)
	}
}

func TestVaultReadKV(t *testing.T) {
	for name, out := range map[string]string{
		"kv v2": `{"lease_id":"","lease_duration":0,"data":{"data":{"username":"app","password":"pw"},"metadata":{"version":3}}}`,
		"kv v1": `{"lease_id":"","lease_duration":2764800,"data":{"username":"app","password":"pw"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			fakeVault(t, out, "", nil)
			c, err := VaultRead(context.Background(), "secret/data/app")
			if err != nil {
				t.Fatal(err)
			}
			if c.User != "app" || string(c.Password) != "pw" || c.LeaseID != "" {
				t.Errorf("login = %+v", c)
			}
		})
	}
	// A KV secret may hold the password only: the profile names the user.
	fakeVault(t, `{"data":{"password":"pw"}}`, "", nil)
	c, err := VaultRead(context.Background(), "secret/app")
	if err != nil || c.User != "" || string(c.Password) != "pw" {
		t.Errorf("password-only secret = %+v, %v", c, err)
	}
}

// Every failure of the CLI maps to an error that says what is wrong and
// what to do.
func TestVaultReadErrors(t *testing.T) {
	const path = "database/creds/app-ro"
	api := func(code int, msg string) string {
		return fmt.Sprintf("Error reading %s: Error making API request.\n\nURL: GET https://vault:8200/v1/%s\nCode: %d. Errors:\n\n* %s\n", path, path, code, msg)
	}
	for name, c := range map[string]struct {
		stderr string
		err    error
		want   error
		says   string
	}{
		"no CLI":          {"", exec.ErrNotFound, ErrVaultMissing, "PATH"},
		"no token":        {api(400, "missing client token"), exitErr, ErrVaultAuth, "vault login"},
		"denied":          {api(403, "permission denied"), exitErr, ErrVaultAuth, "vault login"},
		"expired token":   {api(403, "invalid token"), exitErr, ErrVaultAuth, "invalid token"},
		"unknown role":    {api(400, "unknown role: app-ro"), exitErr, ErrVaultRole, "unknown role: app-ro"},
		"no value":        {"No value found at " + path + "\n", exitErr, ErrVaultPath, "No value found"},
		"no mount":        {api(404, "no handler for route \"database/creds/app-ro\". route entry not found."), exitErr, ErrVaultPath, "check the path"},
		"unreachable":     {"Error reading " + path + `: Get "https://127.0.0.1:8200/v1/x": dial tcp 127.0.0.1:8200: connect: connection refused`, exitErr, ErrVaultUnreachable, "VAULT_ADDR"},
		"timeout":         {"", context.DeadlineExceeded, ErrVaultUnreachable, "VAULT_ADDR"},
		"other":           {api(500, "internal error"), exitErr, ErrVaultFailed, "internal error"},
		"terminal escape": {api(500, "bad\x1b[2Jthing"), exitErr, ErrVaultFailed, "bad[2Jthing"},
	} {
		t.Run(name, func(t *testing.T) {
			fakeVault(t, "", c.stderr, c.err)
			_, err := VaultRead(context.Background(), path)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("err = %q, want it to say %q", err, c.says)
			}
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Errorf("terminal escape kept: %q", err)
			}
		})
	}
}

// A secret that is not a login is refused, and the error names the field,
// never a value.
func TestVaultReadFormat(t *testing.T) {
	for name, out := range map[string]string{
		"not json":      `Key Value`,
		"no password":   `{"data":{"username":"app"}}`,
		"empty":         `{"data":{"username":"app","password":""}}`,
		"number":        `{"data":{"username":"app","password":12345678}}`,
		"user object":   `{"data":{"username":{"x":"s3cr3t-value"},"password":"s3cr3t-value"}}`,
		"kv v2 garbage": `{"data":{"data":"s3cr3t-value","metadata":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			fakeVault(t, out, "", nil)
			_, err := VaultRead(context.Background(), "secret/app")
			if !errors.Is(err, ErrVaultFormat) {
				t.Fatalf("err = %v, want ErrVaultFormat", err)
			}
			if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "12345678") {
				t.Errorf("value in the error: %q", err)
			}
		})
	}
}

// A path the CLI could read as a flag, or split, never reaches it.
func TestVaultReadRefusesBadPath(t *testing.T) {
	args := fakeVault(t, dbCreds, "", nil)
	for _, p := range []string{"", "-address=https://evil", "/database/creds/x", "database/creds/a b", "database/creds/\x1bx", "a‮b"} {
		if _, err := VaultRead(context.Background(), p); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if *args != nil {
		t.Errorf("the CLI ran with %q", *args)
	}
}
