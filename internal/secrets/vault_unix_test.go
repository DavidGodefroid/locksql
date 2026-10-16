//go:build unix

package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeVault puts a shell script named vault first in PATH. It
// writes its arguments and VAULT_ADDR to a file next to it, then runs body.
func installFakeVault(t *testing.T, body string) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" \"addr=$VAULT_ADDR\" > '" + argsFile + "'\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, VaultCommand), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argsFile
}

// The real runner execs the vault CLI found in PATH, with the console's
// environment, and reads its JSON from stdout.
func TestVaultReadRunsTheCLI(t *testing.T) {
	argsFile := installFakeVault(t, `cat <<'EOF'
{"lease_id":"database/creds/ro/x","lease_duration":120,"data":{"username":"v-ro-1","password":"pw-1"}}
EOF`)
	t.Setenv("VAULT_ADDR", "https://vault.example:8200")
	c, err := VaultRead(context.Background(), "database/creds/ro")
	if err != nil {
		t.Fatal(err)
	}
	if c.User != "v-ro-1" || string(c.Password) != "pw-1" {
		t.Errorf("login = %q / %q", c.User, c.Password)
	}
	got, _ := os.ReadFile(argsFile)
	if want := "read\n-format=json\n--\ndatabase/creds/ro\naddr=https://vault.example:8200\n"; string(got) != want {
		t.Errorf("CLI saw %q, want %q", got, want)
	}
}

func TestVaultReadCLIFailure(t *testing.T) {
	installFakeVault(t, `echo 'No value found at database/creds/nope' >&2; exit 2`)
	_, err := VaultRead(context.Background(), "database/creds/nope")
	if !errors.Is(err, ErrVaultPath) || !strings.Contains(err.Error(), "No value found at database/creds/nope") {
		t.Errorf("err = %v", err)
	}
}

func TestVaultReadWithoutCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := VaultRead(context.Background(), "database/creds/ro"); !errors.Is(err, ErrVaultMissing) {
		t.Errorf("err = %v, want ErrVaultMissing", err)
	}
}
