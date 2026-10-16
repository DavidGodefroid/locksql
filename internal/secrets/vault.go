package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

// VaultCommand is the program run to read a secret from HashiCorp Vault.
// It inherits the console's environment (VAULT_ADDR, VAULT_TOKEN,
// VAULT_NAMESPACE, VAULT_CACERT, ...) and its token helper
// (~/.vault-token): locksql never handles the Vault token itself.
const VaultCommand = "vault"

// vaultTimeout bounds one vault read.
const vaultTimeout = 20 * time.Second

// Errors of VaultRead. Each is wrapped with a message that says what to do;
// none carries a value read from Vault.
var (
	// ErrVaultMissing means the vault CLI is not in the console's PATH.
	ErrVaultMissing = errors.New("secrets: vault CLI not found")
	// ErrVaultAuth means Vault refused the request: no token, an expired
	// or revoked one, or a token whose policy may not read the path.
	ErrVaultAuth = errors.New("secrets: vault: not authenticated or not allowed")
	// ErrVaultPath means nothing answers at the path: no secret there, or
	// no secrets engine mounted at its prefix.
	ErrVaultPath = errors.New("secrets: vault: invalid path")
	// ErrVaultRole means the secrets engine has no such role.
	ErrVaultRole = errors.New("secrets: vault: invalid role")
	// ErrVaultUnreachable means the CLI could not reach the Vault server.
	ErrVaultUnreachable = errors.New("secrets: vault: server unreachable")
	// ErrVaultFormat means the secret has no usable password field.
	ErrVaultFormat = errors.New("secrets: vault: unexpected secret format")
	// ErrVaultFailed is any other failure of the CLI.
	ErrVaultFailed = errors.New("secrets: vault read failed")
)

// VaultCredentials is a database login read from Vault. Password lives in
// memory only; the caller wipes it when done.
type VaultCredentials struct {
	// User is the secret's username field, "" when it has none (a KV secret
	// holding the password only).
	User     string
	Password []byte
	// LeaseID and LeaseDuration describe a dynamic secret (the database
	// secrets engine): the login stops working once the lease ends. A
	// static KV secret has no lease ID.
	LeaseID       string
	LeaseDuration time.Duration
}

// vaultRun runs the vault CLI; tests replace it.
var vaultRun = func(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, VaultCommand, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// VaultRead reads the login at path with `vault read -format=json`: the
// fields username and password of the secret's data, or of data.data for
// a KV version 2 secret. Every call reads Vault again; nothing is cached
// or written to disk.
func VaultRead(ctx context.Context, path string) (*VaultCredentials, error) {
	if err := CheckVaultPath(path); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, vaultTimeout)
	defer cancel()
	// "--" ends the flags: the path is never read as one.
	out, stderr, err := vaultRun(ctx, "read", "-format=json", "--", path)
	defer Wipe(out)
	if err != nil {
		return nil, vaultError(path, err, stderr)
	}
	return parseVault(path, out)
}

// CheckVaultPath refuses a path the CLI could misread: empty, starting with
// "-" or "/", or holding a space or a control character.
func CheckVaultPath(path string) error {
	switch {
	case path == "":
		return errors.New("secrets: vault path is empty")
	case strings.HasPrefix(path, "-") || strings.HasPrefix(path, "/"):
		return errors.New("secrets: vault path must not start with '-' or '/'")
	case strings.ContainsFunc(path, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || !unicode.IsPrint(r) }):
		return errors.New("secrets: vault path holds a space, control or non-printable character")
	}
	return nil
}

// vaultError maps a failed CLI run to one of the ErrVault errors, with the
// first line of the CLI's message.
func vaultError(path string, err error, stderr []byte) error {
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("%w: install it in the console account's PATH (https://developer.hashicorp.com/vault/install)", ErrVaultMissing)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: no answer within %s (check VAULT_ADDR)", ErrVaultUnreachable, vaultTimeout)
	}
	msg := vaultMessage(stderr)
	lower := strings.ToLower(string(stderr))
	var kind error
	var hint string
	switch {
	case strings.Contains(lower, "missing client token"), strings.Contains(lower, "permission denied"),
		strings.Contains(lower, "invalid token"), strings.Contains(lower, "token is expired"), strings.Contains(lower, "code: 403"):
		kind, hint = ErrVaultAuth, "run `vault login` as the console account, or check that its token's policy may read "+path
	case strings.Contains(lower, "unknown role"), strings.Contains(lower, "role not found"),
		strings.Contains(lower, "no role"), strings.Contains(lower, "could not find role"),
		strings.Contains(lower, "role") && strings.Contains(lower, "not found"):
		kind, hint = ErrVaultRole, "check the role name at the end of "+path+" (`vault list <mount>/roles`)"
	case strings.Contains(lower, "no value found at"), strings.Contains(lower, "no handler for route"),
		strings.Contains(lower, "code: 404"):
		kind, hint = ErrVaultPath, "nothing at "+path+": check the path and the secrets engine mount"
	case strings.Contains(lower, "connection refused"), strings.Contains(lower, "no such host"),
		strings.Contains(lower, "dial tcp"), strings.Contains(lower, "i/o timeout"),
		strings.Contains(lower, "certificate"), strings.Contains(lower, "tls:"):
		kind, hint = ErrVaultUnreachable, "check VAULT_ADDR and VAULT_CACERT in the console's environment"
	default:
		kind = ErrVaultFailed
	}
	if msg == "" {
		msg = err.Error()
	}
	if hint != "" {
		return fmt.Errorf("%w: %s (%s)", kind, hint, msg)
	}
	return fmt.Errorf("%w: %s", kind, msg)
}

// maxVaultMessage bounds the CLI message quoted in an error.
const maxVaultMessage = 200

// vaultMessage is the most telling line of the CLI's stderr: the server's
// first "* ..." error, or else the first non-empty line, without terminal
// controls and cut at maxVaultMessage bytes.
func vaultMessage(stderr []byte) string {
	var first, starred string
	for l := range strings.SplitSeq(string(stderr), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "* ") && starred == "":
			starred = strings.TrimSpace(l[2:])
		case first == "":
			first = l
		}
	}
	msg := first
	if starred != "" {
		msg = starred
	}
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, msg)
	if len(msg) > maxVaultMessage {
		msg = strings.ToValidUTF8(msg[:maxVaultMessage], "") + "…"
	}
	return msg
}

type vaultResponse struct {
	LeaseID       string                     `json:"lease_id"`
	LeaseDuration int64                      `json:"lease_duration"`
	Data          map[string]json.RawMessage `json:"data"`
}

// parseVault reads the login out of the CLI's JSON. Its errors name the
// fields, never their values.
func parseVault(path string, out []byte) (*VaultCredentials, error) {
	var r vaultResponse
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("%w: the vault CLI did not print JSON for %s", ErrVaultFormat, path)
	}
	data := r.Data
	// KV version 2 nests the secret under data.data, next to data.metadata.
	if inner, ok := data["data"]; ok {
		if _, meta := data["metadata"]; meta {
			data = nil
			if err := json.Unmarshal(inner, &data); err != nil {
				return nil, fmt.Errorf("%w: data.data of %s is not an object", ErrVaultFormat, path)
			}
		}
	}
	field := func(name string) (string, bool, error) {
		raw, ok := data[name]
		if !ok || string(raw) == "null" {
			return "", false, nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false, fmt.Errorf("%w: field %q of %s is not a string", ErrVaultFormat, name, path)
		}
		return s, true, nil
	}
	pw, ok, err := field("password")
	if err != nil {
		return nil, err
	}
	if !ok || pw == "" {
		return nil, fmt.Errorf("%w: %s has no password field", ErrVaultFormat, path)
	}
	user, _, err := field("username")
	if err != nil {
		return nil, err
	}
	if r.LeaseDuration < 0 {
		r.LeaseDuration = 0
	}
	return &VaultCredentials{
		User: user, Password: []byte(pw),
		LeaseID: r.LeaseID, LeaseDuration: time.Duration(r.LeaseDuration) * time.Second,
	}, nil
}
