//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/verbs"
	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestProfileAddInContainer(t *testing.T) {
	e, out, _ := onboardEnv(t)
	e.container = func() bool { return true }
	// name, production, engine, host (the default: the machine's gateway),
	// port, user, database, TLS (default prefer for the gateway), keychain
	// (refused in a container, so the wizard asks again), then vault and
	// its path.
	e.stdin = strings.NewReader("uat\n\nmariadb\n\n\n\n\n\nkeychain\n" +
		"uat\n\nmariadb\n\n\n\n\n\nvault\nsecret/data/uat\n")
	if code := runProfile(e, []string{"add"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	cfg, err := config.LoadFrom(e.cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["uat"]
	if p.Host != containerHostGateway || p.Port != 3306 || p.TLS != config.TLSPrefer ||
		p.Credentials != config.CredentialsVault || p.VaultPath != "secret/data/uat" || p.Production {
		t.Fatalf("profile %+v", p)
	}
	for _, want := range []string{"[host.docker.internal]", "a container has no keychain", "asks for the Vault token"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out.String(), "keychain, vault") {
		t.Errorf("keychain offered in a container:\n%s", out)
	}

	// A second profile: the name taken is refused, the wizard asks again.
	out.Reset()
	e.stdin = strings.NewReader("uat\n\nsqlite\napp.db\nlocal\n\nsqlite\napp.db\n")
	if code := runProfile(e, []string{"add"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, want := range []string{"Profiles already in", "profile uat already exists"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if cfg, err = config.LoadFrom(e.cwd, ""); err != nil || len(cfg.Profiles) != 2 {
		t.Fatalf("profiles %v %v", cfg.Profiles, err)
	}
}

// The interactive form asks only for what the flags did not give.
func TestProfileAddInteractiveAsksTheRest(t *testing.T) {
	e, out, _ := onboardEnv(t)
	// user, database, credentials: the flags gave the rest (a loopback
	// host: no TLS question).
	e.stdin = strings.NewReader("app\n\n\n")
	args := []string{"add", "--profile", "prod", "--production", "--engine", "postgres", "--host", "127.0.0.1", "--port", "5433"}
	if code := runProfile(e, args); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, unasked := range []string{"Profile name", "Production profile", "Engine", "Host", "Port"} {
		if strings.Contains(out.String(), unasked) {
			t.Errorf("asked %q though a flag gave it:\n%s", unasked, out)
		}
	}
	cfg, err := config.LoadFrom(e.cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Profiles["prod"]; !p.Production || p.Port != 5433 || p.User != "app" || p.Credentials != config.CredentialsAsk {
		t.Fatalf("profile %+v", p)
	}

	// A flag value the checks refuse: the wizard asks everything again.
	out.Reset()
	e.stdin = strings.NewReader("lite\n\n" + "lite\n\nsqlite\napp.db\n")
	if code := runProfile(e, []string{"add", "--engine", "oracle"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "invalid: --engine") || !strings.Contains(out.String(), "Engine (") {
		t.Errorf("output:\n%s", out)
	}
}

// verbEnv is onboardEnv with stdout and stderr apart, without a terminal.
func verbEnv(t *testing.T) (env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	e, _, _ := onboardEnv(t)
	var stdout, stderr bytes.Buffer
	e.stdout, e.stderr, e.tty = &stdout, &stderr, false
	return e, &stdout, &stderr
}

// oneJSONLine decodes stdout, which must be exactly one line of JSON.
func oneJSONLine(t *testing.T, stdout string, v any) {
	t.Helper()
	if strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("stdout is not one line:\n%s", stdout)
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("stdout %q: %v", stdout, err)
	}
}

func TestProfileAddNonInteractive(t *testing.T) {
	e, stdout, stderr := verbEnv(t)
	args := []string{"add", "--non-interactive", "--json", "--profile", "prod", "--production", "--engine", "postgres",
		"--host", "db.internal", "--user", "app", "--database", "shop", "--tls", "verify-full",
		"--credentials", "vault", "--vault-path", "database/creds/ro"}
	if code := runProfile(e, args); code != exitOK {
		t.Fatalf("code %d\n%s%s", code, stdout, stderr)
	}
	var got verbs.Profile
	oneJSONLine(t, stdout.String(), &got)
	want := verbs.Profile{Lock: "locksql", Profile: "prod", Config: configPath(e.cwd), Production: true, Credentials: "vault"}
	if got != want {
		t.Errorf("JSON %+v, want %+v", got, want)
	}
	if !strings.Contains(stderr.String(), "Profile prod written") {
		t.Errorf("human text not on stderr: %q", stderr)
	}
	cfg, err := config.LoadFrom(e.cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Profiles["prod"]; p.Port != 5432 || p.VaultPath != "database/creds/ro" || !p.Production || p.User != "app" || p.Database != "shop" {
		t.Fatalf("profile %+v", p)
	}
	written, err := os.ReadFile(configPath(e.cwd))
	if err != nil {
		t.Fatal(err)
	}

	// The same profile again: exists, nothing written.
	stdout.Reset()
	stderr.Reset()
	if code := runProfile(e, args); code == exitOK {
		t.Fatalf("duplicate accepted\n%s", stderr)
	}
	var fail verbs.Error
	oneJSONLine(t, stdout.String(), &fail)
	if fail.Lock != "locksql" || fail.Code != verbs.CodeExists {
		t.Errorf("duplicate: %+v", fail)
	}
	if again, _ := os.ReadFile(configPath(e.cwd)); !bytes.Equal(again, written) {
		t.Errorf("the config changed:\n%s", again)
	}

	// SQLite: no credentials in the JSON; the defaults (name dev, ask).
	stdout.Reset()
	if code := runProfile(e, []string{"add", "--non-interactive", "--json", "--engine", "sqlite", "--path", "app.db"}); code != exitOK {
		t.Fatalf("sqlite: code %d\n%s", code, stderr)
	}
	got = verbs.Profile{}
	oneJSONLine(t, stdout.String(), &got)
	if got.Profile != "dev" || got.Credentials != "" || got.Production {
		t.Errorf("sqlite JSON %+v", got)
	}
	stdout.Reset()
	if code := runProfile(e, []string{"add", "--non-interactive", "--json", "--profile", "local", "--engine", "mysql"}); code != exitOK {
		t.Fatalf("mysql: code %d\n%s", code, stderr)
	}
	got = verbs.Profile{}
	oneJSONLine(t, stdout.String(), &got)
	if got.Credentials != "ask" {
		t.Errorf("mysql JSON %+v", got)
	}
}

// Every refusal of the non-interactive form: its code, nothing written,
// never the value quoted.
func TestProfileAddRefusals(t *testing.T) {
	const canary = "glsa_CanarySecretToken123"
	base := []string{"add", "--non-interactive", "--json", "--profile", "x"}
	for _, c := range []struct {
		name string
		args []string
		code string
		want string
	}{
		{"password flag", []string{"--engine", "postgres", "--password", canary}, verbs.CodeSecret, "unknown flag"},
		{"vault token flag", []string{"--engine", "postgres", "--vault-token", canary}, verbs.CodeSecret, "unknown flag"},
		{"embedded password", []string{"--engine", "postgres", "--host", "app:" + canary + "@db"}, verbs.CodeSecret, "--host"},
		{"dsn password", []string{"--engine", "postgres", "--database", "password=" + canary}, verbs.CodeSecret, "--database"},
		{"keychain", []string{"--engine", "postgres", "--credentials", "keychain"}, verbs.CodeSecret, "--credentials"},
		{"other source", []string{"--engine", "postgres", "--credentials", canary}, verbs.CodeSecret, "--credentials"},
		{"positional", []string{"--engine", "postgres", canary}, verbs.CodeUsage, "positional"},
		{"no engine", []string{"--host", "db"}, verbs.CodeUsage, "--engine"},
		{"bad engine", []string{"--engine", canary}, verbs.CodeUsage, "--engine"},
		{"bad port", []string{"--engine", "postgres", "--port", canary}, verbs.CodeUsage, "--port"},
		{"port range", []string{"--engine", "postgres", "--port", "70000"}, verbs.CodeUsage, "--port"},
		{"bad tls", []string{"--engine", "postgres", "--tls", canary}, verbs.CodeUsage, "--tls"},
		{"vault without path", []string{"--engine", "postgres", "--credentials", "vault"}, verbs.CodeUsage, "--vault-path"},
		{"path without vault", []string{"--engine", "postgres", "--vault-path", "database/creds/ro"}, verbs.CodeUsage, "--vault-path"},
		{"sqlite without path", []string{"--engine", "sqlite"}, verbs.CodeUsage, "--path"},
		{"sqlite with host", []string{"--engine", "sqlite", "--path", "a.db", "--host", "db"}, verbs.CodeUsage, "--path only"},
		{"sqlite with credentials", []string{"--engine", "sqlite", "--path", "a.db", "--credentials", "ask"}, verbs.CodeUsage, "--path only"},
		{"production plain tls", []string{"--engine", "postgres", "--host", "db.internal", "--tls", "prefer", "--production"}, verbs.CodeUsage, "production"},
		{"bad project", []string{"--engine", "sqlite", "--path", "a.db", "--project", "/nonexistent/" + canary}, verbs.CodeUsage, "--project"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, stdout, stderr := verbEnv(t)
			args := append(append([]string{}, base...), c.args...)
			if code := runProfile(e, args); code == exitOK {
				t.Fatalf("accepted\n%s", stderr)
			}
			var fail verbs.Error
			oneJSONLine(t, stdout.String(), &fail)
			if fail.Code != c.code || !strings.Contains(fail.Error, c.want) {
				t.Errorf("error %+v, want code %s naming %q", fail, c.code, c.want)
			}
			if strings.Contains(stdout.String()+stderr.String(), "Canary") {
				t.Errorf("quotes the value:\n%s%s", stdout, stderr)
			}
			if _, err := os.Stat(filepath.Join(e.cwd, ".locksql")); err == nil {
				t.Errorf("wrote .locksql")
			}
		})
	}
}

// Without --non-interactive and without a terminal: a usage error, no
// waiting for an answer, nothing written; and only `add` is a subcommand.
func TestProfileAddUsage(t *testing.T) {
	e, stdout, stderr := verbEnv(t)
	for _, args := range [][]string{
		{"add", "--json", "--engine", "sqlite", "--path", "a.db"},
		{"list", "--json"},
		{"--json"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runProfile(e, args); code != exitUsage {
			t.Errorf("%v: code %d", args, code)
		}
		var fail verbs.Error
		oneJSONLine(t, stdout.String(), &fail)
		if fail.Code != verbs.CodeUsage || !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("%v: %+v\n%s", args, fail, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(e.cwd, ".locksql")); err == nil {
		t.Errorf("wrote .locksql")
	}
	// Without --json: nothing on stdout.
	stdout.Reset()
	if code := runProfile(e, []string{"add", "--engine", "sqlite", "--path", "a.db"}); code != exitUsage || stdout.Len() != 0 {
		t.Errorf("code %d, stdout %q", code, stdout)
	}
}

// --project writes into that project, whatever the current directory.
func TestProfileAddProject(t *testing.T) {
	e, stdout, stderr := verbEnv(t)
	other := t.TempDir()
	if code := runProfile(e, []string{"add", "--non-interactive", "--project", other, "--engine", "sqlite", "--path", "a.db"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, stderr)
	}
	if _, err := os.Stat(configPath(other)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Profile dev written to "+configPath(other)) {
		t.Errorf("stdout %q", stdout)
	}
}

func TestCompleteSpecVaultAndTLS(t *testing.T) {
	bad := []profileSpec{
		{engine: "postgres", credentials: "vault"},
		{engine: "postgres", credentials: "vault", vaultPath: "/abs"},
		{engine: "postgres", credentials: "vault", vaultPath: "a b"},
		{engine: "postgres", vaultPath: "database/creds/ro"},
		{engine: "postgres", tls: "strict"},
		{engine: "sqlite", path: "a.db", tls: "require"},
		{engine: "postgres", name: "y", production: true},
	}
	for _, s := range bad {
		if _, err := completeSpec(s); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	s, err := completeSpec(profileSpec{engine: "postgres", host: "db", tls: "require", credentials: "vault", vaultPath: "secret/data/x", production: true})
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := config.ParseProfiles([]byte(s.toml()), "t", t.TempDir())
	if err != nil {
		t.Fatalf("%v\n%s", err, s.toml())
	}
	if p := profiles["dev"]; p.TLS != "require" || p.VaultPath != "secret/data/x" || !p.Production {
		t.Errorf("profile %+v", p)
	}
}
