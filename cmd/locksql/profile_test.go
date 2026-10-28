//go:build unix

package main

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestProfileAddInContainer(t *testing.T) {
	e, out, _ := onboardEnv(t)
	e.container = func() bool { return true }
	// name, engine, host (the default: the machine's gateway), port, user,
	// database, TLS (default prefer for the gateway), keychain (refused in a
	// container, so the wizard asks again), then vault and its path.
	e.stdin = strings.NewReader("uat\nmariadb\n\n\n\n\n\nkeychain\n" +
		"uat\nmariadb\n\n\n\n\n\nvault\nsecret/data/uat\n")
	if code := runProfile(e, []string{"add"}); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	cfg, err := config.LoadFrom(e.cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["uat"]
	if p.Host != containerHostGateway || p.Port != 3306 || p.TLS != config.TLSPrefer ||
		p.Credentials != config.CredentialsVault || p.VaultPath != "secret/data/uat" {
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
	e.stdin = strings.NewReader("uat\nsqlite\napp.db\nlocal\nsqlite\napp.db\n")
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

func TestProfileAddFlags(t *testing.T) {
	e, out, _ := onboardEnv(t)
	e.tty = false
	args := []string{"add", "--profile", "prod", "--engine", "postgres", "--host", "db.internal",
		"--credentials", "vault", "--vault-path", "database/creds/ro"}
	if code := runProfile(e, args); code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	cfg, err := config.LoadFrom(e.cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Profiles["prod"]; p.Port != 5432 || p.VaultPath != "database/creds/ro" || p.TLS != config.TLSVerifyFull {
		t.Fatalf("profile %+v", p)
	}
	if code := runProfile(e, args); code != exitUsage || !strings.Contains(out.String(), "already in") {
		t.Errorf("duplicate: code %d\n%s", code, out)
	}
	for _, bad := range [][]string{{"add"}, {"list"}, {"add", "--host", "h"}} {
		out.Reset()
		if code := runProfile(e, bad); code != exitUsage {
			t.Errorf("%v: code %d\n%s", bad, code, out)
		}
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
	}
	for _, s := range bad {
		if _, err := completeSpec(s); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	s, err := completeSpec(profileSpec{engine: "postgres", host: "db", tls: "require", credentials: "vault", vaultPath: "secret/data/x"})
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := config.ParseProfiles([]byte(s.toml()), "t", t.TempDir())
	if err != nil {
		t.Fatalf("%v\n%s", err, s.toml())
	}
	if p := profiles["dev"]; p.TLS != "require" || p.VaultPath != "secret/data/x" {
		t.Errorf("profile %+v", p)
	}
}
