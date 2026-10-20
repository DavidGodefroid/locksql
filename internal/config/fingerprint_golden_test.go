package config

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

var updateFingerprints = flag.Bool("update-fingerprints", false, "rewrite testdata/fingerprints_golden.json")

// goldenPolicies are every loadable fixture profile plus three hand-built
// policies: through an SSH bastion, with Vault credentials, with PII mask
// modes.
func goldenPolicies(t *testing.T) map[string]Policy {
	t.Helper()
	out := map[string]Policy{}
	for _, f := range []string{"basic.toml", "user.toml"} {
		data, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		profiles, err := ParseProfiles(data, f, "/srv/app")
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for name, p := range profiles {
			out[f+":"+name] = NewPolicy(p, nil, nil)
		}
	}
	base := Profile{Name: "prod", Engine: EnginePostgres, Host: "db.example.com", Port: 5432, User: "ro", Database: "shop",
		Credentials: CredentialsAsk, TLS: TLSVerifyFull, Tier: TierRead, Production: true,
		Detectors: []string{"email", "iban"}, Limits: DefaultLimits(true)}
	ssh := base
	ssh.TLS = TLSDisable
	ssh.Host = "127.0.0.1"
	ssh.SSH = &SSHProfile{Host: "bastion.example.com", Port: 22, User: "ops", Auth: SSHAuthAgent, Credentials: CredentialsAsk}
	out["hand:ssh"] = NewPolicy(ssh, []string{"shop.users.email"}, nil)
	vault := base
	vault.Credentials, vault.VaultPath, vault.CredentialsTTL = CredentialsVault, "database/creds/ro", 20*time.Minute
	out["hand:vault"] = NewPolicy(vault, nil, []string{"shop.orders.*"})
	pii := base
	pii.Production = false
	pii.Limits = DefaultLimits(false)
	out["hand:pii-modes"] = NewPolicy(pii, []string{"shop.users.email", "shop.users.phone", "shop.users.name"}, []string{"shop.users.id"}).
		WithModes(map[string]string{"shop.users.email": "email", "shop.users.phone": "partial", "shop.users.name": "redact"})
	return out
}

// Approved-policy fingerprints of locksql 0.8 (captured before lockkit): a
// user upgrading is never asked to approve an unchanged policy again.
func TestFingerprintUnchanged(t *testing.T) {
	got := map[string]string{}
	for name, p := range goldenPolicies(t) {
		got[name] = Fingerprint(p)
	}
	path := filepath.Join("testdata", "fingerprints_golden.json")
	if *updateFingerprints {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// A sqlite path is resolved with the OS separator: the golden values
		// were captured on Unix, where locksql runs.
		for name, p := range goldenPolicies(t) {
			if p.Profile.Path != "" {
				delete(want, name)
				delete(got, name)
			}
		}
	}
	var names []string
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(want) < 5 || len(got) != len(want) {
		t.Fatalf("%d policies, golden has %d", len(got), len(want))
	}
	for _, n := range names {
		if got[n] != want[n] {
			t.Errorf("%s: fingerprint %s, want %s", n, got[n], want[n])
		}
	}
	// The approved file a user already has decodes to the same policy.
	state := t.TempDir()
	for _, n := range names {
		key := "golden-" + strings.NewReplacer(":", "-", ".", "-").Replace(n)
		p := goldenPolicies(t)[n]
		if err := SaveApproved(state, key, p); err != nil {
			t.Fatal(err)
		}
		ap, err := LoadApproved(state, key)
		if err != nil || Fingerprint(*ap) != want[n] {
			t.Errorf("%s: approved round trip: %v", n, err)
		}
	}
}
