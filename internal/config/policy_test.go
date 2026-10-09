package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func clonePolicy(p Policy) Policy {
	c := p
	c.Profile.Detectors = append([]string(nil), p.Profile.Detectors...)
	c.PIIMask = append([]string(nil), p.PIIMask...)
	c.PIIAllow = append([]string(nil), p.PIIAllow...)
	return c
}

func anyLoosens(changes []Change) bool {
	for _, c := range changes {
		if c.Loosens {
			return true
		}
	}
	return false
}

func TestDiffLoosening(t *testing.T) {
	base := Policy{Profile: Profile{Tier: TierRead, Credentials: "ask", Limits: Limits{MaxRows: 200}}, PIIMask: []string{"app.users.email"}}
	cases := []struct {
		name    string
		mut     func(*Policy)
		loosens bool
	}{
		{"tier up", func(p *Policy) { p.Profile.Tier = TierWrite }, true},
		{"tier down", func(p *Policy) { p.Profile.Tier = TierRead }, false},
		{"rows up", func(p *Policy) { p.Profile.Limits.MaxRows = 500 }, true},
		{"rows down", func(p *Policy) { p.Profile.Limits.MaxRows = 50 }, false},
		{"pii removed", func(p *Policy) { p.PIIMask = nil }, true},
		{"pii added", func(p *Policy) { p.PIIMask = append(p.PIIMask, "app.users.phone") }, false},
		{"keychain", func(p *Policy) { p.Profile.Credentials = "keychain" }, true},
		{"allow added", func(p *Policy) { p.PIIAllow = []string{"app.t.name"} }, true},
	}
	for _, c := range cases {
		cur := clonePolicy(base)
		c.mut(&cur)
		got := anyLoosens(Diff(base, cur))
		if got != c.loosens {
			t.Errorf("%s: loosens=%v want %v", c.name, got, c.loosens)
		}
	}
}

func fullPolicy() Policy {
	return NewPolicy(Profile{
		Name: "uat", Engine: EngineMariaDB, Host: "db", Port: 3306, Database: "app", User: "ro",
		Credentials: CredentialsAsk, Tier: TierWrite, Production: true, TLS: TLSVerifyFull,
		Detectors: []string{"email", "phone"},
		Limits:    DefaultLimits(true),
	}, []string{"app.users.email", "app.users.phone"}, []string{"app.t.name"})
}

func TestDiffEveryRule(t *testing.T) {
	cases := []struct {
		name    string
		field   string
		mut     func(*Policy)
		loosens bool
	}{
		{"tier read->write", "tier", func(p *Policy) { p.Profile.Tier = TierAdmin }, true},
		{"tier write->read", "tier", func(p *Policy) { p.Profile.Tier = TierRead }, false},
		{"production off", "production", func(p *Policy) { p.Profile.Production = false }, true},
		{"production on", "production", func(p *Policy) { p.Profile.Production = true; p.Profile.Tier = TierRead }, false},
		{"max_rows up", "limits.max_rows", func(p *Policy) { p.Profile.Limits.MaxRows = 500 }, true},
		{"max_rows down", "limits.max_rows", func(p *Policy) { p.Profile.Limits.MaxRows = 10 }, false},
		{"warn up", "limits.explain_rows_warn", func(p *Policy) { p.Profile.Limits.ExplainRowsWarn *= 2 }, true},
		{"refuse up", "limits.explain_rows_refuse", func(p *Policy) { p.Profile.Limits.ExplainRowsRefuse *= 2 }, true},
		{"refuse down", "limits.explain_rows_refuse", func(p *Policy) { p.Profile.Limits.ExplainRowsRefuse /= 2 }, false},
		{"timeout 10s->30s", "limits.statement_timeout", func(p *Policy) { p.Profile.Limits.StatementTimeout = 30 * time.Second }, true},
		{"timeout down", "limits.statement_timeout", func(p *Policy) { p.Profile.Limits.StatementTimeout = time.Second }, false},
		{"cell chars up", "limits.max_cell_chars", func(p *Policy) { p.Profile.Limits.MaxCellChars = 1000 }, true},
		{"output bytes up", "limits.max_output_bytes", func(p *Policy) { p.Profile.Limits.MaxOutputBytes = 1 << 20 }, true},
		{"limit to unlimited", "limits.max_rows", func(p *Policy) { p.Profile.Limits.MaxRows = 0 }, true},
		{"pii rule removed", "pii.mask", func(p *Policy) { p.PIIMask = p.PIIMask[:1] }, true},
		{"pii rule added", "pii.mask", func(p *Policy) { p.PIIMask = append(p.PIIMask, "x.y.z") }, false},
		{"detector removed", "detectors", func(p *Policy) { p.Profile.Detectors = []string{"email"} }, true},
		{"detector added", "detectors", func(p *Policy) { p.Profile.Detectors = append(p.Profile.Detectors, "iban") }, false},
		{"allow added", "pii.allow", func(p *Policy) { p.PIIAllow = append(p.PIIAllow, "a.b.c") }, true},
		{"allow removed", "pii.allow", func(p *Policy) { p.PIIAllow = nil }, false},
		{"host", "host", func(p *Policy) { p.Profile.Host = "other" }, true},
		{"port", "port", func(p *Policy) { p.Profile.Port = 3307 }, true},
		{"engine", "engine", func(p *Policy) { p.Profile.Engine = EngineMySQL }, true},
		{"database", "database", func(p *Policy) { p.Profile.Database = "other" }, true},
		{"path", "path", func(p *Policy) { p.Profile.Path = "/tmp/x.db" }, true},
		{"user", "user", func(p *Policy) { p.Profile.User = "admin" }, true},
		{"tls down", "tls", func(p *Policy) { p.Profile.TLS = TLSRequire }, true},
		{"tls ca changed", "tls_ca", func(p *Policy) { p.Profile.TLSCA = "/other.pem" }, true},
		{"ssh added", "ssh", func(p *Policy) {
			p.Profile.SSH = &SSHProfile{Host: "b", Port: 22, User: "u", Auth: SSHAuthAgent, Credentials: CredentialsAsk}
		}, true},
		{"ask->keychain", "credentials", func(p *Policy) { p.Profile.Credentials = CredentialsKeychain }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := fullPolicy()
			if c.name == "production on" {
				base.Profile.Production = false
				base.Profile.Tier = TierRead
			}
			if c.name == "tier write->read" {
				base.Profile.Tier = TierWrite
			}
			cur := clonePolicy(base)
			c.mut(&cur)
			changes := Diff(base, cur)
			var found bool
			for _, ch := range changes {
				if ch.Field == c.field {
					found = true
					if ch.Loosens != c.loosens {
						t.Errorf("%s: Loosens=%v want %v (%+v)", c.field, ch.Loosens, c.loosens, ch)
					}
				} else {
					t.Errorf("unexpected extra change %+v", ch)
				}
			}
			if !found {
				t.Errorf("no change reported for %s: %+v", c.field, changes)
			}
		})
	}
}

func TestDiffKeychainToAskTightens(t *testing.T) {
	base := fullPolicy()
	base.Profile.Credentials = CredentialsKeychain
	cur := clonePolicy(base)
	cur.Profile.Credentials = CredentialsAsk
	if anyLoosens(Diff(base, cur)) {
		t.Error("keychain -> ask must not loosen")
	}
}

func TestDiffNoChange(t *testing.T) {
	p := fullPolicy()
	q := clonePolicy(p)
	// Reordered lists are the same policy.
	q.Profile.Detectors = []string{"phone", "email"}
	q.PIIMask = []string{"app.users.phone", "app.users.email"}
	if d := Diff(p, q); len(d) != 0 {
		t.Errorf("Diff = %+v, want none", d)
	}
	if Fingerprint(p) != Fingerprint(q) {
		t.Error("Fingerprint must not depend on list order")
	}
}

func TestFingerprint(t *testing.T) {
	p := fullPolicy()
	f := Fingerprint(p)
	if len(f) != 64 {
		t.Errorf("Fingerprint length %d", len(f))
	}
	q := clonePolicy(p)
	q.Profile.Limits.MaxRows++
	if Fingerprint(q) == f {
		t.Error("Fingerprint must change with the policy")
	}
}

func TestNewPolicySortsAndDedupes(t *testing.T) {
	p := NewPolicy(Profile{}, []string{"b", "a", "b"}, []string{"z", "y"})
	if len(p.PIIMask) != 2 || p.PIIMask[0] != "a" || p.PIIAllow[0] != "y" {
		t.Errorf("NewPolicy = %+v", p)
	}
}

func TestApprovedRoundTrip(t *testing.T) {
	state := t.TempDir()
	key := ApprovedKey("/proj", "uat")
	if _, err := LoadApproved(state, key); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadApproved before save: err=%v, want fs.ErrNotExist", err)
	}
	p := fullPolicy()
	if err := SaveApproved(state, key, p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "locksql", "approved", key+".json")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	got, err := LoadApproved(state, key)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(*got) != Fingerprint(p) || len(Diff(p, *got)) != 0 {
		t.Errorf("round trip changed the policy: %+v", got)
	}
	// Overwrite works.
	p.Profile.Limits.MaxRows = 7
	if err := SaveApproved(state, key, p); err != nil {
		t.Fatal(err)
	}
	got, _ = LoadApproved(state, key)
	if got.Profile.Limits.MaxRows != 7 {
		t.Errorf("overwrite lost: %d", got.Profile.Limits.MaxRows)
	}
}

func TestApprovedKey(t *testing.T) {
	if k := ApprovedKey("/proj", "uat"); k != ProjectHash("/proj")+"-uat" {
		t.Errorf("ApprovedKey = %q", k)
	}
	for _, bad := range []string{"", "../x", "a/b", `a\b`, ".."} {
		if err := SaveApproved(t.TempDir(), bad, Policy{}); err == nil {
			t.Errorf("SaveApproved accepted key %q", bad)
		}
	}
}

func TestStateDir(t *testing.T) {
	d, err := StateDir()
	if err != nil {
		t.Skip("no state dir on this host:", err)
	}
	if !filepath.IsAbs(d) {
		t.Errorf("StateDir = %q, want absolute", d)
	}
	if runtime.GOOS == "linux" {
		t.Setenv("XDG_STATE_HOME", "/xdg/state")
		if d, _ := StateDir(); d != "/xdg/state" {
			t.Errorf("StateDir with XDG_STATE_HOME = %q", d)
		}
	}
}

func TestReferenceProbeLoosening(t *testing.T) {
	p := Profile{Name: "uat", Engine: EngineSQLite, Path: "/x", Limits: DefaultLimits(false)}
	a := NewPolicy(p, nil, nil)
	p.Limits.ReferenceProbe = 9
	b := NewPolicy(p, nil, nil)
	ch := Diff(a, b)
	if len(ch) != 1 || ch[0].Field != "limits.reference_probe" || !ch[0].Loosens {
		t.Errorf("raising reference_probe: %+v", ch)
	}
	if ch := Diff(b, a); len(ch) != 1 || ch[0].Loosens {
		t.Errorf("lowering reference_probe: %+v", ch)
	}
	// An approved policy from before the limit existed stores 0: the
	// default is no change.
	old := a
	old.Profile.Limits.ReferenceProbe = 0
	if ch := Diff(old, a); len(ch) != 0 {
		t.Errorf("0 -> default reported: %+v", ch)
	}
}

func TestDiffModesAndNewLimits(t *testing.T) {
	p := Profile{Name: "uat", Engine: EngineSQLite, Path: "/x", Limits: DefaultLimits(false)}
	a := NewPolicy(p, []string{"app.users.email"}, nil)
	field := func(changes []Change, f string) *Change {
		for i := range changes {
			if changes[i].Field == f {
				return &changes[i]
			}
		}
		return nil
	}
	b := a.WithModes(map[string]string{"app.users.email": "partial"})
	if c := field(Diff(a, b), "pii.mode"); c == nil || !c.Loosens {
		t.Errorf("redact → partial: %+v", c)
	}
	c := b.WithModes(map[string]string{"app.users.email": "email"})
	if ch := field(Diff(b, c), "pii.mode"); ch == nil || !ch.Loosens {
		t.Errorf("partial → email: %+v", ch)
	}
	if Fingerprint(a) != Fingerprint(a.WithModes(map[string]string{"app.users.email": "redact"})) {
		t.Error("the default mode changes the fingerprint")
	}
	lower := a
	lower.Profile.Limits.KAnonymity = 2
	if ch := field(Diff(a, lower), "limits.k_anonymity"); ch == nil || !ch.Loosens {
		t.Errorf("k 5 → 2: %+v", ch)
	}
	if ch := field(Diff(lower, a), "limits.k_anonymity"); ch == nil || ch.Loosens {
		t.Errorf("k 2 → 5: %+v", ch)
	}
	ttl := a
	ttl.Profile.CredentialsTTL = 20 * 60e9
	if ch := field(Diff(a, ttl), "credentials_ttl"); ch == nil || ch.Loosens {
		t.Errorf("ttl none → 20m: %+v", ch)
	}
	if ch := field(Diff(ttl, a), "credentials_ttl"); ch == nil || !ch.Loosens {
		t.Errorf("ttl 20m → none: %+v", ch)
	}
	cost := a
	cost.Profile.Limits.ExplainCostRefuse = 1000
	if ch := field(Diff(a, cost), "limits.explain_cost_refuse"); ch == nil || ch.Loosens {
		t.Errorf("cost off → 1000: %+v", ch)
	}
	if ch := field(Diff(cost, a), "limits.explain_cost_refuse"); ch == nil || !ch.Loosens {
		t.Errorf("cost 1000 → off: %+v", ch)
	}
}

func TestDiffTLSUpTightens(t *testing.T) {
	a := fullPolicy()
	a.Profile.TLS = TLSRequire
	c := fullPolicy()
	c.Profile.TLS = TLSVerifyFull
	ch := Diff(a, c)
	if len(ch) != 1 || ch[0].Field != "tls" || ch[0].Loosens {
		t.Fatalf("changes = %+v", ch)
	}
}

func TestDiffLegacyApprovedPolicy(t *testing.T) {
	legacy := fullPolicy()
	legacy.Profile.TLS = "" // approved before the setting existed
	cur := fullPolicy()
	cur.Profile.TLS = TLSPrefer
	if ch := Diff(legacy, cur); len(ch) != 0 {
		t.Errorf("prefer vs legacy: %+v", ch)
	}
	cur.Profile.TLS = TLSVerifyFull
	if ch := Diff(legacy, cur); len(ch) != 1 || ch[0].Loosens {
		t.Errorf("verify-full vs legacy: %+v", ch)
	}
}

func TestDiffSSH(t *testing.T) {
	withSSH := func(mut func(*SSHProfile)) Policy {
		p := fullPolicy()
		s := SSHProfile{Host: "b", Port: 22, User: "u", Auth: SSHAuthKey, Key: "~/.ssh/k", Credentials: CredentialsAsk}
		if mut != nil {
			mut(&s)
		}
		p.Profile.SSH = &s
		return p
	}
	a := withSSH(nil)
	for _, c := range []struct {
		field   string
		mut     func(*SSHProfile)
		loosens bool
	}{
		{"ssh.host", func(s *SSHProfile) { s.Host = "evil" }, true},
		{"ssh.port", func(s *SSHProfile) { s.Port = 2222 }, true},
		{"ssh.user", func(s *SSHProfile) { s.User = "root" }, true},
		{"ssh.auth", func(s *SSHProfile) { s.Auth = SSHAuthAgent; s.Key = "" }, true},
		{"ssh.key", func(s *SSHProfile) { s.Key = "/tmp/k" }, true},
		{"ssh.credentials", func(s *SSHProfile) { s.Credentials = CredentialsKeychain }, true},
	} {
		ch := Diff(a, withSSH(c.mut))
		found := false
		for _, x := range ch {
			if x.Field == c.field {
				found = true
				if x.Loosens != c.loosens {
					t.Errorf("%s: loosens = %v", c.field, x.Loosens)
				}
			}
		}
		if !found {
			t.Errorf("%s: not reported in %+v", c.field, ch)
		}
	}
	removed := fullPolicy()
	if ch := Diff(a, removed); len(ch) != 1 || ch[0].Field != "ssh" || !ch[0].Loosens {
		t.Errorf("ssh removed: %+v", ch)
	}
	if ch := Diff(fullPolicy(), fullPolicy()); len(ch) != 0 {
		t.Errorf("no ssh both sides: %+v", ch)
	}
}
