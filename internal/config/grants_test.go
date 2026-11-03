package config

import (
	"strings"
	"testing"
	"time"
)

func parseGrantLimits(t *testing.T, limits string) (Limits, error) {
	t.Helper()
	body := "[profiles.app]\nengine=\"mysql\"\nhost=\"/run/db.sock\"\n[profiles.app.limits]\n" + limits
	ps, err := ParseProfiles([]byte(body), "config.toml", t.TempDir())
	if err != nil {
		return Limits{}, err
	}
	return ps["app"].Limits, nil
}

// Decision 4: the grant limits default to 1h, 200 statements, 10000 rows
// and 1 MiB; grant_max_duration = 0 disables grants.
func TestGrantLimitsDefaults(t *testing.T) {
	l, err := parseGrantLimits(t, "")
	if err != nil {
		t.Fatal(err)
	}
	g, on := l.Grants()
	if !on || g != (GrantLimits{Duration: time.Hour, Statements: 200, Rows: 10_000, Bytes: 1 << 20}) {
		t.Fatalf("defaults %+v on %v", g, on)
	}
	for _, off := range []string{`grant_max_duration = 0`, `grant_max_duration = "0"`, `grant_max_duration = "0s"`} {
		l, err := parseGrantLimits(t, off+"\n")
		if err != nil {
			t.Fatalf("%s: %v", off, err)
		}
		if _, on := l.Grants(); on {
			t.Errorf("%s: grants still on", off)
		}
	}
	l, err = parseGrantLimits(t, "grant_max_duration = \"30m\"\ngrant_max_statements = 10\ngrant_max_rows = 500\ngrant_max_bytes = 4096\n")
	if err != nil {
		t.Fatal(err)
	}
	if g, on := l.Grants(); !on || g != (GrantLimits{Duration: 30 * time.Minute, Statements: 10, Rows: 500, Bytes: 4096}) {
		t.Fatalf("set %+v on %v", g, on)
	}
}

func TestGrantLimitsRefused(t *testing.T) {
	for _, bad := range []string{
		`grant_max_duration = "-1m"`, `grant_max_duration = "soon"`, `grant_max_duration = "25h"`, `grant_max_duration = 5`,
		`grant_max_statements = -1`, `grant_max_rows = -1`, `grant_max_bytes = -1`,
	} {
		if _, err := parseGrantLimits(t, bad+"\n"); err == nil || !strings.Contains(err.Error(), "grant_max_") {
			t.Errorf("%s: err %v", bad, err)
		}
	}
}

// Decision 4: raising any grant limit is a loosening (:review); lowering
// one, or turning grants off, is not. Explicit defaults leave the
// fingerprint of a policy approved before grants existed.
func TestGrantLimitsDiff(t *testing.T) {
	p := Profile{Name: "uat", Engine: EngineSQLite, Path: "/x", Limits: DefaultLimits(false)}
	a := NewPolicy(p, nil, nil)
	explicit := a
	explicit.Profile.Limits.GrantMaxDuration, explicit.Profile.Limits.GrantMaxStatements = time.Hour, DefaultGrantMaxStatements
	explicit.Profile.Limits.GrantMaxRows, explicit.Profile.Limits.GrantMaxBytes = DefaultGrantMaxRows, DefaultGrantMaxBytes
	if Fingerprint(explicit) != Fingerprint(a) || len(Diff(a, explicit)) != 0 {
		t.Fatalf("explicit defaults changed the policy: %+v", Diff(a, explicit))
	}
	for _, f := range []struct {
		field string
		set   func(*Limits, int64)
		def   int64
	}{
		{"limits.grant_max_duration", func(l *Limits, v int64) { l.GrantMaxDuration = time.Duration(v) }, int64(time.Hour)},
		{"limits.grant_max_statements", func(l *Limits, v int64) { l.GrantMaxStatements = v }, DefaultGrantMaxStatements},
		{"limits.grant_max_rows", func(l *Limits, v int64) { l.GrantMaxRows = v }, DefaultGrantMaxRows},
		{"limits.grant_max_bytes", func(l *Limits, v int64) { l.GrantMaxBytes = v }, DefaultGrantMaxBytes},
	} {
		up, down := a, a
		f.set(&up.Profile.Limits, f.def*2)
		f.set(&down.Profile.Limits, f.def/2)
		if Fingerprint(up) == Fingerprint(a) {
			t.Errorf("%s: not in the fingerprint", f.field)
		}
		if ch := Diff(a, up); len(ch) != 1 || ch[0].Field != f.field || !ch[0].Loosens {
			t.Errorf("raised %s: %+v", f.field, ch)
		}
		if ch := Diff(a, down); len(ch) != 1 || ch[0].Field != f.field || ch[0].Loosens {
			t.Errorf("lowered %s: %+v", f.field, ch)
		}
	}
	off := a
	off.Profile.Limits.GrantsOff = true
	if ch := Diff(a, off); len(ch) != 1 || ch[0].Field != "limits.grant_max_duration" || ch[0].Loosens {
		t.Errorf("grants off: %+v", ch)
	}
	if ch := Diff(off, a); len(ch) != 1 || !ch[0].Loosens || !strings.Contains(ch[0].Old, "off") {
		t.Errorf("grants on again: %+v", ch)
	}
}

// The grant limits go through a shared profile and the config writer.
func TestGrantLimitsShared(t *testing.T) {
	p := Profile{Name: "uat", Engine: EnginePostgres, Host: "db.example.com", Port: 5432, Credentials: CredentialsAsk,
		Limits: DefaultLimits(false)}
	p.Limits.GrantsOff, p.Limits.GrantMaxRows = true, 77
	s, err := ExportProfile(p, "default", false)
	if err != nil {
		t.Fatal(err)
	}
	if l := s.Limits; l.GrantMaxDuration != "0s" || l.GrantMaxRows != 77 {
		t.Fatalf("shared limits %+v", l)
	}
	f := &ConfigFile{profiles: map[string]rawProfile{"uat": s.raw()}}
	text := string(f.TOML(""))
	if !strings.Contains(text, `grant_max_duration = "0s"`) || !strings.Contains(text, "grant_max_rows = 77") {
		t.Fatalf("written:\n%s", text)
	}
	ps, err := ParseProfiles([]byte(text), "config.toml", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if l := ps["uat"].Limits; !l.GrantsOff || l.GrantMaxRows != 77 {
		t.Fatalf("read back %+v", l)
	}
}
