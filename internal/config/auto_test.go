package config

import (
	"strings"
	"testing"
)

func parseAutoProfile(t *testing.T, auto string) (Profile, error) {
	t.Helper()
	body := "[profiles.dev]\nengine = \"sqlite\"\npath = \"dev.db\"\n" + auto
	ps, err := ParseProfiles([]byte(body), "config.toml", t.TempDir())
	if err != nil {
		return Profile{}, err
	}
	return ps["dev"], nil
}

func TestAutoRulesDefaults(t *testing.T) {
	p, err := parseAutoProfile(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Auto != nil {
		t.Fatalf("stored %+v for a profile without auto", p.Auto)
	}
	want := AutoRules{Connect: AutoAsk, Read: AutoAuto, Write: AutoAsk, DDL: AutoAsk, Unmask: AutoAsk}
	if got := p.AutoRules(); got != want {
		t.Fatalf("defaults %+v, want %+v", got, want)
	}
	if s := p.AutoRules().String(); s != "connect ask · read auto · write ask · ddl ask · unmask ask (default)" {
		t.Fatalf("String %q", s)
	}
}

func TestAutoRulesParse(t *testing.T) {
	for _, tc := range []struct {
		name, auto string
		want       AutoRules
		stored     bool
	}{
		{"preset full-auto", `auto = "full-auto"` + "\n", FullAutoRules, true},
		{"preset default", `auto = "default"` + "\n", DefaultAutoRules, false},
		{"table", "[profiles.dev.auto]\nconnect = \"ask\"\nread = \"auto\"\nwrite = \"ask\"\nddl = \"deny\"\n",
			AutoRules{Connect: AutoAsk, Read: AutoAuto, Write: AutoAsk, DDL: AutoDeny, Unmask: AutoAsk}, true},
		{"defaults spelled out", "[profiles.dev.auto]\nconnect = \"ask\"\nread = \"auto\"\nwrite = \"ask\"\nddl = \"ask\"\nunmask = \"ask\"\n",
			DefaultAutoRules, false},
		{"preset overridden", "[profiles.dev.auto]\npreset = \"full-auto\"\nddl = \"ask\"\n",
			AutoRules{Connect: AutoAuto, Read: AutoAuto, Write: AutoAuto, DDL: AutoAsk, Unmask: AutoAuto}, true},
		{"inline table", "auto = { write = \"auto\", unmask = \"deny\" }\n",
			AutoRules{Connect: AutoAsk, Read: AutoAuto, Write: AutoAuto, DDL: AutoAsk, Unmask: AutoDeny}, true},
		{"read denied", "auto = { read = \"deny\" }\n",
			AutoRules{Connect: AutoAsk, Read: AutoDeny, Write: AutoAsk, DDL: AutoAsk, Unmask: AutoAsk}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseAutoProfile(t, tc.auto)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.AutoRules(); got != tc.want {
				t.Fatalf("rules %+v, want %+v", got, tc.want)
			}
			if (p.Auto != nil) != tc.stored {
				t.Fatalf("stored %+v, want stored %v", p.Auto, tc.stored)
			}
		})
	}
}

func TestAutoRulesRefused(t *testing.T) {
	for _, tc := range []struct{ name, auto, want string }{
		{"unknown preset", `auto = "yolo"` + "\n", "auto: unknown preset"},
		{"unknown key", "[profiles.dev.auto]\nconnect = \"auto\"\nexec = \"auto\"\n", `auto: unknown key "exec"`},
		{"unknown value", "[profiles.dev.auto]\nwrite = \"always\"\n", "auto.write: want auto, ask or deny"},
		{"not a string", "[profiles.dev.auto]\nwrite = true\n", "auto.write: want auto, ask or deny"},
		{"unknown preset in table", "[profiles.dev.auto]\npreset = \"all\"\n", "auto: unknown preset"},
		{"preset not a string", "[profiles.dev.auto]\npreset = 1\n", "auto.preset: want a string"},
		{"a number", "auto = 3\n", "auto: want a preset"},
		{"an array", "auto = [\"full-auto\"]\n", "auto: want a preset"},
		{"key with escapes", "[profiles.dev.auto]\n\"\\u001b[2J\" = \"auto\"\n", `auto: unknown key "?[2J"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAutoProfile(t, tc.auto)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), `profile "dev"`) {
				t.Fatalf("error %v, want %q for profile dev", err, tc.want)
			}
			if strings.Contains(err.Error(), "yolo") || strings.Contains(err.Error(), "always") || strings.Contains(err.Error(), "\x1b") {
				t.Fatalf("error quotes the value: %v", err)
			}
		})
	}
}

// Every action × value: the action a statement is decided by, and the
// value it gets.
func TestAutoRuleOfEveryActionAndValue(t *testing.T) {
	values := []AutoValue{AutoAuto, AutoAsk, AutoDeny}
	for _, v := range values {
		for _, a := range AutoActions {
			r := DefaultAutoRules
			*r.field(a) = v
			if got := r.Get(a); got != v {
				t.Errorf("%s=%s: Get %s", a, v, got)
			}
			for _, tc := range []struct {
				class  Tier
				unmask bool
				action AutoAction
			}{
				{TierRead, false, ActionRead}, {TierWrite, false, ActionWrite},
				{TierDDL, false, ActionDDL}, {TierAdmin, false, ActionDDL},
			} {
				act, got := AutoRuleOf(r, tc.class, tc.unmask)
				if act != tc.action || got != r.Get(tc.action) {
					t.Errorf("%s=%s, class %s: %s %s, want %s %s", a, v, tc.class, act, got, tc.action, r.Get(tc.action))
				}
			}
			// An unmasked statement of any class takes the stricter of its
			// class's action and unmask.
			for class, own := range map[Tier]AutoAction{TierRead: ActionRead, TierWrite: ActionWrite, TierDDL: ActionDDL, TierAdmin: ActionDDL} {
				act, got := AutoRuleOf(r, class, true)
				wantAct := own
				if r.Get(ActionUnmask).rank() <= r.Get(own).rank() {
					wantAct = ActionUnmask
				}
				if act != wantAct || got != r.Get(wantAct) {
					t.Errorf("%s=%s, unmasked %s: %s %s, want %s", a, v, class, act, got, wantAct)
				}
			}
		}
	}
	if _, v := AutoRuleOf(FullAutoRules, TierRead, true); v != AutoAuto {
		t.Errorf("full-auto unmasked read: %s", v)
	}
	if a, v := AutoRuleOf(DefaultAutoRules, TierRead, true); a != ActionUnmask || v != AutoAsk {
		t.Errorf("default unmasked read: %s %s", a, v)
	}
}

// An unmasked write (INSERT ... RETURNING, a data-modifying CTE) sends its
// rows back in clear: a looser write rule never lets them through an
// unmask rule that asks or denies.
func TestAutoRuleOfUnmaskedWrite(t *testing.T) {
	for _, tc := range []struct {
		r      AutoRules
		class  Tier
		action AutoAction
		value  AutoValue
	}{
		{AutoRules{Write: AutoAuto, Unmask: AutoDeny}, TierWrite, ActionUnmask, AutoDeny},
		{AutoRules{Write: AutoAuto, Unmask: AutoAsk}, TierWrite, ActionUnmask, AutoAsk},
		{AutoRules{Write: AutoAuto, Unmask: AutoAuto}, TierWrite, ActionUnmask, AutoAuto},
		{AutoRules{Write: AutoDeny, Unmask: AutoAuto}, TierWrite, ActionWrite, AutoDeny},
		{AutoRules{Write: AutoAsk, Unmask: AutoAuto}, TierWrite, ActionWrite, AutoAsk},
		{AutoRules{DDL: AutoAuto, Unmask: AutoDeny}, TierDDL, ActionUnmask, AutoDeny},
		{AutoRules{DDL: AutoAuto, Unmask: AutoAsk}, TierAdmin, ActionUnmask, AutoAsk},
	} {
		a, v := AutoRuleOf(tc.r.Effective(), tc.class, true)
		if a != tc.action || v != tc.value {
			t.Errorf("%s, unmasked %s: %s %s, want %s %s", tc.r, tc.class, a, v, tc.action, tc.value)
		}
		// Masked, the class's own rule decides.
		own := ActionWrite
		if tc.class >= TierDDL {
			own = ActionDDL
		}
		if a, v := AutoRuleOf(tc.r.Effective(), tc.class, false); a != own || v != tc.r.Get(own) {
			t.Errorf("%s, masked %s: %s %s", tc.r, tc.class, a, v)
		}
	}
}

func TestAutoRulesDiff(t *testing.T) {
	base := func(r *AutoRules) Policy {
		p := Profile{Name: "prod", Engine: EngineSQLite, Path: "/x.db", Production: true, Limits: DefaultLimits(true), Auto: r}
		return NewPolicy(p, nil, nil)
	}
	full := FullAutoRules
	def := DefaultAutoRules
	strict := AutoRules{DDL: AutoDeny, Unmask: AutoDeny}
	// Spelled-out defaults and no auto are the same policy.
	if Fingerprint(base(nil)) != Fingerprint(base(&def)) {
		t.Fatal("spelled-out defaults change the fingerprint")
	}
	if ch := Diff(base(nil), base(&def)); len(ch) != 0 {
		t.Fatalf("defaults spelled out: %+v", ch)
	}
	loosen := Diff(base(nil), base(&full))
	if len(loosen) != 4 { // connect, write, ddl, unmask; read already auto
		t.Fatalf("to full-auto: %+v", loosen)
	}
	for _, c := range loosen {
		if !c.Loosens || !strings.HasPrefix(c.Field, "auto.") || c.New != "auto" {
			t.Errorf("to full-auto: %+v", c)
		}
	}
	tighten := Diff(base(&full), base(nil))
	for _, c := range tighten {
		if c.Loosens {
			t.Errorf("from full-auto to the defaults loosens: %+v", c)
		}
	}
	for _, c := range Diff(base(&strict), base(nil)) {
		if !c.Loosens || c.Old != "deny" || c.New != "ask" {
			t.Errorf("deny to ask: %+v", c)
		}
	}
	for _, c := range Diff(base(nil), base(&strict)) {
		if c.Loosens {
			t.Errorf("ask to deny loosens: %+v", c)
		}
	}
	// A policy saved before auto rules existed reads as the defaults.
	if Canonical(base(&def)).Profile.Auto != nil {
		t.Fatal("canonical keeps spelled-out defaults")
	}
}

// The auto rules survive the config writer and a shared config.
func TestAutoRulesRoundTrip(t *testing.T) {
	for _, auto := range []string{
		`auto = "full-auto"` + "\n",
		"[profiles.p.auto]\npreset = \"full-auto\"\nddl = \"deny\"\n",
		"[profiles.p.auto]\nwrite = \"auto\"\nunmask = \"deny\"\n",
	} {
		body := "[profiles.p]\nengine = \"postgres\"\nhost = \"db.internal\"\n" + auto
		want, err := ParseProfiles([]byte(body), "c.toml", "/")
		if err != nil {
			t.Fatal(err)
		}
		f, err := ParseConfigFile([]byte(body), "c.toml", "/")
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseProfiles(f.TOML(""), "c.toml", "/")
		if err != nil {
			t.Fatalf("%v\n%s", err, f.TOML(""))
		}
		if got["p"].AutoRules() != want["p"].AutoRules() {
			t.Errorf("writer: %+v, want %+v\n%s", got["p"].AutoRules(), want["p"].AutoRules(), f.TOML(""))
		}
		sp, err := ExportProfile(want["p"], "p", false)
		if err != nil {
			t.Fatal(err)
		}
		g := &ConfigFile{profiles: map[string]rawProfile{"p": sp.raw()}}
		shared, err := ParseProfiles(g.TOML(""), "c.toml", "/")
		if err != nil {
			t.Fatalf("%v\n%s", err, g.TOML(""))
		}
		if shared["p"].AutoRules() != want["p"].AutoRules() {
			t.Errorf("share: %+v, want %+v", shared["p"].AutoRules(), want["p"].AutoRules())
		}
	}
}
