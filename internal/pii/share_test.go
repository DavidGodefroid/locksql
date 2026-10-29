package pii

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestSharedRoundTrip(t *testing.T) {
	var r Rules
	_ = r.AddMode("app.users.email", ModeEmail)
	_ = r.Add("app.users.phone")
	_ = r.AddAllow("app.templates.name")
	s := ToShared(r)
	if len(s.Mask) != 2 || s.Mask[0].Column != "app.users.email" || s.Mask[0].Mode != "email" || s.Mask[1].Mode != "" || len(s.Allow) != 1 {
		t.Fatalf("shared = %+v", s)
	}
	back, err := FromShared(s)
	if err != nil {
		t.Fatal(err)
	}
	if back.Modes["app.users.email"] != ModeEmail || len(back.Mask) != 2 || len(back.Allow) != 1 {
		t.Fatalf("back = %+v", back)
	}
	if _, err := FromShared(config.SharedRules{Mask: []config.SharedRule{{Column: "a.b"}}}); err == nil {
		t.Error("invalid pattern accepted")
	}
	if _, err := FromShared(config.SharedRules{Mask: []config.SharedRule{{Column: "a.b.c", Mode: "hash"}}}); err == nil {
		t.Error("unknown mode accepted")
	}
	if _, err := FromShared(config.SharedRules{Allow: []config.SharedRule{{Column: "a.b.c", Mode: "email"}}}); err == nil {
		t.Error("mode on an allow rule accepted")
	}
}

func TestMergeRules(t *testing.T) {
	var local, in Rules
	_ = local.AddMode("app.users.email", ModeEmail)
	_ = local.Add("app.users.phone")
	_ = local.AddAllow("app.t.name")
	_ = in.AddMode("app.users.email", ModePartial) // conflict: redact wins
	_ = in.AddMode("app.users.phone", ModePartial) // local redact is stricter
	_ = in.Add("app.users.iban")
	_ = in.AddAllow("app.t.name")
	got, conflicts := MergeRules(local, in)
	if strings.Join(got.Mask, ",") != "app.users.email,app.users.iban,app.users.phone" || len(got.Allow) != 1 {
		t.Fatalf("merged = %+v", got)
	}
	if m := got.Modes["app.users.email"]; m != "" && m != ModeRedact {
		t.Errorf("email mode = %q, want redact", m)
	}
	if m := got.Modes["app.users.phone"]; m != "" && m != ModeRedact {
		t.Errorf("phone mode = %q, want redact", m)
	}
	if len(conflicts) != 2 || !strings.Contains(strings.Join(conflicts, "\n"), "app.users.email") {
		t.Errorf("conflicts = %q", conflicts)
	}
	// Same mode on both sides: no conflict, mode kept.
	var a, b Rules
	_ = a.AddMode("x.y.z", ModeEmail)
	_ = b.AddMode("x.y.z", ModeEmail)
	if got, c := MergeRules(a, b); len(c) != 0 || got.Modes["x.y.z"] != ModeEmail {
		t.Errorf("same mode: %+v %q", got, c)
	}
}

func TestLoadSets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LegacyFile), []byte("[[mask]]\ncolumn = \"a.b.c\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shop, _ := SetPath(dir, "shop")
	var r Rules
	_ = r.Add("s.h.op")
	if err := SaveRulesFile(shop, r); err != nil {
		t.Fatal(err)
	}
	// Not a set: wrong name, temp file.
	_ = os.WriteFile(filepath.Join(dir, SetsDir, "Bad Name.toml"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(dir, SetsDir, ".pii-123.toml"), nil, 0o644)
	sets, err := LoadSets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 || len(sets["shop"].Mask) != 1 || len(sets[DefaultSet].Mask) != 1 {
		t.Fatalf("sets = %+v", sets)
	}
}

func TestFileSet(t *testing.T) {
	has := func(sets ...string) func(string) bool {
		return func(s string) bool {
			for _, x := range sets {
				if x == s {
					return true
				}
			}
			return false
		}
	}
	p := config.Profile{Name: "Uat"}
	if got := FileSet(p, has()); got != "uat" {
		t.Errorf("no sets: %q", got)
	}
	if got := FileSet(p, has(DefaultSet)); got != DefaultSet {
		t.Errorf("default only: %q", got)
	}
	if got := FileSet(p, has(DefaultSet, "uat")); got != "uat" {
		t.Errorf("own set: %q", got)
	}
	p.PIIRules = "shop"
	if got := FileSet(p, has(DefaultSet, "uat")); got != "shop" {
		t.Errorf("explicit: %q", got)
	}
}
