package console

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// A profile without pii_rules whose set another profile also uses shares
// its rules by accident: the console says so at start.
func TestImplicitSharingNotice(t *testing.T) {
	prof := func(name, set string) config.Profile { return config.Profile{Name: name, PIIRules: set} }
	cases := []struct {
		name     string
		profiles []config.Profile
		want     string // "" for no notice; else a part of it
	}{
		{"alone", []config.Profile{prof("uat", "")}, ""},
		{"explicit sharing", []config.Profile{prof("uat", "shop"), prof("prod", "shop")}, ""},
		{"case fold", []config.Profile{prof("Prod", ""), prof("prod", "")}, `"prod"`},
		{"named default", []config.Profile{prof("default", "")}, "default"},
		{"another's explicit set", []config.Profile{prof("shop", ""), prof("uat", "shop")}, "uat"},
		{"explicit default", []config.Profile{prof("uat", "default")}, ""},
	}
	for _, c := range cases {
		all := map[string]config.Profile{}
		for _, p := range c.profiles {
			all[p.Name] = p
		}
		p := c.profiles[0]
		set := config.RuleSetOf(p)
		got := implicitSharingNotice(p, set, all)
		if c.name == "alone" {
			// Kept on the migrated default set: the migration notice said so.
			if n := implicitSharingNotice(p, "default", all); n != "" {
				t.Errorf("migrated profile: %q", n)
			}
		}
		switch {
		case c.want == "" && got != "":
			t.Errorf("%s: unexpected notice %q", c.name, got)
		case c.want != "" && (!strings.Contains(got, c.want) || !strings.Contains(got, "pii_rules")):
			t.Errorf("%s: notice %q, want it to name %s and pii_rules", c.name, got, c.want)
		}
	}
}
