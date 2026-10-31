package pii

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// TestRuleErrorsDoNotEchoValues: a secret pasted as a rule's column or mode
// never appears in the error, which names the entry.
func TestRuleErrorsDoNotEchoValues(t *testing.T) {
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h", "a.b.glsa_Canary c"} {
		check := func(what, key string, err error) {
			t.Helper()
			switch {
			case err == nil:
				t.Errorf("%s = %s: accepted", what, v)
			case strings.Contains(err.Error(), "glsa_Canary"):
				t.Errorf("%s: error quotes the value: %v", what, err)
			case !strings.Contains(err.Error(), key):
				t.Errorf("%s: error does not name %s: %v", what, key, err)
			}
		}
		for what, c := range map[string]struct{ body, key string }{
			"mask column": {"[[mask]]\ncolumn = %q\n", "[[mask]] entry 1"},
			"mask mode":   {"[[mask]]\ncolumn = \"a.b.c\"\nmode = %q\n", "[[mask]] entry 1"},
			"allow":       {"[[allow]]\ncolumn = \"a.b.c\"\n[[allow]]\ncolumn = %q\n", "[[allow]] entry 2"},
		} {
			path := filepath.Join(t.TempDir(), "pii.toml")
			if err := os.WriteFile(path, fmt.Appendf(nil, c.body, v), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadRulesFile(path)
			check(what, c.key, err)
		}
		_, err := FromShared(config.SharedRules{Mask: []config.SharedRule{{Column: v}}})
		check("shared mask column", "mask entry 1", err)
		_, err = FromShared(config.SharedRules{Mask: []config.SharedRule{{Column: "a.b.c", Mode: v}}})
		check("shared mask mode", "mask entry 1", err)
		_, err = FromShared(config.SharedRules{Allow: []config.SharedRule{{Column: v}}})
		check("shared allow column", "allow entry 1", err)
		_, err = FromShared(config.SharedRules{Allow: []config.SharedRule{{Column: v, Mode: v}}})
		check("shared allow mode", "allow entry 1", err)
		var r Rules
		if err := r.Add(v); err == nil || strings.Contains(err.Error(), "glsa_Canary") {
			t.Errorf("Add: %v", err)
		}
	}
}
