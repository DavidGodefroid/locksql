package main

import (
	"strings"
	"testing"
)

// TestSetupErrorsDoNotEchoValues: a secret given to `locksql profile add`
// (a flag or a wizard answer) or to `config import --local` never appears
// in the error, which still names the setting.
func TestSetupErrorsDoNotEchoValues(t *testing.T) {
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h"} {
		for key, s := range map[string]profileSpec{
			"profile name": {engine: "postgres", name: v + "!"},
			"engine":       {engine: v},
			"credentials":  {engine: "postgres", credentials: v},
			"vault path":   {engine: "postgres", credentials: "vault", vaultPath: "/" + v},
			"tls":          {engine: "postgres", tls: v},
		} {
			_, err := completeSpec(s)
			switch {
			case err == nil:
				t.Errorf("%s = %s: accepted", key, v)
			case strings.Contains(err.Error(), "glsa_Canary"):
				t.Errorf("%s: error quotes the value: %v", key, err)
			case !strings.Contains(err.Error(), key):
				t.Errorf("%s: error does not name the setting: %v", key, err)
			}
		}
		// Without '=', the whole argument may be the value.
		_, err := parseLocals([]string{v})
		if err == nil || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), "--local") {
			t.Errorf("--local %s: err = %v", v, err)
		}
	}
}
