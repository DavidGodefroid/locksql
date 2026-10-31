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
		// Base64 padding ends the left side at the first '='.
		for _, arg := range []string{v, v + "==", "dev.tls_cax=" + v} {
			_, err := parseLocals([]string{arg})
			if err == nil || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), "--local") {
				t.Errorf("--local %s: err = %v", arg, err)
			}
		}
		if _, err := parseAllowedUIDs("1000," + v); err == nil || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), "--allowed-uids") {
			t.Errorf("--allowed-uids: err = %v", err)
		}
	}
}

// TestUnknownProfileIsNotEchoed: a --profile naming no configured profile
// (a token or a URL pasted in the wrong place) is not quoted back.
func TestUnknownProfileIsNotEchoed(t *testing.T) {
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		dir := project(t, uatConfig)
		for _, args := range [][]string{{"mcp", "--profile", v}, {"status", "--profile", v}} {
			o := cli(t, dir, "", args...)
			o.want(t, exitUsage, "unknown profile", "--profile", "uat")
			if strings.Contains(o.stdout+o.stderr, "glsa_Canary") {
				t.Errorf("%s: quotes the value: %s", args[0], o.stderr)
			}
		}
		e, _, errb := forgetEnv(t, true)
		if code := runEnv(e, []string{"forget", "--profile", v}); code != exitUsage || !strings.Contains(errb.String(), "--profile") || strings.Contains(errb.String(), "glsa_Canary") {
			t.Errorf("forget: code = %d, stderr = %q", code, errb.String())
		}
		a := newMachine(t)
		a.write(t, teamConfig, nil)
		o := runIn(t, "", false, "config", "export", "--profile", v)
		if o.code == exitOK || !strings.Contains(o.stderr, "--profile 1") || strings.Contains(o.stdout+o.stderr, "glsa_Canary") {
			t.Errorf("config export: code = %d, stderr = %q", o.code, o.stderr)
		}
	}
}
