//go:build unix

package main

import (
	"strings"
	"testing"
)

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
