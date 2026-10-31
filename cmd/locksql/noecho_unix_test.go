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

// TestDoctorUnknownProfileIsNotEchoed: the same for `locksql doctor`.
func TestDoctorUnknownProfileIsNotEchoed(t *testing.T) {
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		dir := project(t, uatConfig)
		o := cli(t, dir, "", "doctor", "--profile", v)
		if !strings.Contains(o.stdout+o.stderr, "--profile names none of the configured profiles: uat") || strings.Contains(o.stdout+o.stderr, "glsa_Canary") {
			t.Errorf("doctor: code %d\nstdout: %s\nstderr: %s", o.code, o.stdout, o.stderr)
		}
	}
}

// TestUnknownCommandIsNotEchoed: an unknown command is not quoted back.
func TestUnknownCommandIsNotEchoed(t *testing.T) {
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		o := cli(t, t.TempDir(), "", v)
		o.want(t, exitUsage, "unknown command", "usage")
		if strings.Contains(o.stdout+o.stderr, "glsa_Canary") {
			t.Errorf("quotes the command: %s", o.stderr)
		}
	}
}

// A --profile not checked against the project's profiles never reaches
// the handoff's command line, printed or run; the handoff checks it first
// and refuses an unknown one naming the flag only.
func TestHandoffDoesNotEchoUncheckedProfile(t *testing.T) {
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		a := consoleArgs{project: "/p", profile: v}
		if s := strings.Join(a.argv(), " ") + " " + a.command(); strings.Contains(s, "glsa_Canary") || !strings.Contains(s, "--profile "+uncheckedProfile) {
			t.Errorf("unchecked profile passed on: %s", s)
		}
		for _, uid := range []int{1000, 1500} { // the agent's account, an administrator's
			h, ran := fakeHandoff(uid, "sudo")
			e, out := handoffTestEnv(t, h)
			writeHandoffConfig(t, e.cwd, "uat")
			code := runEnv(e, []string{"console", "--profile", v})
			if code != exitUsage || *ran != nil || strings.Contains(out.String(), "glsa_Canary") || !strings.Contains(out.String(), "--profile names none of the project's profiles (uat)") {
				t.Errorf("uid %d: code %d, ran %v\n%s", uid, code, *ran, out)
			}
		}
	}
	// A profile of the project is passed on as given.
	h, ran := fakeHandoff(1500, "sudo")
	e, out := handoffTestEnv(t, h)
	writeHandoffConfig(t, e.cwd, "uat")
	if code := runEnv(e, []string{"console", "--profile", "uat"}); code != exitOK || !strings.Contains(strings.Join(*ran, " "), "--profile uat") {
		t.Errorf("known profile: code %d, ran %v\n%s", code, *ran, out)
	}
}
