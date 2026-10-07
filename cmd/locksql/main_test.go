package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnknownCommandIsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"bogus"}, &out, &errb); code != 3 {
		t.Fatalf("code = %d, want 3", code)
	}
	if !strings.Contains(errb.String(), "usage") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestVersionPrintsVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "locksql ") {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != exitUsage {
		t.Fatalf("code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb.String(), "usage") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestHelpPrintsUsageAndSucceeds(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		var out, errb bytes.Buffer
		if code := run([]string{arg}, &out, &errb); code != exitOK {
			t.Fatalf("%s: code = %d, want %d", arg, code, exitOK)
		}
		if !strings.Contains(out.String(), "usage") {
			t.Fatalf("%s: stdout = %q", arg, out.String())
		}
	}
}

func TestExitCodeValues(t *testing.T) {
	got := []int{exitOK, exitFail, exitNoConsole, exitUsage}
	want := []int{0, 1, 2, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("exit codes = %v, want %v", got, want)
		}
	}
}

func TestConsoleUsage(t *testing.T) {
	for _, args := range [][]string{{"console"}, {"console", "--profile"}, {"console", "--profile", "uat", "extra"}, {"console", "--bogus"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitUsage {
			t.Fatalf("%v: code = %d, want %d (stderr %q)", args, code, exitUsage, errb.String())
		}
	}
}
