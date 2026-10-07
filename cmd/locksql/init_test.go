package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	root := t.TempDir()
	sub := filepath.Join(root, "pkg")
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := runEnv(env{stdout: &out, stderr: &errb, cwd: sub}, []string{"init", "claude", "codex"})
	if code != exitOK {
		t.Fatalf("code = %d, stderr %s", code, errb.String())
	}
	for _, rel := range []string{".mcp.json", ".claude/skills/locksql/SKILL.md", "AGENTS.md", ".locksql/config.toml"} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("%s not written at the git root: %v", rel, err)
		}
	}
	s := out.String()
	for _, want := range []string{"created    .mcp.json", "[mcp_servers.locksql]", "locksql console --profile"} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout lacks %q:\n%s", want, s)
		}
	}
	// .locksql/config.toml is shared by both agents and reported once.
	if n := strings.Count(s, ".locksql/config.toml\n"); n != 1 {
		t.Errorf("config reported %d times:\n%s", n, s)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("wrote into HOME: %v", entries)
	}

	out.Reset()
	code = runEnv(env{stdout: &out, stderr: &errb, cwd: sub}, []string{"init", "claude"})
	if code != exitOK || !strings.Contains(out.String(), "unchanged") || strings.Contains(out.String(), "created") {
		t.Fatalf("second run: code %d\n%s", code, out.String())
	}
}

func TestInitUsage(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"init"}, {"init", "vim"}, {"init", "claude", "vim"}, {"init", "--bogus", "claude"}} {
		var out, errb bytes.Buffer
		if code := runEnv(env{stdout: &out, stderr: &errb, cwd: dir}, args); code != exitUsage {
			t.Errorf("%v: code = %d, want %d", args, code, exitUsage)
		}
		if !strings.Contains(errb.String(), "claude|codex|cursor|gemini") {
			t.Errorf("%v: stderr = %q", args, errb.String())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("usage errors wrote files: %v", entries)
	}
}
