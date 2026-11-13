//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runs are the `docker run` calls of calls.
func runs(calls [][]string) [][]string {
	var rs [][]string
	for _, c := range calls {
		if len(c) > 0 && c[0] == "run" {
			rs = append(rs, c)
		}
	}
	return rs
}

// mountsManaged reports whether run mounts a managed directory at all.
func mountsManaged(run []string, dir string) bool {
	for _, a := range run {
		if strings.Contains(a, "/etc/lockfamily") || strings.Contains(a, dir) {
			return true
		}
	}
	return false
}

// withoutManaged is run without the managed directory's -v argument.
func withoutManaged(run []string, dir string) []string {
	var rest []string
	for i := 0; i < len(run); i++ {
		if i+1 < len(run) && run[i] == "-v" && run[i+1] == dir+":/etc/lockfamily:ro" {
			i++
			continue
		}
		rest = append(rest, run[i])
	}
	return rest
}

// The machine's managed directory, when there is one, is mounted read-only
// on /etc/lockfamily in every container (as lox run mounts it in its
// locks), before the image, the other arguments unchanged; without one,
// nothing is.
func TestLauncherManagedMount(t *testing.T) {
	f := newLauncherFixture(t)
	f.fakeUname(t, "Linux")
	commands := [][]string{
		{"managed", "show"}, {"managed", "check", "--profile", "prod"}, {"doctor"}, {"doctor", "--fix", "--yes"},
		{"profile", "add", "p"}, {"init", "claude"}, {"config", "export"}, {"mcp"}, {"status"}, {"run", "x"},
		{"version"}, {"help"},
	}
	without := map[string][][]string{}
	for _, args := range commands {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		rs := runs(calls)
		if len(rs) == 0 {
			t.Fatalf("%v: no docker run in %q", args, calls)
		}
		for _, r := range rs {
			if mountsManaged(r, f.managed) {
				t.Errorf("%v: no managed directory, but mounted: %q", args, r)
			}
		}
		without[strings.Join(args, " ")] = rs
	}
	if err := os.MkdirAll(f.managed, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range commands {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		rs, before := runs(calls), without[strings.Join(args, " ")]
		if len(rs) != len(before) {
			t.Fatalf("%v: %d docker runs, %d without the managed directory", args, len(rs), len(before))
		}
		for i, r := range rs {
			if !hasSeq(r, "-v", f.managed+":/etc/lockfamily:ro") {
				t.Errorf("%v: managed directory not mounted read-only on /etc/lockfamily: %q", args, r)
			}
			if img := imageArgs(r, "locksql"); img == nil || mountsManaged(img, f.managed) {
				t.Errorf("%v: mount after the image: %q", args, r)
			}
			if got := withoutManaged(r, f.managed); strings.Join(got, "\n") != strings.Join(before[i], "\n") {
				t.Errorf("%v: %q, without the directory %q", args, r, before[i])
			}
		}
	}
	// doctor --fix's root repair (docker_run_then) mounts it too.
	if err := os.Remove(filepath.Join(f.bin, "id")); err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(f.bin, "id"), `#!/bin/sh
case "$*" in
-u | -g) echo 4242 ;;
-un) echo someone ;;
*) exit 1 ;;
esac
`)
	out, calls, err := f.run(t, f.project, nil, "doctor", "--fix", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	rs := runs(calls)
	if len(rs) != 2 || !hasSeq(rs[0], "--user", "0") {
		t.Fatalf("root repair: %q", calls)
	}
	for _, r := range rs {
		if !hasSeq(r, "-v", f.managed+":/etc/lockfamily:ro") {
			t.Errorf("doctor --fix: not mounted: %q", r)
		}
	}
}

// The managed directory is the one of the host's OS: macOS' on Darwin,
// /etc/lockfamily elsewhere.
func TestLauncherManagedDirPerOS(t *testing.T) {
	for _, tc := range []struct {
		uname string
		line  int
	}{{"Linux", 0}, {"Darwin", 1}} {
		f := newLauncherFixture(t)
		launcher, err := os.ReadFile(filepath.Join("..", "..", "scripts", "locksql"))
		if err != nil {
			t.Fatal(err)
		}
		// Only this OS's directory is the fixture's: the other one, if the
		// launcher picked it, is not there (or the host's, never this one).
		writeExec(t, f.script, withManagedDir(t, string(launcher), f.managed, managedLines[tc.line]))
		f.fakeUname(t, tc.uname)
		if err := os.MkdirAll(f.managed, 0o755); err != nil {
			t.Fatal(err)
		}
		out, calls, err := f.run(t, f.project, nil, "managed", "show")
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.uname, err, out)
		}
		if run := lastRun(t, calls); !hasSeq(run, "-v", f.managed+":/etc/lockfamily:ro") {
			t.Errorf("%s: %q", tc.uname, run)
		}
	}
}

// A managed path that is not a directory, or that docker -v cannot mount,
// stops the launcher before docker runs; a link to a directory is mounted.
func TestLauncherManagedRefused(t *testing.T) {
	f := newLauncherFixture(t)
	f.fakeUname(t, "Linux")
	if err := os.MkdirAll(filepath.Dir(f.managed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.managed, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, calls, err := f.run(t, f.project, nil, "managed", "show")
	if err == nil || !strings.Contains(out, f.managed+" is not a directory") || len(calls) != 0 {
		t.Errorf("a file: %v, calls %q\n%s", err, calls, out)
	}
	// A link to a directory: what the image checks (root owns it) is the
	// directory it leads to.
	if err := os.Remove(f.managed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), f.managed); err != nil {
		t.Fatal(err)
	}
	out, calls, err = f.run(t, f.project, nil, "managed", "show")
	if err != nil || !hasSeq(lastRun(t, calls), "-v", f.managed+":/etc/lockfamily:ro") {
		t.Errorf("a link to a directory: %v, %q\n%s", err, calls, out)
	}
	// A dangling link: refused, not skipped.
	if err := os.Remove(f.managed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.root, "nowhere"), f.managed); err != nil {
		t.Fatal(err)
	}
	out, calls, err = f.run(t, f.project, nil, "managed", "show")
	if err == nil || !strings.Contains(out, "is not a directory") || len(calls) != 0 {
		t.Errorf("a dangling link: %v, calls %q\n%s", err, calls, out)
	}
	// A ":" in the path.
	b, err := os.ReadFile(f.script)
	if err != nil {
		t.Fatal(err)
	}
	colon := filepath.Join(f.root, "a:b")
	if err := os.MkdirAll(colon, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExec(t, f.script, strings.ReplaceAll(string(b), `managed_dir="`+f.managed+`"`, `managed_dir="`+colon+`"`))
	out, calls, err = f.run(t, f.project, nil, "managed", "show")
	if err == nil || !strings.Contains(out, "which docker -v cannot mount") || len(calls) != 0 {
		t.Errorf("a \":\": %v, calls %q\n%s", err, calls, out)
	}
}
