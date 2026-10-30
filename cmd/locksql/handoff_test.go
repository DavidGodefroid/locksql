//go:build unix

package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

// fakeHandoff runs as uid, with the helpers in onPath; *ran gets the argv
// the console would be exec'd with.
func fakeHandoff(uid int, onPath ...string) (*handoffEnv, *[]string) {
	var ran []string
	return &handoffEnv{
		goos:     "linux",
		uid:      func() int { return uid },
		userName: func(uid int) string { return map[int]string{1000: "alice", 1500: "admin"}[uid] },
		serviceUID: func(*sysconf.Config) (int, error) {
			return 900, nil
		},
		clientAllowed: func(_ *sysconf.Config, uid int) bool { return uid == 1000 },
		lookPath: func(n string) (string, error) {
			if slices.Contains(onPath, n) {
				return "/usr/bin/" + n, nil
			}
			return "", exec.ErrNotFound
		},
		systemd: func() bool { return true },
		binary:  func() (string, error) { return "/usr/local/bin/locksql", nil },
		exec: func(argv []string) error {
			ran = argv
			return nil
		},
	}, &ran
}

func handoffTestEnv(t *testing.T, h *handoffEnv) (env, *bytes.Buffer) {
	var out bytes.Buffer
	return env{stdout: &out, stderr: &out, cwd: t.TempDir(), tty: true, handoff: h,
		sys: func() (*sysconf.Config, error) { return separatedSys(), nil }}, &out
}

// The agent's account never gets the console in its own terminal: it is
// told the one command to run in the console account's session.
func TestConsoleFromAgentAccountIsNotHandedOff(t *testing.T) {
	h, ran := fakeHandoff(1000, "sudo", "machinectl", "su")
	e, out := handoffTestEnv(t, h)
	if code := runEnv(e, []string{"console", "--profile", "dev"}); code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	if *ran != nil {
		t.Fatalf("handed off from the agent's account: %v", *ran)
	}
	for _, want := range []string{"belongs to alice", "group locksql-clients", "the database password",
		"locksql console --project " + e.cwd + " --profile dev"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestConsoleHandoffHelpers(t *testing.T) {
	cases := []struct {
		onPath []string
		goos   string
		want   []string
	}{
		{[]string{"sudo", "machinectl", "su"}, "linux", []string{"/usr/bin/sudo", "-u", "locksql", "-H", "--", "/usr/local/bin/locksql"}},
		{[]string{"machinectl", "su"}, "linux", []string{"/usr/bin/machinectl", "shell", "--quiet", "locksql@", "/usr/local/bin/locksql"}},
		{[]string{"machinectl", "su"}, "darwin", []string{"/usr/bin/su", "-l", "locksql", "-c"}},
		{[]string{"su"}, "linux", []string{"/usr/bin/su", "-l", "locksql", "-c"}},
	}
	for _, c := range cases {
		h, ran := fakeHandoff(1500, c.onPath...)
		h.goos = c.goos
		e, out := handoffTestEnv(t, h)
		proj := filepath.Join(e.cwd, "it's")
		if code := runEnv(e, []string{"console", "--project", proj, "--auto", "--show-results"}); code != exitOK {
			t.Fatalf("%v: code %d\n%s", c.onPath, code, out)
		}
		got := *ran
		if len(got) < len(c.want) || !slices.Equal(got[:len(c.want)], c.want) {
			t.Fatalf("%v on %s: argv %q, want prefix %q", c.onPath, c.goos, got, c.want)
		}
		rest := got[len(c.want):]
		args := []string{"console", "--project", proj, "--auto", "--show-results"}
		if c.want[0] == "/usr/bin/su" {
			// One shell command line, every word quoted.
			want := "'/usr/local/bin/locksql' 'console' '--project' '" + strings.ReplaceAll(proj, "'", `'\''`) + "' '--auto' '--show-results'"
			if len(rest) != 1 || rest[0] != want {
				t.Errorf("su command %q, want %q", rest, want)
			}
		} else if !slices.Equal(rest, args) {
			t.Errorf("console args %q, want %q", rest, args)
		}
		if !strings.Contains(out.String(), "Opening the console as locksql through ") {
			t.Errorf("no notice:\n%s", out)
		}
	}
}

func TestConsoleHandoffRefusals(t *testing.T) {
	h, ran := fakeHandoff(1500)
	e, out := handoffTestEnv(t, h)
	if code := runEnv(e, []string{"console"}); code != exitFail || *ran != nil {
		t.Fatalf("no helper: code %d, ran %v\n%s", code, *ran, out)
	}
	if !strings.Contains(out.String(), "no sudo, machinectl or su") || !strings.Contains(out.String(), "locksql console --project "+e.cwd) {
		t.Errorf("no helper:\n%s", out)
	}

	h, ran = fakeHandoff(1500, "sudo")
	h.binary = func() (string, error) { return "", errors.New("no root-owned locksql binary") }
	e, out = handoffTestEnv(t, h)
	if code := runEnv(e, []string{"console"}); code != exitFail || *ran != nil {
		t.Fatalf("untrusted binary: code %d, ran %v\n%s", code, *ran, out)
	}
	if !strings.Contains(out.String(), "no root-owned locksql binary") {
		t.Errorf("untrusted binary:\n%s", out)
	}
}

// The console account, same-user mode and a system config that does not
// load are not handed off: the console runs (or refuses) here.
func TestConsoleHandoffNotHandled(t *testing.T) {
	h, _ := fakeHandoff(900, "sudo")
	e, _ := handoffTestEnv(t, h)
	if _, handled := handoffConsole(e, consoleArgs{project: e.cwd}); handled {
		t.Error("console account handed off")
	}
	e.sys = func() (*sysconf.Config, error) { return nil, nil }
	if _, handled := handoffConsole(e, consoleArgs{project: e.cwd}); handled {
		t.Error("same-user mode handed off")
	}
	e.sys = func() (*sysconf.Config, error) { return nil, errors.New("bad") }
	if _, handled := handoffConsole(e, consoleArgs{project: e.cwd}); handled {
		t.Error("broken system config handed off")
	}
}

// Without --project the console serves the project of the current
// directory, so the handoff names its root.
func TestConsoleProjectDefaultsToProjectRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locksql", "config.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := consoleProject(sub, ""); err != nil || got != root {
		t.Errorf("consoleProject = %q, %v; want %q", got, err, root)
	}
	if got, _ := consoleProject(sub, "x"); !filepath.IsAbs(got) {
		t.Errorf("--project not made absolute: %q", got)
	}
}

// The handoff forwards every hub flag, --hub-plain-http included (#111):
// the console-account command parses back to the same hub options.
func TestHandoffForwardsHubPlainHTTP(t *testing.T) {
	for _, plain := range []bool{false, true} {
		hub := kconsole.HubOptions{URL: "http://lockhub:8443", KeyFile: "/home/u/.lockfamily/hub.pub", Instance: "sql-1", PlainHTTP: plain}
		argv := consoleArgs{project: "/p", hub: hub}.argv()
		if got := slices.Contains(argv, "--hub-plain-http"); got != plain {
			t.Fatalf("plain %v: argv %q", plain, argv)
		}
		fs := flag.NewFlagSet("console", flag.ContinueOnError)
		fs.String("project", "", "")
		var back kconsole.HubOptions
		back.Register(fs)
		if err := fs.Parse(argv[1:]); err != nil {
			t.Fatal(err)
		}
		if back != hub {
			t.Fatalf("parsed back %+v, want %+v", back, hub)
		}
	}
	if c := (consoleArgs{project: "/p", hub: kconsole.HubOptions{URL: "http://lockhub:8443", KeyFile: "/k", Instance: "i", PlainHTTP: true}}).command(); !strings.Contains(c, " --hub-plain-http") {
		t.Fatalf("command %q", c)
	}
}

// Every flag lockkit's HubOptions registers reaches the console account:
// a flag lockkit adds later fails here rather than being dropped (#111).
func TestHandoffForwardsEveryHubFlag(t *testing.T) {
	fs := flag.NewFlagSet("hub", flag.ContinueOnError)
	var hub kconsole.HubOptions
	hub.Register(fs)
	fs.VisitAll(func(f *flag.Flag) {
		v := "x"
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			v = "true"
		}
		if err := fs.Set(f.Name, v); err != nil {
			t.Fatal(err)
		}
	})
	argv := consoleArgs{project: "/p", hub: hub}.argv()
	fs.VisitAll(func(f *flag.Flag) {
		if !slices.Contains(argv, "--"+f.Name) {
			t.Errorf("--%s is not forwarded: %q", f.Name, argv)
		}
	})
}
