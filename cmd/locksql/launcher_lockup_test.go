//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The agent commands reach the locksql lock `lox up` runs for the
// workspace (lockhub's docs/lox-up.md): its socket volume, named in
// <workspace>/.lockfamily/up.json, mounted read-only once Docker confirms
// it is lox up's. These tests fake Docker's answers for that volume and
// the containers that mount it.

// upLock and upState are lox up's up.json (lockhub's family.UpState),
// with members the launcher does not read, nested as lox up writes them.
type upLock struct {
	Type          string   `json:"type"`
	Profile       string   `json:"profile,omitempty"`
	Socket        string   `json:"socket_volume"`
	GateHome      string   `json:"gate_home_volume,omitempty"`
	GID           string   `json:"client_gid"`
	Devices       bool     `json:"devices,omitempty"`
	RequireDevice []string `json:"require_device,omitempty"`
}

type upState struct {
	Version      int               `json:"version"`
	Project      string            `json:"project"`
	Workspace    string            `json:"workspace"`
	HubNetwork   string            `json:"hub_network"`
	HubURL       string            `json:"hub_url"`
	HubKey       string            `json:"hub_key"`
	FacadeKeys   any               `json:"facade_keys,omitempty"`
	LockHTTPGate int               `json:"lockhttp_gate"`
	Locks        map[string]upLock `json:"locks"`
}

// loxProject is lox up's compose project of the workspace ws.
func loxProject(ws string) string {
	h := sha256.Sum256([]byte(ws))
	return "lockfamily-" + hex.EncodeToString(h[:4])
}

// jsonString is s as Docker's {{json}} prints it (no HTML escaping).
func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// loxUp makes ws a workspace whose locks (instance: type) lox up runs:
// its up.json (the user's, 0644 in a 0755 .lockfamily) and Docker's view
// of each socket volume (lox up's labels; one console container, run by
// compose from lox up's state directory).
func (f *launcherFixture) loxUp(t *testing.T, ws string, locks map[string]string) upState {
	t.Helper()
	p := loxProject(ws)
	s := upState{Version: 1, Project: p, Workspace: ws, HubNetwork: p + "_lockhub", HubURL: "http://lockhub:8443", HubKey: "a2V5",
		FacadeKeys: map[string]any{"v": 1, "keys": []map[string]string{{"id": "deck", "pub": "cHVi"}}}, LockHTTPGate: 1, Locks: map[string]upLock{}}
	for name, typ := range locks {
		l := upLock{Type: typ, Socket: p + "_" + name + "-run", GID: map[string]string{"locksql": "10000", "lockhttp": "10020"}[typ]}
		if typ == "lockhttp" {
			l.GateHome, l.Devices, l.RequireDevice = p+"_"+name+"-gate", true, []string{"write"}
		}
		s.Locks[name] = l
		f.dockerVolume(t, l.Socket, volumeLabels(p, name, typ, ws))
		h := sha256.Sum256([]byte(name))
		id := hex.EncodeToString(h[:])
		f.dockerContainers(t, l.Socket, map[string]string{id: containerLabels(p, f.stateDir(p), "-", "rw ")})
	}
	f.writeUpState(t, ws, s)
	return s
}

// writeUpState writes s as lox up does (json.MarshalIndent, two spaces).
func (f *launcherFixture) writeUpState(t *testing.T, ws string, s upState) {
	t.Helper()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.writeUpFile(t, ws, append(b, '\n'))
}

func (f *launcherFixture) writeUpFile(t *testing.T, ws string, b []byte) {
	t.Helper()
	lf := filepath.Join(ws, ".lockfamily")
	if err := os.MkdirAll(lf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lf, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(lf, "up.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

// stateDir is lox up's state directory of project, for the fixture's
// HOME (no XDG_STATE_HOME).
func (f *launcherFixture) stateDir(project string) string {
	return filepath.Join(f.root, "home", ".local", "state", "lockfamily", project)
}

// volumeLabels is what the launcher's docker volume inspect prints for a
// volume with lox up's labels of the lock name.
func volumeLabels(project, name, typ, ws string) string {
	var out []string
	for _, v := range []string{project, name + "-run", "socket", name, typ, ws} {
		out = append(out, jsonString(v))
	}
	return strings.Join(out, "\n") + "\n"
}

// containerLabels is what the launcher's docker inspect prints for a
// container: compose's project, working directory and files (empty
// strings when compose did not make it), then rw or ro for each of its
// mounts of the volume.
func containerLabels(project, wd, files, mounts string) string {
	return strings.Join([]string{jsonString(project), jsonString(wd), jsonString(files), mounts}, "\n") + "\n"
}

// dockerVolume makes the fake docker know the volume vol, with labels (its
// docker volume inspect output).
func (f *launcherFixture) dockerVolume(t *testing.T, vol, labels string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.fake, "volume-"+vol), []byte(labels), 0o644); err != nil {
		t.Fatal(err)
	}
}

// dockerContainers makes the containers (id: docker inspect output) the
// ones that mount vol.
func (f *launcherFixture) dockerContainers(t *testing.T, vol string, cs map[string]string) {
	t.Helper()
	var ids []string
	for id, out := range cs {
		ids = append(ids, id)
		if err := os.WriteFile(filepath.Join(f.fake, "container-"+id), []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(ids)
	if err := os.WriteFile(filepath.Join(f.fake, "ps-"+vol), []byte(strings.Join(ids, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mountOf is the read-only mount of lox up's socket volume of lock name in
// the workspace ws.
func mountOf(ws, name string) []string {
	return []string{"--mount", "type=volume,src=" + loxProject(ws) + "_" + name + "-run,dst=/run/locksql,readonly"}
}

// hasRun reports whether calls hold a docker run.
func hasRun(calls [][]string) bool {
	for _, c := range calls {
		if len(c) > 0 && c[0] == "run" {
			return true
		}
	}
	return false
}

// The agent commands mount lox up's socket volume read-only on
// /run/locksql, from the workspace or any directory below it, and never
// the fixed locksql-run; the command line the image gets is unchanged.
func TestLauncherLockUpSocket(t *testing.T) {
	f := newLauncherFixture(t)
	for _, args := range [][]string{{"mcp"}, {"status", "--json"}, {"plan", "--profile", "p", "SELECT 1"}, {"run", "--json", "t"}, {"tables"}, {"describe", "x"}, {"request", "tier=write"}, {"logout"}, {"pii", "list"}, {"doctor"}} {
		for _, dir := range []string{f.root, f.project, filepath.Join(f.project, "sub")} {
			out, calls, err := f.run(t, dir, nil, args...)
			if err != nil {
				t.Fatalf("%v from %s: %v\n%s", args, dir, err, out)
			}
			run := lastRun(t, calls)
			if !hasSeq(run, mountOf(f.root, "db")...) {
				t.Errorf("%v from %s: no read-only mount of lox up's socket volume:\n%q", args, dir, run)
			}
			if strings.Contains(strings.Join(run, " "), "locksql-run") {
				t.Errorf("%v: the fixed socket volume: %q", args, run)
			}
			if got, want := strings.Join(imageArgs(run, "locksql")[1:], " "), strings.Join(args, " "); got != want {
				t.Errorf("%v: command %q", args, got)
			}
		}
	}
	// mcp: no terminal.
	_, calls, _ := f.run(t, f.project, nil, "mcp")
	if run := lastRun(t, calls); !hasSeq(run, "-i") || hasSeq(run, "-it") {
		t.Errorf("mcp: %q", run)
	}
}

// Commands that reach no console mount no socket, and need no lox up.
func TestLauncherNoSocketWithoutAConsoleCommand(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.RemoveAll(filepath.Join(f.root, ".lockfamily")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"hub-key", "--instance", "x"}} {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		run := lastRun(t, calls)
		if strings.Contains(strings.Join(run, " "), "/run/locksql") {
			t.Errorf("%v: a socket: %q", args, run)
		}
		if got := imageArgs(run, "locksql")[1:]; strings.Join(got, " ") != strings.Join(args, " ") {
			t.Errorf("%v: command %q", args, got)
		}
	}
}

// Without lox up's state, or with one the launcher cannot trust, an agent
// command says why and what to do (run lox up), exits 2 as a client that
// finds no console, and runs nothing: never the fixed volume instead.
func TestLauncherLockUpRefusals(t *testing.T) {
	upFile := func(f *launcherFixture) string { return filepath.Join(f.root, ".lockfamily", "up.json") }
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *launcherFixture)
		want  string
		args  []string
		// docker's own failures: nothing for lox up to fix
		noHint bool
	}{
		{"no up.json", func(t *testing.T, f *launcherFixture) {
			os.RemoveAll(filepath.Join(f.root, ".lockfamily"))
		}, "no .lockfamily/up.json in ", nil, false},
		{"up.json a link", func(t *testing.T, f *launcherFixture) {
			real := filepath.Join(f.root, "elsewhere.json")
			b, _ := os.ReadFile(upFile(f))
			os.WriteFile(real, b, 0o644)
			os.Remove(upFile(f))
			if err := os.Symlink(real, upFile(f)); err != nil {
				t.Fatal(err)
			}
		}, "up.json is not a regular file (a link?)", nil, false},
		{".lockfamily a link", func(t *testing.T, f *launcherFixture) {
			lf := filepath.Join(f.root, ".lockfamily")
			os.Rename(lf, filepath.Join(f.root, "lf-real"))
			if err := os.Symlink("lf-real", lf); err != nil {
				t.Fatal(err)
			}
		}, ".lockfamily is not a directory (a link?)", nil, false},
		{"up.json group-writable", func(t *testing.T, f *launcherFixture) {
			os.Chmod(upFile(f), 0o664)
		}, "up.json is not yours, or others than you may write it", nil, false},
		{"up.json others-writable", func(t *testing.T, f *launcherFixture) {
			os.Chmod(upFile(f), 0o646)
		}, "up.json is not yours, or others than you may write it", nil, false},
		{".lockfamily group-writable", func(t *testing.T, f *launcherFixture) {
			os.Chmod(filepath.Join(f.root, ".lockfamily"), 0o775)
		}, ".lockfamily is not yours, or others than you may write it", nil, false},
		{"up.json someone else's", func(t *testing.T, f *launcherFixture) {
			// id -u answers another uid: the files are not that user's.
			os.Remove(filepath.Join(f.bin, "id"))
			writeExec(t, filepath.Join(f.bin, "id"), "#!/bin/sh\n[ \"$1\" = -u ] && { echo 4242; exit 0; }\nexit 1\n")
		}, "is not yours, or others than you may write it", nil, false},
		{"another workspace's up.json", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			s.Workspace = f.project
			f.writeUpState(t, f.root, s)
		}, "not this workspace's", nil, false},
		{"another project", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			s.Project = "lockfamily-00000000"
			f.writeUpState(t, f.root, s)
		}, "not this workspace's", nil, false},
		{"not version 1", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			s.Version = 2
			f.writeUpState(t, f.root, s)
		}, "is not lox up's state (version 1)", nil, false},
		{"not lox up's layout", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			b, _ := json.Marshal(s)
			f.writeUpFile(t, f.root, b)
		}, "is not lox up's state (version 1)", nil, false},
		{"an escaped value", func(t *testing.T, f *launcherFixture) {
			b, _ := os.ReadFile(upFile(f))
			b = bytes.Replace(b, []byte(`"type": "locksql"`), []byte(`"type": "lock\u0073ql"`), 1)
			f.writeUpFile(t, f.root, b)
		}, "is not lox up's state (version 1)", nil, false},
		{"no locksql lock", func(t *testing.T, f *launcherFixture) {
			os.RemoveAll(filepath.Join(f.root, ".lockfamily"))
			f.loxUp(t, f.root, map[string]string{"web": "lockhttp"})
		}, "lox up runs no locksql lock in", nil, false},
		{"two locksql locks", func(t *testing.T, f *launcherFixture) {
			f.loxUp(t, f.root, map[string]string{"db": "locksql", "crm-prod": "locksql", "web": "lockhttp"})
		}, "lox up runs several locksql locks in ", nil, false},
		{"an unknown instance", func(t *testing.T, f *launcherFixture) {
			f.loxUp(t, f.root, map[string]string{"db": "locksql", "crm-prod": "locksql"})
		}, "lox up runs no locksql lock nope in", []string{"status", "--instance", "nope"}, false},
		{"an instance of another type", func(t *testing.T, f *launcherFixture) {
			f.loxUp(t, f.root, map[string]string{"db": "locksql", "web": "lockhttp"})
		}, "lox up runs no locksql lock web in", []string{"status", "--instance=web"}, false},
		{"a bad instance name", func(t *testing.T, f *launcherFixture) {}, "--instance: not an instance name", []string{"status", "--instance", "../x"}, false},
		{"another socket volume", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			l := s.Locks["db"]
			l.Socket = s.Project + "_db-home"
			s.Locks["db"] = l
			f.writeUpState(t, f.root, s)
		}, "is not lox up's ", nil, false},
		{"another clients group", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			l := s.Locks["db"]
			l.GID = "10010"
			s.Locks["db"] = l
			f.writeUpState(t, f.root, s)
		}, "clients group 10010, this image's is 10000", nil, false},
		{"no volume", func(t *testing.T, f *launcherFixture) {
			os.Remove(filepath.Join(f.fake, "volume-"+loxProject(f.root)+"_db-run"))
		}, "no volume ", nil, false},
		{"a volume without lox up's labels", func(t *testing.T, f *launcherFixture) {
			f.dockerVolume(t, loxProject(f.root)+"_db-run", volumeLabels(loxProject(f.root), "db", "locksql", f.project))
		}, "is not lox up's socket volume of it (its labels)", nil, false},
		{"a home volume", func(t *testing.T, f *launcherFixture) {
			l := strings.Replace(volumeLabels(loxProject(f.root), "db", "locksql", f.root), `"socket"`, `"home"`, 1)
			f.dockerVolume(t, loxProject(f.root)+"_db-run", l)
		}, "is not lox up's socket volume of it (its labels)", nil, false},
		{"a compose container run from elsewhere", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_db-run", map[string]string{
				strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), "-", "rw "),
				strings.Repeat("b", 64): containerLabels(p, f.root, f.root+"/compose.yaml", "rw "),
			})
		}, "which lox up did not start", nil, false},
		{"a compose container of another file", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_db-run", map[string]string{strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), f.root+"/compose.yaml", "rw ")})
		}, "which lox up did not start", nil, false},
		{"a container docker made, read-write", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_db-run", map[string]string{
				strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), "-", "rw "),
				strings.Repeat("e", 64): containerLabels("", "", "", "ro rw "),
			})
		}, "is mounted read-write by container eeee", nil, false},
		{"a container with no mount by that name", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_db-run", map[string]string{strings.Repeat("e", 64): containerLabels("", "", "", "")})
		}, "is mounted read-write by container eeee", nil, false},
		{"a container docker cannot inspect", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			os.WriteFile(filepath.Join(f.fake, "ps-"+p+"_db-run"), []byte(strings.Repeat("c", 64)+"\n"), 0o644)
		}, "cannot read the containers of", nil, true},
		{"a bad container id", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			os.WriteFile(filepath.Join(f.fake, "ps-"+p+"_db-run"), []byte("*\n"), 0o644)
		}, "cannot read the containers of", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLauncherFixture(t)
			tc.setup(t, f)
			args := tc.args
			if args == nil {
				args = []string{"mcp"}
			}
			out, calls, err := f.run(t, f.project, nil, args...)
			if code := exitCode(err); code != 2 {
				t.Errorf("exit %d (%v), want 2\n%s", code, err, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
			if !tc.noHint && !strings.Contains(out, "lox ") && !strings.Contains(out, "--instance") && !strings.Contains(out, "update locksql") {
				t.Errorf("output says nothing to do:\n%s", out)
			}
			if hasRun(calls) {
				t.Errorf("docker run: %q", calls)
			}
		})
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(interface{ ExitCode() int }); ok {
		return e.ExitCode()
	}
	return -1
}

// Two locksql locks: the error names both; --instance picks one, and the
// launcher takes the option out of the command line.
func TestLauncherLockUpInstance(t *testing.T) {
	f := newLauncherFixture(t)
	f.loxUp(t, f.root, map[string]string{"db": "locksql", "crm-prod": "locksql", "web": "lockhttp"})
	out, _, err := f.run(t, f.project, nil, "mcp")
	if exitCode(err) != 2 || !strings.Contains(out, "(crm-prod db): name one with --instance NAME") {
		t.Errorf("%v\n%s", err, out)
	}
	for _, tc := range []struct {
		name       string
		args, want []string
	}{
		{"crm-prod", []string{"mcp", "--instance", "crm-prod"}, []string{"mcp"}},
		{"db", []string{"mcp", "--instance=db", "--profile", "p"}, []string{"mcp", "--profile", "p"}},
		{"db", []string{"run", "--json", "--instance", "db", "--", "--instance"}, []string{"run", "--json", "--", "--instance"}},
	} {
		out, calls, err := f.run(t, f.project, nil, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", tc.args, err, out)
		}
		run := lastRun(t, calls)
		if !hasSeq(run, mountOf(f.root, tc.name)...) {
			t.Errorf("%v: %q", tc.args, run)
		}
		if got := imageArgs(run, "locksql")[1:]; strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%v: command %q, want %q", tc.args, got, tc.want)
		}
	}
	out, _, err = f.run(t, f.project, nil, "mcp", "--instance")
	if err == nil || !strings.Contains(out, "--instance: name the lock") {
		t.Errorf("%v\n%s", err, out)
	}
}

// lox up's own compose run, with the file on stdin or its state
// directory's compose.yaml, is trusted (XDG_STATE_HOME's state directory
// too); any other container only if it mounts the volume read-only.
func TestLauncherLockUpContainers(t *testing.T) {
	f := newLauncherFixture(t)
	p := loxProject(f.root)
	f.dockerContainers(t, p+"_db-run", map[string]string{
		strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), "-", "rw "),
		strings.Repeat("b", 64): containerLabels(p, f.stateDir(p), f.stateDir(p)+"/compose.yaml", "rw "),
		strings.Repeat("d", 64): containerLabels("", "", "", "ro "),
		strings.Repeat("e", 64): containerLabels(p, f.root, "-", "ro ro "),
	})
	if out, calls, err := f.run(t, f.project, nil, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
		t.Errorf("%v\n%s", err, out)
	}
	state := filepath.Join(f.root, "xdg")
	if out, _, err := f.run(t, f.project, []string{"XDG_STATE_HOME=" + state}, "mcp"); exitCode(err) != 2 || !strings.Contains(out, "which lox up did not start") {
		t.Errorf("XDG_STATE_HOME ignored: %v\n%s", err, out)
	}
	f.dockerContainers(t, p+"_db-run", map[string]string{strings.Repeat("a", 64): containerLabels(p, state+"/lockfamily/"+p, "-", "rw ")})
	if out, calls, err := f.run(t, f.project, []string{"XDG_STATE_HOME=" + state + "/"}, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
		t.Errorf("XDG_STATE_HOME: %v\n%s", err, out)
	}
	// No container at all (lox up down): the volume is still lox up's.
	f.dockerContainers(t, p+"_db-run", nil)
	if out, calls, err := f.run(t, f.project, nil, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
		t.Errorf("%v\n%s", err, out)
	}
}

// The nearest workspace up from here with up.json wins; a sub-project's
// .lockfamily without one is passed over.
func TestLauncherLockUpNearestWorkspace(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, ".lockfamily"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "status"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
		t.Errorf("%v\n%s", err, out)
	}
	f.loxUp(t, f.project, map[string]string{"sql": "locksql"})
	if out, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "status"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.project, "sql")...) {
		t.Errorf("%v\n%s", err, out)
	}
}

// doctor checks the setup without lox up too: with no socket, saying why.
func TestLauncherDoctorWithoutLockUp(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.RemoveAll(filepath.Join(f.root, ".lockfamily")); err != nil {
		t.Fatal(err)
	}
	out, calls, err := f.run(t, f.project, nil, "doctor")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if run := strings.Join(lastRun(t, calls), " "); strings.Contains(run, "/run/locksql") {
		t.Errorf("a socket: %s", run)
	}
	if !strings.Contains(out, "no .lockfamily/up.json in "+f.project) || !strings.Contains(out, "lox up") {
		t.Errorf("output:\n%s", out)
	}
}
