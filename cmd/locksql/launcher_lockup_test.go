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

// The agent commands reach the locksql lock `lox run` runs for the
// workspace (lockhub's docs/lox-run.md): its socket volume, named in
// <workspace>/.lockfamily/up.json, mounted read-only once Docker confirms
// it is lox run's. These tests fake Docker's answers for that volume and
// the containers that mount it.

// upLock and upState are lox run's up.json (lockhub's family.UpState),
// with members the launcher does not read, nested as lox run writes them.
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

// loxProject is lox run's compose project of the workspace ws.
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

// loxUp makes ws a workspace whose locks (instance: type) lox run runs:
// its up.json (the user's, 0644 in a 0755 .lockfamily) and Docker's view
// of each socket volume (lox run's labels; one console container, run by
// compose from lox run's state directory) and home volume.
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
		f.dockerVolume(t, p+"_"+name+"-home", homeLabels(p, name))
		h := sha256.Sum256([]byte(name))
		id := hex.EncodeToString(h[:])
		f.dockerContainers(t, l.Socket, map[string]string{id: containerLabels(p, f.stateDir(p), "-", "rw ")})
	}
	f.writeUpState(t, ws, s)
	return s
}

// writeUpState writes s as lox run does (json.MarshalIndent, two spaces).
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

// stateDir is lox run's state directory of project, for the fixture's
// HOME (no XDG_STATE_HOME).
func (f *launcherFixture) stateDir(project string) string {
	return filepath.Join(f.root, "home", ".local", "state", "lockfamily", project)
}

// volumeLabels is what the launcher's docker volume inspect prints for a
// volume with lox run's labels of the lock name.
func volumeLabels(project, name, typ, ws string) string {
	var out []string
	for _, v := range []string{project, name + "-run", "socket", name, typ, ws} {
		out = append(out, jsonString(v))
	}
	return strings.Join(out, "\n") + "\n"
}

// homeLabels is what the launcher's docker volume inspect prints for lox
// run's home volume of the lock name: compose's labels only.
func homeLabels(project, name string) string {
	return jsonString(project) + "\n" + jsonString(name+"-home") + "\n"
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

// mountOf is the read-only mount of lox run's socket volume of lock name in
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

// The agent commands mount lox run's socket volume read-only on
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
				t.Errorf("%v from %s: no read-only mount of lox run's socket volume:\n%q", args, dir, run)
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

// Commands that reach no console mount no socket, and need no lox run.
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

// Without lox run's state, or with one the launcher cannot trust, an agent
// command says why and what to do (run lox run), exits 2 as a client that
// finds no console, and runs nothing: never the fixed volume instead.
func TestLauncherLockUpRefusals(t *testing.T) {
	upFile := func(f *launcherFixture) string { return filepath.Join(f.root, ".lockfamily", "up.json") }
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *launcherFixture)
		want  string
		args  []string
		// docker's own failures: nothing for lox run to fix
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
		}, "is not lox run's state (version 1)", nil, false},
		{"not lox run's layout", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			b, _ := json.Marshal(s)
			f.writeUpFile(t, f.root, b)
		}, "is not lox run's state (version 1)", nil, false},
		{"an escaped value", func(t *testing.T, f *launcherFixture) {
			b, _ := os.ReadFile(upFile(f))
			b = bytes.Replace(b, []byte(`"type": "locksql"`), []byte(`"type": "lock\u0073ql"`), 1)
			f.writeUpFile(t, f.root, b)
		}, "is not lox run's state (version 1)", nil, false},
		{"no locksql lock", func(t *testing.T, f *launcherFixture) {
			os.RemoveAll(filepath.Join(f.root, ".lockfamily"))
			f.loxUp(t, f.root, map[string]string{"web": "lockhttp"})
		}, "lox run runs no locksql lock in", nil, false},
		{"two locksql locks, one with no volume", func(t *testing.T, f *launcherFixture) {
			f.loxUp(t, f.root, map[string]string{"db": "locksql", "crm-prod": "locksql", "web": "lockhttp"})
			os.Remove(filepath.Join(f.fake, "volume-"+loxProject(f.root)+"_crm-prod-run"))
		}, "lock crm-prod: no volume ", nil, false},
		{"an unknown instance", func(t *testing.T, f *launcherFixture) {
			f.loxUp(t, f.root, map[string]string{"db": "locksql", "crm-prod": "locksql"})
		}, "lox run runs no locksql lock nope in", []string{"status", "--instance", "nope"}, false},
		{"an instance of another type", func(t *testing.T, f *launcherFixture) {
			f.loxUp(t, f.root, map[string]string{"db": "locksql", "web": "lockhttp"})
		}, "lox run runs no locksql lock web in", []string{"status", "--instance=web"}, false},
		{"a bad instance name", func(t *testing.T, f *launcherFixture) {}, "--instance: not an instance name", []string{"status", "--instance", "../x"}, false},
		{"another socket volume", func(t *testing.T, f *launcherFixture) {
			s := f.loxUp(t, f.root, map[string]string{"db": "locksql"})
			l := s.Locks["db"]
			l.Socket = s.Project + "_db-home"
			s.Locks["db"] = l
			f.writeUpState(t, f.root, s)
		}, "is not lox run's ", nil, false},
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
		{"a volume without lox run's labels", func(t *testing.T, f *launcherFixture) {
			f.dockerVolume(t, loxProject(f.root)+"_db-run", volumeLabels(loxProject(f.root), "db", "locksql", f.project))
		}, "is not lox run's socket volume of it (its labels)", nil, false},
		{"a home volume", func(t *testing.T, f *launcherFixture) {
			l := strings.Replace(volumeLabels(loxProject(f.root), "db", "locksql", f.root), `"socket"`, `"home"`, 1)
			f.dockerVolume(t, loxProject(f.root)+"_db-run", l)
		}, "is not lox run's socket volume of it (its labels)", nil, false},
		{"a compose container run from elsewhere", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_db-run", map[string]string{
				strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), "-", "rw "),
				strings.Repeat("b", 64): containerLabels(p, f.root, f.root+"/compose.yaml", "rw "),
			})
		}, "which lox run did not start", nil, false},
		{"a compose container of another file", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_db-run", map[string]string{strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), f.root+"/compose.yaml", "rw ")})
		}, "which lox run did not start", nil, false},
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

// Two locksql locks: without --instance both are mounted, each on
// /run/locksql/<instance> and listed in LEA_LOCKSQL_INSTANCES, as lea mounts
// them (#206); --instance picks one, and the launcher takes the option out
// of the command line.
func TestLauncherLockUpInstance(t *testing.T) {
	f := newLauncherFixture(t)
	f.loxUp(t, f.root, map[string]string{"db": "locksql", "crm-prod": "locksql", "web": "lockhttp"})
	for _, args := range [][]string{{"mcp"}, {"status"}, {"tables", "--profile", "p"}} {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		run := lastRun(t, calls)
		for _, name := range []string{"crm-prod", "db"} {
			if !hasSeq(run, "--mount", "type=volume,src="+loxProject(f.root)+"_"+name+"-run,dst=/run/locksql/"+name+",readonly") {
				t.Errorf("%v: no mount of %s: %q", args, name, run)
			}
		}
		if !hasSeq(run, "-e", "LEA_LOCKSQL_INSTANCES=crm-prod db") || hasSeq(run, mountOf(f.root, "db")...) {
			t.Errorf("%v: %q", args, run)
		}
		if strings.Contains(strings.Join(run, " "), "_web-") {
			t.Errorf("%v: the lockhttp lock: %q", args, run)
		}
		if got := imageArgs(run, "locksql")[1:]; strings.Join(got, " ") != strings.Join(args, " ") {
			t.Errorf("%v: command %q", args, got)
		}
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
	out, _, err := f.run(t, f.project, nil, "mcp", "--instance")
	if err == nil || !strings.Contains(out, "--instance: name the lock") {
		t.Errorf("%v\n%s", err, out)
	}
}

// lox run's own compose run, with the file on stdin or its state
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
	if out, _, err := f.run(t, f.project, []string{"XDG_STATE_HOME=" + state}, "mcp"); exitCode(err) != 2 || !strings.Contains(out, "which lox run did not start") {
		t.Errorf("XDG_STATE_HOME ignored: %v\n%s", err, out)
	}
	f.dockerContainers(t, p+"_db-run", map[string]string{strings.Repeat("a", 64): containerLabels(p, state+"/lockfamily/"+p, "-", "rw ")})
	if out, calls, err := f.run(t, f.project, []string{"XDG_STATE_HOME=" + state + "/"}, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
		t.Errorf("XDG_STATE_HOME: %v\n%s", err, out)
	}
	// No container at all (lox run down): the volume is still lox run's.
	f.dockerContainers(t, p+"_db-run", nil)
	if out, calls, err := f.run(t, f.project, nil, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
		t.Errorf("%v\n%s", err, out)
	}
}

// The nearest workspace up from here with up.json wins; a sub-project's
// .lockfamily without one is passed over, as long as the sub-project has
// no .locksql/config.toml of its own (TestLauncherLockUpOwnLocksql).
func TestLauncherLockUpNearestWorkspace(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, ".lockfamily"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "status"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
		t.Errorf("%v\n%s", err, out)
	}
	// A workspace of its own (lox init there) is served on its own.
	if err := os.WriteFile(filepath.Join(f.project, ".locksql", "config.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.loxUp(t, f.project, map[string]string{"sql": "locksql"})
	if out, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "status"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.project, "sql")...) {
		t.Errorf("%v\n%s", err, out)
	}
}

// A sub-project with its own .locksql/config.toml below the workspace: its
// clients key their socket on the sub-project, lox run's console on the
// workspace. The agent commands say so, exit 2 and mount nothing; from a
// directory without .locksql the workspace's volume is still mounted.
func TestLauncherLockUpOwnLocksql(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, ".locksql", "config.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	want := f.project + " has its own .locksql/ below the workspace " + f.root + ": lox run's console serves the workspace's .locksql only; run locksql from " + f.root + ", or make " + f.project + " a workspace of its own (lox init there)"
	for _, args := range [][]string{{"status"}, {"mcp"}} {
		for _, dir := range []string{f.project, filepath.Join(f.project, "sub")} {
			out, calls, err := f.run(t, dir, nil, args...)
			if code := exitCode(err); code != 2 {
				t.Errorf("%v from %s: exit %d (%v), want 2\n%s", args, dir, code, err, out)
			}
			if !strings.Contains(out, want) {
				t.Errorf("%v from %s: output lacks %q:\n%s", args, dir, want, out)
			}
			if hasRun(calls) {
				t.Errorf("%v from %s: docker run: %q", args, dir, calls)
			}
		}
	}
	other := filepath.Join(f.root, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{f.root, other} {
		if out, calls, err := f.run(t, dir, nil, "status"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "db")...) {
			t.Errorf("from %s: %v\n%s", dir, err, out)
		}
	}
}

// A workspace path with &, < or >, which lox run's state escapes: the
// launcher still refuses it, and says why.
func TestLauncherLockUpEscapedWorkspace(t *testing.T) {
	f := newLauncherFixture(t)
	ws := filepath.Join(f.root, "a&b")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	f.loxUp(t, ws, map[string]string{"db": "locksql"})
	if b, _ := os.ReadFile(filepath.Join(ws, ".lockfamily", "up.json")); !bytes.Contains(b, []byte(`a\u0026b`)) {
		t.Fatalf("up.json does not escape &:\n%s", b)
	}
	out, calls, err := f.run(t, ws, nil, "status")
	if code := exitCode(err); code != 2 {
		t.Errorf("exit %d (%v), want 2\n%s", code, err, out)
	}
	if want := "the workspace's path holds &, < or >, which lox run's state escapes: locksql cannot check it; move or rename the workspace"; !strings.Contains(out, want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
	if strings.Contains(out, "is not lox run's state") {
		t.Errorf("misleading output:\n%s", out)
	}
	if hasRun(calls) {
		t.Errorf("docker run: %q", calls)
	}
}

// doctor checks the setup without lox run too: with no socket, saying why.
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
	if !strings.Contains(out, "no .lockfamily/up.json in "+f.project) || !strings.Contains(out, "lox run") {
		t.Errorf("output:\n%s", out)
	}
}

// homeOf is the mount of lox run's home volume of lock name in the
// workspace ws, on the console account's home.
func homeOf(ws, name string) []string {
	return []string{"--mount", "type=volume,src=" + loxProject(ws) + "_" + name + "-home,dst=/home/locksql"}
}

// stats and forget run as the console account with the home volume lox run
// gives the lock's console (#220): the only lock's, or the one --instance
// names, which the launcher takes out of the command line; several and no
// --instance, they say so. Without lox run's state, the volume
// locksql-home of a console started by hand, but only when it exists:
// never a new, empty one.
func TestLauncherStatsForgetHome(t *testing.T) {
	f := newLauncherFixture(t)
	for _, args := range [][]string{{"stats"}, {"stats", "--top", "3"}, {"forget", "--profile", "p"}} {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		run := lastRun(t, calls)
		if !hasSeq(run, homeOf(f.root, "db")...) || !hasSeq(run, "--user", "locksql") {
			t.Errorf("%v: not the lock's home: %q", args, run)
		}
		if j := strings.Join(run, " "); strings.Contains(j, "locksql-home") || strings.Contains(j, "/run/locksql") {
			t.Errorf("%v: %q", args, run)
		}
		if got := imageArgs(run, "locksql")[1:]; strings.Join(got, " ") != strings.Join(args, " ") {
			t.Errorf("%v: command %q", args, got)
		}
	}

	// Several locksql locks: --instance picks one.
	f.loxUp(t, f.root, map[string]string{"db": "locksql", "crm-prod": "locksql", "web": "lockhttp"})
	for _, tc := range []struct {
		name       string
		args, want []string
	}{
		{"crm-prod", []string{"stats", "--instance", "crm-prod"}, []string{"stats"}},
		{"db", []string{"forget", "--instance=db", "--profile", "p"}, []string{"forget", "--profile", "p"}},
	} {
		out, calls, err := f.run(t, f.project, nil, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", tc.args, err, out)
		}
		run := lastRun(t, calls)
		if !hasSeq(run, homeOf(f.root, tc.name)...) {
			t.Errorf("%v: %q", tc.args, run)
		}
		if got := imageArgs(run, "locksql")[1:]; strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%v: command %q, want %q", tc.args, got, tc.want)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"stats"}, "several locksql locks in " + f.root + " (crm-prod db): name one with --instance NAME"},
		{[]string{"forget", "--instance", "web"}, "lox run runs no locksql lock web in "},
		{[]string{"stats", "--instance", "nope"}, "lox run runs no locksql lock nope in "},
	} {
		out, calls, err := f.run(t, f.project, nil, tc.args...)
		if exitCode(err) != 2 || !strings.Contains(out, tc.want) || hasRun(calls) {
			t.Errorf("%v: exit %d, run %v:\n%s", tc.args, exitCode(err), hasRun(calls), out)
		}
	}

	// The lock's home volume missing, or not lox run's: refused.
	p := loxProject(f.root)
	if err := os.Remove(filepath.Join(f.fake, "volume-"+p+"_db-home")); err != nil {
		t.Fatal(err)
	}
	out, calls, err := f.run(t, f.project, nil, "stats", "--instance", "db")
	if exitCode(err) != 2 || !strings.Contains(out, "lock db: no volume "+p+"_db-home: run `lox run`") || hasRun(calls) {
		t.Errorf("no home volume: exit %d, run %v:\n%s", exitCode(err), hasRun(calls), out)
	}
	for _, labels := range []string{homeLabels("other", "db"), homeLabels(p, "crm-prod"), "\"\"\n\"\"\n"} {
		f.dockerVolume(t, p+"_db-home", labels)
		out, calls, err := f.run(t, f.project, nil, "forget", "--instance", "db")
		if exitCode(err) != 2 || !strings.Contains(out, "volume "+p+"_db-home is not lox run's home volume") || hasRun(calls) {
			t.Errorf("labels %q: exit %d, run %v:\n%s", labels, exitCode(err), hasRun(calls), out)
		}
	}

	// No lox run: the hand-started console's locksql-home when it exists.
	if err := os.RemoveAll(filepath.Join(f.root, ".lockfamily")); err != nil {
		t.Fatal(err)
	}
	out, calls, err = f.run(t, f.project, nil, "stats")
	if exitCode(err) != 2 || !strings.Contains(out, "no .lockfamily/up.json in ") || hasRun(calls) {
		t.Errorf("no lox run, no locksql-home: exit %d, run %v:\n%s", exitCode(err), hasRun(calls), out)
	}
	f.dockerVolume(t, "locksql-home", "")
	for _, args := range [][]string{{"stats"}, {"forget", "--profile", "p"}} {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		run := lastRun(t, calls)
		if !hasSeq(run, "--mount", "type=volume,src=locksql-home,dst=/home/locksql") || !strings.Contains(out, "a console started by hand") {
			t.Errorf("%v: %q\n%s", args, run, out)
		}
	}
	// A broken up.json is no fallback.
	f.writeUpFile(t, f.root, []byte("{}\n"))
	out, calls, err = f.run(t, f.project, nil, "stats")
	if exitCode(err) != 2 || !strings.Contains(out, "is not lox run's state") || hasRun(calls) {
		t.Errorf("broken up.json: exit %d, run %v:\n%s", exitCode(err), hasRun(calls), out)
	}
}
