//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// launcherFixture runs scripts/locksql, the host launcher, with a fake
// docker that records each call, one argument per line, a call ending with
// "--". PATH holds only the tools the launcher needs.
type launcherFixture struct {
	root, bin, project, calls, script string
	env                               []string
}

func newLauncherFixture(t *testing.T) *launcherFixture {
	t.Helper()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	f := &launcherFixture{
		root:    root,
		bin:     filepath.Join(root, "bin"),
		project: filepath.Join(root, "project"),
		calls:   filepath.Join(root, "calls"),
	}
	for _, d := range []string{f.bin, filepath.Join(f.project, ".locksql"), filepath.Join(f.project, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"sh", "dirname", "id", "cat", "printf", "awk", "sha256sum", "shasum", "tar", "gzip", "install", "mktemp", "rm", "uname", "sed", "tr", "tail", "grep", "cksum"} {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// docker inspect prints DOCKER_INSPECT; docker run ... version prints
	// the image's version.
	f.fakeDocker(t)
	launcher, err := os.ReadFile(filepath.Join("..", "..", "scripts", "locksql"))
	if err != nil {
		t.Fatal(err)
	}
	f.script = filepath.Join(root, "locksql")
	writeExec(t, f.script, string(launcher))
	f.env = []string{"PATH=" + f.bin, "HOME=" + filepath.Join(root, "home")}
	return f
}

func (f *launcherFixture) fakeDocker(t *testing.T) {
	writeExec(t, filepath.Join(f.bin, "docker"), `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done >> '`+f.calls+`'
echo -- >> '`+f.calls+`'
case "$1" in
inspect) printf '%s\n' "${DOCKER_INSPECT:-}" ;;
run) for a in "$@"; do [ "$a" = version ] && echo "locksql 9.9.9"; done ;;
esac
exit 0
`)
}

// setVersion makes the launcher one a release installed, without digests
// (installed with LOCKSQL_SKIP_COSIGN=1).
func (f *launcherFixture) setVersion(t *testing.T, v string) {
	t.Helper()
	f.setVersionDigests(t, v, "", "")
}

// setVersionDigests makes the launcher one a release installed, with the
// digests of its verified images.
func (f *launcherFixture) setVersionDigests(t *testing.T, v, digest, vault string) {
	t.Helper()
	b, err := os.ReadFile(f.script)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(b), "\nlauncher_version=dev\n", "\nlauncher_version="+v+"\n", 1)
	s = strings.Replace(s, "\nimage_digest=\n", "\nimage_digest="+digest+"\n", 1)
	s = strings.Replace(s, "\nvault_image_digest=\n", "\nvault_image_digest="+vault+"\n", 1)
	writeExec(t, f.script, s)
}

// run runs the launcher with args from dir, and returns its output and the
// docker calls, each a list of arguments.
func (f *launcherFixture) run(t *testing.T, dir string, env []string, args ...string) (string, [][]string, error) {
	t.Helper()
	_ = os.Remove(f.calls)
	cmd := exec.Command(filepath.Join(f.bin, "sh"), append([]string{f.script}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, f.env...), env...)
	out, err := cmd.CombinedOutput()
	var calls [][]string
	b, _ := os.ReadFile(f.calls)
	var cur []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "--" {
			calls = append(calls, cur)
			cur = nil
		} else if l != "" {
			cur = append(cur, l)
		}
	}
	return string(out), calls, err
}

// lastRun is the last `docker run` call.
func lastRun(t *testing.T, calls [][]string) []string {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if len(calls[i]) > 0 && calls[i][0] == "run" {
			return calls[i]
		}
	}
	t.Fatalf("no docker run in %q", calls)
	return nil
}

// hasSeq reports whether args hold seq, in order and adjacent.
func hasSeq(args []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		ok := true
		for j, s := range seq {
			if args[i+j] != s {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// imageArgs are the arguments from the image on: the image and its command
// (the account locksql of --user is not the image locksql).
func imageArgs(args []string, image string) []string {
	for i, a := range args {
		if a == image && (i == 0 || args[i-1] != "--user") {
			return args[i:]
		}
	}
	return nil
}

// The console runs as the console account, in its named container, with
// the socket and home volumes, on the project found up from here.
func TestLauncherConsole(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "console", "--profile", "uat")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	run := lastRun(t, calls)
	for _, seq := range [][]string{
		{"run", "--rm", "-v", f.project + ":" + f.project, "-w", filepath.Join(f.project, "sub")},
		{"--log-driver", "none"}, {"--user", "locksql"},
		{"--add-host=host.docker.internal:host-gateway"}, {"-e", "VAULT_ADDR"}, {"-e", "VAULT_NAMESPACE"},
		{"-v", "locksql-run:/run/locksql"}, {"-v", "locksql-home:/home/locksql"},
		{"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"}, {"--read-only"},
		{"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m"}, {"--pids-limit", "256"}, {"--memory", "1g"},
	} {
		if !hasSeq(run, seq...) {
			t.Errorf("console run lacks %q:\n%q", seq, run)
		}
	}
	if hasSeq(run, "-v", f.project+":"+f.project+":ro") {
		t.Errorf("project read-only without LOCKSQL_READONLY_PROJECT: %q", run)
	}
	if got, want := strings.Join(imageArgs(run, "locksql"), " "), "locksql console --project "+f.project+" --profile uat"; got != want {
		t.Errorf("image and command %q, want %q", got, want)
	}
	if hasSeq(run, "-it") {
		t.Errorf("a terminal without one: %q", run)
	}
}

// LOCKSQL_READONLY_PROJECT=1: the console mounts the project read-only and
// only .locksql/ writable; a .locksql that is not a directory stops it.
func TestLauncherConsoleReadOnlyProject(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, f.project, []string{"LOCKSQL_READONLY_PROJECT=1"}, "console")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	run := lastRun(t, calls)
	dir := filepath.Join(f.project, ".locksql")
	if !hasSeq(run, "-v", f.project+":"+f.project+":ro") || !hasSeq(run, "-v", dir+":"+dir) {
		t.Errorf("%q", run)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	out, calls, err = f.run(t, f.project, []string{"LOCKSQL_READONLY_PROJECT=1"}, "console")
	if err == nil || !strings.Contains(out, "is not a directory") || len(calls) != 0 {
		t.Errorf("symlinked .locksql: %v, calls %q\n%s", err, calls, out)
	}
}

// --project given is kept, not doubled; a stopped console of the same name
// is removed first.
func TestLauncherConsoleProjectAndStaleContainer(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, f.root, []string{"DOCKER_INSPECT=false"}, "console", "--project=/elsewhere")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := strings.Join(imageArgs(lastRun(t, calls), "locksql"), " "); got != "locksql console --project=/elsewhere" {
		t.Errorf("command %q", got)
	}
	removed := false
	for _, c := range calls {
		if len(c) == 2 && c[0] == "rm" && strings.HasPrefix(c[1], "locksql-console-") {
			removed = true
		}
	}
	if !removed {
		t.Errorf("stopped console not removed: %q", calls)
	}
}

// Each command runs with the account and the volumes it needs.
func TestLauncherAccountsPerCommand(t *testing.T) {
	f := newLauncherFixture(t)
	me := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	home := filepath.Join(f.root, "home")
	for _, tc := range []struct {
		args       []string
		want, deny [][]string
	}{
		{[]string{"mcp"}, [][]string{{"-i"}, {"-v", "locksql-run:/run/locksql"}}, [][]string{{"-it"}, {"--user"}, {"-v", "locksql-home:/home/locksql"}}},
		{[]string{"status", "--json"}, [][]string{{"-v", "locksql-run:/run/locksql"}}, [][]string{{"--user"}, {"-v", "locksql-home:/home/locksql"}}},
		{[]string{"plan", "--profile", "p", "SELECT 1"}, [][]string{{"-v", "locksql-run:/run/locksql"}}, [][]string{{"--user"}}},
		{[]string{"doctor"}, [][]string{{"-v", "locksql-run:/run/locksql"}}, [][]string{{"--user"}}},
		{[]string{"doctor", "--fix", "--yes"}, [][]string{{"--user", "0"}}, [][]string{{"-v", "locksql-run:/run/locksql"}}},
		{[]string{"init", "claude"}, [][]string{{"--user", me}, {"-e", "HOME=" + home}, {"-v", home + ":" + home}}, [][]string{{"-v", "locksql-run:/run/locksql"}}},
		{[]string{"config", "export", "--output", "team.json"}, [][]string{{"--user", me}, {"-e", "HOME=" + home}, {"-v", home + ":" + home}}, [][]string{{"-v", "locksql-run:/run/locksql"}}},
		{[]string{"profile", "add"}, [][]string{{"--user", me}, {"-e", "HOME=/tmp"}}, [][]string{{"-v", "locksql-run:/run/locksql"}}},
		{[]string{"stats", "--top", "3"}, [][]string{{"--user", "locksql"}, {"-v", "locksql-home:/home/locksql"}}, [][]string{{"-v", "locksql-run:/run/locksql"}}},
		{[]string{"forget", "--profile", "p"}, [][]string{{"--user", "locksql"}, {"-v", "locksql-home:/home/locksql"}}, nil},
		{nil, [][]string{{"-v", "locksql-run:/run/locksql"}}, [][]string{{"--user"}}},
	} {
		out, calls, err := f.run(t, f.project, nil, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", tc.args, err, out)
		}
		run := lastRun(t, calls)
		for _, seq := range tc.want {
			if !hasSeq(run, seq...) {
				t.Errorf("%v: lacks %q:\n%q", tc.args, seq, run)
			}
		}
		for _, seq := range tc.deny {
			if hasSeq(run, seq...) {
				t.Errorf("%v: has %q:\n%q", tc.args, seq, run)
			}
		}
		if got, want := strings.Join(imageArgs(run, "locksql")[1:], " "), strings.Join(tc.args, " "); got != want {
			t.Errorf("%v: command %q", tc.args, got)
		}
		if !hasSeq(run, "-v", f.project+":"+f.project) {
			t.Errorf("%v: project not mounted: %q", tc.args, run)
		}
	}
}

// Outside any project the directory itself is mounted.
func TestLauncherOutsideAProject(t *testing.T) {
	f := newLauncherFixture(t)
	dir := filepath.Join(f.root, "bin")
	_, calls, err := f.run(t, dir, nil, "status")
	if err != nil {
		t.Fatal(err)
	}
	if run := lastRun(t, calls); !hasSeq(run, "-v", dir+":"+dir, "-w", dir) {
		t.Errorf("%q", run)
	}
}

// The image: a release's launcher runs its own version from the registry,
// with the vault variant on request; LOCKSQL_IMAGE overrides it.
func TestLauncherImage(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "1.2.3")
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{nil, "ghcr.io/davidgodefroid/locksql:1.2.3"},
		{[]string{"LOCKSQL_VAULT=1"}, "ghcr.io/davidgodefroid/locksql:1.2.3-vault"},
		{[]string{"LOCKSQL_IMAGE=my/locksql:x"}, "my/locksql:x"},
	} {
		_, calls, err := f.run(t, f.project, tc.env, "status")
		if err != nil {
			t.Fatal(err)
		}
		if imageArgs(lastRun(t, calls), tc.want) == nil {
			t.Errorf("%v: image %q not run: %q", tc.env, tc.want, lastRun(t, calls))
		}
	}
}

// A launcher installed with verified images runs them by digest.
func TestLauncherRunsTheVerifiedDigest(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersionDigests(t, "1.2.3", fakeDigest, fakeVaultDigest)
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{nil, "ghcr.io/davidgodefroid/locksql@" + fakeDigest},
		{[]string{"LOCKSQL_VAULT=1"}, "ghcr.io/davidgodefroid/locksql@" + fakeVaultDigest},
		{[]string{"LOCKSQL_IMAGE=mine"}, "mine"},
	} {
		_, calls, err := f.run(t, f.project, tc.env, "console")
		if err != nil {
			t.Fatal(err)
		}
		if imageArgs(lastRun(t, calls), tc.want) == nil {
			t.Errorf("%v: %q not run: %q", tc.env, tc.want, lastRun(t, calls))
		}
	}
}

// version prints the launcher's version and its image's.
func TestLauncherVersion(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "1.2.3")
	out, calls, err := f.run(t, f.project, nil, "version")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "locksql launcher 1.2.3 (image ghcr.io/davidgodefroid/locksql:1.2.3)") || !strings.Contains(out, "locksql 9.9.9") {
		t.Errorf("output:\n%s", out)
	}
	if got := imageArgs(lastRun(t, calls), "ghcr.io/davidgodefroid/locksql:1.2.3"); len(got) != 2 || got[1] != "version" {
		t.Errorf("run %q", lastRun(t, calls))
	}
}

// LOCKSQL_DOCKER_ARGS go before the image, split on spaces.
func TestLauncherExtraDockerArgs(t *testing.T) {
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, f.project, []string{"LOCKSQL_DOCKER_ARGS=--network shop"}, "console")
	if err != nil {
		t.Fatal(err)
	}
	run := lastRun(t, calls)
	if !hasSeq(run, "--network", "shop") || len(imageArgs(run, "shop")) <= len(imageArgs(run, "locksql")) {
		t.Errorf("%q", run)
	}
}

func TestLauncherWithoutDocker(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.Remove(filepath.Join(f.bin, "docker")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"status"}, {"console"}} {
		out, _, err := f.run(t, f.project, nil, args...)
		if err == nil || !strings.Contains(out, "docker is required") {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
	}
}

// update replaces the launcher with a release's, after the signature and
// checksum checks, then pulls that release's image.
func TestLauncherUpdate(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "0.9.0")
	rel := newShFixture(t)
	rel.cosign(t, true)
	for _, tool := range []string{"curl", "cosign"} {
		if err := os.Symlink(filepath.Join(rel.bin, tool), filepath.Join(f.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	out, calls, err := f.run(t, f.project, nil, "update", "v"+shVersion)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	b, _ := os.ReadFile(f.script)
	if !strings.Contains(string(b), "\nlauncher_version="+shVersion+"\n") || !strings.Contains(string(b), "\nimage_digest="+fakeDigest+"\n") {
		t.Fatalf("launcher not replaced:\n%s", out)
	}
	if len(calls) != 1 || !hasSeq(calls[0], "pull", "ghcr.io/davidgodefroid/locksql@"+fakeDigest) {
		t.Errorf("calls %q", calls)
	}
	args, _ := os.ReadFile(rel.cosignArgs)
	exact := "--certificate-identity\nhttps://github.com/DavidGodefroid/locksql/.github/workflows/release.yml@refs/tags/v" + shVersion + "\n"
	if strings.Count(string(args), exact) != 3 { // checksums.txt and both images
		t.Errorf("cosign args %s", args)
	}
}

func TestLauncherUpdateRefusesABadSignature(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "0.9.0")
	rel := newShFixture(t)
	rel.cosign(t, false)
	for _, tool := range []string{"curl", "cosign"} {
		if err := os.Symlink(filepath.Join(rel.bin, tool), filepath.Join(f.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	out, calls, err := f.run(t, f.project, nil, "update", "v"+shVersion)
	if err == nil || !strings.Contains(out, "does not verify") || len(calls) != 0 {
		t.Fatalf("%v, calls %q\n%s", err, calls, out)
	}
	b, _ := os.ReadFile(f.script)
	if !strings.Contains(string(b), "\nlauncher_version=0.9.0\n") {
		t.Fatal("launcher replaced")
	}
}

// update refuses a release whose image does not verify, and keeps the
// launcher.
func TestLauncherUpdateRefusesAnUnverifiedImage(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "0.9.0")
	rel := newShFixture(t)
	rel.cosignImages(t, true, false)
	for _, tool := range []string{"curl", "cosign"} {
		if err := os.Symlink(filepath.Join(rel.bin, tool), filepath.Join(f.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	out, calls, err := f.run(t, f.project, nil, "update", "v"+shVersion)
	if err == nil || !strings.Contains(out, "does not verify") || len(calls) != 0 {
		t.Fatalf("%v, calls %q\n%s", err, calls, out)
	}
	b, _ := os.ReadFile(f.script)
	if !strings.Contains(string(b), "\nlauncher_version=0.9.0\n") {
		t.Fatal("launcher replaced")
	}
}

// The launcher and install.sh bind every signature to the release workflow
// run for the exact tag they install: a tag moved to an older release's
// signed files does not verify.
func TestScriptsPinTheExactReleaseTag(t *testing.T) {
	for _, name := range []string{"locksql", "install.sh"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `identity="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag"`) {
			t.Errorf("scripts/%s does not bind the identity to the tag", name)
		}
		if strings.Contains(string(b), "--certificate-identity-regexp") {
			t.Errorf("scripts/%s still accepts any release's signature", name)
		}
	}
}

// Each project gets its own console container, so two can run;
// LOCKSQL_CONSOLE_NAME names it.
func TestLauncherConsoleNamePerProject(t *testing.T) {
	f := newLauncherFixture(t)
	other := filepath.Join(f.root, "other")
	if err := os.MkdirAll(filepath.Join(other, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	name := func(dir string, env ...string) string {
		_, calls, err := f.run(t, dir, env, "console")
		if err != nil {
			t.Fatal(err)
		}
		run := lastRun(t, calls)
		for i, a := range run {
			if a == "--name" && i+1 < len(run) {
				return run[i+1]
			}
		}
		t.Fatalf("no --name: %q", run)
		return ""
	}
	a, b := name(f.project), name(other)
	if !strings.HasPrefix(a, "locksql-console-") || !strings.HasPrefix(b, "locksql-console-") || a == b {
		t.Errorf("names %q and %q", a, b)
	}
	if a != name(filepath.Join(f.project, "sub")) {
		t.Errorf("not stable within a project")
	}
	if got := name(f.project, "LOCKSQL_CONSOLE_NAME=locksql-console"); got != "locksql-console" {
		t.Errorf("LOCKSQL_CONSOLE_NAME: %q", got)
	}
}

// A path with ":" cannot be a docker -v source or target: refused, before
// any docker call.
func TestLauncherRefusesAColonInAPath(t *testing.T) {
	f := newLauncherFixture(t)
	dir := filepath.Join(f.root, "a:b")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, calls, err := f.run(t, dir, nil, "status")
	if err == nil || !strings.Contains(out, `":"`) || len(calls) != 0 {
		t.Errorf("project: %v, calls %q\n%s", err, calls, out)
	}
	out, calls, err = f.run(t, f.project, []string{"HOME=" + dir}, "init", "claude")
	if err == nil || !strings.Contains(out, `":"`) || len(calls) != 0 {
		t.Errorf("home: %v, calls %q\n%s", err, calls, out)
	}
}

// LOCKSQL_DOCKER_ARGS is split on spaces but never globbed.
func TestLauncherDockerArgsNotGlobbed(t *testing.T) {
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, f.project, []string{"LOCKSQL_DOCKER_ARGS=--label x=* --label *"}, "status")
	if err != nil {
		t.Fatal(err)
	}
	if run := lastRun(t, calls); !hasSeq(run, "--label", "x=*", "--label", "*") {
		t.Errorf("%q", run)
	}
}

// VAULT_CACERT reaches the console with its file, mounted read-only; a
// missing file stops it.
func TestLauncherVaultCACert(t *testing.T) {
	f := newLauncherFixture(t)
	ca := filepath.Join(f.project, "vault-ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, calls, err := f.run(t, f.project, []string{"VAULT_CACERT=" + ca}, "console")
	if err != nil {
		t.Fatal(err)
	}
	if run := lastRun(t, calls); !hasSeq(run, "-v", ca+":"+ca+":ro") || !hasSeq(run, "-e", "VAULT_CACERT="+ca) {
		t.Errorf("%q", run)
	}
	out, calls, err := f.run(t, f.project, []string{"VAULT_CACERT=" + ca + ".missing"}, "console")
	if err == nil || !strings.Contains(out, "VAULT_CACERT") || len(calls) != 0 {
		t.Errorf("missing file: %v, calls %q\n%s", err, calls, out)
	}
}

// update takes only a version tag: anything else never reaches a URL or
// the sed that writes the launcher.
func TestLauncherUpdateRefusesABadTag(t *testing.T) {
	f := newLauncherFixture(t)
	f.setVersion(t, "0.9.0")
	for _, tag := range []string{"v1.2", "v1.2.3/x", "v1.2.3;id", "latest", "v1.2.3-rc.1&"} {
		out, calls, err := f.run(t, f.project, nil, "update", tag)
		if err == nil || !strings.Contains(out, "invalid version") || len(calls) != 0 {
			t.Errorf("%q: %v, calls %q\n%s", tag, err, calls, out)
		}
	}
}
