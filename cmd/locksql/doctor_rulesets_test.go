//go:build unix

package main

import (
	"io/fs"
	"os"
	"strings"
	"testing"
)

// The console account owns .locksql/pii, where it writes the PII rule
// sets, and reads the set of every project profile.
func TestProjectChecksRuleSets(t *testing.T) {
	dir := func(mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{"d", fs.ModeDir | mode}, uid, uid}
	}
	file := func(name string, mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{name, mode}, uid, uid}
	}
	const p = "/home/alice/proj/.locksql"
	files := map[string]ownedInfo{
		"/":                     dir(0o755, 0),
		"/home":                 dir(0o755, 0),
		"/home/alice":           dir(0o755, 1000),
		"/home/alice/proj":      dir(0o755, 1000),
		p:                       dir(0o755, 900),
		p + "/config.toml":      file("config.toml", 0o644, 1000),
		p + "/pii":              dir(0o755, 1000), // cloned by alice
		p + "/pii/shop.toml":    file("shop.toml", 0o600, 1000),
		p + "/pii/billing.toml": file("billing.toml", 0o644, 900),
		p + "/pii/other.toml":   file("other.toml", 0o600, 1000), // no profile uses it
	}
	var ran [][]string
	d := accessDoctor(files, &ran)
	d.readFile = func(path string) ([]byte, error) {
		if path != p+"/config.toml" {
			return nil, fs.ErrNotExist
		}
		return []byte("[profiles.shop-dev]\nengine = \"mariadb\"\nhost = \"db\"\npii_rules = \"shop\"\n[profiles.billing]\nengine = \"mariadb\"\nhost = \"db2\"\n"), nil
	}
	svc := svcAccount{name: "locksql", uid: 900, gids: []int{900}}
	byTitle := map[string]check{}
	for _, c := range projectChecks(d, "/home/alice/proj", svc, 1000) {
		byTitle[c.title] = c
	}
	sets := byTitle["project .locksql/pii"]
	if sets.state != checkFail || sets.repair == nil || sets.repair.root != giveDirScript(p+"/pii", 900) {
		t.Errorf("project .locksql/pii: %+v", sets)
	}
	shop := byTitle["project pii/shop.toml"]
	if shop.state != checkFail || shop.repair == nil || shop.repair.apply == nil || !strings.Contains(shop.fix, "chmod 0644") {
		t.Errorf("project pii/shop.toml: %+v", shop)
	}
	if _, ok := byTitle["project pii/other.toml"]; ok {
		t.Error("a set no profile uses was checked")
	}
	if c, ok := byTitle["project pii/billing.toml"]; ok && c.state != checkOK {
		t.Errorf("readable set: %+v", c)
	}

	// Once repaired, every check passes.
	files[p+"/pii"] = dir(0o755, 900)
	files[p+"/pii/shop.toml"] = file("shop.toml", 0o644, 1000)
	for _, c := range projectChecks(d, "/home/alice/proj", svc, 1000) {
		if c.state != checkOK {
			t.Errorf("after repair: %+v", c)
		}
	}
}

// A .locksql/pii that is a symbolic link gets no repair.
func TestProjectChecksSymlinkedRuleSets(t *testing.T) {
	dir := func(mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{"d", fs.ModeDir | mode}, uid, uid}
	}
	const p = "/home/alice/proj/.locksql"
	files := map[string]ownedInfo{
		"/": dir(0o755, 0), "/home": dir(0o755, 0), "/home/alice": dir(0o755, 1000),
		"/home/alice/proj": dir(0o755, 1000), p: dir(0o755, 900), p + "/pii": dir(0o755, 900),
	}
	var ran [][]string
	d := accessDoctor(files, &ran)
	d.lstat = func(path string) (os.FileInfo, error) {
		if path == p+"/pii" {
			return ownedInfo{fakeInfo{"pii", fs.ModeSymlink | 0o777}, 1000, 1000}, nil
		}
		return d.stat(path)
	}
	svc := svcAccount{name: "locksql", uid: 900, gids: []int{900}}
	for _, c := range projectChecks(d, "/home/alice/proj", svc, 1000) {
		if c.title == "project .locksql/pii" {
			if c.state != checkFail || c.repair != nil || !strings.Contains(c.detail, "symbolic link") {
				t.Errorf("symlinked pii: %+v", c)
			}
			return
		}
	}
	t.Error("no project .locksql/pii check")
}

// Under lock up the console keeps its PII rule sets in its own directory
// (LOCKSQL_PII_DIR): a .locksql and .locksql/pii the console does not own
// are a warning, not a failure, when doctor has the variable or the project
// is a lock up workspace (#130); the directory in force is checked. Without
// either, the ownership check fails as before; writable by others fails
// either way.
func TestProjectChecksPIIDirInForce(t *testing.T) {
	dir := func(mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{"d", fs.ModeDir | mode}, uid, uid}
	}
	const p = "/home/alice/proj/.locksql"
	const inForce = "/home/locksql/pii-rules"
	newFiles := func() map[string]ownedInfo {
		return map[string]ownedInfo{
			"/": dir(0o755, 0), "/home": dir(0o755, 0), "/home/alice": dir(0o755, 1000),
			"/home/alice/proj":   dir(0o755, 1000),
			p:                    dir(0o755, 1000),
			p + "/config.toml":   {fakeInfo{"config.toml", 0o644}, 1000, 1000},
			p + "/pii":           dir(0o755, 1000), // the human's
			p + "/pii/shop.toml": {fakeInfo{"shop.toml", 0o644}, 1000, 1000},
		}
	}
	svc := svcAccount{name: "locksql", uid: 900, gids: []int{900}}
	var statErr map[string]error
	var links map[string]bool
	run := func(files map[string]ownedInfo, env map[string]string) map[string]check {
		var ran [][]string
		d := accessDoctor(files, &ran)
		stat := d.stat
		d.stat = func(path string) (os.FileInfo, error) {
			if err := statErr[path]; err != nil {
				return nil, err
			}
			return stat(path)
		}
		d.lstat = func(path string) (os.FileInfo, error) {
			if links[path] {
				return ownedInfo{fakeInfo{"l", fs.ModeSymlink | 0o777}, 1000, 1000}, nil
			}
			return d.stat(path)
		}
		d.getenv = func(k string) string { return env[k] }
		out := map[string]check{}
		for _, c := range projectChecks(d, "/home/alice/proj", svc, 1000) {
			out[c.title] = c
		}
		return out
	}
	env := map[string]string{"LOCKSQL_PII_DIR": inForce}

	// Not under lock up: as before.
	if c := run(newFiles(), nil)["project .locksql/pii"]; c.state != checkFail || c.repair == nil {
		t.Errorf("without LOCKSQL_PII_DIR: %+v", c)
	}
	if _, ok := run(newFiles(), nil)["PII rule sets"]; ok {
		t.Error("PII rule sets checked without LOCKSQL_PII_DIR")
	}

	// LOCKSQL_PII_DIR, not made yet: warnings naming why, no repair, and
	// the directory in force reported.
	files := newFiles()
	got := run(files, env)
	for _, title := range []string{"project .locksql", "project .locksql/pii"} {
		if c := got[title]; c.state != checkWarn || c.repair != nil || !strings.Contains(c.detail, "LOCKSQL_PII_DIR is set here") {
			t.Errorf("%s with LOCKSQL_PII_DIR: %+v", title, c)
		}
	}
	if c := got["PII rule sets"]; c.state != checkOK || !strings.Contains(c.detail, inForce) || !strings.Contains(c.detail, "not created yet") {
		t.Errorf("PII rule sets: %+v", c)
	}

	// The directory in force and its pii/: owned by the console, ok; by
	// another, group-writable, not a directory, a link: fail; out of
	// sight: warn.
	files[inForce] = dir(0o700, 900)
	files[inForce+"/pii"] = dir(0o700, 900)
	if c := run(files, env)["PII rule sets"]; c.state != checkOK || !strings.Contains(c.detail, "owned by locksql") {
		t.Errorf("console-owned %s: %+v", inForce, c)
	}
	for name, bad := range map[string]ownedInfo{
		"owned by another": dir(0o755, 1000), "group-writable": dir(0o775, 900),
		"a file": {fakeInfo{"pii", 0o644}, 900, 900},
	} {
		for _, at := range []string{inForce, inForce + "/pii"} {
			f := newFiles()
			f[inForce], f[inForce+"/pii"] = dir(0o700, 900), dir(0o700, 900)
			f[at] = bad
			if c := run(f, env)["PII rule sets"]; c.state != checkFail || !strings.Contains(c.detail, at) {
				t.Errorf("%s %s: %+v", at, name, c)
			}
		}
	}
	links = map[string]bool{inForce + "/pii": true}
	if c := run(files, env)["PII rule sets"]; c.state != checkFail || !strings.Contains(c.detail, "symbolic link") {
		t.Errorf("linked %s/pii: %+v", inForce, c)
	}
	links = map[string]bool{p + "/pii": true}
	if c := run(files, env)["project .locksql/pii"]; c.state != checkFail || !strings.Contains(c.detail, "symbolic link") {
		t.Errorf("linked seed: %+v", c)
	}
	links = nil
	statErr = map[string]error{inForce: fs.ErrPermission}
	if c := run(files, env)["PII rule sets"]; c.state != checkWarn || !strings.Contains(c.detail, "not checked") {
		t.Errorf("unreadable %s: %+v", inForce, c)
	}
	statErr = nil

	// A seed writable by others fails, with a repair: the console seeds
	// its sets from it.
	files[p+"/pii"] = dir(0o777, 1000)
	if c := run(files, env)["project .locksql/pii"]; c.state != checkFail || !strings.Contains(c.fix, "go-w") || c.repair == nil || c.repair.apply == nil {
		t.Errorf("world-writable seed: %+v", c)
	}
	files[p+"/pii"] = dir(0o777, 900)
	if c := run(files, env)["project .locksql/pii"]; c.state != checkFail || c.repair == nil || !strings.Contains(c.repair.root, "chmod go-w") {
		t.Errorf("world-writable console-owned seed: %+v", c)
	}
	// A seed the console cannot read fails: it reads its config there.
	files[p+"/pii"] = dir(0o700, 1000)
	if c := run(files, env)["project .locksql/pii"]; c.state != checkFail || !strings.Contains(c.detail, "cannot list") {
		t.Errorf("unreadable seed: %+v", c)
	}
	// Owned by the console but closed to others: the usual failure.
	files[p+"/pii"] = dir(0o700, 900)
	if c := run(files, env)["project .locksql/pii"]; c.state != checkFail || c.repair == nil || !strings.Contains(c.detail, "every account read it") {
		t.Errorf("console-owned 0700 seed: %+v", c)
	}
	files[p+"/pii"] = dir(0o755, 1000)

	// A relative LOCKSQL_PII_DIR is a config error of the console.
	if c := run(files, map[string]string{"LOCKSQL_PII_DIR": "pii-rules"})["PII rule sets"]; c.state != checkFail {
		t.Errorf("relative LOCKSQL_PII_DIR: %+v", c)
	}

	// A lock up workspace, doctor without LOCKSQL_PII_DIR: warnings, in
	// either layout; a bare .lockfamily/ is not one.
	for _, marker := range []string{"/home/alice/proj/.lockfamily/lockfamily.yaml", "/home/alice/proj/lockfamily.yaml"} {
		f := newFiles()
		f[marker] = ownedInfo{fakeInfo{"lockfamily.yaml", 0o644}, 1000, 1000}
		if strings.Contains(marker, ".lockfamily/") {
			f["/home/alice/proj/.lockfamily"] = dir(0o755, 1000)
		}
		got := run(f, nil)
		if c := got["project .locksql/pii"]; c.state != checkWarn || !strings.Contains(c.detail, "lock up workspace") {
			t.Errorf("%s: project .locksql/pii %+v", marker, c)
		}
		if c := got["PII rule sets"]; c.state != checkOK || !strings.Contains(c.detail, "lock up") {
			t.Errorf("%s: PII rule sets %+v", marker, c)
		}
	}
	f := newFiles()
	f["/home/alice/proj/.lockfamily"] = dir(0o755, 1000)
	if c := run(f, nil)["project .locksql/pii"]; c.state != checkFail {
		t.Errorf("bare .lockfamily/: %+v", c)
	}
	// A root lockfamily.yaml beside a .lockfamily/ is never read by lock
	// up: not a signal.
	f["/home/alice/proj/lockfamily.yaml"] = ownedInfo{fakeInfo{"lockfamily.yaml", 0o644}, 1000, 1000}
	if c := run(f, nil)["project .locksql/pii"]; c.state != checkFail {
		t.Errorf("root lockfamily.yaml beside .lockfamily/: %+v", c)
	}
}
