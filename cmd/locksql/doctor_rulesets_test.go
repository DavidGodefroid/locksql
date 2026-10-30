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
// (LOCKSQL_PII_DIR): the project's .locksql and .locksql/pii, owned by
// the human, are a seed it reads, not a directory it must own (#130); the
// directory in force is checked instead. Without it, and outside a lock up
// workspace, the ownership check fails as before.
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
	run := func(files map[string]ownedInfo, env map[string]string) map[string]check {
		var ran [][]string
		d := accessDoctor(files, &ran)
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

	// LOCKSQL_PII_DIR, not made yet: everything passes.
	files := newFiles()
	got := run(files, env)
	for _, title := range []string{"project .locksql", "project .locksql/pii", "PII rule sets"} {
		if c, ok := got[title]; !ok || c.state != checkOK {
			t.Errorf("%s with LOCKSQL_PII_DIR: %+v (present %v)", title, c, ok)
		}
	}
	if c := got["PII rule sets"]; !strings.Contains(c.detail, inForce) || !strings.Contains(c.detail, "not created yet") {
		t.Errorf("PII rule sets: %+v", c)
	}

	// The directory in force, owned by the console: ok; by another: fail.
	files[inForce] = dir(0o755, 900)
	if c := run(files, env)["PII rule sets"]; c.state != checkOK || !strings.Contains(c.detail, "owned by locksql") {
		t.Errorf("console-owned %s: %+v", inForce, c)
	}
	files[inForce] = dir(0o755, 1000)
	if c := run(files, env)["PII rule sets"]; c.state != checkFail || !strings.Contains(c.fix, "chown 900") {
		t.Errorf("%s owned by another: %+v", inForce, c)
	}
	files[inForce] = dir(0o775, 900)
	if c := run(files, env)["PII rule sets"]; c.state != checkFail {
		t.Errorf("group-writable %s: %+v", inForce, c)
	}
	delete(files, inForce)

	// The seed must still be readable by the console.
	files[p+"/pii"] = dir(0o700, 1000)
	if c := run(files, env)["project .locksql/pii"]; c.state != checkFail || !strings.Contains(c.detail, "not readable") {
		t.Errorf("unreadable seed: %+v", c)
	}
	files[p+"/pii"] = dir(0o755, 1000)

	// A relative LOCKSQL_PII_DIR is a config error of the console.
	if c := run(files, map[string]string{"LOCKSQL_PII_DIR": "pii-rules"})["PII rule sets"]; c.state != checkFail {
		t.Errorf("relative LOCKSQL_PII_DIR: %+v", c)
	}

	// A lock up workspace, doctor run outside the console's container (no
	// LOCKSQL_PII_DIR here): the same, in either layout.
	for _, marker := range []string{"/home/alice/proj/.lockfamily", "/home/alice/proj/lockfamily.yaml"} {
		f := newFiles()
		if strings.HasSuffix(marker, ".yaml") {
			f[marker] = ownedInfo{fakeInfo{"lockfamily.yaml", 0o644}, 1000, 1000}
		} else {
			f[marker] = dir(0o755, 1000)
		}
		got := run(f, nil)
		if c := got["project .locksql/pii"]; c.state != checkOK {
			t.Errorf("%s: project .locksql/pii %+v", marker, c)
		}
		if c := got["PII rule sets"]; c.state != checkOK || !strings.Contains(c.detail, "lock up") {
			t.Errorf("%s: PII rule sets %+v", marker, c)
		}
	}
}
