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

// Under lox up the console keeps its PII rule sets in its own directory
// (LOCKSQL_PII_DIR): in a lox up workspace, a .locksql and .locksql/pii
// the console does not own but can read are a warning, not a failure
// (#130). Otherwise, and whatever doctor's own environment holds (the
// console it starts gets a fresh one), the ownership check fails as
// before; unreadable or writable by others fails either way.
func TestProjectChecksLockUpWorkspace(t *testing.T) {
	dir := func(mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{"d", fs.ModeDir | mode}, uid, uid}
	}
	file := func(mode fs.FileMode, uid int) ownedInfo {
		return ownedInfo{fakeInfo{"f", mode}, uid, uid}
	}
	const proj = "/home/alice/proj"
	const p = proj + "/.locksql"
	const marker = proj + "/.lockfamily/lockfamily.yaml"
	newFiles := func() map[string]ownedInfo {
		return map[string]ownedInfo{
			"/": dir(0o755, 0), "/home": dir(0o755, 0), "/home/alice": dir(0o755, 1000),
			proj:                  dir(0o755, 1000),
			p:                     dir(0o755, 1000),
			p + "/config.toml":    file(0o644, 1000),
			p + "/pii":            dir(0o755, 1000), // the human's
			p + "/pii/shop.toml":  file(0o644, 1000),
			proj + "/.lockfamily": dir(0o755, 1000),
			marker:                file(0o644, 1000),
		}
	}
	svc := svcAccount{name: "locksql", uid: 900, gids: []int{900}}
	var links map[string]bool
	run := func(files map[string]ownedInfo) map[string]check {
		var ran [][]string
		d := accessDoctor(files, &ran)
		d.lstat = func(path string) (os.FileInfo, error) {
			if links[path] {
				return ownedInfo{fakeInfo{"l", fs.ModeSymlink | 0o777}, 1000, 1000}, nil
			}
			return d.stat(path)
		}
		d.getenv = func(k string) string {
			if k == "LOCKSQL_PII_DIR" {
				return "/home/locksql/pii-rules"
			}
			return ""
		}
		out := map[string]check{}
		for _, c := range projectChecks(d, proj, svc, 1000) {
			out[c.title] = c
		}
		return out
	}

	// A lox up workspace: warnings naming why, no repair; the rule sets
	// reported as not checked.
	files := newFiles()
	got := run(files)
	for _, title := range []string{"project .locksql", "project .locksql/pii"} {
		if c := got[title]; c.state != checkWarn || c.repair != nil || !strings.Contains(c.detail, "lox up workspace") {
			t.Errorf("%s: %+v", title, c)
		}
	}
	if c := got["PII rule sets"]; c.state != checkOK || !strings.Contains(c.detail, "not checked here") {
		t.Errorf("PII rule sets: %+v", c)
	}

	// The layout before .lockfamily: lockfamily.yaml at the root.
	f := newFiles()
	delete(f, marker)
	delete(f, proj+"/.lockfamily")
	f[proj+"/lockfamily.yaml"] = file(0o644, 1000)
	if c := run(f)["project .locksql/pii"]; c.state != checkWarn {
		t.Errorf("root lockfamily.yaml: %+v", c)
	}
	// Not a lox up workspace: a bare .lockfamily/; a root lockfamily.yaml
	// beside a .lockfamily (a directory or anything else), which lox up
	// never reads; nothing at all, LOCKSQL_PII_DIR in doctor's environment
	// notwithstanding.
	f[proj+"/.lockfamily"] = file(0o644, 1000)
	if c := run(f)["project .locksql/pii"]; c.state != checkFail || c.repair == nil {
		t.Errorf("root lockfamily.yaml beside a .lockfamily file: %+v", c)
	}
	f[proj+"/.lockfamily"] = dir(0o755, 1000)
	if c := run(f)["project .locksql/pii"]; c.state != checkFail {
		t.Errorf("root lockfamily.yaml beside .lockfamily/: %+v", c)
	}
	delete(f, proj+"/lockfamily.yaml")
	if c := run(f)["project .locksql/pii"]; c.state != checkFail {
		t.Errorf("bare .lockfamily/: %+v", c)
	}
	delete(f, proj+"/.lockfamily")
	got = run(f)
	if c := got["project .locksql/pii"]; c.state != checkFail || c.repair == nil {
		t.Errorf("no workspace: %+v", c)
	}
	if _, ok := got["PII rule sets"]; ok {
		t.Error("PII rule sets reported outside a lox up workspace")
	}

	// In the workspace: a seed writable by others fails, with a repair.
	files[p+"/pii"] = dir(0o777, 1000)
	if c := run(files)["project .locksql/pii"]; c.state != checkFail || !strings.Contains(c.fix, "go-w") || c.repair == nil || c.repair.apply == nil {
		t.Errorf("world-writable seed: %+v", c)
	}
	files[p+"/pii"] = dir(0o777, 900)
	if c := run(files)["project .locksql/pii"]; c.state != checkFail || c.repair == nil || !strings.Contains(c.repair.root, "chmod go-w") {
		t.Errorf("world-writable console-owned seed: %+v", c)
	}
	// A seed the console cannot read fails.
	files[p+"/pii"] = dir(0o700, 1000)
	if c := run(files)["project .locksql/pii"]; c.state != checkFail || !strings.Contains(c.detail, "cannot list") {
		t.Errorf("unreadable seed: %+v", c)
	}
	// Owned by the console but closed to others: the usual failure.
	files[p+"/pii"] = dir(0o700, 900)
	if c := run(files)["project .locksql/pii"]; c.state != checkFail || c.repair == nil || !strings.Contains(c.detail, "every account read it") {
		t.Errorf("console-owned 0700 seed: %+v", c)
	}
	files[p+"/pii"] = dir(0o755, 1000)
	// A linked seed still fails.
	links = map[string]bool{p + "/pii": true}
	if c := run(files)["project .locksql/pii"]; c.state != checkFail || !strings.Contains(c.detail, "symbolic link") {
		t.Errorf("linked seed: %+v", c)
	}
}
