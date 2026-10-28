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
