package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every action a workflow runs is pinned to a full commit SHA, with its
// version as a comment for the reader and Dependabot: a tag can be moved,
// and the release job runs with an OIDC token that signs releases.
func TestWorkflowActionsArePinnedBySHA(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	uses := regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*(\S+)(.*)$`)
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	comment := regexp.MustCompile(`^\s+# v\d+\.\d+\.\d+$`)
	n := 0
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			m := uses.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			n++
			if !pinned.MatchString(m[1]) || !comment.MatchString(m[2]) {
				t.Errorf("%s:%d: %q is not pinned as owner/repo@<40-hex sha> # vX.Y.Z", filepath.Base(file), i+1, strings.TrimSpace(line))
			}
		}
	}
	if n == 0 {
		t.Error("no uses: line found")
	}
}

// The release job builds, signs and generates SBOMs with fixed versions of
// its tools, not whatever is newest on the day of the tag.
func TestReleaseWorkflowPinsToolVersions(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, re := range []string{`(?m)^\s+cosign-release: v\d+\.\d+\.\d+\s*$`, `(?m)^\s+syft-version: v\d+\.\d+\.\d+\s*$`,
		`(?m)^\s+version: v\d+\.\d+\.\d+\s*$`} {
		if !regexp.MustCompile(re).MatchString(s) {
			t.Errorf("release.yml lacks %s", re)
		}
	}
	for _, bad := range []string{"check-latest: true", `"~> v2"`} {
		if strings.Contains(s, bad) {
			t.Errorf("release.yml lets a toolchain float: %s", bad)
		}
	}
}
