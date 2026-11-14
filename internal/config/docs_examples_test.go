package config

import (
	"os"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

// docTOMLBlocks returns the ```toml blocks of a doc file.
func docTOMLBlocks(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var blocks []string
	var cur []string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case !in && strings.TrimSpace(line) == "```toml":
			in, cur = true, nil
		case in && strings.TrimSpace(line) == "```":
			in = false
			blocks = append(blocks, strings.Join(cur, "\n"))
		case in:
			cur = append(cur, line)
		}
	}
	return blocks
}

// The managed-file examples of the docs load as written (#249): a doc
// example copied as is must not stop every console of the machine.
func TestDocsManagedExamplesLoad(t *testing.T) {
	n := 0
	for _, block := range docTOMLBlocks(t, "../../docs/configuration.md") {
		if !strings.Contains(block, "[locksql.") || !strings.Contains(block, "version = 1") {
			continue
		}
		n++
		f, err := managed.Parse([]byte(block))
		if err != nil {
			t.Errorf("managed.Parse of the example:\n%s\n: %v", block, err)
			continue
		}
		if _, err := ParseManaged(f); err != nil {
			t.Errorf("ParseManaged of the example:\n%s\n: %v", block, err)
		}
	}
	if n == 0 {
		t.Fatal("no managed example found in docs/configuration.md")
	}
}
