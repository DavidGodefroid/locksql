//go:build unix

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileSHA256 is the hex sha256 of the file at path.
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestInstallSourceRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locksql")
	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// Root-owned and not group- or world-writable: trusted.
		if msg, err := installSourceRefusal(path); err != nil || msg != "" {
			t.Errorf("root-owned 0755 binary refused: %q %v", msg, err)
		}
		if err := os.Chmod(path, 0o775); err != nil {
			t.Fatal(err)
		}
		if msg, _ := installSourceRefusal(path); !strings.Contains(msg, "could have been replaced") {
			t.Errorf("group-writable root binary accepted: %q", msg)
		}
		return
	}
	msg, err := installSourceRefusal(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{path + " is owned by ", "could have been replaced by the agent",
		"sha256 " + fileSHA256(t, path)} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal lacks %q:\n%s", want, msg)
		}
	}
	if _, err := installSourceRefusal(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing source binary is not an error")
	}
}
