//go:build unix

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// setVersion sets main.version for one test.
func setVersion(t *testing.T, v string) {
	t.Helper()
	saved := version
	version = v
	t.Cleanup(func() { version = saved })
}

// tarGz is a .tar.gz holding one regular file per name.
func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestCompareSemver(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.7.0", "0.7.0", 0}, {"0.8.0", "0.7.0", 1}, {"0.7.0", "0.10.0", -1}, {"1.0.0", "0.99.99", 1},
		{"1.0.0-rc.1", "1.0.0", -1}, {"1.0.0-rc.2", "1.0.0-rc.10", -1}, {"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-1", "1.0.0-alpha", -1}, {"1.0.0+build", "1.0.0", 0},
	} {
		if got, err := compareSemver(c.a, c.b); err != nil || got != c.want {
			t.Errorf("compare(%s, %s) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"dev", "1.2", "1.2.x", "01.2.3", "1.2.3-", ""} {
		if _, err := parseSemver(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// The verification steps of the package hint stop at the first failure:
// a failed download, signature or checksum never prints "verified".
func TestPackageHintStopsOnFailure(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is not installed")
	}
	hint := packageHint("/usr/bin/locksql")
	start := strings.Index(hint, "  F=")
	end := strings.Index(hint, "\nthen")
	if start < 0 || end < start {
		t.Fatalf("no verification block in %q", hint)
	}
	script := "V=0.9.0 P=deb\n" + hint[start:end] + "\n"
	pkg := "locksql_0.9.0_linux_" + runtime.GOARCH + ".deb"
	for name, c := range map[string]struct {
		curl, cosign string
		sum          string // checksums.txt line for pkg; "" for none
		want         bool
	}{
		"ok":           {"0", "0", "good", true},
		"cosign fails": {"0", "1", "good", false},
		"curl fails":   {"1", "0", "good", false},
		"bad checksum": {"0", "0", "bad", false},
		"not listed":   {"0", "0", "", false},
	} {
		dir, bin := t.TempDir(), t.TempDir()
		data := []byte("package")
		if err := os.WriteFile(filepath.Join(dir, pkg), data, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(data))
		if c.sum == "bad" {
			sum = strings.Repeat("0", 64)
		}
		lines := "1111111111111111111111111111111111111111111111111111111111111111  x" + pkg + "\n"
		if c.sum != "" {
			lines += sum + "  " + pkg + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(lines), 0o644); err != nil {
			t.Fatal(err)
		}
		for tool, code := range map[string]string{"curl": c.curl, "cosign": c.cosign} {
			if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\nexit "+code+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("sh", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, _ := cmd.CombinedOutput()
		if got := strings.Contains(string(out), "verified: "+pkg); got != c.want {
			t.Errorf("%s: verified = %v, want %v; output:\n%s", name, got, c.want, out)
		}
	}
}
