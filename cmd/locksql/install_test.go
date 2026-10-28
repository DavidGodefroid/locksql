//go:build unix

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// The test binary is the source install would copy: it belongs to the
// account running the tests, which in a separated setup is the agent's.
func TestInstallRefusesABinaryAnotherAccountCanChange(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the test binary is root-owned: nothing to refuse")
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		t.Fatal(err)
	}
	sum := fileSHA256(t, bin)

	o := cli(t, t.TempDir(), "", "install", "--client", "agent", "--print")
	o.want(t, exitFail, bin+" is owned by ", "could have been replaced by the agent",
		"install a release into a root-owned directory (scripts/install.sh with the default /usr/local/bin)",
		"--trust-binary", "sha256 "+sum)
	if strings.Contains(o.stdout, "These commands run as root") {
		t.Errorf("the root script was printed for an untrusted binary:\n%s", o.stdout)
	}

	o = cli(t, t.TempDir(), "", "install", "--client", "agent", "--print", "--trust-binary")
	check := "sha256sum -c -"
	if runtime.GOOS == "darwin" {
		check = "shasum -a 256 -c -"
	}
	o.want(t, exitOK, "sha256 "+sum, "These commands run as root", "install -m 0755 -o root",
		"echo '"+sum+"  '\"$tmp\" | "+check)
	if !strings.Contains(o.stdout, `-o root -g `) || strings.Contains(o.stdout, "install -m 0755 -o root -g root "+shellQuote(bin)) {
		t.Errorf("--trust-binary installs the unchecked binary:\n%s", o.stdout)
	}
}

// With --trust-binary the root script copies the binary, checks the copy
// against the printed sha256, and stops before any change when it differs.
func TestInstallPinnedSourceChecksTheCopy(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "lock sql")
	if err := os.WriteFile(bin, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	prefix, src := pinnedSource("locksql install", bin, fileSHA256(t, bin), "sha256sum -c -")
	run := func() (string, error) {
		out, err := exec.Command("sh", "-c", "set -eu\n"+prefix+"cat "+src+"; echo; echo DONE").CombinedOutput()
		return string(out), err
	}
	if out, err := run(); err != nil || !strings.Contains(out, "binary\nDONE") {
		t.Fatalf("unchanged binary: %v\n%s", err, out)
	}
	if err := os.WriteFile(bin, []byte("replaced"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := run()
	if err == nil || strings.Contains(out, "DONE") || !strings.Contains(out, "the binary changed since its sha256 was printed") {
		t.Fatalf("replaced binary: %v\n%s", err, out)
	}
	if prefix, src := pinnedSource("locksql install", bin, "", "sha256sum -c -"); prefix != "" || src != shellQuote(bin) {
		t.Errorf("without a pin: %q, %q", prefix, src)
	}
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
		"--trust-binary", "sha256 " + fileSHA256(t, path)} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal lacks %q:\n%s", want, msg)
		}
	}
	if _, err := installSourceRefusal(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing source binary is not an error")
	}
}

// A release already at /usr/local/bin (scripts/install.sh) is not copied
// onto itself: install(1) refuses that, and the script would stop there.
func TestInstallScriptSkipsCopyOntoItself(t *testing.T) {
	for _, script := range []string{
		linuxInstallScript(installedBinary, "agent", "locksql", "locksql-clients", ""),
		darwinInstallScript(installedBinary, "agent", "locksql", "locksql-clients", ""),
	} {
		if strings.Contains(script, "install -m 0755") {
			t.Errorf("copies the binary onto itself:\n%s", script)
		}
	}
	for _, script := range []string{
		linuxInstallScript("/opt/locksql", "agent", "locksql", "locksql-clients", ""),
		linuxInstallScript(installedBinary, "agent", "locksql", "locksql-clients", strings.Repeat("a", 64)),
	} {
		if !strings.Contains(script, "install -m 0755 -o root -g root ") {
			t.Errorf("binary not installed:\n%s", script)
		}
	}
}

// --yes runs the root script without a terminal; without it, install
// needs one to confirm.
func TestInstallYes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("install only prints its commands on macOS")
	}
	var out, errb strings.Builder
	var scripts []string
	e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, cwd: t.TempDir(),
		root: func(s string) error { scripts = append(scripts, s); return nil }}
	if code := runEnv(e, []string{"install", "--client", "agent", "--trust-binary"}); code != exitUsage || len(scripts) != 0 {
		t.Fatalf("no terminal: code %d, scripts %d\n%s%s", code, len(scripts), out.String(), errb.String())
	}
	if code := runEnv(e, []string{"install", "--client", "agent", "--trust-binary", "--yes"}); code != exitOK || len(scripts) != 1 {
		t.Fatalf("--yes: code %d, scripts %d\n%s%s", code, len(scripts), out.String(), errb.String())
	}
	if !strings.Contains(scripts[0], "usermod -aG locksql-clients agent") || !strings.Contains(out.String(), "Done. Next:") {
		t.Errorf("script:\n%s\nout:\n%s", scripts[0], out.String())
	}
}

// A trusted, root-owned source is pinned too: root copies it after the
// prompt, from a directory another account may still be able to write, so
// the root script checks its copy against the sha256 shown to the human.
func TestInstallSourcePinsATrustedBinary(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip(err)
	}
	if msg, err := installSourceRefusal(sh); err != nil || msg != "" {
		t.Skipf("%s is not a trusted root-owned binary here: %q %v", sh, msg, err)
	}
	sum := fileSHA256(t, sh)
	pin, shown, msg, err := installSource(sh, false)
	if err != nil || msg != "" || pin != sum || shown != sum {
		t.Errorf("installSource(%s) = pin %q, shown %q, refusal %q, %v; want pin and shown %s", sh, pin, shown, msg, err, sum)
	}
	for _, script := range []string{
		linuxInstallScript(sh, "agent", "locksql", "locksql-clients", pin),
		darwinInstallScript(sh, "agent", "locksql", "locksql-clients", pin),
	} {
		if !strings.Contains(script, "echo '"+sum+"  '\"$tmp\"") || strings.Contains(script, "install -m 0755 -o root -g root "+shellQuote(sh)) {
			t.Errorf("trusted binary installed unpinned:\n%s", script)
		}
	}
}

// The sha256 of the binary install copies stands beside the prompt, so the
// human can compare it before answering.
func TestInstallShowsTheDigestBesideThePrompt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("install only prints its commands on macOS")
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		t.Fatal(err)
	}
	sum := fileSHA256(t, bin)
	var out, errb strings.Builder
	e := env{stdin: strings.NewReader("n\n"), stdout: &out, stderr: &errb, cwd: t.TempDir(), tty: true,
		root: func(string) error { t.Error("root ran"); return nil }}
	if code := runEnv(e, []string{"install", "--client", "agent", "--trust-binary"}); code != exitOK {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	want := "binary: " + bin + "\nsha256: " + sum + "\nRun them now with sudo? [y/N] "
	if !strings.Contains(out.String(), want) {
		t.Errorf("prompt lacks %q:\n%s", want, out.String())
	}
}
