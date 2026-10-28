//go:build unix

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

// updFixture is a fake release server, a fake cosign on PATH and a root
// stub that records the scripts it is given.
type updFixture struct {
	files     map[string][]byte // path under /releases/download/<tag>/
	latest    string            // tag /releases/latest redirects to
	bin       []byte            // the locksql of the archive
	cosignDir string
	cosignOK  bool
	roots     []string
	exe       string
	refusal   func(string) (string, error)
	srv       *httptest.Server
}

// archiveName is the release archive of this platform.
func archiveName(ver string) string {
	return fmt.Sprintf("locksql_%s_%s_%s.tar.gz", ver, runtime.GOOS, runtime.GOARCH)
}

// newUpdFixture serves a valid, signed release ver (without its v) as the
// latest one, and installs a cosign that accepts it.
func newUpdFixture(t *testing.T, ver string) *updFixture {
	t.Helper()
	f := &updFixture{latest: "v" + ver, cosignOK: true, exe: installedBinary,
		refusal: func(string) (string, error) { return "", nil }}
	f.setRelease(t, ver, "locksql "+ver)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/releases/latest":
			http.Redirect(w, r, "/releases/tag/"+f.latest, http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/releases/tag/"):
			fmt.Fprintln(w, "release page")
		case strings.HasPrefix(r.URL.Path, "/releases/download/"):
			b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/releases/download/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	f.cosignDir = t.TempDir()
	f.writeCosign(t)
	t.Setenv("PATH", f.cosignDir)
	return f
}

// setRelease publishes release ver whose binary prints says.
func (f *updFixture) setRelease(t *testing.T, ver, says string) {
	t.Helper()
	tag := "v" + ver
	f.bin = []byte("#!/bin/sh\necho '" + says + "'\n")
	archive := tarGz(t, map[string][]byte{"locksql": f.bin, "README.md": []byte("readme")})
	sums := fmt.Sprintf("%s  %s\n%s  locksql_%s_linux_amd64.deb\n", hexSum(archive), archiveName(ver), hexSum([]byte("deb")), ver)
	if f.files == nil {
		f.files = map[string][]byte{}
	}
	f.files[tag+"/"+archiveName(ver)] = archive
	f.files[tag+"/checksums.txt"] = []byte(sums)
	f.files[tag+"/checksums.txt.sigstore.json"] = []byte(`{"bundle":true}`)
}

// writeCosign installs a fake cosign that records its arguments and
// accepts the signature when f.cosignOK.
func (f *updFixture) writeCosign(t *testing.T) {
	t.Helper()
	code := "0"
	if !f.cosignOK {
		code = "1"
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shellQuote(filepath.Join(f.cosignDir, "args")) + "\n" +
		"[ " + code + " = 0 ] || echo 'Error: none of the expected identities matched' >&2\nexit " + code + "\n"
	if err := os.WriteFile(filepath.Join(f.cosignDir, "cosign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (f *updFixture) run(t *testing.T, tty bool, stdin string, args ...string) outcome {
	t.Helper()
	var out, errb bytes.Buffer
	e := env{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, cwd: t.TempDir(), tty: tty,
		root: func(script string) error { f.roots = append(f.roots, script); return nil },
		upd: &updateEnv{
			exe:           func() (string, error) { return f.exe, nil },
			installed:     installedBinary,
			sourceRefusal: f.refusal,
			releases:      f.srv.URL + "/releases",
			client:        f.srv.Client(),
		}}
	code := runEnv(e, append([]string{"update"}, args...))
	return outcome{code, out.String(), errb.String()}
}

func (f *updFixture) wantNoRoot(t *testing.T) {
	t.Helper()
	if len(f.roots) != 0 {
		t.Fatalf("the root stub ran:\n%s", strings.Join(f.roots, "\n---\n"))
	}
}

func TestUpdateInstallsAVerifiedRelease(t *testing.T) {
	setVersion(t, "0.7.0")
	f := newUpdFixture(t, "0.8.0")
	o := f.run(t, false, "", "--yes")
	pin := hexSum(f.bin)
	o.want(t, exitOK, "cosign: checksums.txt signature verified", "sha256 of the new binary: "+pin,
		"restart the console (`locksql console` in the locksql account) to use v0.8.0")
	if len(f.roots) != 1 {
		t.Fatalf("root ran %d times", len(f.roots))
	}
	script := f.roots[0]
	check := "echo '" + pin + "  '\"$tmp\" | "
	install := "install -m 0755 -o root -g "
	if i, j := strings.Index(script, check), strings.Index(script, install); i < 0 || j < i {
		t.Errorf("the script does not check the pin before install:\n%s", script)
	}
	if !strings.Contains(script, "\"$tmp\" "+installedBinary+"\n") || !strings.Contains(script, "locksql update: the binary changed") {
		t.Errorf("script:\n%s", script)
	}
	if strings.Index(o.stdout, pin) > strings.Index(o.stdout, "restart the console") {
		t.Errorf("the sha256 is printed after the replacement:\n%s", o.stdout)
	}
	// The binary the script copied came from a private directory, removed
	// once update returns.
	extracted := strings.Fields(script[strings.Index(script, "cat "):])[1]
	if p := strings.Trim(extracted, "'"); !strings.Contains(p, "locksql-update-") {
		t.Errorf("source %q", p)
	} else if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
		t.Errorf("temp dir %s left behind: %v", filepath.Dir(p), err)
	}
	args, err := os.ReadFile(filepath.Join(f.cosignDir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"verify-blob", "--bundle", "--certificate-identity-regexp\n" + ReleaseCertIdentityRegexp + "\n",
		"--certificate-oidc-issuer\nhttps://token.actions.githubusercontent.com\n", "checksums.txt.sigstore.json\n"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("cosign args lack %q:\n%s", want, args)
		}
	}
}

func TestUpdateRefusalsNeverReachRoot(t *testing.T) {
	cases := []struct {
		name    string
		running string
		args    []string
		setup   func(t *testing.T, f *updFixture)
		want    []string
	}{
		{"bad signature", "0.7.0", nil, func(t *testing.T, f *updFixture) { f.cosignOK = false; f.writeCosign(t) },
			[]string{"signature of checksums.txt does not verify", "install cosign"}},
		{"cosign missing", "0.7.0", nil, func(t *testing.T, f *updFixture) { t.Setenv("PATH", t.TempDir()) },
			[]string{"cosign is not installed", "install cosign"}},
		{"checksum mismatch", "0.7.0", nil, func(t *testing.T, f *updFixture) {
			k := "v0.8.0/checksums.txt"
			f.files[k] = []byte(strings.Replace(string(f.files[k]), hexSum(f.files["v0.8.0/"+archiveName("0.8.0")]), strings.Repeat("0", 64), 1))
		}, []string{"does not match its checksum"}},
		{"archive not in checksums.txt", "0.7.0", nil, func(t *testing.T, f *updFixture) {
			f.files["v0.8.0/checksums.txt"] = []byte(hexSum([]byte("x")) + "  locksql_0.8.0_plan9_mips.tar.gz\n")
		}, []string{archiveName("0.8.0") + " is not listed in checksums.txt"}},
		{"extracted version mismatch", "0.7.0", nil, func(t *testing.T, f *updFixture) { f.setRelease(t, "0.8.0", "locksql 0.9.0") },
			[]string{`reports version "locksql 0.9.0", not 0.8.0`}},
		{"downgrade", "0.9.0", nil, nil, []string{"v0.8.0 is older than the running v0.9.0", "--allow-downgrade"}},
		{"dev build without --version", "dev", nil, nil, []string{"development build", "--version"}},
		{"no tty without --yes", "0.7.0", nil, nil, []string{"confirm in a terminal, or run with --yes"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setVersion(t, c.running)
			f := newUpdFixture(t, "0.8.0")
			if c.setup != nil {
				c.setup(t, f)
			}
			args := c.args
			if args == nil && c.name != "no tty without --yes" {
				args = []string{"--yes"}
			}
			o := f.run(t, false, "", args...)
			code := exitFail
			if c.name == "no tty without --yes" {
				code = exitUsage
			}
			o.want(t, code, c.want...)
			f.wantNoRoot(t)
		})
	}
}

func TestUpdateDowngradeAndDevNeedTheirFlag(t *testing.T) {
	setVersion(t, "0.9.0")
	f := newUpdFixture(t, "0.8.0")
	f.run(t, false, "", "--yes", "--allow-downgrade").want(t, exitOK, "to use v0.8.0")

	setVersion(t, "dev")
	f = newUpdFixture(t, "0.8.0")
	f.latest = "v9.9.9" // not followed: --version names the release
	f.run(t, false, "", "--yes", "--version", "v0.8.0").want(t, exitOK, "to use v0.8.0")
	if len(f.roots) != 1 {
		t.Fatalf("root ran %d times", len(f.roots))
	}
}

// Release builds stamp main.version without the v; tags carry one.
func TestUpdateAlreadyAtTheTarget(t *testing.T) {
	for _, running := range []string{"0.7.0", "v0.7.0"} {
		for _, args := range [][]string{nil, {"--version", "v0.7.0"}, {"--version", "0.7.0"}} {
			setVersion(t, running)
			f := newUpdFixture(t, "0.7.0")
			o := f.run(t, false, "", args...)
			o.want(t, exitOK, "already at v0.7.0")
			f.wantNoRoot(t)
		}
	}
}

func TestUpdateConfirmsOnATerminal(t *testing.T) {
	setVersion(t, "0.7.0")
	f := newUpdFixture(t, "0.8.0")
	f.run(t, true, "n\n").want(t, exitOK, "Replace /usr/local/bin/locksql with v0.8.0 now with sudo? [y/N]", "nothing done")
	f.wantNoRoot(t)
	f.run(t, true, "y\n").want(t, exitOK, "to use v0.8.0")
	if len(f.roots) != 1 {
		t.Fatalf("root ran %d times", len(f.roots))
	}
}

func TestUpdateRefusesOtherChannels(t *testing.T) {
	setVersion(t, "0.7.0")

	f := newUpdFixture(t, "0.8.0")
	f.exe = "/usr/bin/locksql"
	f.run(t, false, "", "--yes").want(t, exitFail, "installed by a package", "F=locksql_${V}_linux_",
		"checksums.txt.sigstore.json", "cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp '"+
			ReleaseCertIdentityRegexp+"' --certificate-oidc-issuer "+releaseOIDCIssuer+" checksums.txt",
		"| sha256sum -c -", "sudo apt install \"./$F\"", "sudo dnf install \"./$F\"", "sudo apk add --allow-untrusted \"./$F\"")
	f.wantNoRoot(t)

	f = newUpdFixture(t, "0.8.0")
	f.exe = "/home/agent/go/bin/locksql"
	f.run(t, false, "", "--yes").want(t, exitFail, "/home/agent/go/bin/locksql is not /usr/local/bin/locksql",
		"scripts/install.sh", "then run sudo locksql install")
	f.wantNoRoot(t)

	// The real installSourceRefusal, on a file standing in for
	// installedBinary: owned by this account, then writable by all.
	for _, mode := range []os.FileMode{0o755, 0o777} {
		if mode == 0o755 && os.Geteuid() == 0 {
			continue // root owns it: not refused
		}
		path := filepath.Join(t.TempDir(), "locksql")
		if err := os.WriteFile(path, []byte("binary"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		f = newUpdFixture(t, "0.8.0")
		f.exe = path
		f.refusal = installSourceRefusal
		var out, errb bytes.Buffer
		e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &errb,
			root: func(s string) error { f.roots = append(f.roots, s); return nil },
			upd: &updateEnv{exe: func() (string, error) { return path, nil }, installed: path,
				releases: f.srv.URL + "/releases", client: f.srv.Client()}}
		o := outcome{runEnv(e, []string{"update", "--yes"}), out.String(), errb.String()}
		o.want(t, exitFail, "is not owned by root, or group or others may write it", "scripts/install.sh", "sudo locksql install")
		f.wantNoRoot(t)
	}
}

func TestUpdateScriptChecksThePinBeforeInstall(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	for goos, want := range map[string][2]string{
		"linux":  {"sha256sum -c -", "install -m 0755 -o root -g root \"$tmp\" /usr/local/bin/locksql"},
		"darwin": {"shasum -a 256 -c -", "install -m 0755 -o root -g wheel \"$tmp\" /usr/local/bin/locksql"},
	} {
		s := updateScript("/tmp/locksql-update-1/locksql", pin, goos)
		check := "echo '" + pin + "  '\"$tmp\" | " + want[0]
		i, j := strings.Index(s, check), strings.Index(s, want[1])
		if i < 0 || j < 0 || j < i || !strings.HasPrefix(s, "set -eu\n") || !strings.Contains(s, "trap 'rm -f \"$tmp\"' EXIT") {
			t.Errorf("%s:\n%s", goos, s)
		}
		if !strings.Contains(s, "locksql update: the binary changed") || strings.Contains(s, "locksql install:") {
			t.Errorf("%s: refusal prefix:\n%s", goos, s)
		}
	}
}

func TestUpdateLatestWithoutARelease(t *testing.T) {
	setVersion(t, "0.7.0")
	f := newUpdFixture(t, "0.8.0")
	f.latest = "" // /releases/tag/ : GitHub sends /releases when there is none
	f.run(t, false, "", "--yes").want(t, exitFail, "no published release found")
	f.wantNoRoot(t)
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

func TestUpdateRejectsAnInvalidVersion(t *testing.T) {
	setVersion(t, "0.7.0")
	f := newUpdFixture(t, "0.8.0")
	f.run(t, false, "", "--yes", "--version", "latest").want(t, exitFail, `invalid version "latest"`)
	f.wantNoRoot(t)
	f.run(t, false, "", "extra").want(t, exitUsage, "usage: locksql update")
}
