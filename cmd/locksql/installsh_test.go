//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// shFixture runs scripts/install.sh against a fake release: curl serves
// files from a directory, and cosign, when present, records its arguments.
// PATH holds only the tools the script needs, so that a cosign installed on
// the machine is not found.
type shFixture struct {
	release, bin, dest, cosignArgs string
	env                            []string
}

const shVersion = "0.9.1"

func newShFixture(t *testing.T) *shFixture {
	t.Helper()
	root := t.TempDir()
	f := &shFixture{
		release:    filepath.Join(root, "release"),
		bin:        filepath.Join(root, "bin"),
		dest:       filepath.Join(root, "dest"),
		cosignArgs: filepath.Join(root, "cosign-args"),
	}
	for _, d := range []string{f.release, f.bin, f.dest} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"sh", "awk", "sha256sum", "shasum", "tar", "gzip", "install", "mktemp", "rm", "mkdir", "uname", "cat", "sed", "tr", "tail", "printf", "grep"} {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// curl -fsSL -o OUT URL: the last path segment of URL, from the release.
	writeExec(t, filepath.Join(f.bin, "curl"), `#!/bin/sh
out=""; while [ $# -gt 1 ]; do [ "$1" = -o ] && { out=$2; shift; }; shift; done
cat "`+f.release+`/${1##*/}" > "$out"
`)

	osName := map[string]string{"linux": "linux", "darwin": "darwin"}[runtime.GOOS]
	if osName == "" {
		t.Skip("install.sh supports Linux and macOS only")
	}
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		t.Skip("install.sh supports amd64 and arm64 only")
	}
	archive := "locksql_" + shVersion + "_" + osName + "_" + arch + ".tar.gz"
	launcher, err := os.ReadFile(filepath.Join("..", "..", "scripts", "locksql"))
	if err != nil {
		t.Fatal(err)
	}
	data := tarGz(t, map[string][]byte{"locksql": []byte("#!/bin/sh\necho locksql " + shVersion + "\n"), "scripts/locksql": launcher})
	if err := os.WriteFile(filepath.Join(f.release, archive), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.release, "checksums.txt"), []byte(hexSum(data)+"  "+archive+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.release, "checksums.txt.sigstore.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.env = []string{"PATH=" + f.bin, "HOME=" + root, "LOCKSQL_VERSION=v" + shVersion, "LOCKSQL_INSTALL_DIR=" + f.dest}
	return f
}

// cosign installs a fake cosign that records its arguments and accepts the
// signature when ok.
func (f *shFixture) cosign(t *testing.T, ok bool) {
	t.Helper()
	f.cosignImages(t, ok, ok)
}

// Digests the fake cosign reports for the release images.
var (
	fakeDigest      = "sha256:" + strings.Repeat("a", 64)
	fakeVaultDigest = "sha256:" + strings.Repeat("b", 64)
)

// cosignImages installs a fake cosign that records its arguments (every
// call, appended), accepts the signature of checksums.txt when blobOK, and
// verifies the release images, printing their digests, when imageOK.
func (f *shFixture) cosignImages(t *testing.T, blobOK, imageOK bool) {
	t.Helper()
	code := func(ok bool) string {
		if ok {
			return "0"
		}
		return "1"
	}
	writeExec(t, filepath.Join(f.bin, "cosign"), `#!/bin/sh
printf '%s\n' "$@" >> '`+f.cosignArgs+`'
case "$1" in
verify-blob) exit `+code(blobOK)+` ;;
verify)
	[ `+code(imageOK)+` = 0 ] || exit 1
	for a in "$@"; do ref=$a; done
	case "$ref" in *-vault) d='`+fakeVaultDigest+`' ;; *) d='`+fakeDigest+`' ;; esac
	printf '[{"critical":{"identity":{"docker-reference":"%s"},"image":{"docker-manifest-digest":"%s"},"type":"cosign container image signature"}}]\n' "${ref%:*}" "$d"
	;;
esac
`)
}

func (f *shFixture) run(t *testing.T, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(f.bin, "sh"), filepath.Join("..", "..", "scripts", "install.sh"))
	cmd.Env = append(append([]string{}, f.env...), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *shFixture) installed() bool {
	_, err := os.Stat(filepath.Join(f.dest, "locksql"))
	return err == nil
}

// install.sh installs the release's launcher, not its binary, set to run
// the release's image.
func TestInstallShInstallsTheLauncher(t *testing.T) {
	f := newShFixture(t)
	f.cosign(t, true)
	out, err := f.run(t)
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(f.dest, "locksql"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nlauncher_version="+shVersion+"\n") || !strings.Contains(string(b), "docker run") {
		t.Fatalf("not the launcher of %s:\n%s", shVersion, b)
	}
	for _, want := range []string{"\nimage_digest=" + fakeDigest + "\n", "\nvault_image_digest=" + fakeVaultDigest + "\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("launcher lacks %q", want)
		}
	}
	args, _ := os.ReadFile(f.cosignArgs)
	for _, want := range []string{"verify\n", "ghcr.io/davidgodefroid/locksql:" + shVersion + "\n", "ghcr.io/davidgodefroid/locksql:" + shVersion + "-vault\n", "--certificate-identity\nhttps://github.com/DavidGodefroid/locksql/.github/workflows/release.yml@refs/tags/v" + shVersion + "\n"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("cosign args lack %q:\n%s", want, args)
		}
	}
	if !strings.Contains(out, "ghcr.io/davidgodefroid/locksql:"+shVersion) {
		t.Errorf("no image named:\n%s", out)
	}
}

// An image whose signature does not verify (or not published yet) stops
// the install: the launcher would run it.
func TestInstallShRefusesAnUnverifiedImage(t *testing.T) {
	f := newShFixture(t)
	f.cosignImages(t, true, false)
	out, err := f.run(t)
	if err == nil || f.installed() || !strings.Contains(out, "does not verify, or the image is not published yet") {
		t.Fatalf("%v, installed %v\n%s", err, f.installed(), out)
	}
}

// Without cosign (LOCKSQL_SKIP_COSIGN=1) the launcher runs the image by
// its tag, and says so.
func TestInstallShSkipCosignLeavesNoDigest(t *testing.T) {
	f := newShFixture(t)
	out, err := f.run(t, "LOCKSQL_SKIP_COSIGN=1")
	if err != nil || !strings.Contains(out, "the image is NOT verified") {
		t.Fatalf("%v\n%s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(f.dest, "locksql"))
	if !strings.Contains(string(b), "\nimage_digest=\n") {
		t.Errorf("a digest without cosign:\n%s", b)
	}
}

// LOCKSQL_VERSION takes only a version tag.
func TestInstallShRefusesABadVersion(t *testing.T) {
	f := newShFixture(t)
	f.cosign(t, true)
	out, err := f.run(t, "LOCKSQL_VERSION=v1.2.3;id")
	if err == nil || f.installed() || !strings.Contains(out, "invalid version") {
		t.Fatalf("%v, installed %v\n%s", err, f.installed(), out)
	}
}

// A release before the launcher has none in its archive: install.sh says so
// and installs nothing.
func TestInstallShRefusesAnArchiveWithoutLauncher(t *testing.T) {
	f := newShFixture(t)
	f.cosign(t, true)
	archive := "locksql_" + shVersion + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	data := tarGz(t, map[string][]byte{"locksql": []byte("#!/bin/sh\n")})
	if err := os.WriteFile(filepath.Join(f.release, archive), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.release, "checksums.txt"), []byte(hexSum(data)+"  "+archive+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := f.run(t)
	if err == nil || f.installed() || !strings.Contains(out, "holds no launcher") {
		t.Fatalf("%v, installed %v\n%s", err, f.installed(), out)
	}
}

func writeExec(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The signature of checksums.txt is checked against the release workflow
// run for a version tag, the identity locksql update checks too, not any
// workflow or ref of the repository.
func TestInstallShChecksTheReleaseWorkflowIdentity(t *testing.T) {
	f := newShFixture(t)
	f.cosign(t, true)
	out, err := f.run(t)
	if err != nil || !f.installed() {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	if !strings.Contains(out, "cosign: checksums.txt signature verified") {
		t.Errorf("no verification message:\n%s", out)
	}
	args, err := os.ReadFile(f.cosignArgs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"verify-blob\n", "--certificate-identity\nhttps://github.com/DavidGodefroid/locksql/.github/workflows/release.yml@refs/tags/v" + shVersion + "\n",
		"--certificate-oidc-issuer\n" + releaseOIDCIssuer + "\n"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("cosign args lack %q:\n%s", want, args)
		}
	}
}

// Without cosign the script refuses: the checksum comes from the same
// release, so only the signature says who made it. LOCKSQL_SKIP_COSIGN=1 is
// the explicit way past it.
func TestInstallShRequiresCosign(t *testing.T) {
	f := newShFixture(t)
	out, err := f.run(t)
	if err == nil || f.installed() || !strings.Contains(out, "cosign is required") || !strings.Contains(out, "LOCKSQL_SKIP_COSIGN=1") {
		t.Fatalf("without cosign: %v, installed %v\n%s", err, f.installed(), out)
	}
	out, err = f.run(t, "LOCKSQL_SKIP_COSIGN=1")
	if err != nil || !f.installed() || !strings.Contains(out, "LOCKSQL_SKIP_COSIGN=1: the signature of checksums.txt is NOT checked") {
		t.Fatalf("LOCKSQL_SKIP_COSIGN=1: %v, installed %v\n%s", err, f.installed(), out)
	}
}

func TestInstallShRefusesABadSignatureOrChecksum(t *testing.T) {
	f := newShFixture(t)
	f.cosign(t, false)
	out, err := f.run(t, "LOCKSQL_SKIP_COSIGN=1")
	if err == nil || f.installed() || !strings.Contains(out, "signature of checksums.txt does not verify") {
		t.Fatalf("bad signature: %v, installed %v\n%s", err, f.installed(), out)
	}

	f = newShFixture(t)
	f.cosign(t, true)
	if err := os.WriteFile(filepath.Join(f.release, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  locksql_"+shVersion+"_"+runtime.GOOS+"_"+runtime.GOARCH+".tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = f.run(t)
	if err == nil || f.installed() || !strings.Contains(out, "checksum mismatch") {
		t.Fatalf("bad checksum: %v, installed %v\n%s", err, f.installed(), out)
	}
}

// The verification command in .goreleaser.yaml's comment is the one users
// copy: it pins the same identity.
func TestGoreleaserCommentPinsTheIdentity(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "--certificate-identity-regexp '"+ReleaseCertIdentityRegexp+"'") {
		t.Errorf(".goreleaser.yaml does not show the pinned identity %s", ReleaseCertIdentityRegexp)
	}
}
