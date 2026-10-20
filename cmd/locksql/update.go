package main

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/update"
)

// ReleaseCertIdentityRegexp is the certificate identity a release's
// checksums.txt must be signed with: the release workflow of this
// repository, run for a version tag. scripts/install.sh is to share it.
const ReleaseCertIdentityRegexp = `^https://github\.com/DavidGodefroid/locksql/\.github/workflows/release\.yml@refs/tags/v[0-9]`

// releaseOIDCIssuer is the issuer of that certificate: GitHub Actions.
const releaseOIDCIssuer = "https://token.actions.githubusercontent.com"

// releasesURL is where the releases are published.
const releasesURL = "https://github.com/DavidGodefroid/locksql/releases"

// cosignHint tells how to get cosign, which update cannot do without.
const cosignHint = "install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) and run locksql update again"

// Download limits: a release archive is a few tens of MB.
const (
	maxArchiveSize = 256 << 20
	maxSmallFile   = 1 << 20
)

// updateEnv is what `locksql update` reads from the system; nil fields
// mean the real one.
type updateEnv struct {
	// exe returns the running binary, symlinks resolved.
	exe func() (string, error)
	// installed is the binary update may replace (installedBinary).
	installed string
	// sourceRefusal is installSourceRefusal.
	sourceRefusal func(bin string) (string, error)
	// releases is the base URL of the releases (releasesURL).
	releases string
	// client fetches the release files.
	client *http.Client
}

// updateOpts are the settings of `locksql update`.
type updateOpts struct {
	version        string
	yes            bool
	allowDowngrade bool
}

// runUpdate is `locksql update`: it replaces /usr/local/bin/locksql with a
// release whose signature, checksum and version it checked first, in the
// invoking account; only the final copy runs as root.
func runUpdate(e env, args []string) int {
	const usage = "locksql update [--version vX.Y.Z] [--yes] [--allow-downgrade]"
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o updateOpts
	fs.StringVar(&o.version, "version", "", "the release to install (default: the latest)")
	fs.BoolVar(&o.yes, "yes", false, "replace the binary without asking")
	fs.BoolVar(&o.allowDowngrade, "allow-downgrade", false, "install a release older than the running one")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(e.stderr, "usage:", usage)
		return exitUsage
	}
	u := e.upd
	if u == nil {
		u = &updateEnv{}
	}
	return doUpdate(e, u.withDefaults(), o)
}

func (u *updateEnv) withDefaults() updateEnv {
	d := *u
	if d.exe == nil {
		d.exe = func() (string, error) {
			bin, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(bin)
		}
	}
	if d.installed == "" {
		d.installed = installedBinary
	}
	if d.sourceRefusal == nil {
		d.sourceRefusal = installSourceRefusal
	}
	if d.releases == "" {
		d.releases = releasesURL
	}
	if d.client == nil {
		d.client = &http.Client{Timeout: 5 * time.Minute}
	}
	return d
}

func doUpdate(e env, u updateEnv, o updateOpts) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(e.stderr, "locksql update: "+format+"\n", a...)
		return exitFail
	}

	// 1. Channel: only a release installed as root at installedBinary.
	bin, err := u.exe()
	if err != nil {
		return fail("%v", err)
	}
	if strings.HasPrefix(bin, "/usr/bin/") {
		fmt.Fprint(e.stderr, packageHint(bin))
		return exitFail
	}
	if bin != u.installed {
		fmt.Fprint(e.stderr, channelHint(bin, bin+" is not "+u.installed))
		return exitFail
	}
	if msg, err := u.sourceRefusal(bin); err != nil {
		return fail("%v", err)
	} else if msg != "" {
		fmt.Fprint(e.stderr, channelHint(bin, bin+" is not owned by root, or group or others may write it"))
		return exitFail
	}

	// 2. Target.
	running := strings.TrimPrefix(version, "v")
	if running == "dev" && o.version == "" {
		return fail("this is a development build (version dev): name the release with --version vX.Y.Z")
	}
	tag := o.version
	if tag == "" {
		if tag, err = latestTag(u); err != nil {
			return fail("%v", err)
		}
	}
	target := strings.TrimPrefix(tag, "v")
	if _, err := parseSemver(target); err != nil {
		return fail("invalid version %q", tag)
	}
	tag = "v" + target
	if running != "dev" {
		c, err := compareSemver(target, running)
		if err != nil {
			return fail("the running version %q: %v", version, err)
		}
		if c == 0 {
			fmt.Fprintf(e.stdout, "locksql update: already at %s\n", tag)
			return exitOK
		}
		if c < 0 && !o.allowDowngrade {
			return fail("%s is older than the running v%s: pass --allow-downgrade to install it", tag, running)
		}
	}

	// 3. Verification, in this account, in a private directory.
	dir, err := os.MkdirTemp("", "locksql-update-")
	if err != nil {
		return fail("%v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return fail("%v", err)
	}
	extracted, pin, err := fetchVerified(e, u, dir, tag, target)
	if err != nil {
		return fail("%v", err)
	}

	// 4. Replacement, as root.
	script := updateScript(extracted, pin, runtime.GOOS)
	fmt.Fprintf(e.stdout, "locksql %s verified: signature of checksums.txt, archive checksum, version.\n"+
		"sha256 of the new binary: %s\n\nThese commands run as root:\n\n%s\n", tag, pin, indent(script))
	if !o.yes {
		if !e.tty {
			fmt.Fprintln(e.stderr, "locksql update: confirm in a terminal, or run with --yes")
			return exitUsage
		}
		if !confirm(e, fmt.Sprintf("Replace %s with %s now with sudo? [y/N] ", installedBinary, tag)) {
			fmt.Fprintln(e.stdout, "nothing done")
			return exitOK
		}
	}
	if err := e.asRoot(script); err != nil {
		return fail("%v", err)
	}
	// 5.
	fmt.Fprintf(e.stdout, "locksql updated to %s: restart the console (`locksql console` in the locksql account) to use %s\n", tag, tag)
	return exitOK
}

// packageHint is the refusal for a binary a package manager installed.
func packageHint(bin string) string {
	a := runtime.GOARCH
	return fmt.Sprintf(`locksql update: %[1]s was installed by a package (deb, rpm or apk): upgrade it with the package manager.
With V the new version (without its v), for example:
  Debian, Ubuntu:  curl -fsSLO %[2]s/download/v$V/locksql_${V}_linux_%[3]s.deb && sudo apt install ./locksql_${V}_linux_%[3]s.deb
  Fedora, RHEL:    sudo dnf install %[2]s/download/v$V/locksql_${V}_linux_%[3]s.rpm
  Alpine:          curl -fsSLO %[2]s/download/v$V/locksql_${V}_linux_%[3]s.apk && sudo apk add --allow-untrusted ./locksql_${V}_linux_%[3]s.apk
`, bin, releasesURL, a)
}

// channelHint is the refusal for a binary update may not replace.
func channelHint(bin, why string) string {
	return fmt.Sprintf(`locksql update: only a release installed as %s, owned by root and writable by root alone, is updated in place;
%s. Install a release with scripts/install.sh (default /usr/local/bin), then run sudo locksql install.
`, installedBinary, why)
}

// latestTag follows the redirect of <releases>/latest and returns the last
// segment of the URL it lands on, the tag of the latest release.
func latestTag(u updateEnv) (string, error) {
	resp, err := u.client.Get(u.releases + "/latest")
	if err != nil {
		return "", fmt.Errorf("finding the latest release: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxSmallFile))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("finding the latest release: %s", resp.Status)
	}
	tag := path.Base(resp.Request.URL.Path)
	if !strings.HasPrefix(tag, "v") {
		return "", errors.New("no published release found; name one with --version")
	}
	return tag, nil
}

// download fetches name from release tag, at most max bytes.
func download(u updateEnv, tag, name string, max int64) ([]byte, error) {
	resp, err := u.client.Get(u.releases + "/download/" + tag + "/" + name)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", name, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("download %s: larger than %d bytes", name, max)
	}
	return b, nil
}

// fetchVerified downloads release tag into dir, checks the cosign signature
// of checksums.txt, the archive's checksum and the extracted binary's
// version, and returns the binary's path and sha256.
func fetchVerified(e env, u updateEnv, dir, tag, target string) (bin, pin string, err error) {
	archive := fmt.Sprintf("locksql_%s_%s_%s.tar.gz", target, runtime.GOOS, runtime.GOARCH)
	sums, err := download(u, tag, "checksums.txt", maxSmallFile)
	if err != nil {
		return "", "", err
	}
	bundle, err := download(u, tag, "checksums.txt.sigstore.json", maxSmallFile)
	if err != nil {
		return "", "", err
	}
	sumsPath, bundlePath := filepath.Join(dir, "checksums.txt"), filepath.Join(dir, "checksums.txt.sigstore.json")
	for p, b := range map[string][]byte{sumsPath: sums, bundlePath: bundle} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return "", "", err
		}
	}
	if err := cosignVerify(sumsPath, bundlePath); err != nil {
		return "", "", err
	}
	fmt.Fprintln(e.stdout, "cosign: checksums.txt signature verified")

	want, err := checksumFor(sums, archive)
	if err != nil {
		return "", "", err
	}
	data, err := download(u, tag, archive, maxArchiveSize)
	if err != nil {
		return "", "", err
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != want {
		return "", "", fmt.Errorf("%s does not match its checksum in checksums.txt; nothing installed", archive)
	}
	exe, err := extractBinary(data)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", archive, err)
	}
	sum := sha256.Sum256(exe)
	pin = hex.EncodeToString(sum[:])
	bin = filepath.Join(dir, "locksql")
	if err := os.WriteFile(bin, exe, 0o700); err != nil {
		return "", "", err
	}
	if err := checkBinaryVersion(bin, target); err != nil {
		return "", "", err
	}
	return bin, pin, nil
}

// cosignVerify checks the keyless signature of checksums.txt against the
// release workflow's identity. A missing cosign is a refusal too.
func cosignVerify(sums, bundle string) error {
	id := update.Identity{CertIdentityRegexp: ReleaseCertIdentityRegexp, OIDCIssuer: releaseOIDCIssuer}
	err := update.VerifyFiles(context.Background(), sums, bundle, id, update.Options{})
	var ve *update.VerifyError
	switch {
	case errors.Is(err, update.ErrCosignMissing):
		return fmt.Errorf("cosign is not installed, and the release's signature must be checked: %s", cosignHint)
	case errors.As(err, &ve):
		return fmt.Errorf("cosign: the signature of checksums.txt does not verify (%v): %s\nnothing installed; if cosign itself is broken, %s",
			ve.Err, ve.Output, cosignHint)
	}
	return err
}

// checksumFor returns the sha256 checksums.txt lists for name.
func checksumFor(sums []byte, name string) (string, error) { return update.ChecksumFor(sums, name) }

// extractBinary returns the regular file `locksql` of a .tar.gz.
func extractBinary(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("no locksql binary in the archive")
		}
		if err != nil {
			return nil, err
		}
		if path.Clean(h.Name) != "locksql" || h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxArchiveSize+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxArchiveSize {
			return nil, errors.New("the locksql binary is too large")
		}
		return b, nil
	}
}

// checkBinaryVersion runs `bin version` and checks it prints "locksql
// target".
func checkBinaryVersion(bin, target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return fmt.Errorf("the downloaded binary does not run: %v", err)
	}
	got := strings.TrimPrefix(strings.TrimSpace(string(out)), "locksql ")
	if strings.TrimPrefix(got, "v") != target {
		return fmt.Errorf("the downloaded binary reports version %q, not %s; nothing installed", strings.TrimSpace(string(out)), target)
	}
	return nil
}

// updateScript is the root script that installs src as installedBinary
// after checking a root-owned copy of it against pin.
func updateScript(src, pin, goos string) string {
	sumCmd, group := "sha256sum -c -", "root"
	if goos == "darwin" {
		sumCmd, group = "shasum -a 256 -c -", "wheel"
	}
	prefix, from := pinnedSource("locksql update", src, pin, sumCmd)
	return fmt.Sprintf("set -eu\n%sinstall -m 0755 -o root -g %s %s %s\n", prefix, group, from, installedBinary)
}

// semver is a parsed X.Y.Z[-pre][+build].
type semver struct {
	core [3]int
	pre  []string
}

func parseSemver(s string) (semver, error) {
	var v semver
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if s[i+1:] == "" {
			return v, fmt.Errorf("invalid version %q", s)
		}
		v.pre = strings.Split(s[i+1:], ".")
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("invalid version %q", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return v, fmt.Errorf("invalid version %q", s)
		}
		v.core[i] = n
	}
	return v, nil
}

// compareSemver compares two versions without a leading v: -1, 0 or 1.
func compareSemver(a, b string) (int, error) {
	va, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for i := range va.core {
		if va.core[i] != vb.core[i] {
			return cmp.Compare(va.core[i], vb.core[i]), nil
		}
	}
	// A pre-release is older than its release.
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0, nil
	case len(va.pre) == 0:
		return 1, nil
	case len(vb.pre) == 0:
		return -1, nil
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		x, y := va.pre[i], vb.pre[i]
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				return cmp.Compare(nx, ny), nil
			}
		case ex == nil:
			return -1, nil
		case ey == nil:
			return 1, nil
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c, nil
			}
		}
	}
	return cmp.Compare(len(va.pre), len(vb.pre)), nil
}
