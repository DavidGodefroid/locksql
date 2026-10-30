package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ReleaseCertIdentityRegexp is the certificate identity a release's
// checksums.txt must be signed with: the release workflow of this
// repository, run for a version tag. scripts/install.sh and the comment
// in .goreleaser.yaml check the same one (installsh_test.go).
const ReleaseCertIdentityRegexp = `^https://github\.com/DavidGodefroid/locksql/\.github/workflows/release\.yml@refs/tags/v[0-9]`

// releaseOIDCIssuer is the issuer of that certificate: GitHub Actions.
const releaseOIDCIssuer = "https://token.actions.githubusercontent.com"

// releasesURL is where the releases are published.
const releasesURL = "https://github.com/DavidGodefroid/locksql/releases"

// Download limits: a release archive is a few tens of MB.
const (
	maxArchiveSize = 256 << 20
	maxSmallFile   = 1 << 20
)

// updateEnv is what the new-version notice reads from the system; nil
// fields mean the real one.
type updateEnv struct {
	// exe returns the running binary, symlinks resolved.
	exe func() (string, error)
	// installed is the binary the launcher updates (installedBinary).
	installed string
	// releases is the base URL of the releases (releasesURL).
	releases string
	// client fetches the release files.
	client *http.Client
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
	if d.releases == "" {
		d.releases = releasesURL
	}
	if d.client == nil {
		d.client = &http.Client{Timeout: 5 * time.Minute}
	}
	return d
}

// packageHint is the refusal for a binary a package manager installed. The
// packages are covered by the signed checksums.txt, like the archives: the
// commands check the signature and the checksum before installing, and
// stop at the first failure (&& chaining; the download loop exits a
// subshell, not the user's shell).
func packageHint(bin string) string {
	return fmt.Sprintf(`locksql update: %[1]s was installed by a package (deb, rpm or apk): upgrade it with the package manager.
Download the package, checksums.txt and its signature, check both, then install. With V the new version
(without its v) and P the package type (deb, rpm or apk), for example V=0.9.0 P=deb:
  F=locksql_${V}_linux_%[3]s.$P
  (for f in "$F" checksums.txt checksums.txt.sigstore.json; do curl -fsSLO "%[2]s/download/v$V/$f" || exit 1; done) &&
  cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp '%[4]s' --certificate-oidc-issuer %[5]s checksums.txt &&
  awk -v f="$F" '$2 == f { n++; print } END { exit !n }' checksums.txt >"$F.sha256" && sha256sum -c "$F.sha256" &&
  echo "verified: $F"
then, only after "verified: <package>":
  Debian, Ubuntu:  sudo apt install "./$F"
  Fedora, RHEL:    sudo dnf install "./$F"
  Alpine:          sudo apk add --allow-untrusted "./$F"   (no apk key signs it: the cosign check above does)
`, bin, releasesURL, runtime.GOARCH, ReleaseCertIdentityRegexp, releaseOIDCIssuer)
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
