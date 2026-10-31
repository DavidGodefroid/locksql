//go:build unix

package console

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/fingerprint"
)

// A --profile that names no profile (a token or a URL pasted in the
// wrong place) is not quoted back.
func TestRunUnknownProfileIsNotEchoed(t *testing.T) {
	root := t.TempDir()
	writeProjectConfig(t, root, 200)
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		io := &fakeIO{}
		err := Run(context.Background(), Options{Hub: runHub(t), Profile: v, IO: io, StateDir: t.TempDir(), Cwd: root})
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "--profile") || !strings.Contains(err.Error(), "uat") {
			t.Fatalf("--profile %s: err = %v", v, err)
		}
		if strings.Contains(err.Error(), "glsa_Canary") || strings.Contains(io.output(), "glsa_Canary") {
			t.Errorf("--profile is quoted back: %v\n%s", err, io.output())
		}
	}
}
