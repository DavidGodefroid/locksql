//go:build unix

package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/fingerprint"
)

// questionIO is a fakeIO that records where Run asked it to keep its
// questions, and how many prompts came before.
type questionIO struct {
	*fakeIO
	path   string
	before int
}

func (q *questionIO) SetQuestionFile(path string) {
	q.path, q.before = path, q.promptCount()
}

// Run keeps the question the console waits for next to its socket, from
// before the first question (#182): lox attach and lea read it there,
// since the question was printed before they attached.
func TestRunRecordsQuestions(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(prodConfig, "%d", "100", 1)
	if err := os.WriteFile(filepath.Join(root, ".locksql", "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := newIsolationEnv
	newIsolationEnv = func(*os.File) isolationEnv {
		env := desktopEnvFake(t)
		env.newVerifier = func(string) (fingerprint.Verifier, error) { return nil, fingerprint.ErrUnavailable }
		return env
	}
	t.Cleanup(func() { newIsolationEnv = old })
	io := &questionIO{fakeIO: &fakeIO{}}
	// Ends at the policy review, which gets no answer.
	_ = Run(context.Background(), Options{Hub: runHub(t), Profile: "prod", IO: io, StateDir: state, Cwd: root})
	if io.promptCount() == 0 {
		t.Fatal("no question asked")
	}
	if !strings.HasSuffix(io.path, "-prod.question") || !filepath.IsAbs(io.path) || io.before != 0 {
		t.Fatalf("question file %q set after %d prompts", io.path, io.before)
	}
}
