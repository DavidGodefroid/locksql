package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/product"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// managedFile parses a managed file's bytes as Load would return them.
func managedFile(t *testing.T, body string) *managed.File {
	t.Helper()
	f, err := managed.Parse([]byte("version = 1\norganisation = \"Acme\"\n" + body))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// The server bounds a policy through lockkit's CheckManaged: a violation
// cites the managed key, an allowlist bound names it too.
func TestManagedBoundsThroughTheConsole(t *testing.T) {
	h := newHarness(t, uatProfile())
	p := uatProfile()
	p.Tier = config.TierDDL
	err := kconsole.CheckManaged(product.P, h.s, kpolicy{config.NewPolicy(p, nil, nil)}, managedFile(t, "[locksql.bounds]\ntier = \"write\"\n"))
	want := "blocked by company policy: locksql.bounds.tier = write (profile uat: tier = ddl)"
	if !errors.Is(err, kconsole.ErrManaged) || strings.Join(kconsole.ManagedLines(err), "|") != want {
		t.Fatalf("err = %v, lines %q", err, kconsole.ManagedLines(err))
	}
	err = kconsole.CheckManaged(product.P, h.s, kpolicy{config.NewPolicy(p, nil, nil)}, managedFile(t, "[locksql.bounds]\nhosts = [\"*.internal\"]\n"))
	want = "blocked by company policy: locksql.bounds.hosts does not allow db.uat.example.com (profile uat: host + db.uat.example.com)"
	if strings.Join(kconsole.ManagedLines(err), "|") != want {
		t.Fatalf("hosts: lines %q", kconsole.ManagedLines(err))
	}
	p.Tier = config.TierWrite
	if err := kconsole.CheckManaged(product.P, h.s, kpolicy{config.NewPolicy(p, nil, nil)}, managedFile(t, "[locksql.bounds]\ntier = \"write\"\n")); err != nil {
		t.Fatalf("within the bounds: %v", err)
	}
}

// newStarter is a start-up with no terminal answers and the managed file m.
func newStarter(t *testing.T, m *managed.File) (*starter, *fakeIO, string) {
	t.Helper()
	state := t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{}
	return &starter{io: io, log: log, profile: uatProfile(), approver: newTypedApprover(io), managed: m}, io, state
}

// At start, a policy beyond the bounds is refused before any prompt and
// audited refused-managed; one within them is reviewed and approved with
// managed_sha256.
func TestManagedStartPolicy(t *testing.T) {
	m := managedFile(t, "[locksql.bounds]\ntier = \"write\"\n")
	p := uatProfile()
	p.Tier = config.TierDDL
	st, io, state := newStarter(t, m)
	_, _, err := st.startPolicy(context.Background(), state, "user-uat", config.NewPolicy(p, nil, nil))
	if !errors.Is(err, kconsole.ErrManaged) || io.promptCount() != 0 {
		t.Fatalf("err = %v, prompts %d", err, io.promptCount())
	}
	out := io.output()
	if !strings.Contains(out, "Managed by Acme (sha256:") || !strings.Contains(out, "blocked by company policy: locksql.bounds.tier = write (profile uat: tier = ddl)") {
		t.Fatalf("output: %s", out)
	}
	logText := readAudit(t, state)
	if !strings.Contains(logText, `"decision":"refused-managed"`) || !strings.Contains(logText, `"managed":"`+m.Fingerprint+`"`) {
		t.Fatalf("audit: %s", logText)
	}

	p.Tier = config.TierWrite
	st, io, state = newStarter(t, m)
	io.answers = []string{"y"}
	if _, _, err := st.startPolicy(context.Background(), state, "user-uat", config.NewPolicy(p, nil, nil)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(state, product.P.Name, "approved", "user-uat.json"))
	if err != nil || !strings.Contains(string(b), `"managed_sha256": "`+m.Fingerprint+`"`) {
		t.Fatalf("approved file: %s %v", b, err)
	}
}

// A refused managed file refuses the start before the config is read:
// audited refused-managed, an error wrapping ErrManaged with its line.
func TestManagedRefusedFileRefusesTheStart(t *testing.T) {
	io := &fakeIO{}
	state := t.TempDir()
	err := refuseManagedStart(Options{IO: io, StateDir: state, Profile: "uat"}, errors.New("managed: /etc/lockfamily/managed.toml must be owned by root (it is owned by uid 1000)"))
	if !errors.Is(err, kconsole.ErrManaged) {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(ManagedLines(err), "|"); got != "blocked by company policy: managed: /etc/lockfamily/managed.toml must be owned by root (it is owned by uid 1000)" {
		t.Fatalf("lines %q", got)
	}
	if !strings.Contains(readAudit(t, state), `"decision":"refused-managed"`) {
		t.Fatal("not audited")
	}
}

// While the console serves, a managed file tightened on disk is applied at
// the next poll (LoadManaged), and a loosening edit of the profile beyond
// the bounds is refused without becoming pending.
func TestManagedPoll(t *testing.T) {
	cur := managedFile(t, "[locksql.bounds]\ntier = \"write\"\n")
	files := uatProfile()
	files.Tier = config.TierWrite
	start := files
	h := newHarness(t, start, func(c *ServerConfig) {
		c.Managed = cur
		c.LoadManaged = func(context.Context) (*managed.File, error) { return cur, nil }
		c.LoadPolicy = func() (config.Policy, error) { return config.NewPolicy(files, []string{"app.users.email"}, nil), nil }
	})

	// A loosening beyond the bounds: refused, never pending.
	files.Tier = config.TierDDL
	h.s.CheckPolicy()
	if h.s.k.PolicyPending() || !h.s.k.PolicyRefused() {
		t.Fatalf("pending %v refused %v", h.s.k.PolicyPending(), h.s.k.PolicyRefused())
	}
	if !strings.Contains(h.io.output(), "refused by the company's managed configuration") || !strings.Contains(h.auditLog(t), `"decision":"refused-managed"`) {
		t.Fatalf("output: %s", h.io.output())
	}
	if h.s.profile.Tier != config.TierWrite {
		t.Fatalf("tier in force %s", h.s.profile.Tier)
	}

	// The company tightens to read, and the files follow: the policy in
	// force is replaced at the next poll.
	files.Tier = config.TierRead
	cur = managedFile(t, "[locksql.bounds]\ntier = \"read\"\n")
	h.s.CheckPolicy()
	if h.s.profile.Tier != config.TierRead {
		t.Fatalf("tier in force %s after the stricter managed file", h.s.profile.Tier)
	}
	if !strings.Contains(h.auditLog(t), `"decision":"managed-changed"`) || !strings.Contains(h.auditLog(t), `"managed":"`+cur.Fingerprint+`"`) {
		t.Fatalf("audit: %s", h.auditLog(t))
	}
	if _, ended := h.s.Ended(); ended {
		t.Fatal("session ended")
	}

	// Stricter again, but the files stay beyond it: the session ends.
	cur = managedFile(t, "[locksql.bounds]\nlimits.max_rows = 10\n")
	h.s.CheckPolicy()
	if _, ended := h.s.Ended(); !ended {
		t.Fatal("the policy in force beyond the managed file did not end the session")
	}
}

func readAudit(t *testing.T, state string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(state, product.P.Name, "audit*"))
	var out strings.Builder
	for _, m := range matches {
		_ = filepath.WalkDir(m, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := os.ReadFile(p)
				out.Write(b)
			}
			return nil
		})
	}
	return out.String()
}
