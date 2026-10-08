package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

type columnsSession struct {
	fakeSession
	cols []engine.ColumnInfo
}

func (c *columnsSession) Columns(context.Context, string) ([]engine.ColumnInfo, error) {
	return c.cols, nil
}

// The schema is scanned at every start: a new column that looks like PII
// and that no rule names is proposed, and accepting it only adds to the
// file on disk.
func TestPIIScanAtEveryStart(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{}
	p := uatProfile()
	st := &starter{io: io, log: log, profile: p}
	sess := &columnsSession{cols: []engine.ColumnInfo{
		{DB: "app", Table: "users", Column: "email", Type: "varchar"},
		{DB: "app", Table: "users", Column: "id", Type: "int"},
	}}
	key := config.ApprovedKey(root, p.Name)
	ap := config.NewPolicy(p, nil, nil)

	// First run: the file is written.
	io.answers = []string{"a"}
	ap, err = st.piiBootstrap(context.Background(), sess, []string{"app"}, root, state, key, ap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ap.PIIMask, ",") != "app.users.email" {
		t.Fatalf("first run rules: %v", ap.PIIMask)
	}

	// The human edits the file meanwhile (a comment and a new allow rule).
	path := filepath.Join(root, pii.RulesFile)
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(b, []byte("\n[[allow]]\ncolumn = \"app.users.nickname\"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	// Next start: nothing new, no prompt.
	io.prompts = nil
	if _, err := st.piiBootstrap(context.Background(), sess, []string{"app"}, root, state, key, ap); err != nil {
		t.Fatal(err)
	}
	if len(io.prompts) != 0 {
		t.Fatalf("prompted with nothing new: %v", io.prompts)
	}

	// A new PII-looking column appears: it is proposed and added.
	sess.cols = append(sess.cols, engine.ColumnInfo{DB: "app", Table: "users", Column: "phone_number", Type: "varchar"},
		engine.ColumnInfo{DB: "app", Table: "users", Column: "nickname", Type: "varchar"})
	io.answers = []string{"a"}
	ap, err = st.piiBootstrap(context.Background(), sess, []string{"app"}, root, state, key, ap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(ap.PIIMask, ","), "app.users.phone_number") {
		t.Fatalf("new column not masked: %v", ap.PIIMask)
	}
	onDisk, err := pii.LoadRules(root)
	if err != nil {
		t.Fatal(err)
	}
	if !onDisk.Matches("app", "users", "phone_number") || len(onDisk.Allow) != 1 {
		t.Errorf("file on disk: %+v", onDisk)
	}
	if strings.Contains(io.output(), "nickname") {
		t.Error("an allowed column was proposed")
	}
}
