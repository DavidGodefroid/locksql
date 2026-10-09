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
	rulesPath := filepath.Join(root, pii.RulesFile)
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
	ap, err = st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, ap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ap.PIIMask, ",") != "app.users.email" {
		t.Fatalf("first run rules: %v", ap.PIIMask)
	}

	// The human edits the file meanwhile (a comment and a new allow rule).
	path := rulesPath
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(b, []byte("\n[[allow]]\ncolumn = \"app.users.nickname\"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	// Next start: nothing new, no prompt.
	io.prompts = nil
	if _, err := st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, ap); err != nil {
		t.Fatal(err)
	}
	if len(io.prompts) != 0 {
		t.Fatalf("prompted with nothing new: %v", io.prompts)
	}

	// A new PII-looking column appears: it is proposed and added.
	sess.cols = append(sess.cols, engine.ColumnInfo{DB: "app", Table: "users", Column: "phone_number", Type: "varchar"},
		engine.ColumnInfo{DB: "app", Table: "users", Column: "nickname", Type: "varchar"})
	io.answers = []string{"a"}
	ap, err = st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, ap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(ap.PIIMask, ","), "app.users.phone_number") {
		t.Fatalf("new column not masked: %v", ap.PIIMask)
	}
	onDisk, err := pii.LoadRulesFile(rulesPath)
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

func TestPIIScanQuasiIdentifiers(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	rulesPath := filepath.Join(root, pii.RulesFile)
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{}
	p := uatProfile()
	st := &starter{io: io, log: log, profile: p}
	sess := &columnsSession{cols: []engine.ColumnInfo{
		{DB: "app", Table: "users", Column: "email", Type: "varchar"},
		{DB: "app", Table: "users", Column: "birth_date", Type: "date"},
		{DB: "app", Table: "users", Column: "zip_code", Type: "varchar"},
		{DB: "app", Table: "users", Column: "gender", Type: "varchar"},
	}}
	key := config.ApprovedKey(root, p.Name)
	// Quasi-identifiers are asked in sorted order: birth_date, gender, zip_code.
	// PII: accept all; birth_date: yes; gender: no; zip_code: no answer.
	io.answers = []string{"a", "y", "n"}
	ap, err := st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, config.NewPolicy(p, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(io.prompts, "\n"), pii.QuasiLimit) {
		t.Errorf("limit not shown in the prompts:\n%q", io.prompts)
	}
	if got := strings.Join(ap.PIIMask, ","); got != "app.users.birth_date,app.users.email" {
		t.Errorf("mask = %s", got)
	}
	if got := strings.Join(ap.PIIAllow, ","); got != "app.users.gender" {
		t.Errorf("allow = %s", got)
	}
	onDisk, _ := pii.LoadRulesFile(rulesPath)
	if !onDisk.Covered("app", "users", "gender") || onDisk.Covered("app", "users", "zip_code") {
		t.Errorf("file on disk: %+v", onDisk)
	}

	// Next start: zip_code is asked again, nothing else.
	io.prompts, io.answers = nil, []string{"n"}
	ap, err = st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, ap)
	if err != nil {
		t.Fatal(err)
	}
	if len(io.prompts) != 1 || !strings.Contains(io.prompts[0], "zip_code") {
		t.Fatalf("prompts %q", io.prompts)
	}
	onDisk, _ = pii.LoadRulesFile(rulesPath)
	if !onDisk.Covered("app", "users", "gender") || !onDisk.Covered("app", "users", "zip_code") {
		t.Errorf("allow not merged into the file on disk: %+v", onDisk)
	}
}
