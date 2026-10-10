package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/secrets"
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

// A quasi-identifier answer is read like the other prompts: yes masks, no
// or Enter allows, and anything else is no answer, so nothing is written.
func TestPIIScanQuasiAnswers(t *testing.T) {
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
		{DB: "app", Table: "users", Column: "birth_date", Type: "date"},
		{DB: "app", Table: "users", Column: "gender", Type: "varchar"},
		{DB: "app", Table: "users", Column: "zip_code", Type: "varchar"},
	}}
	key := config.ApprovedKey(root, p.Name)
	// birth_date: " Yes "; gender: "maybe"; zip_code: no answer.
	io.answers = []string{" Yes ", "maybe"}
	ap, err := st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, config.NewPolicy(p, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ap.PIIMask, ","); got != "app.users.birth_date" {
		t.Errorf("mask = %s", got)
	}
	if len(ap.PIIAllow) != 0 {
		t.Errorf("allow = %v", ap.PIIAllow)
	}
	onDisk, _ := pii.LoadRulesFile(rulesPath)
	if onDisk.Covered("app", "users", "gender") || onDisk.Covered("app", "users", "zip_code") {
		t.Errorf("file on disk: %+v", onDisk)
	}

	// Next start: gender and zip_code are asked again; "NO" and Enter allow.
	io.prompts, io.answers = nil, []string{"NO", ""}
	ap, err = st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, ap)
	if err != nil {
		t.Fatal(err)
	}
	if len(io.prompts) != 2 {
		t.Fatalf("prompts %q", io.prompts)
	}
	if got := strings.Join(ap.PIIAllow, ","); got != "app.users.gender,app.users.zip_code" {
		t.Errorf("allow = %s", got)
	}
}

// keychainStarter returns a starter connecting through the fake engine with
// credentials = "keychain", port as given, and a legacy keychain item
// "<profile>@<host>" stored before the port was part of the name. The fake
// engine counts as one whose default port is 3306.
func keychainStarter(t *testing.T, port int) (*starter, *fakeIO, config.Profile) {
	t.Helper()
	keyring.MockInit()
	p := uatProfile()
	p.Engine, p.Credentials, p.Port = fakeEngineName, config.CredentialsKeychain, port
	if err := keyring.Set(secrets.KeychainService, p.Name+"@"+p.Host, "s3cret"); err != nil {
		t.Fatal(err)
	}
	oldNext, oldPort := fakeNext, defaultPort
	fakeNext = &fakeSession{}
	defaultPort = func(engine string) int {
		if engine == fakeEngineName {
			return 3306
		}
		return oldPort(engine)
	}
	t.Cleanup(func() { fakeNext, defaultPort = oldNext, oldPort })
	io := &fakeIO{}
	return &starter{io: io, profile: p, user: p.User}, io, p
}

// On the engine's default port, a keychain item stored before the port was
// part of its name is moved to the new name at connect, once, and the human
// is told.
func TestConnectMigratesLegacyKeychainItem(t *testing.T) {
	st, io, p := keychainStarter(t, 3306)
	legacy := p.Name + "@" + p.Host
	for range 2 {
		sess, err := st.connect(context.Background(), true)
		if err != nil || sess == nil {
			t.Fatalf("connect: %v", err)
		}
	}
	if io.promptCount() != 0 {
		t.Errorf("prompts %q: the migrated secret was not used", io.prompts)
	}
	want := "moved the keychain secret of " + legacy + " to " + secrets.KeychainAccount(p.Name, p.Host, p.Port)
	if n := strings.Count(io.output(), want); n != 1 {
		t.Errorf("migration line shown %d times in %q", n, io.output())
	}
	if _, err := keyring.Get(secrets.KeychainService, legacy); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("legacy item kept: %v", err)
	}
}

// On another port the legacy item, which names no port, is deleted unread:
// the human is told once, the secret is asked, and nothing is stored unless
// the human saves it. A later start on the default port finds nothing to
// migrate to an agent-run listener.
func TestConnectRemovesLegacyKeychainItemOnOtherPort(t *testing.T) {
	st, io, p := keychainStarter(t, 3307)
	io.secrets = []string{"typed", "typed"}
	io.answers = []string{"n", "n"} // do not save
	for range 2 {
		if _, err := st.connect(context.Background(), true); err != nil {
			t.Fatalf("connect: %v", err)
		}
	}
	if n := strings.Count(strings.Join(io.prompts, "\n"), "Password for "); n != 2 {
		t.Errorf("prompts %q: the secret was not asked at each start", io.prompts)
	}
	want := `removed the pre-upgrade keychain item ` + p.Name + "@" + p.Host + `; answer "Save in OS keychain?" to store the secret for ` + p.Host + ":3307"
	if n := strings.Count(io.output(), want); n != 1 {
		t.Errorf("removal line shown %d times in %q", n, io.output())
	}
	if strings.Contains(io.output(), "moved the keychain secret") {
		t.Errorf("migrated on a non-default port: %q", io.output())
	}
	for _, account := range []string{p.Name + "@" + p.Host, secrets.KeychainAccount(p.Name, p.Host, p.Port), secrets.KeychainAccount(p.Name, p.Host, 3306)} {
		if _, err := keyring.Get(secrets.KeychainService, account); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("%s after a start on another port: %v", account, err)
		}
	}
}
