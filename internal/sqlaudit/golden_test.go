package sqlaudit

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DavidGodefroid/lockkit/audit"

	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

var update = flag.Bool("update", false, "rewrite testdata/audit_golden.jsonl")

// goldenRecords are six events with every field set that the event uses.
func goldenRecords() []Record {
	uid := 1000
	root := 0
	return []Record{
		{Event: EventLogin, Profile: "prod", Engine: "postgres", Host: "db.example.com", DB: "shop", DBUser: "ro_<&>",
			SSHHost: "bastion.example.com:22", SSHHostKey: "SHA256:abc", Approval: "session", PeerUID: &root, PeerPID: 1, PeerUser: "root"},
		{Event: EventRefused, Profile: "prod", Engine: "postgres", DB: "shop", Class: "read", SQL: "SELECT email FROM users ORDER BY email LIMIT 5",
			Verdict: "refused", Error: "a PII column that orders rows", Code: string(refusal.MaskedOrder),
			Span: &refusal.Span{Line: 1, Col: 34, Token: "email"}, Intent: "list users <b>", PeerUID: &uid, PeerPID: 4242, PeerUser: "alice"},
		{Event: EventApproved, Profile: "prod", Engine: "postgres", DB: "shop", Class: "read", SQL: "SELECT id FROM orders LIMIT 10",
			Verdict: "ok", Decision: "approved", Warnings: []string{"seq scan on orders", "k < 5 & more"}, Intent: "count", Approval: "desktop+fingerprint",
			PeerUID: &uid, PeerPID: 4242, PeerUser: "alice"},
		{Event: EventRun, Profile: "prod", Engine: "postgres", DB: "shop", Class: "read", SQL: "SELECT id FROM orders LIMIT 10",
			Decision: "ok", Rows: 10, Affected: 0, DurationMS: 37, Truncated: true, Unmasked: true, Intent: "count", PeerUID: &uid, PeerPID: 4242},
		{Event: EventDenied, Profile: "uat", Engine: "mysql", Host: "/run/mysqld/mysqld.sock", DB: "crm", Class: "write",
			SQL: "UPDATE t SET a = 1 WHERE id = 2", Decision: "denied", Reason: "not now \"please\"", Affected: 0, PeerUID: &uid, PeerPID: 7},
		{Event: EventPolicy, Profile: "uat", Decision: "refused", Warnings: []string{"tier read -> write"}, Error: "loosening refused"},
		{Event: EventLogout, Profile: "uat", Decision: "idle"},
	}
}

var (
	tsRe    = regexp.MustCompile(`^\{"ts":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}(Z|[+-]\d\d:\d\d)",`)
	chainRe = regexp.MustCompile(`,"prev_hash":"(genesis|sha256:[0-9a-f]{64})"\}\n$`)
)

// The audit lines locksql writes are byte-identical to those of locksql
// 0.8 (captured before lockkit), timestamp aside, up to lockkit's
// prev_hash, which comes last: the 0.8 line is a byte-identical prefix,
// and the lines the chain links verify.
func TestAuditLineUnchanged(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range goldenRecords() {
		if err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	for _, line := range bytes.SplitAfter(raw, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if !tsRe.Match(line) || !chainRe.Match(line) {
			t.Fatalf("line without a leading timestamp or a trailing prev_hash: %s", line)
		}
		line = chainRe.ReplaceAll(line, []byte("}\n"))
		got.Write(tsRe.ReplaceAll(line, []byte(`{"ts":"TS",`)))
	}
	golden := filepath.Join("testdata", "audit_golden.jsonl")
	if *update {
		if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("audit lines changed:\ngot:\n%s\nwant:\n%s", got.Bytes(), want)
	}
	if s, err := audit.Verify(bytes.NewReader(raw)); err != nil || s.Records != len(goldenRecords()) || s.Legacy != 0 {
		t.Errorf("chain: %+v, %v", s, err)
	}
}

// A log of locksql 0.8, before the chain, stays readable: new records
// chain onto its last line, and the whole log verifies.
func TestAuditChainExtendsAnOldLog(t *testing.T) {
	dir := t.TempDir()
	old, err := os.ReadFile(filepath.Join("testdata", "audit_golden.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	old = bytes.ReplaceAll(old, []byte(`{"ts":"TS",`), []byte(`{"ts":"2025-06-01T10:00:00.000Z",`))
	p := filepath.Join(dir, "locksql", "audit.log")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, old, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range goldenRecords() {
		if err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	n := len(goldenRecords())
	if s, err := audit.Verify(bytes.NewReader(raw)); err != nil || s.Records != 2*n || s.Legacy != n {
		t.Fatalf("chain: %+v, %v", s, err)
	}
	// An edited old line breaks the link of the first new one.
	edited := bytes.Replace(raw, []byte(`"decision":"idle"`), []byte(`"decision":"none"`), 1)
	if _, err := audit.Verify(bytes.NewReader(edited)); err == nil {
		t.Fatal("an edited record verifies")
	}
}
