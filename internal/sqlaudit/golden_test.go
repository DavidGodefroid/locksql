package sqlaudit

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

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

var tsRe = regexp.MustCompile(`^\{"ts":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}(Z|[+-]\d\d:\d\d)",`)

// The audit lines locksql writes are byte-identical to those of locksql
// 0.8 (captured before lockkit), timestamp aside: existing logs keep one
// format.
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
		if !tsRe.Match(line) {
			t.Fatalf("line without a leading timestamp: %s", line)
		}
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
}
