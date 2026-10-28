package sqlaudit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// locksql's log stays where locksql 0.8 wrote it.
func TestOpenPath(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "locksql", "audit.log"); l.Path() != want {
		t.Fatalf("path = %q, want %q", l.Path(), want)
	}
}

// TestRecordFieldSet pins the JSON field set. Record has no field able to
// hold a password or row data; adding one must be a deliberate change here.
func TestRecordFieldSet(t *testing.T) {
	want := []string{
		"affected", "allow_loosen", "approval", "class", "code", "db", "db_user", "decision", "duration_ms", "engine", "error",
		"event", "host", "intent", "peer_pid", "peer_uid", "peer_user", "profile", "profiles", "reason", "rows", "scope", "span", "sql", "ssh_host", "ssh_host_key", "truncated", "ts",
		"unmasked", "verdict", "warnings",
	}
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	full := Record{
		Event: EventApproved, Profile: "p", Engine: "mysql", Host: "h", DB: "d", DBUser: "u",
		Class: "read", SQL: "s", Verdict: "OK", Decision: "y", Error: "e",
		Rows: 1, Affected: 2, DurationMS: 3, Truncated: true, Unmasked: true, Warnings: []string{"w"}, Intent: "i", Reason: "r", Approval: "session",
		SSHHost: "b", SSHHostKey: "SHA256:k", PeerUID: new(int), PeerPID: 4, PeerUser: "agent",
		Code: "E_NO_LIMIT", Span: &refusal.Span{Line: 1, Col: 2, Token: "FROM"},
		Scope: "user", Profiles: []string{"p"}, AllowLoosen: true,
	}
	if err := l.Append(full); err != nil {
		t.Fatal(err)
	}
	got := readLines(t, l.Path())[0]
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("field set = %v\nwant        %v", keys, want)
	}
	if got["peer_uid"] != float64(0) {
		t.Errorf("peer uid 0 (root) not recorded: %v", got["peer_uid"])
	}

	// Compile-time shape: every Record field is accounted for.
	rt := reflect.TypeOf(Record{})
	if rt.NumField() != len(want)-1 { // ts is added by Append
		t.Fatalf("Record has %d fields, want %d", rt.NumField(), len(want)-1)
	}
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		if strings.Contains(name, "pass") || strings.Contains(name, "secret") || strings.Contains(name, "token") {
			t.Errorf("Record field %s could hold a secret", rt.Field(i).Name)
		}
	}
}
