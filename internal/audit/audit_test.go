package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestOpenPathAndModes(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "locksql", "audit.log")
	if l.Path() != want {
		t.Fatalf("path = %q, want %q", l.Path(), want)
	}
	if err := l.Write(Record{Event: EventLogin, Profile: "uat"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(want)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(want))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
}

func TestOpenTightensLooseFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "locksql", "audit.log")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{\"event\":\"old\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Record{Event: EventLogout}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(p))
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
	if got := readLines(t, p); len(got) != 2 || got[0]["event"] != "old" {
		t.Fatalf("existing content not kept: %v", got)
	}
}

func TestAppendOnlyTwoRecordsTwoLines(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Record{Event: EventApproved, SQL: "SELECT 1\nLIMIT 1", Rows: 1}); err != nil {
		t.Fatal(err)
	}
	// A second Log on the same file appends, it never truncates.
	l2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Write(Record{Event: EventDenied}); err != nil {
		t.Fatal(err)
	}
	got := readLines(t, l.Path())
	if len(got) != 2 {
		t.Fatalf("want 2 lines, got %d", len(got))
	}
	if got[0]["event"] != "approved" || got[1]["event"] != "denied" {
		t.Fatalf("events = %v / %v", got[0]["event"], got[1]["event"])
	}
	if got[0]["sql"] != "SELECT 1\nLIMIT 1" {
		t.Fatalf("sql = %q", got[0]["sql"])
	}
	ts, ok := got[0]["ts"].(string)
	if !ok {
		t.Fatal("ts missing")
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Fatalf("ts %q is not RFC 3339: %v", ts, err)
	}
}

func TestConcurrentWritesStayWholeLines(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Write(Record{Event: EventCatalog, SQL: strings.Repeat("x", 5000)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := readLines(t, l.Path()); len(got) != 50 {
		t.Fatalf("want 50 lines, got %d", len(got))
	}
}

// TestRecordFieldSet pins the JSON field set. Record has no field able to
// hold a password or row data; adding one must be a deliberate change here.
func TestRecordFieldSet(t *testing.T) {
	want := []string{
		"affected", "class", "db", "db_user", "decision", "duration_ms", "engine", "error",
		"event", "host", "profile", "rows", "sql", "ssh_host", "ssh_host_key", "truncated", "ts", "unmasked", "verdict", "warnings",
	}
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	full := Record{
		Event: EventApproved, Profile: "p", Engine: "mysql", Host: "h", DB: "d", DBUser: "u",
		Class: "read", SQL: "s", Verdict: "OK", Decision: "y", Error: "e",
		Rows: 1, Affected: 2, DurationMS: 3, Truncated: true, Unmasked: true, Warnings: []string{"w"},
		SSHHost: "b", SSHHostKey: "SHA256:k",
	}
	if err := l.Write(full); err != nil {
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

	// Compile-time shape: every Record field is accounted for.
	rt := reflect.TypeOf(Record{})
	if rt.NumField() != len(want)-1 { // ts is added by Write
		t.Fatalf("Record has %d fields, want %d", rt.NumField(), len(want)-1)
	}
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		if strings.Contains(name, "pass") || strings.Contains(name, "secret") || strings.Contains(name, "token") {
			t.Errorf("Record field %s could hold a secret", rt.Field(i).Name)
		}
	}
}

func TestEmptyRecordKeepsEvent(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Record{}); err == nil {
		t.Fatal("a record without an event was accepted")
	}
	if err := l.Write(Record{Event: EventLogout}); err != nil {
		t.Fatal(err)
	}
	got := readLines(t, l.Path())
	if len(got) != 1 || got[0]["event"] != "logout" {
		t.Fatalf("got %v", got)
	}
}
