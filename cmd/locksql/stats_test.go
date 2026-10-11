//go:build unix

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/refusal"
)

// writeAudit writes records to the audit log of the state dir of this
// test's account.
func writeAudit(t *testing.T, recs ...audit.Record) string {
	t.Helper()
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("HOME", t.TempDir())
	l, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := l.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	return l.Path()
}

func TestStatsCountsTheLocalAuditLog(t *testing.T) {
	path := writeAudit(t,
		audit.Record{Event: audit.EventRefused, Engine: "mariadb", Code: "E_MASKED_FILTER", SQL: "SELECT id FROM customers WHERE email LIKE 'acme%' LIMIT 1",
			Span: &refusal.Span{Line: 1, Col: 38, Token: "LIKE"}},
		audit.Record{Event: audit.EventRefused, Engine: "mariadb", Code: "E_NO_LIMIT", SQL: "SELECT id FROM customers"},
		audit.Record{Event: audit.EventApproved, SQL: "SELECT 1 LIMIT 1"},
	)
	cli(t, t.TempDir(), "", "stats").want(t, exitOK, "2 refusals", "E_MASKED_FILTER", "LIKE", "E_NO_LIMIT")

	// --log reads another file; a missing one is an error.
	o := cli(t, t.TempDir(), "", "stats", "--log", path)
	o.want(t, exitOK, "2 refusals")
	cli(t, t.TempDir(), "", "stats", "--log", filepath.Join(t.TempDir(), "none.log")).want(t, exitFail, "no audit log")
	cli(t, t.TempDir(), "", "stats", "extra").want(t, exitUsage, "usage")

	// --export is the anonymised report.
	o = cli(t, t.TempDir(), "", "stats", "--export")
	o.want(t, exitOK)
	var ex struct {
		Refusals int `json:"refusals"`
		Shapes   []struct {
			Shape string `json:"shape"`
		} `json:"shapes"`
	}
	if err := json.Unmarshal([]byte(o.stdout), &ex); err != nil {
		t.Fatalf("%v\n%s", err, o.stdout)
	}
	if ex.Refusals != 2 || len(ex.Shapes) != 2 {
		t.Fatalf("export %+v", ex)
	}
	for _, s := range []string{"customers", "acme", "email"} {
		if strings.Contains(o.stdout, s) {
			t.Errorf("the export holds %q:\n%s", s, o.stdout)
		}
	}
}

// stats reads the log without changing it.
func TestStatsLeavesTheLogAlone(t *testing.T) {
	path := writeAudit(t, audit.Record{Event: audit.EventRefused, Code: "E_NO_LIMIT"})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cli(t, t.TempDir(), "", "stats").want(t, exitOK)
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("stats changed the audit log")
	}
}
