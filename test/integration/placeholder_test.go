//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// assertPlaceholderRefused runs, through a console server on a real
// engine, a typed placeholder on the masked big.email and references to
// cells: no value is typed in lockhub, so the placeholder's run is refused
// (E_PLACEHOLDER) before anything reaches the hub or the engine, and a
// reference, which no result of the session made, is refused at plan
// time. The row holding the value is never found.
func assertPlaceholderRefused(t *testing.T, s engine.Session, rules pii.Rules) {
	t.Helper()
	call := consoleServer(t, s, "app", rules, config.TierRead, []string{"email"})
	for _, q := range []string{
		"SELECT id, email FROM big WHERE email = '${email}' LIMIT 5",
		"SELECT id, status FROM big WHERE email = '${r1.1.2}' LIMIT 5",
		"SELECT id FROM big WHERE email IN ('${r3.1.2}') LIMIT 5",
	} {
		resp := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		if strings.Contains(q, "${r") {
			if resp.Error == nil || !strings.Contains(resp.Error.Message, "unknown reference") {
				t.Errorf("%s: plan %s %+v, want an unknown reference", q, resp.Result, resp.Error)
			}
			continue
		}
		if resp.Error != nil {
			t.Fatalf("%s: plan: %s", q, resp.Error.Message)
		}
		var pr ipc.PlanResult
		if err := json.Unmarshal(resp.Result, &pr); err != nil {
			t.Fatal(err)
		}
		resp = call(ipc.MethodQueryRun, ipc.RunParams{PlanID: pr.PlanID})
		if resp.Error == nil || resp.Error.Data == nil || resp.Error.Data.Code != "E_PLACEHOLDER" {
			t.Errorf("%s: run %s %+v, want E_PLACEHOLDER", q, resp.Result, resp.Error)
		}
		if resp.Error != nil && strings.Contains(resp.Error.Message, "brien") {
			t.Errorf("%s: the refusal names the value: %q", q, resp.Error.Message)
		}
	}
}

func insertObrien(t *testing.T, s engine.Session, table string) int64 {
	t.Helper()
	ins := sqlclass.Statement{Class: sqlclass.Write, Kind: "insert",
		SQL: "INSERT INTO " + table + " (status, email) VALUES ('sent', 'o''brien@example.org')", Limit: -1}
	if _, err := s.Run(context.Background(), "app", ins, 10); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		del := sqlclass.Statement{Class: sqlclass.Write, Kind: "delete",
			SQL: "DELETE FROM " + table + " WHERE email = 'o''brien@example.org'", Limit: -1}
		if _, err := s.Run(context.Background(), "app", del, 10); err != nil {
			t.Error(err)
		}
	})
	r, err := s.Run(context.Background(), "app", read("SELECT id FROM "+table+" WHERE email = 'o''brien@example.org'"), 10)
	if err != nil || len(r.Rows) != 1 {
		t.Fatalf("seeded row: %v %v", r.Rows, err)
	}
	var id int64
	if _, err := fmt.Sscan(fmt.Sprint(r.Rows[0][0]), &id); err != nil {
		t.Fatal(err)
	}
	return id
}
