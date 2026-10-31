//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// assertPlaceholderRefused plans, through a console server on a real
// engine, a typed placeholder on the masked big.email and references to
// cells: neither is supported, so each is refused at plan time
// (E_PLACEHOLDER, saying so) before anything reaches the hub or the
// engine. The row holding the value is never found.
func assertPlaceholderRefused(t *testing.T, s engine.Session, rules pii.Rules) {
	t.Helper()
	call := consoleServer(t, s, "app", rules, config.TierRead, []string{"email"})
	for _, q := range []string{
		"SELECT id, email FROM big WHERE email = '${email}' LIMIT 5",
		"SELECT id, status FROM big WHERE email = '${r1.1.2}' LIMIT 5",
		"SELECT id FROM big WHERE email IN ('${r3.1.2}') LIMIT 5",
	} {
		resp := call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		if resp.Error == nil || resp.Error.Data == nil || resp.Error.Data.Code != "E_PLACEHOLDER" || !strings.Contains(resp.Error.Message, "not supported") {
			t.Errorf("%s: plan %s %+v, want E_PLACEHOLDER (not supported)", q, resp.Result, resp.Error)
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
