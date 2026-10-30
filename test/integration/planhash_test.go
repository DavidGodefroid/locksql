//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// The plan hash on a real PostgreSQL: what a statement resolves to changes
// with CREATE OR REPLACE FUNCTION / VIEW (the OIDs stay), a new trigger or
// row-level policy on a table a view reads, a grant and the search path;
// a guarded run checks it in the statement's transaction; and through the
// console a plan whose objects changed is refused with E_STALE.
func TestPlanHashPG(t *testing.T) {
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			// Its own container: the test changes the schema.
			srv := startPostgresVariant(t, v, "planhash")
			psql := func(sql string) {
				t.Helper()
				if err := Exec(srv, sql, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app"); err != nil {
					t.Fatal(err)
				}
			}
			psql(`CREATE SCHEMA ph_alt;
CREATE TABLE ph_t (id int PRIMARY KEY, label text);
INSERT INTO ph_t VALUES (1, 'a'), (2, 'b');
CREATE FUNCTION ph_f(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT $1';
CREATE VIEW ph_v AS SELECT id, ph_f(id) AS f FROM ph_t;
CREATE FUNCTION ph_trg() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
GRANT USAGE ON SCHEMA ph_alt TO ro, rw;
GRANT SELECT ON ph_t, ph_v TO ro;
GRANT SELECT, UPDATE ON ph_t TO rw;`)
			ctx := context.Background()
			refs := engine.ObjectRefs{Relations: []string{"ph_v"}, Functions: []string{"ph_f"}, Operators: []string{}}
			state := func(s engine.Session) engine.ObjectState {
				t.Helper()
				st, err := engine.ObjectStateOf(ctx, s, "app", refs)
				if err != nil {
					t.Fatal(err)
				}
				return st
			}
			s := connectPG(t, srv, "ro", config.TierRead, 30*time.Second)
			base := state(s)
			if again := state(s); !reflect.DeepEqual(base, again) {
				t.Fatalf("the state changed with nothing changed:\n%+v\n%+v", base, again)
			}
			names := map[string]bool{}
			for _, o := range base.Objects {
				names[o.Kind+" "+o.Name] = true
			}
			for _, want := range []string{"relation ph_v", "relation ph_t", "function ph_f(integer)"} {
				if !names[want] {
					t.Errorf("state lacks %q: %v", want, names)
				}
			}

			prev := base
			for _, c := range []struct{ name, sql string }{
				{"CREATE OR REPLACE FUNCTION", `CREATE OR REPLACE FUNCTION ph_f(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT $1 + 1'`},
				{"CREATE OR REPLACE VIEW", `CREATE OR REPLACE VIEW ph_v AS SELECT id, ph_f(id) AS f FROM ph_t WHERE id > 0`},
				{"new trigger", `CREATE TRIGGER ph_tr BEFORE UPDATE ON ph_t FOR EACH ROW EXECUTE FUNCTION ph_trg()`},
				{"trigger function replaced", `CREATE OR REPLACE FUNCTION ph_trg() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN NEW.label := ''x''; RETURN NEW; END'`},
				{"new policy", `CREATE POLICY ph_p ON ph_t USING (id > 1)`},
				{"row-level security on", `ALTER TABLE ph_t ENABLE ROW LEVEL SECURITY`},
				{"grant", `GRANT INSERT ON ph_t TO rw`},
				{"security definer", `ALTER FUNCTION ph_f(int) SECURITY DEFINER`},
				{"function setting", `ALTER FUNCTION ph_f(int) SET search_path = ph_alt`},
			} {
				psql(c.sql)
				cur := state(s)
				if reflect.DeepEqual(prev, cur) {
					t.Errorf("%s: the state did not change", c.name)
				}
				prev = cur
			}

			// What a write reaches beyond its table: defaults, foreign keys
			// that cascade into another table and that table's triggers,
			// partitions.
			wrefs := engine.ObjectRefs{Relations: []string{"ph_w", "ph_part"}, Functions: []string{}, Operators: []string{}, Writes: true}
			psql(`CREATE TABLE ph_w (id int PRIMARY KEY, label text);
CREATE TABLE ph_part (id int, k int) PARTITION BY RANGE (k);
CREATE TABLE ph_part_1 PARTITION OF ph_part FOR VALUES FROM (0) TO (10);
GRANT SELECT ON ph_w, ph_part TO ro;`)
			wprev := writeState(t, s, wrefs)
			for _, c := range []struct{ name, sql string }{
				{"SET DEFAULT", `ALTER TABLE ph_w ALTER label SET DEFAULT 'x'`},
				{"generated column", `ALTER TABLE ph_w ADD COLUMN g int GENERATED ALWAYS AS (id * 2) STORED`},
				{"foreign key with cascade", `CREATE TABLE ph_child (id int, w_id int REFERENCES ph_w (id) ON DELETE CASCADE)`},
				{"trigger on the cascaded table", `CREATE TRIGGER ph_ctr BEFORE DELETE ON ph_child FOR EACH ROW EXECUTE FUNCTION ph_trg()`},
				{"new partition", `CREATE TABLE ph_part_2 PARTITION OF ph_part FOR VALUES FROM (10) TO (20)`},
				{"trigger on a partition", `CREATE TRIGGER ph_ptr BEFORE INSERT ON ph_part_1 FOR EACH ROW EXECUTE FUNCTION ph_trg()`},
				{"check constraint", `ALTER TABLE ph_w ADD CONSTRAINT ph_ck CHECK (id > 0)`},
			} {
				psql(c.sql)
				cur := writeState(t, s, wrefs)
				if reflect.DeepEqual(wprev, cur) {
					t.Errorf("%s: the state did not change", c.name)
				}
				wprev = cur
			}

			// Deeper than the bound: refused, never hashed in part.
			chain := "CREATE VIEW ph_d0 AS SELECT id FROM ph_t;\n"
			for i := 1; i <= 10; i++ {
				chain += fmt.Sprintf("CREATE VIEW ph_d%d AS SELECT id FROM ph_d%d;\n", i, i-1)
			}
			psql(chain + "GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro;")
			if _, err := engine.ObjectStateOf(ctx, s, "app", engine.ObjectRefs{Relations: []string{"ph_d10"}}); err == nil || !strings.Contains(err.Error(), "deeper") {
				t.Errorf("a view chain past the bound: %v, want a refusal", err)
			}
			if _, err := engine.ObjectStateOf(ctx, s, "app", engine.ObjectRefs{Relations: []string{"ph_d3"}}); err != nil {
				t.Errorf("a short view chain: %v", err)
			}

			// The search path of a new session: ALTER ROLE applies at login.
			psql(`ALTER ROLE ro SET search_path = ph_alt, public`)
			s2 := connectPG(t, srv, "ro", config.TierRead, 30*time.Second)
			if cur := state(s2); cur.SearchPath == prev.SearchPath {
				t.Errorf("search_path change not seen: %q", cur.SearchPath)
			}
			psql(`ALTER ROLE ro RESET search_path`)

			// A guarded write whose check fails after the statement is
			// rolled back (row 2: the policy above hides row 1 from rw).
			rw := connectPG(t, srv, "rw", config.TierWrite, 30*time.Second)
			errCheck := errors.New("changed")
			st := sqlclass.Statement{SQL: "UPDATE ph_t SET label = 'z' WHERE id = 2", Class: sqlclass.Write}
			checks := 0
			_, err := engine.RunGuarded(ctx, rw, "app", st, 10, engine.ObjectRefs{Relations: []string{"ph_t"}, Functions: []string{}, Operators: []string{}},
				func(_ engine.ObjectState, at engine.Step) error {
					checks++
					if at.After {
						return errCheck
					}
					return nil
				})
			if !errors.Is(err, errCheck) || checks != 2 {
				t.Fatalf("guarded run: %v after %d checks", err, checks)
			}
			res, err := rw.Run(ctx, "app", sqlclass.Statement{SQL: "SELECT label FROM ph_t WHERE id = 2", Class: sqlclass.Read}, 10)
			if err != nil || len(res.Rows) != 1 || res.Rows[0][0] != "b" {
				t.Fatalf("the write was not rolled back: %v %v", res.Rows, err)
			}
			if err := rw.Ping(ctx); err != nil {
				t.Fatalf("a failed check lost the session: %v", err)
			}

			// Through the console: plan, change the function, run.
			call := consoleServer(t, s, "app", pii.Rules{}, config.TierRead, nil)
			const q = "SELECT id, f FROM ph_v LIMIT 5"
			if _, msg := agentRun(t, call, "app", q); msg != "" {
				t.Fatalf("plan and run of %q: %s", q, msg)
			}
			resp := call("query.plan", map[string]any{"db": "app", "sql": q})
			if resp.Error != nil {
				t.Fatal(resp.Error.Message)
			}
			var pr struct {
				PlanID   string `json:"plan_id"`
				PlanHash string `json:"plan_hash"`
			}
			if err := json.Unmarshal(resp.Result, &pr); err != nil || !strings.HasPrefix(pr.PlanHash, "sha256:") {
				t.Fatalf("plan result %s: %v", resp.Result, err)
			}
			psql(`CREATE OR REPLACE FUNCTION ph_f(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT $1 * 10'`)
			run := call("query.run", map[string]any{"plan_id": pr.PlanID})
			if run.Error == nil || run.Error.Data == nil || run.Error.Data.Code != "E_STALE" {
				t.Fatalf("run after CREATE OR REPLACE FUNCTION: %+v", run.Error)
			}
		})
	}
}

func writeState(t *testing.T, s engine.Session, refs engine.ObjectRefs) engine.ObjectState {
	t.Helper()
	st, err := engine.ObjectStateOf(context.Background(), s, "app", refs)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
