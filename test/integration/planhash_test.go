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

			// A NO ACTION or RESTRICT foreign key only refuses a write: the
			// referencing tables are not followed, so a change in a wide
			// graph of them leaves the plan as it is (#105). The key itself
			// is hashed with the table's constraints.
			wide := ""
			for i := range 40 {
				wide += fmt.Sprintf("CREATE TABLE ph_ref%d (id int, w_id int REFERENCES ph_w (id)%s);\n", i, map[bool]string{true: " ON DELETE RESTRICT"}[i%2 == 0])
			}
			psql(wide)
			wprev = writeState(t, s, wrefs)
			psql(`ALTER TABLE ph_ref7 ADD COLUMN note text; CREATE TRIGGER ph_rtr BEFORE INSERT ON ph_ref8 FOR EACH ROW EXECUTE FUNCTION ph_trg();`)
			if cur := writeState(t, s, wrefs); !reflect.DeepEqual(wprev, cur) {
				t.Error("a change in a table referencing the written one without a cascade made the plan stale")
			}
			psql(`ALTER TABLE ph_ref9 DROP CONSTRAINT ph_ref9_w_id_fkey; ALTER TABLE ph_ref9 ADD FOREIGN KEY (w_id) REFERENCES ph_w (id) ON DELETE SET NULL`)
			cur := writeState(t, s, wrefs)
			if reflect.DeepEqual(wprev, cur) {
				t.Error("a key turned into SET NULL: the state did not change")
			}
			wprev = cur
			psql(`ALTER TABLE ph_ref9 ADD COLUMN note text`)
			if cur := writeState(t, s, wrefs); reflect.DeepEqual(wprev, cur) {
				t.Error("a change in a table a cascade reaches: the state did not change")
			}

			// TRUNCATE ... CASCADE empties every referencing table, whatever
			// its key's action: a DDL statement follows them all.
			trefs := engine.ObjectRefs{Relations: []string{"ph_w"}, Functions: []string{}, Operators: []string{}, Writes: true, DDL: true}
			tprev := writeState(t, s, trefs)
			for _, c := range []struct{ name, sql string }{
				{"ON TRUNCATE trigger on a RESTRICT referencing table", `CREATE FUNCTION ph_ttrg() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END';
CREATE TRIGGER ph_ttr AFTER TRUNCATE ON ph_ref0 FOR EACH STATEMENT EXECUTE FUNCTION ph_ttrg()`},
				{"new key onto a referencing table", `CREATE TABLE ph_ref0_child (id int, r int); ALTER TABLE ph_ref0 ADD PRIMARY KEY (id); ALTER TABLE ph_ref0_child ADD FOREIGN KEY (r) REFERENCES ph_ref0 (id)`},
			} {
				psql(c.sql)
				cur := writeState(t, s, trefs)
				if reflect.DeepEqual(tprev, cur) {
					t.Errorf("TRUNCATE CASCADE, %s: the state did not change", c.name)
				}
				tprev = cur
			}

			// Domains of the columns: ALTER DOMAIN changes their CHECK in
			// place (#105), through a domain over a domain too. (A domain an
			// array column uses cannot be altered.)
			psql(`CREATE DOMAIN ph_pos AS int CHECK (VALUE > 0);
CREATE DOMAIN ph_small AS ph_pos CHECK (VALUE < 1000);
CREATE TABLE ph_dom (id int, a ph_pos, b ph_small);
GRANT SELECT ON ph_dom TO ro;`)
			drefs := engine.ObjectRefs{Relations: []string{"ph_dom"}, Functions: []string{}, Operators: []string{}, Writes: true}
			dprev := writeState(t, s, drefs)
			for _, c := range []struct{ name, sql string }{
				{"domain CHECK added", `ALTER DOMAIN ph_pos ADD CONSTRAINT ph_pos_even CHECK (VALUE % 2 = 0) NOT VALID`},
				{"domain over a domain, CHECK dropped", `ALTER DOMAIN ph_small DROP CONSTRAINT ph_small_check`},
				{"domain default", `ALTER DOMAIN ph_small SET DEFAULT 2`},
				{"domain NOT NULL", `ALTER DOMAIN ph_pos SET NOT NULL`},
			} {
				psql(c.sql)
				cur := writeState(t, s, drefs)
				if reflect.DeepEqual(dprev, cur) {
					t.Errorf("%s: the state did not change", c.name)
				}
				dprev = cur
			}
			psql(`CREATE FUNCTION ph_dck(int) RETURNS bool LANGUAGE sql IMMUTABLE AS 'SELECT true';
ALTER DOMAIN ph_pos ADD CONSTRAINT ph_pos_f CHECK (ph_dck(VALUE));`)
			dprev = writeState(t, s, drefs)
			psql(`CREATE OR REPLACE FUNCTION ph_dck(int) RETURNS bool LANGUAGE sql IMMUTABLE AS 'SELECT $1 < 50'`)
			if cur := writeState(t, s, drefs); reflect.DeepEqual(dprev, cur) {
				t.Error("the function of a domain CHECK replaced: the state did not change")
			}

			// A function in a domain DEFAULT runs on an INSERT that omits the
			// column; domains reached through a composite type or a range.
			psql(`CREATE FUNCTION ph_ddef() RETURNS int LANGUAGE sql VOLATILE AS 'SELECT 1';
CREATE DOMAIN ph_defd AS int DEFAULT ph_ddef();
CREATE DOMAIN ph_cd AS int CHECK (VALUE > 0);
CREATE TYPE ph_comp AS (x ph_cd);
CREATE DOMAIN ph_rd AS int CHECK (VALUE < 100);
CREATE TYPE ph_rng AS RANGE (subtype = ph_rd);
CREATE TABLE ph_dom2 (id int, d ph_defd, c ph_comp, r ph_rng);
GRANT SELECT ON ph_dom2 TO ro;`)
			d2refs := engine.ObjectRefs{Relations: []string{"ph_dom2"}, Functions: []string{}, Operators: []string{}, Writes: true}
			d2prev := writeState(t, s, d2refs)
			for _, c := range []struct{ name, sql string }{
				{"function of a domain DEFAULT replaced", `CREATE OR REPLACE FUNCTION ph_ddef() RETURNS int LANGUAGE sql VOLATILE AS 'SELECT 2'`},
				{"domain of a composite attribute", `ALTER DOMAIN ph_cd ADD CONSTRAINT ph_cd2 CHECK (VALUE < 10) NOT VALID`},
				{"domain of a range subtype", `ALTER DOMAIN ph_rd ADD CONSTRAINT ph_rd2 CHECK (VALUE > -5) NOT VALID`},
			} {
				psql(c.sql)
				cur := writeState(t, s, d2refs)
				if reflect.DeepEqual(d2prev, cur) {
					t.Errorf("%s: the state did not change", c.name)
				}
				d2prev = cur
			}

			// Event triggers run on DDL: their definitions and functions are
			// in the state of a DDL statement (#105), not of a read.
			erefs := engine.ObjectRefs{Relations: []string{"ph_t"}, Functions: []string{}, Operators: []string{}, Writes: true, DDL: true}
			eprev, rprev := writeState(t, s, erefs), state(s)
			psql(`CREATE FUNCTION ph_evt() RETURNS event_trigger LANGUAGE plpgsql AS 'BEGIN END';
CREATE EVENT TRIGGER ph_et ON ddl_command_start EXECUTE FUNCTION ph_evt();`)
			ecur := writeState(t, s, erefs)
			if reflect.DeepEqual(eprev, ecur) {
				t.Error("new event trigger: the DDL state did not change")
			}
			if !reflect.DeepEqual(rprev, state(s)) {
				t.Error("an event trigger changed the state of a read")
			}
			psql(`CREATE OR REPLACE FUNCTION ph_evt() RETURNS event_trigger LANGUAGE plpgsql AS 'BEGIN RAISE NOTICE ''x''; END'`)
			if cur := writeState(t, s, erefs); reflect.DeepEqual(ecur, cur) {
				t.Error("event trigger function replaced: the DDL state did not change")
			}
			psql(`DROP EVENT TRIGGER ph_et`)

			// An operator used inside a view, a policy, a CHECK or a domain
			// CHECK is recorded in pg_depend against pg_operator, not its
			// function: replacing the function changes them all (#119).
			psql(`CREATE FUNCTION ph_opf(int, int) RETURNS bool LANGUAGE sql IMMUTABLE AS 'SELECT $1 = $2';
CREATE OPERATOR === (LEFTARG = int, RIGHTARG = int, FUNCTION = ph_opf);
CREATE VIEW ph_opv AS SELECT id FROM ph_t WHERE id === 1;
CREATE TABLE ph_opc (id int CHECK (id === id));
CREATE TABLE ph_opp (id int);
CREATE POLICY ph_opp_p ON ph_opp USING (id === 1);
CREATE DOMAIN ph_opd AS int CHECK (VALUE === VALUE);
CREATE TABLE ph_opdt (id int, d ph_opd);
GRANT SELECT ON ph_opv, ph_opc, ph_opp, ph_opdt TO ro;`)
			opRefs := map[string]engine.ObjectRefs{
				"view":         {Relations: []string{"ph_opv"}, Functions: []string{}, Operators: []string{}},
				"CHECK":        {Relations: []string{"ph_opc"}, Functions: []string{}, Operators: []string{}, Writes: true},
				"policy":       {Relations: []string{"ph_opp"}, Functions: []string{}, Operators: []string{}},
				"domain CHECK": {Relations: []string{"ph_opdt"}, Functions: []string{}, Operators: []string{}, Writes: true},
			}
			opPrev := map[string]engine.ObjectState{}
			for k, r := range opRefs {
				opPrev[k] = writeState(t, s, r)
				found := false
				for _, o := range opPrev[k].Objects {
					found = found || o.Kind == "operator" && strings.HasPrefix(o.Name, "===")
				}
				if !found {
					t.Errorf("operator in a %s: not in the state %v", k, opPrev[k].Objects)
				}
			}
			psql(`CREATE OR REPLACE FUNCTION ph_opf(int, int) RETURNS bool LANGUAGE sql IMMUTABLE AS 'SELECT $1 <> $2'`)
			for k, r := range opRefs {
				if reflect.DeepEqual(opPrev[k], writeState(t, s, r)) {
					t.Errorf("the function of an operator in a %s replaced: the state did not change", k)
				}
			}

			// DDL with CASCADE drops what depends on its relation: the
			// views over it (and over those), the policies and constraints
			// of other tables that use it (#119).
			psql(`CREATE TABLE ph_cas (id int PRIMARY KEY, label text);
CREATE TABLE ph_cas_other (id int);
GRANT SELECT ON ph_cas, ph_cas_other TO ro;`)
			crefs := engine.ObjectRefs{Relations: []string{"ph_cas"}, Functions: []string{}, Operators: []string{}, Writes: true, DDL: true}
			wcrefs := engine.ObjectRefs{Relations: []string{"ph_cas"}, Functions: []string{}, Operators: []string{}, Writes: true}
			cprev, wcprev := writeState(t, s, crefs), writeState(t, s, wcrefs)
			for _, c := range []struct{ name, sql string }{
				{"view over the table", `CREATE VIEW ph_casv AS SELECT id, label FROM ph_cas`},
				{"view over the view", `CREATE VIEW ph_casv2 AS SELECT id FROM ph_casv`},
				{"view over the view replaced", `CREATE OR REPLACE VIEW ph_casv2 AS SELECT id FROM ph_casv WHERE id > 0`},
				{"policy of another table reading it", `CREATE POLICY ph_cas_p ON ph_cas_other USING (id IN (SELECT id FROM ph_cas))`},
			} {
				psql(c.sql)
				cur := writeState(t, s, crefs)
				if reflect.DeepEqual(cprev, cur) {
					t.Errorf("DDL, %s: the state did not change", c.name)
				}
				cprev = cur
			}
			if !reflect.DeepEqual(wcprev, writeState(t, s, wcrefs)) {
				t.Error("a view over the table changed the state of a write to it")
			}

			// Enum labels and composite types of the columns (#119).
			psql(`CREATE TYPE ph_mood AS ENUM ('sad', 'happy');
CREATE TYPE ph_pair AS (a int, b text);
CREATE TABLE ph_ty (id int, m ph_mood, ms ph_mood[], p ph_pair);
GRANT SELECT ON ph_ty TO ro;`)
			tyrefs := engine.ObjectRefs{Relations: []string{"ph_ty"}, Functions: []string{}, Operators: []string{}, Writes: true}
			typrev := writeState(t, s, tyrefs)
			for _, c := range []struct{ name, sql string }{
				{"enum value added", `ALTER TYPE ph_mood ADD VALUE 'ok' BEFORE 'happy'`},
				{"enum value renamed", `ALTER TYPE ph_mood RENAME VALUE 'sad' TO 'blue'`},
				// (A composite type a column uses cannot gain, lose or retype
				// an attribute; it can rename one.)
				{"composite attribute renamed", `ALTER TYPE ph_pair RENAME ATTRIBUTE b TO label`},
			} {
				psql(c.sql)
				cur := writeState(t, s, tyrefs)
				if reflect.DeepEqual(typrev, cur) {
					t.Errorf("%s: the state did not change", c.name)
				}
				typrev = cur
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
