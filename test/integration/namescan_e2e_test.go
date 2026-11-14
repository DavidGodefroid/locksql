//go:build integration && linux

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// nameScanSeed is the fixture of locksql#236 (lockkit#163): person names
// in customers.name, things in products.name and roles.name.
const nameScanSeed = `
CREATE TABLE customers (id int PRIMARY KEY, name text, email text, phone text, iban text, vat text, city text);
INSERT INTO customers VALUES
  (1, 'Alice Dupont', 'alice@example.com', '+32 470 00 00 01', 'BE68539007547034', 'BE0123456789', 'Namur'),
  (2, 'Bob Martin', 'bob@example.com', '+32 470 00 00 02', 'BE71096123456769', 'BE0987654321', 'Liège'),
  (3, 'Chloé Lambert', 'chloe@example.com', '+32 470 00 00 03', 'BE62510007547061', 'BE0111222333', 'Gent');
CREATE TABLE products (id int PRIMARY KEY, name varchar(80));
INSERT INTO products VALUES (1, 'Laptop Pro 14'), (2, 'USB-C Hub'), (3, 'Wireless Mouse');
CREATE TABLE roles (id int PRIMARY KEY, name varchar(40));
INSERT INTO roles VALUES (1, 'admin'), (2, 'editor'), (3, 'viewer');
CREATE ROLE ro LOGIN PASSWORD '` + ROPassword + `';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro;
`

// SampleColumn on the real servers: at most n non-null values, read on a
// read-only tier, and the sampled customers.name is a person-name column
// for lockkit, products.name and roles.name are not.
//
//	go test -tags integration -run TestSampleColumnServers ./test/integration
func TestSampleColumnServers(t *testing.T) {
	ctx := context.Background()
	t.Run("postgres", func(t *testing.T) {
		srv := startNameScanPostgres(t)
		s := connectPG(t, srv, "ro", config.TierRead, 5*time.Second)
		cols, err := s.Columns(ctx, "app")
		if err != nil {
			t.Fatal(err)
		}
		var named []string
		for _, c := range pii.NameCandidates(cols) {
			v, err := engine.SampleColumn(ctx, s, "app", c, 20)
			if err != nil {
				t.Fatalf("%s.%s: %v", c.Table, c.Column, err)
			}
			if len(v) != 3 {
				t.Errorf("%s.%s: %q", c.Table, c.Column, v)
			}
			if pat := pii.ProposeName(c, v); pat != "" {
				named = append(named, pat)
			}
		}
		if !slices.Equal(named, []string{"public.customers.name"}) {
			t.Errorf("proposed %v", named)
		}
		if v, err := engine.SampleColumn(ctx, s, "app", engine.ColumnInfo{DB: "public", Table: "customers", Column: "name"}, 2); err != nil || len(v) != 2 {
			t.Errorf("n = 2: %q, %v", v, err)
		}
	})
	t.Run("mariadb", func(t *testing.T) {
		m := mysqlTarget{engine.FlavorMariaDB, "11.4"}
		s := connectMySQL(t, m, startMySQL(t, m), "ro", config.TierRead, 5*time.Second)
		v, err := engine.SampleColumn(ctx, s, "app", engine.ColumnInfo{DB: "app", Table: "small", Column: "label"}, 2)
		if err != nil || len(v) != 2 {
			t.Errorf("small.label: %q, %v", v, err)
		}
	})
}

func startNameScanPostgres(t *testing.T) Server {
	env := []string{"POSTGRES_PASSWORD=" + RootPassword, "POSTGRES_DB=app"}
	ready := func(ctx context.Context, host string, port int) error {
		c, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%d user=postgres password=%s dbname=app sslmode=disable",
			host, port, RootPassword))
		if err != nil {
			return err
		}
		defer c.Close(context.Background())
		return c.Ping(ctx)
	}
	return StartVariant(t, "names", "postgres:17", 5432, env, nil, nil, ready, func(s Server) error {
		return Exec(s, nameScanSeed, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "app")
	})
}

// The first-start scan samples the columns whose name means "name" and
// proposes public.customers.name, whose values are person names, and not
// products.name nor roles.name; the sampled values appear neither on the
// console nor in the audit log, and the accepted rule masks the names.
//
//	go test -tags integration -run TestFirstStartScanProposesPersonNames ./test/integration
func TestFirstStartScanProposesPersonNames(t *testing.T) {
	srv := startNameScanPostgres(t)

	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".locksql"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`[profiles.p]
engine = "postgres"
host = "127.0.0.1"
port = %d
user = "ro"
database = "app"
`, srv.Port)
	if err := os.WriteFile(filepath.Join(project, ".locksql", "config.toml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(home, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, "state")
	envs := []string{
		"HOME=" + home, "PATH=" + os.Getenv("PATH"), "TERM=xterm",
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_STATE_HOME=" + state,
		"XDG_RUNTIME_DIR=" + runDir,
	}

	c := startConsole(t, project, envs, "--profile", "p")
	c.expect("Apply these changes? [y/N]")
	c.send("y\n")
	c.expect("Password for ro@127.0.0.1: ")
	c.send(ROPassword + "\n")
	seen := c.expect("Accept all [a], review [r], skip [s]: ")
	var customers string
	for _, l := range strings.Split(seen, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "public.customers: ") {
			customers = l
		}
		if strings.HasPrefix(l, "public.products: ") || strings.HasPrefix(l, "public.roles: ") {
			t.Errorf("a column of things is proposed: %q", l)
		}
	}
	if !strings.Contains(", "+strings.TrimPrefix(customers, "public.customers: ")+",", " name,") {
		t.Fatalf("public.customers.name is not proposed:\n%s", seen)
	}
	c.send("a\n")
	seen = c.expect("Listening…")
	m := socketLine.FindStringSubmatch(seen)
	if m == nil {
		t.Fatalf("no socket path in %q", seen)
	}

	cl := dialConsole(t, m[1])
	var hr ipc.HelloResult
	if e := cl.call(ipc.MethodHello, confinedHello, &hr); e != nil {
		t.Fatal(e)
	}
	var pr ipc.PlanResult
	if e := cl.call(ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: "SELECT id, name FROM customers ORDER BY id LIMIT 3"}, &pr); e != nil {
		t.Fatalf("plan: %v", e)
	}
	var rr ipc.RunResult
	if e := cl.run(c.hub, pr.PlanID, &rr); e != nil {
		t.Fatalf("run: %v", e)
	}
	if len(rr.Rows) != 3 {
		t.Fatalf("rows: %+v", rr.Rows)
	}
	for _, r := range rr.Rows {
		if !strings.HasPrefix(fmt.Sprint(r[1]), "<redacted") {
			t.Errorf("name not masked: %+v", r)
		}
	}
	c.send("\x03")
	if err := c.wait(); err != nil {
		t.Fatalf("console exit: %v", err)
	}
	log, err := os.ReadFile(filepath.Join(state, "locksql", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"Alice Dupont", "Bob Martin", "Chloé Lambert", "Laptop Pro 14", "Wireless Mouse"} {
		if strings.Contains(c.output(), v) || strings.Contains(string(log), v) {
			t.Errorf("sampled value %q left the console's memory", v)
		}
	}
}
