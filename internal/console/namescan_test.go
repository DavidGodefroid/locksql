package console

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// samplingSession answers SampleColumn from values, keyed by "table.column".
type samplingSession struct {
	columnsSession
	values  map[string][]string
	err     error
	delay   time.Duration
	sampled []string
	rows    []int
}

func (s *samplingSession) SampleColumn(ctx context.Context, db string, c engine.ColumnInfo, n int) ([]string, error) {
	s.sampled = append(s.sampled, c.Table+"."+c.Column)
	s.rows = append(s.rows, n)
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.values[c.Table+"."+c.Column], nil
}

func nameScanCols() []engine.ColumnInfo {
	return []engine.ColumnInfo{
		{DB: "public", Table: "customers", Column: "id", Type: "integer"},
		{DB: "public", Table: "customers", Column: "name", Type: "text"},
		{DB: "public", Table: "customers", Column: "email", Type: "text"},
		{DB: "public", Table: "customers", Column: "city", Type: "text"},
		{DB: "public", Table: "products", Column: "name", Type: "character varying(80)"},
		{DB: "public", Table: "roles", Column: "name", Type: "character varying(40)"},
		{DB: "public", Table: "cities", Column: "name", Type: "text"},
		{DB: "public", Table: "tags", Column: "name", Type: "text"},
	}
}

func nameScanValues() map[string][]string {
	return map[string][]string{
		"customers.name": {"Alice Dupont", "Bob Martin", "Chloé Lambert"},
		"products.name":  {"Laptop Pro 14", "USB-C Hub", "Wireless Mouse"},
		"roles.name":     {"admin", "editor", "viewer"},
		"cities.name":    {"Namur", "Liège", "Gent"},
		"tags.name":      {"urgent", "billing", "Lambert"},
	}
}

func nameScanStarter(t *testing.T) (*starter, *fakeIO, string, string) {
	t.Helper()
	root, state := t.TempDir(), t.TempDir()
	log, err := audit.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{}
	return &starter{io: io, log: log, profile: uatProfile()}, io, filepath.Join(root, pii.RulesFile), state
}

// The first-start scan proposes customers.name from its sampled values,
// and not the name columns of things; the values are never printed.
func TestPIIScanProposesPersonNameColumns(t *testing.T) {
	st, io, rulesPath, state := nameScanStarter(t)
	sess := &samplingSession{columnsSession: columnsSession{cols: nameScanCols()}, values: nameScanValues()}
	io.answers = []string{"a"}
	key := config.ApprovedKey(filepath.Dir(rulesPath), st.profile.Name)
	ap, err := st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, config.NewPolicy(st.profile, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ap.PIIMask, "public.customers.name") {
		t.Fatalf("customers.name not proposed: %v", ap.PIIMask)
	}
	for _, pat := range ap.PIIMask {
		if strings.HasSuffix(pat, ".name") && pat != "public.customers.name" {
			t.Errorf("a name column of things is proposed: %s", pat)
		}
	}
	// Only the text columns whose name means "name" are read, 20 rows each.
	slices.Sort(sess.sampled)
	if want := []string{"cities.name", "customers.name", "products.name", "roles.name", "tags.name"}; !slices.Equal(sess.sampled, want) {
		t.Errorf("sampled %v, want %v", sess.sampled, want)
	}
	for _, n := range sess.rows {
		if n != nameSampleRows {
			t.Errorf("sampled %d rows, want %d", n, nameSampleRows)
		}
	}
	for _, vs := range nameScanValues() {
		for _, v := range vs {
			if strings.Contains(io.output(), v) {
				t.Errorf("sampled value %q printed", v)
			}
		}
	}
}

// The column name alone never proposes a column: without sampling (a
// session that cannot sample, or a read error) nothing is proposed for it.
func TestPIIScanNameColumnNeedsSamples(t *testing.T) {
	for name, sess := range map[string]engine.Session{
		"no sampler": &columnsSession{cols: nameScanCols()},
		"read error": &samplingSession{columnsSession: columnsSession{cols: nameScanCols()}, err: errors.New("permission denied for table customers")},
	} {
		t.Run(name, func(t *testing.T) {
			st, io, rulesPath, state := nameScanStarter(t)
			io.answers = []string{"a"}
			key := config.ApprovedKey(filepath.Dir(rulesPath), st.profile.Name)
			ap, err := st.piiBootstrap(context.Background(), sess, []string{"app"}, rulesPath, state, key, config.NewPolicy(st.profile, nil, nil))
			if err != nil {
				t.Fatal(err)
			}
			for _, pat := range ap.PIIMask {
				if strings.HasSuffix(pat, ".name") {
					t.Errorf("proposed without samples: %s", pat)
				}
			}
			if strings.Contains(io.output(), "permission denied") {
				t.Error("the read error was printed")
			}
		})
	}
}

// Sampling is bounded in time: a slow column is cut at nameSampleTimeout
// and the whole scan at nameSampleBudget; what is left is counted, not read.
func TestPIIScanNameSamplingBounded(t *testing.T) {
	defer func(t, b time.Duration) { nameSampleTimeout, nameSampleBudget = t, b }(nameSampleTimeout, nameSampleBudget)
	nameSampleTimeout, nameSampleBudget = 100*time.Millisecond, 500*time.Millisecond
	var cols []engine.ColumnInfo
	for _, tb := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		cols = append(cols, engine.ColumnInfo{DB: "public", Table: tb, Column: "name", Type: "text"})
	}
	sess := &samplingSession{columnsSession: columnsSession{cols: cols}, delay: time.Minute}
	ns := nameSampling{deadline: time.Now().Add(nameSampleBudget)}
	start := time.Now()
	if got := ns.names(context.Background(), sess, "app", cols); len(got) != 0 {
		t.Errorf("proposed %v", got)
	}
	if d := time.Since(start); d > nameSampleBudget+300*time.Millisecond {
		t.Errorf("sampling took %s, budget %s", d, nameSampleBudget)
	}
	if per := int(nameSampleBudget / nameSampleTimeout); len(sess.sampled) > per+1 {
		t.Errorf("sampled %d columns past the budget", len(sess.sampled))
	}
	if ns.skipped != len(cols) {
		t.Errorf("skipped %d, want %d", ns.skipped, len(cols))
	}

	// And in columns.
	many := make([]engine.ColumnInfo, nameSampleColumns+5)
	for i := range many {
		many[i] = engine.ColumnInfo{DB: "public", Table: "t" + strings.Repeat("x", i), Column: "name", Type: "text"}
	}
	fast := &samplingSession{columnsSession: columnsSession{cols: many}}
	ns = nameSampling{deadline: time.Now().Add(nameSampleBudget)}
	ns.names(context.Background(), fast, "app", many)
	if len(fast.sampled) != nameSampleColumns || ns.skipped != 5 {
		t.Errorf("sampled %d, skipped %d", len(fast.sampled), ns.skipped)
	}
}
