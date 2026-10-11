//go:build integration

package integration

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/render"
)

// heapGrowth runs f and returns how much the live heap grew across it,
// measured after f with its result still referenced.
func heapGrowth(f func() any) (any, uint64) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v := f()
	runtime.GC()
	runtime.ReadMemStats(&after)
	if after.HeapAlloc < before.HeapAlloc {
		return v, 0
	}
	return v, after.HeapAlloc - before.HeapAlloc
}

// checkCut checks a result whose every cell is longer than the engine cap:
// each one is cut, reported in CutCells, and the rendering stays within
// the profile's caps and says so.
func checkCut(t *testing.T, res engine.Result, l config.Limits) {
	t.Helper()
	if len(res.Rows) != 1 {
		t.Fatalf("%d rows", len(res.Rows))
	}
	for i, v := range res.Rows[0] {
		if n := len(fmt.Sprint(v)); n > engine.MaxCellBytes || !res.IsCut(0, i) {
			t.Errorf("column %s: %d bytes, cut %v", res.Columns[i].Label, n, res.IsCut(0, i))
		}
	}
	var b strings.Builder
	if err := render.Render(&b, res, l, render.FormatJSON); err != nil {
		t.Fatal(err)
	}
	if b.Len() > l.MaxOutputBytes || !strings.Contains(b.String(), fmt.Sprintf(`"cut_cells":%d`, len(res.Rows[0]))) {
		t.Errorf("json rendering of %d bytes: %.300s", b.Len(), b.String())
	}
}

// TestPostgresHugeValues runs a ~10 MB numeric array, the largest numeric
// and a deep jsonb_pretty: the session keeps at most the engine cap of each
// cell, however large the value the server sends.
func TestPostgresHugeValues(t *testing.T) {
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			srv := startPostgres(t, v)
			s := connectPG(t, srv, "ro", config.TierRead, 60*time.Second)
			q := `SELECT array_fill(1e131071::numeric, ARRAY[80]) AS nums, 10::numeric ^ 131071 AS num,
				jsonb_pretty((repeat('{"a":[', 1500) || '1' || repeat(']}', 1500))::jsonb) AS pretty`
			got, grew := heapGrowth(func() any {
				res, err := s.Run(context.Background(), "", read(q), 10)
				if err != nil {
					t.Fatalf("run: %v", err)
				}
				return res
			})
			res := got.(engine.Result)
			checkCut(t, res, config.DefaultLimits(false))
			if grew > 8<<20 {
				t.Errorf("the session kept %d bytes for a result capped at %d per cell", grew, engine.MaxCellBytes)
			}
			// The connection is still in sync after the dropped bytes.
			if r := mustRun(t, s, "SELECT 41 + 1 AS n"); fmt.Sprint(r.Rows[0][0]) != "42" {
				t.Errorf("next query: %v", r.Rows)
			}
		})
	}
}

// TestMySQLHugeValues does the same on MariaDB and MySQL, whose rows the
// driver reads whole: the cell is cut before it is copied out of it.
func TestMySQLHugeValues(t *testing.T) {
	for _, m := range mysqlTargets() {
		t.Run(m.image(), func(t *testing.T) {
			srv := startMySQL(t, m)
			s := connectMySQL(t, m, srv, "ro", config.TierRead, 60*time.Second)
			res := mustRun(t, s, "SELECT REPEAT('7', 10000000) AS num, REPEAT('[1, ', 2000000) AS js")
			checkCut(t, res, config.DefaultLimits(false))
		})
	}
}
