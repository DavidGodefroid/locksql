package mysql

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// ParsePlan normalises the output of EXPLAIN FORMAT=JSON, in either the
// MariaDB or the MySQL 8 shape, into an engine.Plan whose Raw is the
// server's plan unchanged.
//
// Both shapes nest a "query_block" holding the tables of one SELECT, either
// as "table" or as an ordered "nested_loop" list, wrapped in operation
// objects (MariaDB: filesort, temporary_table, read_sorted_file,
// block-nl-join; MySQL: ordering_operation, grouping_operation,
// duplicates_removal with using_filesort/using_temporary_table flags).
// Subqueries hang off "*subqueries" lists, derived tables off "materialized"
// (MariaDB) or "materialized_from_subquery" (MySQL), and UNION arms off
// "union_result.query_specifications".
//
// Rows: MySQL's rows_examined_per_scan, MariaDB's rows. Correlated: MySQL's
// "dependent": true, MariaDB's expression_cache / subquery_cache wrapper
// (the cache only exists for dependent subqueries).
func ParsePlan(raw []byte) (engine.Plan, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var top map[string]any
	if err := dec.Decode(&top); err != nil {
		return engine.Plan{}, fmt.Errorf("explain: not a JSON plan: %w", err)
	}
	qb, ok := top["query_block"].(map[string]any)
	if !ok {
		return engine.Plan{}, errors.New("explain: plan has no query_block")
	}
	root := engine.PlanNode{Detail: "QUERY", EstRows: -1}
	block(qb, &root)
	return engine.Plan{Root: root, Cost: blockCost(qb), Raw: json.RawMessage(bytes.Clone(raw))}, nil
}

// blockCost is MySQL's cost_info.query_cost (a string) or MariaDB's cost
// (a number), -1 when absent.
func blockCost(qb map[string]any) float64 {
	num := func(v any) float64 {
		switch x := v.(type) {
		case json.Number:
			if f, err := x.Float64(); err == nil {
				return f
			}
		case string:
			if f, err := json.Number(x).Float64(); err == nil {
				return f
			}
		}
		return -1
	}
	if ci, ok := qb["cost_info"].(map[string]any); ok {
		if c := num(ci["query_cost"]); c >= 0 {
			return c
		}
	}
	if c, ok := qb["cost"]; ok {
		return num(c)
	}
	return -1
}

// keyOrder visits "table" and "nested_loop" first, so that a block's
// pipeline comes before the subqueries hanging off it, then the other keys
// sorted, for a deterministic result.
func keyOrder(obj map[string]any) []string {
	rank := func(k string) int {
		switch k {
		case "table":
			return 0
		case "nested_loop":
			return 1
		}
		return 2
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if ri, rj := rank(keys[i]), rank(keys[j]); ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	return keys
}

func isTrue(v any) bool { b, _ := v.(bool); return b }

// block walks one object of a query block into group g.
func block(obj map[string]any, g *engine.PlanNode) {
	for _, k := range keyOrder(obj) {
		v := obj[k]
		switch {
		case k == "table":
			if t, ok := v.(map[string]any); ok {
				if _, named := t["table_name"].(string); named {
					table(t, g, false)
				} else {
					block(t, g)
				}
			}
		case k == "nested_loop":
			list, _ := v.([]any)
			for _, e := range list {
				if entry, ok := e.(map[string]any); ok {
					loopEntry(entry, g)
				}
			}
		case k == "union_result":
			if u, ok := v.(map[string]any); ok {
				g.Children = append(g.Children, union(u))
			}
		case strings.HasSuffix(k, "subqueries"):
			list, _ := v.([]any)
			for _, e := range list {
				g.Children = append(g.Children, subGroup(e, k))
			}
		case k == "query_block":
			g.Children = append(g.Children, subGroup(map[string]any{k: v}, k))
		case k == "materialized" || k == "materialized_from_subquery":
			g.Children = append(g.Children, subGroup(v, "derived"))
		case k == "using_filesort":
			g.Sort = g.Sort || isTrue(v)
		case k == "using_temporary_table":
			g.Temp = g.Temp || isTrue(v)
		case k == "filesort":
			g.Sort = true
			walk(v, g)
		case k == "temporary_table":
			g.Temp = true
			walk(v, g)
		default:
			walk(v, g)
		}
	}
}

// walk descends into a wrapper value.
func walk(v any, g *engine.PlanNode) {
	switch x := v.(type) {
	case map[string]any:
		block(x, g)
	case []any:
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				block(m, g)
			}
		}
	}
}

// loopEntry handles one nested_loop element: a table, possibly under
// wrappers (MariaDB block-nl-join, read_sorted_file, ...) that may carry
// the join condition themselves.
func loopEntry(entry map[string]any, g *engine.PlanNode) {
	if t, ok := entry["table"].(map[string]any); ok {
		if _, named := t["table_name"].(string); named {
			table(t, g, false)
			rest := make(map[string]any, len(entry))
			for k, v := range entry {
				if k != "table" {
					rest[k] = v
				}
			}
			block(rest, g)
			return
		}
	}
	if t, wrappers := findTable(entry); t != nil {
		table(t, g, wrappersHaveCond(wrappers))
		for _, w := range wrappers {
			if isTrue(w["using_filesort"]) || w["filesort"] != nil || w["read_sorted_file"] != nil {
				g.Sort = true
			}
			if isTrue(w["using_temporary_table"]) || w["temporary_table"] != nil {
				g.Temp = true
			}
			for _, k := range keyOrder(w) {
				switch {
				case k == "query_block":
					g.Children = append(g.Children, subGroup(map[string]any{k: w[k]}, k))
				case k == "materialized" || k == "materialized_from_subquery":
					g.Children = append(g.Children, subGroup(w[k], "derived"))
				case strings.HasSuffix(k, "subqueries"):
					list, _ := w[k].([]any)
					for _, e := range list {
						g.Children = append(g.Children, subGroup(e, k))
					}
				}
			}
		}
		return
	}
	block(entry, g)
}

// findTable descends through single wrapper objects to the table of a
// nested_loop entry, returning the wrappers on the way. It does not descend
// into query blocks, subqueries or materialisations.
func findTable(obj map[string]any) (map[string]any, []map[string]any) {
	path := []map[string]any{obj}
	cur := obj
	for depth := 0; depth < 16; depth++ {
		if t, ok := cur["table"].(map[string]any); ok {
			if _, named := t["table_name"].(string); named {
				return t, path
			}
			return nil, nil
		}
		var next map[string]any
		for _, k := range keyOrder(cur) {
			if k == "query_block" || k == "materialized" || k == "materialized_from_subquery" || strings.HasSuffix(k, "subqueries") {
				continue
			}
			if m, ok := cur[k].(map[string]any); ok {
				if next != nil {
					return nil, nil // more than one branch: not a plain wrapper
				}
				next = m
			}
		}
		if next == nil {
			return nil, nil
		}
		path = append(path, next)
		cur = next
	}
	return nil, nil
}

func wrappersHaveCond(ws []map[string]any) bool {
	for _, w := range ws {
		if _, ok := w["attached_condition"]; ok {
			return true
		}
	}
	return false
}

// table adds a table access to g's pipeline. A full or index scan joined
// after another table with no condition at all reads every row of it for
// each outer row: NoJoinCond.
func table(t map[string]any, g *engine.PlanNode, wrapperCond bool) {
	name, _ := t["table_name"].(string)
	access, _ := t["access_type"].(string)
	n := engine.PlanNode{Table: name, Access: accessOf(access), EstRows: rowsOf(t)}
	_, cond := t["attached_condition"]
	if (n.Access == engine.AccessFull || n.Access == engine.AccessIndex) && !cond && !wrapperCond && pipelineLen(g) > 0 {
		n.NoJoinCond = true
	}
	g.Children = append(g.Children, n)
	for _, k := range keyOrder(t) {
		v := t[k]
		switch {
		case k == "materialized" || k == "materialized_from_subquery":
			g.Children = append(g.Children, subGroup(v, "derived "+name))
		case strings.HasSuffix(k, "subqueries"):
			list, _ := v.([]any)
			for _, e := range list {
				g.Children = append(g.Children, subGroup(e, k))
			}
		case k == "using_filesort":
			g.Sort = g.Sort || isTrue(v)
		case k == "using_temporary_table":
			g.Temp = g.Temp || isTrue(v)
		}
	}
}

func pipelineLen(g *engine.PlanNode) int {
	n := 0
	for _, c := range g.Children {
		if c.Table != "" {
			n++
		}
	}
	return n
}

// subGroup turns a subquery entry, a materialisation or a union arm into a
// group, descending through its wrappers to the query block.
func subGroup(v any, detail string) engine.PlanNode {
	g := engine.PlanNode{Detail: detail, EstRows: -1}
	obj, _ := v.(map[string]any)
	for depth := 0; obj != nil && depth < 16; depth++ {
		if isTrue(obj["dependent"]) {
			g.Correlated = true
		}
		if isTrue(obj["using_temporary_table"]) {
			g.Temp = true
		}
		if isTrue(obj["using_filesort"]) {
			g.Sort = true
		}
		if c, ok := obj["expression_cache"].(map[string]any); ok {
			g.Correlated = true
			obj = c
			continue
		}
		if c, ok := obj["subquery_cache"].(map[string]any); ok {
			g.Correlated = true
			obj = c
			continue
		}
		if qb, ok := obj["query_block"].(map[string]any); ok {
			block(qb, &g)
		} else {
			block(obj, &g)
		}
		break
	}
	return g
}

// union is the group of a UNION/INTERSECT/EXCEPT: one child group per arm.
// The result goes through a temporary table unless the server says it does
// not (MySQL reports using_temporary_table; MariaDB names the result table
// "<union...>").
func union(u map[string]any) engine.PlanNode {
	g := engine.PlanNode{Detail: "union", EstRows: -1}
	if t, ok := u["using_temporary_table"]; ok {
		g.Temp = isTrue(t)
	} else if name, _ := u["table_name"].(string); strings.HasPrefix(name, "<") {
		g.Temp = true
	}
	specs, _ := u["query_specifications"].([]any)
	for _, s := range specs {
		g.Children = append(g.Children, subGroup(s, "union arm"))
	}
	return g
}

func accessOf(t string) string {
	switch strings.TrimPrefix(t, "hash_") {
	case "ALL":
		return engine.AccessFull
	case "index":
		return engine.AccessIndex
	case "range", "index_merge":
		return engine.AccessRange
	case "system", "const", "eq_ref", "ref", "ref_or_null", "fulltext", "unique_subquery", "index_subquery":
		return engine.AccessLookup
	}
	return engine.AccessUnknown
}

// rowsOf reads the row estimate: MySQL's rows_examined_per_scan, MariaDB's
// rows; -1 when absent or unusable.
func rowsOf(t map[string]any) int64 {
	v, ok := t["rows_examined_per_scan"]
	if !ok {
		v, ok = t["rows"]
	}
	if !ok {
		return -1
	}
	var f float64
	switch x := v.(type) {
	case json.Number:
		var err error
		if f, err = strconv.ParseFloat(string(x), 64); err != nil {
			return -1
		}
	case float64:
		f = x
	default:
		return -1
	}
	switch {
	case math.IsNaN(f) || f < 0:
		return -1
	case f >= math.MaxInt64:
		return math.MaxInt64
	}
	return int64(math.Round(f))
}
