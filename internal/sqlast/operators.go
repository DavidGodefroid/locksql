package sqlast

import (
	"reflect"
	"slices"
	"strings"
)

// implicitOps are the comparisons a statement may use without writing
// them: joins and IN (=, <>), BETWEEN, sorts and the k-anonymity counts.
var implicitOps = []string{"=", "<>", "<", ">", "<=", ">="}

// Operators returns, as PostgreSQL names them, the operators st uses,
// sorted and unique: the operators written, those LIKE and ILIKE stand for,
// and implicitOps. PostgreSQL resolves an operator like a function, to the
// best match over the search path (see engine.FunctionShadows).
func Operators(st *Statement) []string {
	ops := slices.Clone(implicitOps)
	walkNodes(reflect.ValueOf(st), func(n any) {
		switch n := n.(type) {
		case *Binary:
			switch op := strings.Fields(n.Op)[0]; op {
			case "AND", "OR", "XOR", "<=>":
			case "!=":
				ops = append(ops, "<>")
			case "==":
				ops = append(ops, "=")
			default:
				ops = append(ops, op)
			}
		case *Unary:
			if n.Op != "NOT" {
				ops = append(ops, n.Op)
			}
		case *Like:
			op := map[string]string{"LIKE": "~~", "ILIKE": "~~*"}[n.Op]
			if op != "" && n.Not {
				op = "!" + op
			}
			if op != "" {
				ops = append(ops, op)
			}
		}
	})
	slices.Sort(ops)
	return slices.Compact(ops)
}

// walkNodes calls fn on every pointer reachable from v, by reflection, so
// that a node type added to the AST later is not skipped.
func walkNodes(v reflect.Value, fn func(any)) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		if v.Kind() == reflect.Pointer {
			fn(v.Interface())
		}
		walkNodes(v.Elem(), fn)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				walkNodes(v.Field(i), fn)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			walkNodes(v.Index(i), fn)
		}
	}
}
