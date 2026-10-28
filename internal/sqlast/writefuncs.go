package sqlast

import (
	"errors"
	"reflect"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
)

// writeFuncs are the built-ins a write may call under write_functions =
// "allowlist" on top of the read allowlist: key and identifier generators.
// SETVAL, LAST_INSERT_ID(n) and the session or catalog functions stay out.
var writeFuncs = map[sqlclass.Dialect]set{
	sqlclass.MySQL:    newSet("UUID", "UUID_SHORT", "UUID_TO_BIN", "BIN_TO_UUID", "SYS_GUID"),
	sqlclass.Postgres: newSet("GEN_RANDOM_UUID", "UUIDV4", "UUIDV7", "NEXTVAL"),
	sqlclass.SQLite:   newSet("RANDOMBLOB"),
}

// strictHint is the hint of a write refused under write_functions =
// "allowlist" because it cannot be checked.
const strictHint = `write_functions = "allowlist" checks every function a write calls: rewrite it as a single-table INSERT, REPLACE, UPDATE or DELETE that calls allowlisted functions only, or ask the human to change the profile`

// CheckWriteFunctions applies write_functions = "allowlist" to a
// data-modifying statement (issue #60): every function it calls, at any
// depth, must be on the read allowlist of the dialect or on writeFuncs.
// Schema-qualified calls are refused, as are calls through a quoted name
// or a name with non-ASCII letters, which the classifier folds but the
// engine may resolve to another function (PostgreSQL "LOWER" is not
// lower). A statement the write parser does not read (MERGE, multi-table
// writes, CALL, ...) is refused: its calls cannot be listed.
func CheckWriteFunctions(d sqlclass.Dialect, sql string) error {
	st, err := ParseWrite(d, sql)
	if err != nil {
		var r *sqlclass.Refusal
		if errors.As(err, &r) {
			c := *r
			c.Hint = strictHint
			return &c
		}
		return err
	}
	var bad error
	walkFuncs(reflect.ValueOf(st), func(f *FuncCall) {
		if bad != nil {
			return
		}
		// The name as written: up to the first '(' of the call.
		written := st.SQL[f.Sp.Pos:f.Sp.End]
		written = written[:max(strings.IndexByte(written, '('), 0)]
		switch {
		case strings.ContainsAny(written, "\"`[") || !ascii(written):
			bad = refuse(refusal.Function, "function calls through a quoted name or a name with non-ASCII letters are not allowed in a write under write_functions = \"allowlist\"").At(f.Sp.Pos, "")
		case !funcAllowed(d, f.Name) && !writeFuncs[d][f.Name]:
			bad = refusef(refusal.Function, "function %.64s is not in the allowlist (write_functions = \"allowlist\")", strings.ToLower(f.Name)).At(f.Sp.Pos, "")
		}
	})
	return bad
}

// walkFuncs calls fn on every *FuncCall reachable from v. It walks the
// tree by reflection, so that a node type added to the AST later is not
// skipped.
func walkFuncs(v reflect.Value, fn func(*FuncCall)) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		if f, ok := v.Interface().(*FuncCall); ok {
			fn(f)
		}
		walkFuncs(v.Elem(), fn)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				walkFuncs(v.Field(i), fn)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			walkFuncs(v.Index(i), fn)
		}
	}
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
