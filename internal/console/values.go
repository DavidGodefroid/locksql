package console

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DavidGodefroid/locksql/internal/audit"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
)

// typedValue is a value the human typed for a placeholder name. It lives
// in the console's memory only.
type typedValue struct {
	value string
	at    time.Time
}

// typedNames returns the names typed so far, sorted.
func (s *Server) typedNames() []string {
	names := make([]string, 0, len(s.typed))
	for n := range s.typed {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// placeholders splits the typed placeholders of a plan into the names the
// human has not typed yet and those already typed, each once, in order.
func (s *Server) placeholders(pl *plan) (missing, reused []string) {
	if pl.an == nil {
		return nil, nil
	}
	for _, v := range pl.an.Values {
		if v.Kind != sqlast.ValueTyped || slices.Contains(missing, v.Name) || slices.Contains(reused, v.Name) {
			continue
		}
		if _, ok := s.typed[v.Name]; ok {
			reused = append(reused, v.Name)
		} else {
			missing = append(missing, v.Name)
		}
	}
	return missing, reused
}

// placeholderColumns names the PII columns a placeholder name is compared
// with, each once: "db.table.column", the column alone when it has no
// table, "?" when the analysis could not name one.
func placeholderColumns(pl *plan, name string) string {
	var cols []string
	for _, v := range pl.an.Values {
		if v.Name != name || v.Column == (sqlast.Source{}) {
			continue
		}
		c := v.Column.String()
		if v.Column.Table == "" {
			c = v.Column.Column
		}
		if !slices.Contains(cols, c) {
			cols = append(cols, c)
		}
	}
	if len(cols) == 0 {
		return "?"
	}
	return strings.Join(cols, ", ")
}

// askValues prompts, echo off, for each name. A cancelled or unusable
// answer denies the request and keeps the name unknown.
func (s *Server) askValues(ctx context.Context, id int64, pl *plan, rec audit.Record, names []string) *ipc.Response {
	for _, n := range names {
		b, err := s.cfg.IO.AskSecret(ctx, paint.Paint(s.frameColour(), "│ ")+fmt.Sprintf("value for ${%s} (%s): ", n, safeText(placeholderColumns(pl, n), false)))
		v := string(b)
		clear(b)
		switch {
		case err != nil && ctx.Err() != nil:
			rec.Event, rec.Decision = audit.EventAbandoned, "abandoned"
			s.audit(rec)
			s.println(paint.Fail("client gone: request cancelled"))
			r := errResp(id, ipc.CodeDenied, "the request was cancelled")
			return &r
		case errors.Is(err, errSecretTimeout):
			rec.Event, rec.Decision = audit.EventTimeout, "timeout"
			s.audit(rec)
			s.println(paint.Fail("no value typed in time: denied"))
			r := errResp(id, ipc.CodeDenied, "the human typed no value for ${"+n+"}; do not retry unless asked")
			return &r
		case err != nil || v == "":
			rec.Event, rec.Decision = audit.EventDenied, "no value"
			s.audit(rec)
			s.println(paint.Fail("no value typed: denied"))
			r := errResp(id, ipc.CodeDenied, "the human typed no value for ${"+n+"}; do not retry unless asked")
			return &r
		case strings.ContainsAny(v, "\\\x00"):
			rec.Event, rec.Decision = audit.EventDenied, "unsafe value"
			s.audit(rec)
			s.println(paint.Fail("a backslash or a NUL cannot be substituted safely: denied"))
			r := errResp(id, ipc.CodeDenied, "the value typed for ${"+n+"} cannot be substituted safely; do not retry unless asked")
			return &r
		}
		s.typed[n] = typedValue{value: v, at: s.now()}
	}
	return nil
}

// planValues are the values substituted for the placeholders of a plan,
// typed or referenced, each also in its SQL-quoted form (” for '): a
// database error may quote them either way.
func (s *Server) planValues(pl *plan) [][]byte {
	if pl == nil || pl.an == nil {
		return nil
	}
	var vals [][]byte
	for _, u := range pl.an.Values {
		var v string
		var ok bool
		if u.Kind == sqlast.ValueRef {
			v, ok = s.refs.get(u.Name)
		} else {
			var tv typedValue
			tv, ok = s.typed[u.Name]
			v = tv.value
		}
		if !ok || v == "" {
			continue
		}
		vals = append(vals, []byte(v))
		if q := strings.ReplaceAll(v, "'", "''"); q != v {
			vals = append(vals, []byte(q))
		}
	}
	return vals
}
