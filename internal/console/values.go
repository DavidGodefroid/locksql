package console

import (
	"slices"
	"strings"
	"time"

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
