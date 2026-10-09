package console

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// warnings are the approval-screen warnings of a read plan. They never
// refuse; they go to the audit log with the decision. They name references
// and columns, never a value.
func (s *Server) warnings(ctx context.Context, sess engine.Session, pl *plan) []string {
	if pl.an == nil || pl.unmask {
		return nil
	}
	var out []string
	if s.clearLiteral(pl.st.SQL) {
		out = append(out, "the agent received this value in clear (it is in its statement): next time, have it write a placeholder '${name}' and type the value here")
	}
	var refs []sqlast.ValueUse
	for _, v := range pl.an.Values {
		if v.Kind == sqlast.ValueRef {
			refs = append(refs, v)
		}
	}
	if len(refs) == 0 {
		return out
	}
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.Name
	}
	list := strings.Join(names, ", ")
	for _, k := range pl.an.KeyFilters {
		if s.uniqueKey(ctx, sess, k) {
			out = append(out, fmt.Sprintf("this statement tests whether one row (%s.%s) has the same value as %s", k.Table, k.Column, list))
			break
		}
	}
	if countsOnly(pl.an.Outputs) {
		out = append(out, "the result holds only counts: this statement tests whether rows have the same value as "+list)
	}
	return append(out, s.scanWarnings(refs)...)
}

// clearLiteral reports a literal of the statement that a detector
// recognises (an address, a phone number, ...): the agent had the value.
func (s *Server) clearLiteral(sql string) bool {
	toks, err := sqlclass.Lex(s.dialect, sql)
	if err != nil {
		return false
	}
	for _, t := range toks {
		text := t.Text
		switch t.Kind {
		case sqlclass.TokString:
			if len(text) < 2 || text[0] != '\'' {
				continue
			}
			text = strings.ReplaceAll(text[1:len(text)-1], "''", "'")
			if _, _, isPH, _ := sqlast.ParsePlaceholder(text); isPH {
				continue
			}
		case sqlclass.TokNumber:
		default:
			continue
		}
		if pii.Detects(text, s.detectors) {
			return true
		}
	}
	return false
}

func countsOnly(outs []sqlast.Output) bool {
	if len(outs) == 0 {
		return false
	}
	for _, o := range outs {
		if k := o.Prov.Kind; k != sqlast.KindCount && k != sqlast.KindAggregate && k != sqlast.KindConst {
			return false
		}
	}
	return true
}

// uniqueKey reports whether src is a one-column primary key or unique
// index (looked up once per session).
func (s *Server) uniqueKey(ctx context.Context, sess engine.Session, src sqlast.Source) bool {
	key := src.String()
	if v, ok := s.keys[key]; ok {
		return v
	}
	info, err := sess.Describe(ctx, src.DB, src.Table)
	unique := false
	if err == nil {
		for _, ix := range info.Indexes {
			if (ix.Unique || ix.Primary) && len(ix.Columns) == 1 && fold(ix.Columns[0]) == fold(src.Column) {
				unique = true
			}
		}
	}
	s.keys[key] = unique
	return unique
}

// scanWarnings counts, per result, the distinct reference uses (one
// reference, or one IN list) and warns past limits.reference_probe.
func (s *Server) scanWarnings(refs []sqlast.ValueUse) []string {
	lists := map[int][]string{}
	for _, r := range refs {
		n := resultOf(r.Name)
		if r.InList {
			lists[n] = append(lists[n], r.Name)
			continue
		}
		s.probe(n, r.Name)
	}
	for n, l := range lists {
		slices.Sort(l)
		s.probe(n, "in:"+strings.Join(l, ","))
	}
	var out []string
	for n, uses := range s.probes {
		if len(uses) > s.profile.Limits.ReferenceProbe && slices.ContainsFunc(refs, func(r sqlast.ValueUse) bool { return resultOf(r.Name) == n }) {
			out = append(out, fmt.Sprintf("the agent has compared %d distinct cells of result r%d, one statement each: it may be rebuilding which values are equal", len(uses), n))
		}
	}
	slices.Sort(out)
	return out
}

func (s *Server) probe(n int, key string) {
	if s.probes[n] == nil {
		s.probes[n] = map[string]bool{}
	}
	s.probes[n][key] = true
}

// resultOf is N in "rN.R.C".
func resultOf(name string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(strings.SplitN(name, ".", 2)[0], "r"))
	return n
}
