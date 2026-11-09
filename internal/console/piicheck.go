package console

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/DavidGodefroid/lockkit/secrets"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
	"github.com/DavidGodefroid/locksql/internal/pii"
)

// servedColumns reads the column catalog of every database served, afresh:
// a pattern is checked against the columns as they are now. The first
// segment of a column is its ColumnInfo.DB: the schema on PostgreSQL.
func (s *Server) servedColumns(ctx context.Context, sess engine.Session) ([]engine.ColumnInfo, error) {
	var out []engine.ColumnInfo
	for _, db := range s.cfg.Databases {
		cols, err := sess.Columns(ctx, db)
		if err != nil {
			return nil, err
		}
		out = append(out, cols...)
	}
	return out, nil
}

// resolveMask checks a canonical mask pattern against the catalog
// (locksql#207). A pattern without '*' that names no column is refused,
// with the columns it may have meant: the rule would mask nothing and the
// client would believe the column protected. A glob that matches nothing
// today is accepted, as it may match a column created later, and the
// console says so; the client learns it from pii.unmatched. A catalog that
// cannot be read does not block the rule: a mask rule only tightens.
func (s *Server) resolveMask(ctx context.Context, pattern string) error {
	notChecked := func(why string) error {
		s.println(paint.Warn("mask rule " + safeText(pattern, false) + " not checked against the catalog: " + safeText(why, false)))
		return nil
	}
	sess, r := s.session(ctx, 0)
	if r != nil {
		return notChecked(r.Error.Message)
	}
	cols, err := s.servedColumns(ctx, sess)
	if err != nil {
		return notChecked(secrets.Sanitize(err))
	}
	if pii.MatchesColumn(pattern, cols) {
		return nil
	}
	if pii.Glob(pattern) {
		s.println(paint.Warn("mask rule " + safeText(pattern, false) + " matches no column today"))
		return nil
	}
	return noColumnError(pattern, sess.Flavor() == engine.FlavorPostgres, cols)
}

// noColumnError is the refusal of a pattern that names no column.
func noColumnError(pattern string, postgres bool, cols []engine.ColumnInfo) error {
	var b strings.Builder
	fmt.Fprintf(&b, "pii rule: %s matches no column", pattern)
	if c := pii.Candidates(pattern, cols); len(c) > 0 {
		fmt.Fprintf(&b, "; did you mean %s?", strings.Join(c, ", "))
	} else {
		b.WriteString(".")
	}
	if postgres {
		b.WriteString(" On PostgreSQL a rule is schema.table.column, as describe names the column")
		if segs := pii.FirstSegments(cols); len(segs) > 0 && len(segs) <= 10 {
			fmt.Fprintf(&b, " (schemas: %s)", strings.Join(segs, ", "))
		}
		b.WriteString(".")
	}
	b.WriteString(" Only a rule with '*' may name columns that do not exist yet.")
	return errors.New(b.String())
}

// piiUnmatched answers pii.unmatched: the rules in force that name no
// column of the databases served, so that pii list can flag dead rules.
func (s *Server) piiUnmatched(ctx context.Context, req ipc.Request) ipc.Response {
	sess, r := s.session(ctx, req.ID)
	if r != nil {
		return *r
	}
	cols, err := s.servedColumns(ctx, sess)
	if err != nil {
		return s.failed(req.ID, req.Method, err, "")
	}
	return okResp(req.ID, ipc.PIIUnmatchedResult{
		Mask:  nonNil(pii.Unmatched(s.rules.Mask, cols)),
		Allow: nonNil(pii.Unmatched(s.rules.Allow, cols)),
	})
}
