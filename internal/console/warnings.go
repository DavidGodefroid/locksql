package console

import (
	"strings"

	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// warnings are the approval-screen warnings of a plan. They never refuse;
// they go to the audit log with the decision. They never name a value. A
// write plan gets only the PII join warning.
func (s *Server) warnings(pl *plan) []string {
	if pl.unmask {
		return nil
	}
	var out []string
	if j := piiJoins(pl); len(j) > 0 {
		out = append(out, "joins PII columns: "+strings.Join(j, ", ")+"; if either side holds a value the agent knows, the result tells it which subjects share it")
	}
	if pl.an == nil || pl.st.Class != sqlclass.Read {
		return out
	}
	if s.clearLiteral(pl.st.SQL) {
		out = append(out, "the agent received this value in clear (it is in its statement)")
	}
	return out
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
			v, ok := sqlast.StringValue(s.dialect, text)
			if !ok {
				continue
			}
			text = v
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
