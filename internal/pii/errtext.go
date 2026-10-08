package pii

import "strings"

// errQuotes are the quote characters server error messages put around the
// values they echo.
const errQuotes = `"'` + "`"

// redacted replaces the quoted part of a server error message.
const redacted = `"<value redacted>"`

// errGaps is the server text that may sit between two quoted names of one
// message ("Unknown column 'x' in 'where clause'"). A value equal to one of
// them reveals nothing.
var errGaps = map[string]bool{
	" in ": true, " for column ": true, " for key ": true, " at row ": true, " of ": true,
	" and ": true, ", ": true, " to ": true, " on ": true, ".": true,
}

// errQuoted is server text MySQL quotes itself ("in 'field list'").
var errQuoted = map[string]bool{
	"field list": true, "where clause": true, "on clause": true, "order clause": true,
	"group statement": true, "having clause": true, "from clause": true,
}

// RedactMessage removes from a database error message the row values it may
// quote: a failed cast or function call in a WHERE clause echoes the value
// it choked on ("invalid input syntax for type integer: \"Smith\""), and
// that value reaches no result row, so no rule or detector masks it.
//
// Everything from the first quote character to the last one is replaced,
// unless each quoted part is text of the statement itself (a syntax error,
// an unknown column) or a known server phrase, joined only by known server
// words: a value cannot
// shift the pairing of quotes, since its text would then sit in a gap. A
// single stray quote redacts the rest of the message. The detectors then
// run over what is left; an unquoted value they cannot recognise is not
// caught.
func RedactMessage(msg, sql string, ds []Detector) string {
	if first := strings.IndexAny(msg, errQuotes); first >= 0 {
		last := strings.LastIndexAny(msg, errQuotes)
		switch {
		case last == first:
			msg = msg[:first] + redacted
		case !quotedFromSQL(msg[first:last+1], sql):
			msg = msg[:first] + redacted + msg[last+1:]
		}
	}
	for _, d := range ds {
		msg = d.Mask(msg)
	}
	return msg
}

// quotedFromSQL reports whether span, which starts and ends with a quote
// character, is a run of quoted parts whose contents all appear in sql
// (ignoring case), separated by gaps from errGaps.
func quotedFromSQL(span, sql string) bool {
	lower := strings.ToLower(sql)
	for i := 0; i < len(span); {
		q := span[i]
		end := strings.IndexByte(span[i+1:], q)
		if end < 0 {
			return false
		}
		if part := strings.ToLower(span[i+1 : i+1+end]); !errQuoted[part] && !strings.Contains(lower, part) {
			return false
		}
		i += end + 2
		if i == len(span) {
			return true
		}
		k := strings.IndexAny(span[i:], errQuotes)
		if k < 0 || !errGaps[span[i:i+k]] {
			return false
		}
		i += k
	}
	return true
}
