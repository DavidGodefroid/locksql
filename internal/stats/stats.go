// Package stats reads the console's audit log and counts the refusals by
// code and by the token or node that triggered them, so that grammar work
// starts with the constructs users hit most. It reads a local file and
// never touches the network.
//
// The export is the one form meant to leave the machine: it holds counts,
// codes, engine names and SQL shapes, statements whose literals,
// identifiers and comments are replaced by fixed markers. Every string in
// it comes from a closed vocabulary (ShapeToken), so it holds no literal,
// identifier or refusal message of the log.
package stats

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/audit"
	refusal "github.com/DavidGodefroid/locksql/internal/sqlrefusal"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

const (
	// Uncoded groups the refusals of a log written before refusal codes.
	Uncoded = "uncoded"
	// NoToken groups the refusals that point at no token.
	NoToken = "-"
	// MaxShape bounds a shape, in bytes.
	MaxShape = 300
	// maxShapes bounds the shapes of an export.
	maxShapes = 100
	// ExportNote heads an export.
	ExportNote = "locksql refusal statistics: SQL shapes only, literals, identifiers and comments removed"
	// maxLine bounds an audit line; a longer one is skipped.
	maxLine = 4 << 20
)

// Count is the number of refusals of a code, and of a token under it.
type Count struct {
	Code  string `json:"code"`
	Token string `json:"token,omitempty"`
	N     int    `json:"n"`
}

// Report counts the refusals of an audit log.
type Report struct {
	// Refusals is the number of refusal records, Skipped the number of
	// lines that are not audit records.
	Refusals, Skipped int
	ByCode            []Count
	// ByToken counts per code and token (upper-cased; NoToken when the
	// refusal points at none).
	ByToken []Count
	recs    []record
}

type record struct {
	code, token, engine, sql string
}

// Read reads an audit log and counts its refusals.
func Read(r io.Reader) (*Report, error) {
	rep := &Report{}
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br)
		if len(line) > 0 {
			rep.add(line)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("stats: %w", err)
		}
	}
	rep.ByCode = count(rep.recs, func(r record) Count { return Count{Code: r.code} })
	rep.ByToken = count(rep.recs, func(r record) Count { return Count{Code: r.code, Token: r.token} })
	return rep, nil
}

// readLine reads one line; a line over maxLine comes back truncated (and
// is then skipped as invalid JSON).
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(line) < maxLine {
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

func (rep *Report) add(line []byte) {
	var rec audit.Record
	if len(strings.TrimSpace(string(line))) == 0 {
		return
	}
	if err := json.Unmarshal(line, &rec); err != nil || rec.Event == "" {
		rep.Skipped++
		return
	}
	if rec.Event != audit.EventRefused {
		return
	}
	rep.Refusals++
	r := record{code: rec.Code, token: NoToken, engine: rec.Engine, sql: rec.SQL}
	if r.code == "" {
		r.code = Uncoded
	}
	if rec.Span != nil && rec.Span.Token != "" {
		r.token = strings.ToUpper(rec.Span.Token)
	}
	rep.recs = append(rep.recs, r)
}

// count groups recs by key and ranks the groups, most frequent first.
func count(recs []record, key func(record) Count) []Count {
	n := map[Count]int{}
	for _, r := range recs {
		n[key(r)]++
	}
	out := make([]Count, 0, len(n))
	for k, v := range n {
		k.N = v
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b Count) int {
		return cmp.Or(cmp.Compare(b.N, a.N), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Token, b.Token))
	})
	return out
}

// WriteText writes the report for the console account's human: every
// code, then the top tokens.
func (rep *Report) WriteText(w io.Writer, top int) {
	fmt.Fprintf(w, "%d refusals", rep.Refusals)
	if rep.Skipped > 0 {
		fmt.Fprintf(w, " (%d lines skipped: not audit records)", rep.Skipped)
	}
	fmt.Fprintln(w)
	if rep.Refusals == 0 {
		return
	}
	fmt.Fprintln(w, "\nby code")
	for _, c := range rep.ByCode {
		fmt.Fprintf(w, "%6d  %-22s %s\n", c.N, c.Code, refusal.Code(c.Code).Title())
	}
	fmt.Fprintln(w, "\nby code and token (where the check stopped)")
	for i, c := range rep.ByToken {
		if top > 0 && i == top {
			fmt.Fprintf(w, "  … %d more\n", len(rep.ByToken)-top)
			break
		}
		fmt.Fprintf(w, "%6d  %-22s %s\n", c.N, c.Code, printable(c.Token))
	}
}

// printable escapes control and format characters of a token.
func printable(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

// Export is the anonymised report.
type Export struct {
	Version     string       `json:"locksql_version"`
	Note        string       `json:"note"`
	Refusals    int          `json:"refusals"`
	Skipped     int          `json:"skipped"`
	ByCode      []Count      `json:"by_code"`
	ByConstruct []Count      `json:"by_construct"`
	Shapes      []ShapeCount `json:"shapes"`
}

// ShapeCount is the number of refusals of one code, engine and shape.
type ShapeCount struct {
	Code   string `json:"code"`
	Engine string `json:"engine"`
	Shape  string `json:"shape"`
	N      int    `json:"n"`
}

// engines are the engine names an export may hold.
var engines = map[string]bool{"mysql": true, "mariadb": true, "postgres": true, "sqlite": true}

// WriteExport writes the anonymised report as JSON. version is the
// locksql version, kept only when it is a plain version string.
func (rep *Report) WriteExport(w io.Writer, version string) error {
	ex := Export{Note: ExportNote, Refusals: rep.Refusals, Skipped: rep.Skipped, Version: "unknown"}
	if plainVersion(version) {
		ex.Version = version
	}
	recs := make([]record, len(rep.recs))
	for i, r := range rep.recs {
		if !refusal.Code(r.code).Known() {
			r.code = Uncoded
		}
		if !engines[r.engine] {
			r.engine = "other"
		}
		r.token = ExportToken(r.token)
		recs[i] = r
	}
	ex.ByCode = count(recs, func(r record) Count { return Count{Code: r.code} })
	ex.ByConstruct = count(recs, func(r record) Count { return Count{Code: r.code, Token: r.token} })
	shapes := map[ShapeCount]int{}
	for _, r := range recs {
		shapes[ShapeCount{Code: r.code, Engine: r.engine, Shape: Shape(r.sql)}]++
	}
	for k, v := range shapes {
		k.N = v
		ex.Shapes = append(ex.Shapes, k)
	}
	slices.SortFunc(ex.Shapes, func(a, b ShapeCount) int {
		return cmp.Or(cmp.Compare(b.N, a.N), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Engine, b.Engine), cmp.Compare(a.Shape, b.Shape))
	})
	if len(ex.Shapes) > maxShapes {
		ex.Shapes = ex.Shapes[:maxShapes]
	}
	if ex.Shapes == nil {
		ex.Shapes = []ShapeCount{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ex)
}

// plainVersion reports whether v is a version string (digits, letters,
// dots, dashes, plus): the build's, never the log's.
func plainVersion(v string) bool {
	if v == "" || len(v) > 40 {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.ContainsRune(".-+_", c)) {
			return false
		}
	}
	return true
}

// ExportToken is a refusal token as an export may hold it: a keyword, a
// known function name or punctuation stays (upper-cased), any other word
// becomes "id", and no token is NoToken.
func ExportToken(tok string) string {
	switch {
	case tok == "" || tok == NoToken:
		return NoToken
	case allPunct(tok):
		return tok
	}
	up := strings.ToUpper(tok)
	if keywords[up] || knownFunction(up) {
		return up
	}
	return "id"
}

// The markers of a shape.
const (
	mIdent      = "id"
	mBackquoted = "`id`"
	mQuoted     = `"id"`
	mBracketed  = "[id]"
	mString     = "'?'"
	mNumber     = "N"
	mParam      = "$N"
	mDollar     = "$$?$$"
	mLineCmt    = "--…"
	mBlockCmt   = "/*…*/"
	mCut        = "…"
)

var markers = map[string]bool{mIdent: true, mBackquoted: true, mQuoted: true, mBracketed: true, mString: true,
	mNumber: true, mParam: true, mDollar: true, mLineCmt: true, mBlockCmt: true, mCut: true}

// ShapeToken reports whether tok belongs to the closed vocabulary of
// shapes: a marker, a keyword, a known function name or punctuation.
func ShapeToken(tok string) bool {
	return markers[tok] || keywords[tok] || knownFunction(tok) || allPunct(tok)
}

const punct = "()[]{},.;+-*/%<>=!~^&|:@?#$\\"

func allPunct(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(punct, rune(s[i])) {
			return false
		}
	}
	return true
}

func knownFunction(up string) bool { return sqlast.KnownFunction(up) || sqlclass.ForbiddenFunction(up) }

// keywords are the SQL words a shape keeps. Words often used as names
// (USER, DATE, KEY, NAME, STATUS, ...) are left out, so that a column
// named like one never shows in a shape.
var keywords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`
		SELECT FROM WHERE GROUP HAVING ORDER BY LIMIT OFFSET FETCH FIRST NEXT ROWS ONLY UNION ALL DISTINCT
		DISTINCTROW INTERSECT EXCEPT MINUS JOIN INNER LEFT RIGHT FULL OUTER CROSS NATURAL ON USING AS AND
		OR NOT XOR IN IS NULL LIKE ILIKE GLOB REGEXP RLIKE SIMILAR ESCAPE BETWEEN SYMMETRIC EXISTS CASE
		WHEN THEN ELSE END CAST CONVERT WITH RECURSIVE EXPLAIN ANALYZE INSERT INTO VALUES UPDATE SET DELETE
		MERGE REPLACE CREATE ALTER DROP TRUNCATE RENAME TABLE VIEW SHOW DESCRIBE ASC PRAGMA FOR SHARE
		LOCK UNLOCK OVER PARTITION WINDOW FILTER WITHIN LATERAL RETURNING TRUE FALSE INTERVAL COLLATE ANY
		SOME NULLS TIES ROLLUP CUBE GROUPING SETS BEGIN COMMIT ROLLBACK SAVEPOINT GRANT REVOKE COPY LOAD
		CALL EXECUTE PREPARE DEALLOCATE OUTFILE DUMPFILE PROCEDURE STRAIGHT_JOIN SEPARATOR FORCE IGNORE
		PRECEDING FOLLOWING UNBOUNDED CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER
		SESSION_USER LOCALTIME LOCALTIMESTAMP MATERIALIZED TABLESAMPLE QUALIFY NOWAIT HIGH_PRIORITY
		SQL_CALC_FOUND_ROWS SQL_NO_CACHE ATTACH DETACH VACUUM REINDEX HANDLER KILL OPTIMIZE`) {
		m[w] = true
	}
	return m
}()

// Shape replaces the literals, identifiers and comments of sql by markers
// and keeps its keywords, known function names and punctuation, one token
// per space. It reads any text, valid SQL or not, and never returns a
// byte of a literal, an identifier or a comment.
func Shape(sql string) string {
	var out []string
	size := 0
	emit := func(tok string) bool {
		if size+len(tok)+1 > MaxShape {
			out = append(out, mCut)
			return false
		}
		out = append(out, tok)
		size += len(tok) + 1
		return true
	}
	s := sql
	for i := 0; i < len(s); {
		c := s[i]
		var tok string
		next := i + 1
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' || c < 0x20 || c == 0x7f:
			i++
			continue
		case c == '-' && at(s, i+1) == '-', c == '#':
			tok, next = mLineCmt, lineEnd(s, i)
		case c == '/' && at(s, i+1) == '*':
			tok, next = mBlockCmt, blockEnd(s, i+2)
		case c == '\'':
			tok, next = mString, quoteEnd(s, i+1, '\'', true)
		case c == '"':
			tok, next = mQuoted, quoteEnd(s, i+1, '"', true)
		case c == '`':
			tok, next = mBackquoted, quoteEnd(s, i+1, '`', false)
		case c == '[':
			// SQLite's [name], or an array subscript: either way no text
			// of it is kept.
			if j := strings.IndexByte(s[i+1:], ']'); j >= 0 && !strings.ContainsAny(s[i+1:i+1+j], "[\n") {
				tok, next = mBracketed, i+1+j+1
			} else {
				tok = "["
			}
		case c == '$' && isDigit(at(s, i+1)):
			next = i + 1
			for next < len(s) && isDigit(s[next]) {
				next++
			}
			tok = mParam
		case c == '$':
			tok, next = dollar(s, i)
		case isDigit(c) || c == '.' && isDigit(at(s, i+1)):
			next = i + 1
			for next < len(s) && (isWordByte(s[next]) || s[next] == '.' ||
				(s[next] == '+' || s[next] == '-') && (s[next-1] == 'e' || s[next-1] == 'E')) {
				next++
			}
			tok = mNumber
		case isWordStart(c):
			next = i + 1
			for next < len(s) && isWordByte(s[next]) {
				next++
			}
			word := strings.ToUpper(s[i:next])
			switch {
			case next-i <= 2 && at(s, next) == '\'' && strings.ContainsAny(word[:1], "EXBNU"):
				// A string prefix: E'..', X'..', B'..', N'..'.
				tok, next = mString, quoteEnd(s, next+1, '\'', true)
			case keywords[word]:
				tok = word
			case knownFunction(word) && at(s, skipSpace(s, next)) == '(':
				tok = word
			default:
				tok = mIdent
			}
		case strings.IndexByte(punct, c) >= 0:
			tok = string(c)
		default:
			tok = mIdent // any other byte: dropped as a name would be
		}
		if !emit(tok) {
			break
		}
		i = next
	}
	return strings.Join(out, " ")
}

func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isWordStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= 0x80
}
func isWordByte(c byte) bool { return isWordStart(c) || isDigit(c) || c == '$' }

func skipSpace(s string, i int) int {
	for i < len(s) && strings.IndexByte(" \t\n\r\f\v", s[i]) >= 0 {
		i++
	}
	return i
}

func lineEnd(s string, i int) int {
	if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
		return i + j + 1
	}
	return len(s)
}

func blockEnd(s string, i int) int {
	if j := strings.Index(s[i:], "*/"); j >= 0 {
		return i + j + 2
	}
	return len(s)
}

// quoteEnd is the end of a quoted token whose text starts at i: a doubled
// quote escapes itself, and with backslash a backslash escapes the next
// byte. An unterminated token runs to the end.
func quoteEnd(s string, i int, q byte, backslash bool) int {
	for i < len(s) {
		switch {
		case backslash && s[i] == '\\':
			i += 2
		case s[i] == q && at(s, i+1) == q:
			i += 2
		case s[i] == q:
			return i + 1
		default:
			i++
		}
	}
	return len(s)
}

// dollar shapes a token starting with '$' at i: a $tag$...$tag$ string,
// or a lone '$'.
func dollar(s string, i int) (string, int) {
	j := i + 1
	for j < len(s) && (isWordStart(s[j]) && s[j] < 0x80 || isDigit(s[j])) {
		j++
	}
	if at(s, j) != '$' {
		return "$", i + 1
	}
	tag := s[i : j+1]
	if k := strings.Index(s[j+1:], tag); k >= 0 {
		return mDollar, j + 1 + k + len(tag)
	}
	return mDollar, len(s)
}
