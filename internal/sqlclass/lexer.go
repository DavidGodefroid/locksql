package sqlclass

import (
	"strings"
)

// TokKind is the lexical kind of a token.
type TokKind int

// Token kinds.
const (
	TokWord        TokKind = iota // keyword or unquoted identifier; Text is upper-cased
	TokNumber                     // numeric literal (or a MySQL identifier starting with a digit); Text is upper-cased
	TokString                     // string literal, E'' string or $tag$ body; Text is the raw source with quotes
	TokQuotedIdent                // quoted identifier: "x" (PG, SQLite), `x` (MySQL, SQLite), [x] (SQLite); Text is raw
	TokPunct                      // a single punctuation or operator character
)

// Token is one lexical unit. Depth is the parenthesis depth: an opening
// parenthesis carries the depth it opens, a closing one the depth it returns
// to, so a top-level token has Depth 0.
type Token struct {
	Kind  TokKind
	Text  string
	Depth int
}

// Name returns the identifier a word or quoted identifier names, folded to
// upper case for comparisons. It returns "" for other kinds.
func (t Token) Name() string {
	switch t.Kind {
	case TokWord:
		return t.Text
	case TokQuotedIdent:
		if len(t.Text) < 2 {
			return ""
		}
		open, body := t.Text[0], t.Text[1:len(t.Text)-1]
		if open != '[' {
			q := string(open)
			body = strings.ReplaceAll(body, q+q, q)
		}
		return fold(body)
	}
	return ""
}

// nameIn is Name, plus the MySQL double-quoted token: the lexer reads it as a
// string, but a server whose sql_mode contains ANSI_QUOTES (or ANSI) reads it
// as an identifier. Use it wherever a name must be caught whatever the
// server's sql_mode (forbidden calls, guarded settings); a false match only
// makes locksql refuse more.
func (t Token) nameIn(d Dialect) string {
	if d == MySQL && t.Kind == TokString && len(t.Text) >= 2 && t.Text[0] == '"' {
		return fold(strings.ReplaceAll(t.Text[1:len(t.Text)-1], `""`, `"`))
	}
	return t.Name()
}

// fold upper-cases s for keyword and name comparisons. Lower-casing first
// also folds characters such as the Kelvin sign (U+212A) that servers with
// case-insensitive collations treat as their ASCII letter; upper-casing then
// maps the long s (U+017F) to S. A false match only makes locksql refuse more.
func fold(s string) string {
	return strings.ToUpper(strings.ToLower(s))
}

// Lex splits sql into tokens using the quoting rules of the dialect. It
// refuses (with a *Refusal) comments, variables, assignments, bind parameters,
// backslashes outside PostgreSQL E” strings, unterminated quotes and
// unbalanced parentheses.
func Lex(d Dialect, sql string) ([]Token, error) {
	l := lexer{d: d, s: sql}
	return l.run()
}

type lexer struct {
	d      Dialect
	s      string
	i      int
	depth  int
	tokens []Token
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isIdentStart reports whether c can start an unquoted identifier. Bytes of
// non-ASCII characters are identifier characters in all three engines.
func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= 0x80
}

// isIdentChar reports whether c can continue an unquoted identifier.
func isIdentChar(c byte) bool {
	return isIdentStart(c) || isDigit(c) || c == '$'
}

func (l *lexer) peek(off int) byte {
	if l.i+off < len(l.s) {
		return l.s[l.i+off]
	}
	return 0
}

func (l *lexer) emit(kind TokKind, text string) {
	l.tokens = append(l.tokens, Token{Kind: kind, Text: text, Depth: l.depth})
}

const errBackslash = "backslashes are not allowed outside PostgreSQL E'' strings (escape quotes by doubling them)"

func (l *lexer) run() ([]Token, error) {
	for l.i < len(l.s) {
		c := l.s[l.i]
		switch {
		case isSpace(c):
			l.i++
		case c == '\\':
			return nil, refuse(errBackslash)
		case c == '-' && l.peek(1) == '-', c == '/' && l.peek(1) == '*', c == '*' && l.peek(1) == '/':
			return nil, refuse("comments are not allowed")
		case c == '#' && l.d != Postgres:
			// '#' starts a comment in MySQL; SQLite has no use for it. In
			// PostgreSQL it is the XOR operator.
			return nil, refuse("comments are not allowed ('#')")
		case c == ':' && l.peek(1) == '=':
			return nil, refuse("assignments (:=) are not allowed")
		case c == '@' && l.d == MySQL && l.accountAt():
			// MySQL account names: 'user'@'host', `user`@`host`.
			l.emit(TokPunct, "@")
			l.i++
		case c == '@':
			// PostgreSQL has @-operators (@>, <@, @@, @ for abs); an '@'
			// directly followed by a name is a variable everywhere else.
			if l.d != Postgres || isIdentChar(l.peek(1)) || l.peek(1) == '"' {
				return nil, refuse("user and system variables (@) are not allowed")
			}
			l.emit(TokPunct, "@")
			l.i++
		case c == '?' && l.d != Postgres:
			// In PostgreSQL '?' is a jsonb operator.
			return nil, refuse("bind parameters (?) are not allowed")
		case c == ':' && l.d == SQLite && isIdentStart(l.peek(1)):
			return nil, refuse("bind parameters (:name) are not allowed")
		case c == '$' && l.d == Postgres:
			if err := l.dollar(); err != nil {
				return nil, err
			}
		case c == '$' && l.d == SQLite:
			return nil, refuse("bind parameters ($name) are not allowed")
		case c == '\'':
			if err := l.quoted('\'', '\'', TokString, false); err != nil {
				return nil, err
			}
		case c == '"':
			kind := TokQuotedIdent
			if l.d == MySQL {
				kind = TokString // without ANSI_QUOTES, "x" is a string in MySQL
			}
			if err := l.quoted('"', '"', kind, false); err != nil {
				return nil, err
			}
		case c == '`' && l.d != Postgres:
			if err := l.quoted('`', '`', TokQuotedIdent, false); err != nil {
				return nil, err
			}
		case c == '[' && l.d == SQLite:
			if err := l.quoted('[', ']', TokQuotedIdent, false); err != nil {
				return nil, err
			}
		case l.d == Postgres && (c == 'E' || c == 'e') && l.peek(1) == '\'':
			l.i++ // the E prefix stays in the token text
			start := l.i - 1
			if err := l.quoted('\'', '\'', TokString, true); err != nil {
				return nil, err
			}
			l.tokens[len(l.tokens)-1].Text = l.s[start:l.i]
		case isDigit(c) || c == '.' && isDigit(l.peek(1)):
			if err := l.number(); err != nil {
				return nil, err
			}
		case isIdentStart(c) || c == '$' && l.d == MySQL:
			j := l.i
			for j < len(l.s) && isIdentChar(l.s[j]) {
				j++
			}
			l.emit(TokWord, fold(l.s[l.i:j]))
			l.i = j
		case c == '&' && l.d == Postgres && l.i > 0 && (l.s[l.i-1] == 'U' || l.s[l.i-1] == 'u') &&
			(l.peek(1) == '"' || l.peek(1) == '\''):
			// U&"..." and U&'...' carry Unicode escapes, and UESCAPE can
			// pick any escape character: U&"pg_sl!0065ep" UESCAPE '!' names
			// pg_sleep. Refused rather than decoded.
			return nil, refuse("Unicode escapes (U&\"...\" or U&'...') are not allowed")
		default:
			switch c {
			case '(':
				l.depth++
			case ')':
				l.depth--
				if l.depth < 0 {
					return nil, refuse("unbalanced parentheses")
				}
			}
			l.emit(TokPunct, string(c))
			l.i++
		}
	}
	if l.depth != 0 {
		return nil, refuse("unbalanced parentheses")
	}
	return l.tokens, nil
}

// quoted lexes a quoted token from l.i (the opening quote) to the closing
// quote. A doubled closing quote escapes itself. With backslashEscapes
// (PostgreSQL E” strings) a backslash escapes the next byte; otherwise a
// backslash is refused, except inside SQLite [brackets], which have no
// escape and hold it as a plain character.
func (l *lexer) quoted(open, close byte, kind TokKind, backslashEscapes bool) error {
	start := l.i
	j := l.i + 1
	for {
		if j >= len(l.s) {
			return refuse("unterminated quoted literal or identifier")
		}
		c := l.s[j]
		switch {
		case c == '\\' && backslashEscapes:
			j += 2
			continue
		case c == '\\' && open != '[':
			return refuse(errBackslash)
		case c == close:
			if open != '[' && j+1 < len(l.s) && l.s[j+1] == close {
				j += 2
				continue
			}
			l.i = j + 1
			l.emit(kind, l.s[start:l.i])
			return nil
		}
		j++
	}
}

// dollar lexes a PostgreSQL token starting with '$': a $tag$...$tag$ string
// (tag [A-Za-z_][A-Za-z0-9_]* or empty) or a positional parameter, which is
// refused.
func (l *lexer) dollar() error {
	j := l.i + 1
	if j < len(l.s) && isDigit(l.s[j]) {
		return refuse("bind parameters ($n) are not allowed")
	}
	if j < len(l.s) && (isASCIILetter(l.s[j]) || l.s[j] == '_') {
		for j < len(l.s) && (isASCIILetter(l.s[j]) || isDigit(l.s[j]) || l.s[j] == '_') {
			j++
		}
	}
	if j >= len(l.s) || l.s[j] != '$' {
		return refuse("unexpected '$' (only $tag$ quoting is allowed)")
	}
	delim := l.s[l.i : j+1]
	end := strings.Index(l.s[j+1:], delim)
	if end < 0 {
		return refuse("unterminated dollar-quoted string")
	}
	stop := j + 1 + end + len(delim)
	l.emit(TokString, l.s[l.i:stop])
	l.i = stop
	return nil
}

// accountAt reports whether the '@' at l.i joins the two quoted halves of a
// MySQL account name: it directly follows a quoted token, with no blank in
// between, and is directly followed by a quote. Unquoted user@host is refused
// with the variables, since it cannot be told apart from one.
func (l *lexer) accountAt() bool {
	if len(l.tokens) == 0 || l.i == 0 {
		return false
	}
	prev := l.tokens[len(l.tokens)-1]
	if prev.Kind != TokString && prev.Kind != TokQuotedIdent {
		return false
	}
	before, after := l.s[l.i-1], l.peek(1)
	return (before == '\'' || before == '"' || before == '`') && (after == '\'' || after == '"' || after == '`')
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// number lexes a numeric literal: digits with an optional fraction. Any
// identifier characters that follow (exponent, 0x1F, a MySQL name such as
// 1abc) stay in the same token; the sign of an exponent becomes punctuation.
//
// In PostgreSQL '$' is not an identifier start, so 1$$ and 1e3$$ are a
// number then a dollar quote. When other trailing identifier characters
// come first, servers disagree: PostgreSQL 13 and 14 end the number there
// and read the rest as an identifier, which then takes the '$' (1x0$$ is
// the integer 1 and the identifier x0$$), while 15+ reject the trailing
// junk. Such a token directly followed by '$' is refused, since locksql
// cannot tell whether a dollar quote opens there.
func (l *lexer) number() error {
	j := l.i
	for j < len(l.s) && isDigit(l.s[j]) {
		j++
	}
	if j < len(l.s) && l.s[j] == '.' {
		j++
		for j < len(l.s) && isDigit(l.s[j]) {
			j++
		}
	}
	if l.d == Postgres {
		if j+1 < len(l.s) && (l.s[j] == 'e' || l.s[j] == 'E') && isDigit(l.s[j+1]) {
			j += 2
			for j < len(l.s) && isDigit(l.s[j]) {
				j++
			}
		}
		junk := j
		for j < len(l.s) && isIdentChar(l.s[j]) && l.s[j] != '$' {
			j++
		}
		if j > junk && j < len(l.s) && l.s[j] == '$' {
			return refuse("a number directly followed by letters and '$' is ambiguous in PostgreSQL; add a space")
		}
	} else {
		for j < len(l.s) && isIdentChar(l.s[j]) {
			j++
		}
	}
	l.emit(TokNumber, fold(l.s[l.i:j]))
	l.i = j
	return nil
}
