// Package refusal names why locksql refused a statement. Every refusal
// carries a stable code an agent can act on, the place of the statement it
// points at when one is known, and a rewrite hint.
//
// A refusal never carries more than the agent could already see: the
// reason and the hint are written by locksql (never the database's text),
// and the token of a span is a word or a punctuation sign of the agent's
// own statement, never a literal.
package refusal

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Code is a stable refusal code. Codes are part of the client protocol
// and of the agent instructions: never rename one.
type Code string

// The refusal codes. docs/usage.md describes each one.
const (
	// Parsing and statement shape.
	UnsupportedSyntax Code = "E_UNSUPPORTED_SYNTAX"
	MultiStatement    Code = "E_MULTI_STATEMENT"
	ForbiddenToken    Code = "E_FORBIDDEN_TOKEN"
	StatementKind     Code = "E_STATEMENT_KIND"
	InvalidSQL        Code = "E_INVALID_SQL"
	UnknownName       Code = "E_UNKNOWN_NAME"
	TooComplex        Code = "E_TOO_COMPLEX"
	Size              Code = "E_SIZE"
	// Constructs refused at every tier.
	Forbidden    Code = "E_FORBIDDEN"
	Function     Code = "E_FUNCTION"
	SystemObject Code = "E_SYSTEM_OBJECT"
	// Limits and policy.
	NoLimit           Code = "E_NO_LIMIT"
	LimitTooHigh      Code = "E_LIMIT_TOO_HIGH"
	Tier              Code = "E_TIER"
	DatabaseNotServed Code = "E_DATABASE_NOT_SERVED"
	UnmaskOff         Code = "E_UNMASK_OFF"
	Cost              Code = "E_COST"
	// KAnon is no longer emitted (v0.5.2): a k-anonymity count under k
	// is a warning on the approval screen. The code stays known so that
	// past audit records keep it, and is never reused.
	//
	// Deprecated: no refusal carries it.
	KAnon            Code = "E_K_ANON"
	Engine           Code = "E_ENGINE"
	Placeholder      Code = "E_PLACEHOLDER"
	MaskedFilter     Code = "E_MASKED_FILTER"
	MaskedExpression Code = "E_MASKED_EXPRESSION"
	MaskedOrder      Code = "E_MASKED_ORDER"
	MaskedSetOp      Code = "E_MASKED_SET_OP"
	MaskUncertain    Code = "E_MASK_UNCERTAIN"
	MaskedWrite      Code = "E_MASKED_WRITE"
	// Policy is the fail-closed code of a refusal no check named: it
	// should never be seen, and is a bug to report.
	Policy Code = "E_POLICY"
)

// Retry is what an agent may do after a refusal.
type Retry string

const (
	// RetryRewrite: the statement can be fixed. Rewrite it as the hint
	// says and plan it again; the console checks the new one in full.
	RetryRewrite Retry = "rewrite"
	// RetryAskUser: only the human can lift this. Tell the user;
	// locksql_request_change may queue a proposal.
	RetryAskUser Retry = "ask_user"
	// RetryStop: final for this question. Tell the user; do not reword,
	// split or retry it.
	RetryStop Retry = "stop"
)

type entry struct {
	retry Retry
	title string
	hint  string
}

// retired codes are no longer emitted: they stay known for past audit
// records, and Codes leaves them out.
var retired = map[Code]bool{KAnon: true}

var table = map[Code]entry{
	UnsupportedSyntax: {RetryRewrite, "a construct locksql cannot parse with certainty",
		"rewrite it with plainer SQL: standard operators and functions, a subquery or a CTE instead of the construct"},
	MultiStatement: {RetryRewrite, "more than one statement",
		"send one statement per plan, without ';' chaining"},
	ForbiddenToken: {RetryRewrite, "a comment, variable, bind parameter, backslash or escape",
		"remove comments and variables; write values as literals, or as '${name}' placeholders compared with a PII column"},
	StatementKind: {RetryRewrite, "a statement kind this path does not run",
		"send SELECT, WITH ... SELECT or EXPLAIN SELECT; list and describe tables with locksql_list_tables and locksql_describe"},
	InvalidSQL: {RetryRewrite, "an invalid statement (column counts, aliases, positions, clauses)",
		"fix the statement as the message says"},
	UnknownName: {RetryRewrite, "an unknown or ambiguous table, column or database",
		"check the names with locksql_list_tables and locksql_describe; qualify an ambiguous table with its schema"},
	TooComplex: {RetryRewrite, "a statement nested too deeply to analyse",
		"simplify the statement: fewer nesting levels and CTE steps"},
	Size: {RetryRewrite, "a statement that could build an oversized value",
		"select the columns as they are, without building large strings (REPEAT, LPAD, wide concatenations, growing recursive CTEs)"},
	Forbidden: {RetryStop, "a construct refused at every tier (files, locks, transactions, session or server control, credentials, sequences)",
		"do not look for another way to get the same effect; tell the user"},
	Function: {RetryRewrite, "a function outside the allowlist",
		"use a function from the allowlist (see docs/usage.md), or select the column and let the user read it"},
	SystemObject: {RetryRewrite, "a system catalog, statement history or session metadata",
		"use locksql_list_tables and locksql_describe for metadata; system relations and session functions are never read"},
	NoLimit: {RetryRewrite, "a top-level LIMIT is missing or malformed",
		"end the statement with LIMIT n (n at most limits.max_rows; LIMIT 1 for an aggregate)"},
	LimitTooHigh: {RetryRewrite, "a LIMIT above limits.max_rows",
		"lower the LIMIT to limits.max_rows or less (locksql_status shows it)"},
	Tier: {RetryAskUser, "a statement class above the profile tier",
		"only the human can raise the tier: tell the user (locksql_request_change queues a proposal)"},
	DatabaseNotServed: {RetryAskUser, "a database this profile does not serve",
		"use a database listed by locksql_status, or ask the user"},
	UnmaskOff: {RetryAskUser, "unmasked output is off in this console",
		"run the query masked, or ask the user to allow unmasked output in the console (:unmask, or --allow-unmask at start)"},
	Cost: {RetryRewrite, "the weight check refused the plan",
		"make it cheaper: filter on an indexed column, narrow the range, join less; or ask the user to raise limits.explain_rows_refuse"},
	KAnon: {RetryStop, "no longer emitted since v0.5.2 (was: fewer than k rows behind a PII filter, group or aggregate)",
		"none: k-anonymity counts are a warning for the human now; tell the user"},
	Engine: {RetryStop, "the database could not plan or run a check; the details stay on the console",
		"tell the user: the human sees the database's message in the console"},
	Placeholder: {RetryRewrite, "a misused placeholder or cell reference",
		"compare a PII column with a placeholder in the WHERE or HAVING of a read: col = '${name}' or col IN ('${a}', '${b}')"},
	MaskedFilter: {RetryRewrite, "a PII column filtered or joined other than by equality",
		"filter on a non-PII key, or compare the PII column with =, IN (literals or placeholders) or IS NULL, under AND only"},
	MaskedExpression: {RetryRewrite, "a function or expression over a PII column",
		"select the PII column plainly (it comes back masked), or COUNT, MIN or MAX it"},
	MaskedOrder: {RetryRewrite, "a PII column that orders, groups or partitions rows",
		"order, group or partition by a non-PII column"},
	MaskedSetOp: {RetryRewrite, "a set operation that compares a PII column with other values",
		"combine PII columns only with other PII columns, with UNION ALL and without DISTINCT"},
	MaskUncertain: {RetryRewrite, "a result whose masking could not be proven",
		"select PII columns by their plain name, without alias, expression or whole-row reference"},
	MaskedWrite: {RetryStop, "a write that copies a PII column or stores a chosen value in one",
		"a masked column may only be set to NULL or DEFAULT; tell the user"},
	Policy: {RetryStop, "refused by the policy (no more specific code: please report it)",
		"tell the user"},
}

// Codes lists every code a refusal may carry, sorted; retired codes are
// left out.
func Codes() []Code {
	out := make([]Code, 0, len(table))
	for c := range table {
		if !retired[c] {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// Known reports whether c is a defined code.
func (c Code) Known() bool { _, ok := table[c]; return ok }

// Retry is what an agent may do after a refusal with code c.
func (c Code) Retry() Retry {
	if e, ok := table[c]; ok {
		return e.retry
	}
	return RetryStop
}

// Title is a short description of the refusals of code c.
func (c Code) Title() string { return table[c].title }

// Hint is the default rewrite hint of code c.
func (c Code) Hint() string { return table[c].hint }

// MaxToken bounds the token of a span, in bytes.
const MaxToken = 40

// Span is where a refusal points in the statement the agent sent: line
// and column count from 1, the column in characters.
type Span struct {
	Line  int    `json:"line"`
	Col   int    `json:"col"`
	Token string `json:"token,omitempty"`
}

// Info is the structured form of a refusal, sent to clients next to the
// prose message.
type Info struct {
	Code  Code   `json:"code"`
	Retry Retry  `json:"retry"`
	Hint  string `json:"hint,omitempty"`
	Span  *Span  `json:"span,omitempty"`
}

// Error is a refused statement. Reason is the prose message; it never
// quotes a literal of the statement nor any text from the database.
type Error struct {
	Code   Code
	Reason string
	// Hint overrides the code's default hint.
	Hint string
	// Pos is the byte offset, in the text the check read, of what the
	// refusal points at; -1 when unknown. Token is the word or
	// punctuation sign found there, "" for a literal or a quoted name.
	Pos   int
	Token string
	// Secret marks a statement that may carry a secret (a password): its
	// literals must not be recorded.
	Secret bool
}

func (e *Error) Error() string { return e.Reason }

// New returns a refusal without position.
func New(code Code, reason string) *Error { return &Error{Code: code, Reason: reason, Pos: -1} }

// Newf is New with a formatted reason.
func Newf(code Code, format string, args ...any) *Error {
	return New(code, fmt.Sprintf(format, args...))
}

// WithHint sets the rewrite hint and returns e.
func (e *Error) WithHint(hint string) *Error { e.Hint = hint; return e }

// At sets the position and the token and returns e. Pass "" as the token
// of a literal or a quoted name.
func (e *Error) At(pos int, token string) *Error { e.Pos, e.Token = pos, token; return e }

// Shift moves a known position by off bytes, when the text the check
// read starts off bytes into a larger one.
func (e *Error) Shift(off int) {
	if e.Pos >= 0 {
		e.Pos += off
	}
}

// From returns the refusal err is or wraps. An error without a known code
// is still a refusal (fail closed), under the Policy code.
func From(err error) *Error {
	var r *Error
	if errors.As(err, &r) && r.Code.Known() {
		return r
	}
	if r != nil {
		c := *r
		c.Code = Policy
		return &c
	}
	return New(Policy, err.Error())
}

// Info is the structured form of e. src is the statement the agent sent
// and base the offset in src of the text e's position counts in. A
// position outside src, or inside a character, gives no span.
func (e *Error) Info(src string, base int) Info {
	in := Info{Code: e.Code, Retry: e.Code.Retry(), Hint: e.Hint}
	if !e.Code.Known() {
		in.Code, in.Retry = Policy, Policy.Retry()
	}
	if in.Hint == "" {
		in.Hint = in.Code.Hint()
	}
	if e.Pos < 0 {
		return in
	}
	pos := base + e.Pos
	if pos < 0 || pos > len(src) || (pos < len(src) && !utf8.RuneStart(src[pos])) {
		return in
	}
	head := src[:pos]
	line := 1 + strings.Count(head, "\n")
	col := 1 + utf8.RuneCountInString(head[strings.LastIndexByte(head, '\n')+1:])
	tok := e.Token
	if n := len(tok); n > 0 && pos+n <= len(src) && strings.EqualFold(src[pos:pos+n], tok) {
		tok = src[pos : pos+n] // as written, not as folded by the lexer
	}
	in.Span = &Span{Line: line, Col: col, Token: cleanToken(tok)}
	return in
}

// cleanToken bounds a token and drops one holding a control or format
// character.
func cleanToken(t string) string {
	for _, r := range t {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ""
		}
	}
	if len(t) <= MaxToken {
		return t
	}
	cut := MaxToken
	for cut > 0 && !utf8.RuneStart(t[cut]) {
		cut--
	}
	return t[:cut]
}
