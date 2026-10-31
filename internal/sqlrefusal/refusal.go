// Package sqlrefusal holds locksql's refusal codes, registered with
// lockkit's refusal package, and re-exports that package so call sites
// import one name. Every refusal carries a stable code an agent can act
// on, the place of the statement it points at when one is known, and a
// rewrite hint.
//
// A refusal never carries more than the agent could already see: the
// reason and the hint are written by locksql (never the database's text),
// and the token of a span is a word or a punctuation sign of the agent's
// own statement, never a literal.
package sqlrefusal

import "github.com/DavidGodefroid/lockkit/refusal"

// The types and functions of lockkit's refusal package.
type (
	Code  = refusal.Code
	Retry = refusal.Retry
	Span  = refusal.Span
	Info  = refusal.Info
	Error = refusal.Error
)

const (
	RetryRewrite = refusal.RetryRewrite
	RetryAskUser = refusal.RetryAskUser
	RetryStop    = refusal.RetryStop
	MaxToken     = refusal.MaxToken
)

var (
	New   = refusal.New
	Newf  = refusal.Newf
	From  = refusal.From
	Codes = refusal.Codes
)

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
	// Stale: what the statement resolves to on the server (functions,
	// views, rules, triggers, policies, grants, search path) changed since
	// the plan: the plan hash no longer matches.
	Stale Code = "E_STALE"
	// Policy is the fail-closed code of a refusal no check named: it
	// should never be seen, and is a bug to report. lockkit defines it.
	Policy Code = refusal.Policy
)

// table describes locksql's codes; init registers them.
var table = map[Code]struct {
	retry       Retry
	title, hint string
}{
	UnsupportedSyntax: {RetryRewrite, "a construct locksql cannot parse with certainty",
		"rewrite it with plainer SQL: standard operators and functions, a subquery or a CTE instead of the construct"},
	MultiStatement: {RetryRewrite, "more than one statement",
		"send one statement per plan, without ';' chaining"},
	ForbiddenToken: {RetryRewrite, "a comment, variable, bind parameter, backslash or escape",
		"remove comments and variables; write values as literals"},
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
	Placeholder: {RetryRewrite, "a placeholder or cell reference ('${...}'), which is not supported",
		"write the statement without '${...}': requests are decided in lockhub, where no value is typed; masked cells come back as <redacted>, without a reference"},
	MaskedFilter: {RetryRewrite, "a PII column filtered or joined other than by equality",
		"filter on a non-PII key, or compare the PII column with =, IN (literals) or IS NULL, under AND only"},
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
	Stale: {RetryRewrite, "the database objects the statement uses changed since the plan",
		"plan the statement again (locksql_plan): the human approves the new plan"},
}

func init() {
	for c, e := range table {
		refusal.Register(c, e.retry, e.title, e.hint)
	}
	// KAnon stays known for the audit records that carry it.
	refusal.Retire(KAnon)
}
