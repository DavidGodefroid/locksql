package sqlast

import (
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// Functions are allowed by name, per dialect: a function missing from the
// allowlist is refused, whatever it does. The lists hold pure functions on
// values (strings, numbers, dates, JSON, conditionals) and the usual
// aggregates and window functions. Nothing that reads files, opens
// connections, sleeps, locks, changes the session or reads server, session
// or catalog metadata is listed.

// aggregates are the aggregate functions; their arguments are values of
// many rows. countAggs only count rows; identityAggs return one of the
// values they aggregate.
var (
	countAggs    = newSet("COUNT")
	identityAggs = newSet("MIN", "MAX", "ANY_VALUE")
	aggregates   = newSet("COUNT", "MIN", "MAX", "SUM", "AVG", "ANY_VALUE", "GROUP_CONCAT", "STRING_AGG",
		"ARRAY_AGG", "STDDEV", "STDDEV_POP", "STDDEV_SAMP", "VARIANCE", "VAR_POP", "VAR_SAMP", "STD",
		"BIT_AND", "BIT_OR", "BIT_XOR", "BOOL_AND", "BOOL_OR", "EVERY", "TOTAL", "JSON_AGG", "JSONB_AGG",
		"JSON_ARRAYAGG", "JSON_GROUP_ARRAY", "JSON_OBJECT_AGG", "JSONB_OBJECT_AGG", "JSON_OBJECTAGG",
		"JSON_GROUP_OBJECT")
	// windowOnly are window functions that are not aggregates.
	windowOnly = newSet("ROW_NUMBER", "RANK", "DENSE_RANK", "PERCENT_RANK", "CUME_DIST", "NTILE", "LAG",
		"LEAD", "FIRST_VALUE", "LAST_VALUE", "NTH_VALUE")
)

// commonFuncs are allowed in every dialect.
var commonFuncs = newSet(
	// Strings.
	"LOWER", "UPPER", "LENGTH", "CHAR_LENGTH", "CHARACTER_LENGTH", "OCTET_LENGTH", "SUBSTRING", "SUBSTR",
	"TRIM", "LTRIM", "RTRIM", "REPLACE", "CONCAT", "CONCAT_WS", "LEFT", "RIGHT", "LPAD", "RPAD", "REVERSE",
	"POSITION", "INSTR", "REPEAT", "INITCAP", "ASCII", "CHR", "CHAR", "HEX", "UNHEX", "FORMAT",
	// Conditionals.
	"COALESCE", "NULLIF", "IFNULL", "IF", "IIF", "GREATEST", "LEAST", "NVL",
	// Numbers.
	"ABS", "ROUND", "FLOOR", "CEIL", "CEILING", "MOD", "POWER", "POW", "SQRT", "SIGN", "TRUNC", "TRUNCATE",
	"EXP", "LN", "LOG", "LOG10", "LOG2", "PI", "DEGREES", "RADIANS", "SIN", "COS", "TAN", "ASIN", "ACOS",
	"ATAN", "ATAN2", "COT", "DIV",
	// Dates and times.
	"NOW", "EXTRACT", "DATE", "TIME", "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND", "INTERVAL",
)

var dialectFuncs = map[sqlclass.Dialect]set{
	sqlclass.MySQL: newSet(
		"LOCATE", "MID", "LCASE", "UCASE", "FIELD", "FIND_IN_SET", "ELT", "SPACE", "STRCMP", "SUBSTRING_INDEX",
		"CURDATE", "CURTIME", "SYSDATE", "UTC_DATE", "UTC_TIME", "UTC_TIMESTAMP", "DATE_FORMAT", "DATE_ADD",
		"DATE_SUB", "ADDDATE", "SUBDATE", "ADDTIME", "SUBTIME", "DATEDIFF", "TIMEDIFF", "TIMESTAMPDIFF",
		"TIMESTAMPADD", "DAYOFWEEK", "DAYOFMONTH", "DAYOFYEAR", "DAYNAME", "MONTHNAME", "WEEK", "WEEKDAY",
		"WEEKOFYEAR", "QUARTER", "YEARWEEK", "LAST_DAY", "MAKEDATE", "MAKETIME", "STR_TO_DATE",
		"FROM_UNIXTIME", "UNIX_TIMESTAMP", "FROM_DAYS", "TO_DAYS", "TO_SECONDS", "SEC_TO_TIME", "TIME_TO_SEC",
		"CONVERT_TZ", "TIMESTAMP", "MICROSECOND", "PERIOD_ADD", "PERIOD_DIFF", "RAND", "CRC32", "CONV",
		"BIN", "OCT", "JSON_EXTRACT", "JSON_UNQUOTE", "JSON_VALUE", "JSON_CONTAINS", "JSON_CONTAINS_PATH",
		"JSON_LENGTH", "JSON_KEYS", "JSON_TYPE", "JSON_VALID", "JSON_OBJECT", "JSON_ARRAY", "JSON_QUOTE",
		"JSON_SEARCH", "JSON_DEPTH",
	),
	sqlclass.Postgres: newSet(
		"STRPOS", "SPLIT_PART", "BTRIM", "TRANSLATE", "STARTS_WITH", "REGEXP_REPLACE", "REGEXP_MATCH",
		"TO_CHAR", "TO_DATE", "TO_TIMESTAMP", "TO_NUMBER", "DATE_TRUNC", "DATE_PART", "AGE", "MAKE_DATE",
		"MAKE_TIME", "MAKE_TIMESTAMP", "MAKE_INTERVAL", "JUSTIFY_DAYS", "JUSTIFY_HOURS", "JUSTIFY_INTERVAL",
		"ISFINITE", "CLOCK_TIMESTAMP", "STATEMENT_TIMESTAMP", "TRANSACTION_TIMESTAMP", "TIMEOFDAY",
		"WIDTH_BUCKET", "CBRT", "RANDOM", "GCD", "LCM", "SCALE", "NUM_NONNULLS", "NUM_NULLS",
		"JSONB_EXTRACT_PATH", "JSONB_EXTRACT_PATH_TEXT", "JSON_EXTRACT_PATH", "JSON_EXTRACT_PATH_TEXT",
		"JSONB_TYPEOF", "JSON_TYPEOF", "JSONB_ARRAY_LENGTH", "JSON_ARRAY_LENGTH", "JSONB_BUILD_OBJECT",
		"JSON_BUILD_OBJECT", "JSONB_BUILD_ARRAY", "JSON_BUILD_ARRAY", "TO_JSON", "TO_JSONB", "JSONB_PRETTY",
		"ARRAY_LENGTH", "CARDINALITY",
	),
	sqlclass.SQLite: newSet(
		"STRFTIME", "DATETIME", "JULIANDAY", "UNIXEPOCH", "TIMEDIFF", "PRINTF", "UNICODE", "ZEROBLOB",
		"TYPEOF", "LIKELIHOOD", "LIKELY", "UNLIKELY", "RANDOM", "JSON", "JSON_EXTRACT", "JSON_ARRAY",
		"JSON_OBJECT", "JSON_TYPE", "JSON_VALID", "JSON_ARRAY_LENGTH", "JSON_QUOTE",
	),
}

// maxSizeArg caps the length argument of the functions that build a value
// of a given size: the result is allocated per cell, and an EXPLAIN plan
// does not show its cost.
const maxSizeArg = 65536

// sizeArg is, per size function, the index of its length argument.
var sizeArg = map[string]int{"REPEAT": 1, "LPAD": 1, "RPAD": 1, "SPACE": 0, "ZEROBLOB": 0}

// checkSizeArg refuses a size function whose length argument is not an
// integer literal of at most maxSizeArg.
func checkSizeArg(f *FuncCall) error {
	i, ok := sizeArg[f.Name]
	if !ok || i >= len(f.Args) {
		return nil
	}
	if l, ok := f.Args[i].(*Literal); ok && l.Kind == LitNumber && l.Text != "" && strings.Trim(l.Text, "0123456789") == "" {
		if n, err := strconv.Atoi(l.Text); err == nil && n <= maxSizeArg {
			return nil
		}
	}
	return refusef("%s: the length argument must be an integer literal at most %d", strings.ToLower(f.Name), maxSizeArg)
}

// funcAllowed reports whether the function name may be called.
func funcAllowed(d sqlclass.Dialect, name string) bool {
	if strings.Contains(name, ".") {
		return false // schema-qualified: possibly a user-defined function
	}
	return commonFuncs[name] || dialectFuncs[d][name] || aggregates[name] || windowOnly[name]
}

// systemSchemas hold server, catalog or session metadata. They are refused:
// the catalog commands describe the schema instead.
var systemSchemas = newSet("INFORMATION_SCHEMA", "PG_CATALOG", "PG_TOAST", "MYSQL", "PERFORMANCE_SCHEMA", "SYS")

// systemRelation reports whether a table name, as written, names server,
// catalog or session metadata.
func systemRelation(d sqlclass.Dialect, parts []string) bool {
	for _, p := range parts[:len(parts)-1] {
		if systemSchemas[p] {
			return true
		}
	}
	name := parts[len(parts)-1]
	switch d {
	case sqlclass.Postgres:
		// pg_catalog is searched first, before any schema in search_path.
		return strings.HasPrefix(name, "PG_")
	case sqlclass.SQLite:
		return strings.HasPrefix(name, "SQLITE_") || name == "DBSTAT"
	}
	return false
}
