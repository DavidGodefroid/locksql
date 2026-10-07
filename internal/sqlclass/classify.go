package sqlclass

import (
	"fmt"
	"strings"
)

// Statement is a classified statement, ready for the policy checks.
type Statement struct {
	Class Class
	// Kind is the lower-cased leading keyword ("select", "show", "describe",
	// "pragma", "insert", "create", "set", ...). SELECT, WITH, VALUES and
	// TABLE reads are "select"; a WITH that modifies data takes the kind of
	// its first data-modifying keyword ("delete", ...).
	Kind string
	// SQL is the statement as it will run: the input without surrounding
	// blanks and without one trailing ';'. It is never otherwise rewritten.
	SQL string
	// Limit is the row count of the top-level LIMIT/FETCH of a READ select,
	// or -1 when the statement has none (SHOW, DESCRIBE, PRAGMA, writes...).
	Limit int
}

// Refusal is the error Classify and Lex return for a refused statement.
// Reason never quotes literal values from the statement.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

func refuse(reason string) *Refusal { return &Refusal{Reason: reason} }

func refusef(format string, args ...any) *Refusal {
	return &Refusal{Reason: fmt.Sprintf(format, args...)}
}

type set map[string]struct{}

func newSet(words ...string) set {
	s := make(set, len(words))
	for _, w := range words {
		s[w] = struct{}{}
	}
	return s
}

func (s set) has(w string) bool { _, ok := s[w]; return ok }

// lead is the class and kind a first word gives a statement. commonLeading
// and dialectLeading map first words to it; a first word missing from both
// cannot be classified and is refused. WITH is resolved by scanning for
// data-modifying keywords.
type lead struct {
	class Class
	kind  string
}

var commonLeading = map[string]lead{
	// Reads. SHOW, DESCRIBE and PRAGMA need no LIMIT; the others do.
	"SELECT": {Read, "select"}, "WITH": {Read, "select"}, "VALUES": {Read, "select"},
	// Data modification.
	"INSERT": {Write, "insert"}, "UPDATE": {Write, "update"}, "DELETE": {Write, "delete"},
	// Schema changes.
	"CREATE": {DDL, "create"}, "ALTER": {DDL, "alter"}, "DROP": {DDL, "drop"},
	// Maintenance.
	"ANALYZE": {Admin, "analyze"},
}

var dialectLeading = map[Dialect]map[string]lead{
	MySQL: {
		"SHOW": {Read, "show"}, "DESCRIBE": {Read, "describe"}, "DESC": {Read, "describe"}, "TABLE": {Read, "select"},
		"REPLACE":  {Write, "replace"},
		"TRUNCATE": {DDL, "truncate"}, "RENAME": {DDL, "rename"},
		"GRANT": {Admin, "grant"}, "REVOKE": {Admin, "revoke"}, "KILL": {Admin, "kill"}, "SET": {Admin, "set"},
		"OPTIMIZE": {Admin, "optimize"}, "CALL": {Admin, "call"},
	},
	Postgres: {
		"SHOW": {Read, "show"}, "TABLE": {Read, "select"},
		"MERGE":    {Write, "merge"},
		"TRUNCATE": {DDL, "truncate"}, "COMMENT": {DDL, "comment"},
		"GRANT": {Admin, "grant"}, "REVOKE": {Admin, "revoke"}, "SET": {Admin, "set"}, "VACUUM": {Admin, "vacuum"},
		"CALL": {Admin, "call"}, "REINDEX": {Admin, "reindex"}, "CLUSTER": {Admin, "cluster"}, "REFRESH": {Admin, "refresh"},
	},
	SQLite: {
		"PRAGMA":  {Read, "pragma"},
		"REPLACE": {Write, "replace"},
		"VACUUM":  {Admin, "vacuum"}, "REINDEX": {Admin, "reindex"},
	},
}

// forbiddenLeading lists statements refused at every tier, in every dialect.
var forbiddenLeading = map[string]string{
	// EXPLAIN is issued by the console only (EXPLAIN ANALYZE would run the statement).
	"EXPLAIN": "the console issues EXPLAIN itself",
	// File, OS and native-code access.
	"LOAD": "file or library access", "COPY": "file and program access", "ATTACH": "opens another database file",
	"DETACH": "database attachment", "INSTALL": "loads native code", "UNINSTALL": "native code",
	// Transaction and session control: the console owns the session.
	"BEGIN": "the console owns the transaction", "START": "the console owns the transaction",
	"COMMIT": "the console owns the transaction", "END": "the console owns the transaction",
	"ROLLBACK": "the console owns the transaction", "SAVEPOINT": "the console owns the transaction",
	"RELEASE": "the console owns the transaction", "XA": "the console owns the transaction",
	"USE": "changes the session's database", "RESET": "session tampering", "DISCARD": "session tampering",
	// Locks.
	"LOCK": "explicit locks", "UNLOCK": "explicit locks",
	// Dynamic SQL and anonymous code: the human must approve exactly what runs.
	"DO": "runs code the classifier cannot see", "PREPARE": "dynamic SQL", "EXECUTE": "dynamic SQL",
	"DEALLOCATE": "dynamic SQL", "HANDLER": "low-level table access",
	// Server control.
	"SHUTDOWN": "server control", "RESTART": "server control", "FLUSH": "server control", "PURGE": "server control",
	"CHECKPOINT": "server control", "CHANGE": "replication control", "STOP": "replication control",
	"CLONE": "server control", "BINLOG": "server control", "BACKUP": "server control",
	"SIGNAL": "stored-program control", "RESIGNAL": "stored-program control",
	"LISTEN": "session state", "NOTIFY": "session state", "UNLISTEN": "session state",
}

// Forbidden functions are refused when called (name followed by '('), at any
// depth, in every class and every dialect: a name harmless in one engine may
// be a user-defined function or extension in another. Quoted names count too.
var forbiddenFuncs = newSet(
	// MySQL/MariaDB: delays and resource abuse.
	"SLEEP", "BENCHMARK",
	// MySQL/MariaDB: named locks.
	"GET_LOCK", "RELEASE_LOCK", "RELEASE_ALL_LOCKS", "IS_FREE_LOCK", "IS_USED_LOCK",
	// MySQL/MariaDB: replication waits that block a connection.
	"MASTER_POS_WAIT", "SOURCE_POS_WAIT", "MASTER_GTID_WAIT", "WAIT_FOR_EXECUTED_GTID_SET",
	"WAIT_UNTIL_SQL_THREAD_AFTER_GTIDS",
	// MySQL/MariaDB: file access and well-known command-execution UDFs.
	"LOAD_FILE", "SYS_EXEC", "SYS_EVAL",
	// PostgreSQL: server file access.
	"PG_READ_FILE", "PG_READ_BINARY_FILE", "PG_STAT_FILE", "LO_IMPORT", "LO_EXPORT",
	"PG_FILE_WRITE", "PG_FILE_RENAME", "PG_FILE_UNLINK", "PG_LOGDIR_LS",
	// PostgreSQL: functions that run SQL passed as a string, out of the classifier's sight.
	"QUERY_TO_XML", "QUERY_TO_XMLSCHEMA", "QUERY_TO_XML_AND_XMLSCHEMA", "TS_STAT",
	// PostgreSQL: session tampering.
	"SET_CONFIG",
	// PostgreSQL: server and backend control.
	"PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND", "PG_RELOAD_CONF", "PG_ROTATE_LOGFILE", "PG_PROMOTE",
	"PG_SWITCH_WAL", "PG_CREATE_RESTORE_POINT",
	// SQLite: native code and known escape hatches.
	"LOAD_EXTENSION", "FTS3_TOKENIZER", "READFILE", "WRITEFILE", "EDIT",
)

// forbiddenFuncPrefixes covers function families.
var forbiddenFuncPrefixes = []string{
	// PostgreSQL: pg_sleep, pg_sleep_for, pg_sleep_until.
	"PG_SLEEP",
	// PostgreSQL: advisory locks.
	"PG_ADVISORY", "PG_TRY_ADVISORY",
	// PostgreSQL: directory listings (pg_ls_dir, pg_ls_logdir, pg_ls_waldir, ...).
	"PG_LS_",
	// PostgreSQL: remote connections (dblink, dblink_exec, dblink_connect, ...).
	"DBLINK",
}

// sequenceFuncs advance or set a sequence; they are refused in a READ statement.
var sequenceFuncs = newSet("NEXTVAL", "SETVAL")

// sessionSettings may not be the target of SET: changing them would weaken the
// console's session guards (read-only transaction, timeouts, role, lexing
// assumptions such as the character set and SQL mode).
var sessionSettings = newSet(
	// Identity.
	"ROLE", "AUTHORIZATION", "SESSION_AUTHORIZATION",
	// Read-only transaction.
	"TRANSACTION", "CHARACTERISTICS", "TRANSACTION_READ_ONLY", "TX_READ_ONLY", "DEFAULT_TRANSACTION_READ_ONLY",
	"AUTOCOMMIT", "SESSION_REPLICATION_ROLE",
	// Timeouts.
	"STATEMENT_TIMEOUT", "MAX_STATEMENT_TIME", "MAX_EXECUTION_TIME", "LOCK_TIMEOUT",
	"IDLE_IN_TRANSACTION_SESSION_TIMEOUT", "TRANSACTION_TIMEOUT",
	// Character set and quoting rules the lexer relies on; name resolution.
	"NAMES", "CHARSET", "CHARACTER", "SQL_MODE", "CLIENT_ENCODING", "STANDARD_CONFORMING_STRINGS", "SEARCH_PATH",
	// Binary logging.
	"SQL_LOG_BIN",
)

var sessionSettingPrefixes = []string{"CHARACTER_SET_", "COLLATION_"}

// credentialWords carry a password or an authentication method; such
// statements would put a secret in the audit log.
var credentialWords = newSet("PASSWORD", "IDENTIFIED")

// describeStop are words that turn DESCRIBE into EXPLAIN (DESCRIBE SELECT,
// DESC ANALYZE, DESCRIBE FORMAT=JSON, DESCRIBE FOR CONNECTION, ...).
var describeStop = newSet("SELECT", "WITH", "INSERT", "UPDATE", "DELETE", "REPLACE", "TABLE", "VALUES",
	"ANALYZE", "FORMAT", "EXTENDED", "PARTITIONS", "FOR", "CONNECTION")

// analyzeStatement words, directly after ANALYZE, make it run a statement
// (MariaDB ANALYZE [FORMAT=JSON] SELECT|UPDATE|DELETE|...). Elsewhere they are
// harmless (MySQL ANALYZE TABLE t UPDATE HISTOGRAM ON c WITH 10 BUCKETS).
var analyzeStatement = newSet("SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "WITH", "FORMAT", "VALUES")

// SQLite pragmas that only report. pragmaIntrospect may take one argument
// (a table or index name); pragmaSettings are read in their no-argument
// form only, since PRAGMA name(value) sets them.
var pragmaIntrospect = newSet("TABLE_INFO", "TABLE_XINFO", "TABLE_LIST", "INDEX_INFO", "INDEX_XINFO",
	"INDEX_LIST", "FOREIGN_KEY_LIST", "COLLATION_LIST", "DATABASE_LIST", "FUNCTION_LIST", "MODULE_LIST",
	"PRAGMA_LIST", "COMPILE_OPTIONS")

var pragmaSettings = newSet("APPLICATION_ID", "AUTO_VACUUM", "AUTOMATIC_INDEX", "BUSY_TIMEOUT", "CACHE_SIZE",
	"CACHE_SPILL", "CELL_SIZE_CHECK", "CHECKPOINT_FULLFSYNC", "DATA_VERSION", "DEFER_FOREIGN_KEYS", "ENCODING",
	"FOREIGN_KEYS", "FREELIST_COUNT", "FULLFSYNC", "HARD_HEAP_LIMIT", "IGNORE_CHECK_CONSTRAINTS", "JOURNAL_MODE",
	"JOURNAL_SIZE_LIMIT", "LEGACY_ALTER_TABLE", "LOCKING_MODE", "MAX_PAGE_COUNT", "MMAP_SIZE", "PAGE_COUNT",
	"PAGE_SIZE", "QUERY_ONLY", "READ_UNCOMMITTED", "RECURSIVE_TRIGGERS", "REVERSE_UNORDERED_SELECTS",
	"SECURE_DELETE", "SOFT_HEAP_LIMIT", "SYNCHRONOUS", "TEMP_STORE", "THREADS", "TRUSTED_SCHEMA",
	"USER_VERSION", "SCHEMA_VERSION", "WAL_AUTOCHECKPOINT", "ANALYSIS_LIMIT")

// Classify lexes and classifies one statement. A READ select must end with a
// top-level LIMIT (or PostgreSQL FETCH FIRST) of at most maxRows rows; a
// maxRows of 0 or less only requires the LIMIT. Classify does not know the
// profile tier: FORBIDDEN constructs are refused whatever the tier. The
// error, if any, is a *Refusal.
func Classify(d Dialect, sql string, maxRows int) (Statement, error) {
	text := strings.TrimSpace(sql)
	if strings.HasSuffix(text, ";") {
		text = strings.TrimSpace(text[:len(text)-1])
	}
	if text == "" {
		return Statement{}, refuse("empty statement")
	}
	toks, err := Lex(d, text)
	if err != nil {
		return Statement{}, err
	}

	// 1. A single statement.
	for _, t := range toks {
		if t.Kind == TokPunct && t.Text == ";" {
			return Statement{}, refuse("exactly one statement is allowed (no ';' chaining)")
		}
	}

	// 2. FORBIDDEN constructs, whatever the class.
	if err := checkForbidden(d, toks); err != nil {
		return Statement{}, err
	}

	// 3. Class from the first word.
	first := toks[0]
	if first.Kind != TokWord {
		what := "'" + first.Text + "'"
		if first.Kind != TokPunct {
			what = "a literal or quoted name" // never echo literal values
		}
		return Statement{}, refusef("statements starting with %s cannot be classified", what)
	}
	if why, ok := forbiddenLeading[first.Text]; ok {
		return Statement{}, refusef("%s is not allowed (%s)", first.Text, why)
	}
	l, ok := commonLeading[first.Text]
	if !ok {
		l, ok = dialectLeading[d][first.Text]
	}
	if !ok {
		return Statement{}, refusef("statements starting with %.40s cannot be classified", first.Text)
	}
	st := Statement{Class: l.class, Kind: l.kind, SQL: text, Limit: -1}
	if st.Class == Read && st.Kind == "select" {
		// Data-modifying keywords inside a read-led statement (a PostgreSQL
		// or SQLite WITH ... DELETE) make the whole statement WRITE.
		if kind := dataModifying(toks); kind != "" {
			st.Class, st.Kind = Write, kind
		}
	}

	switch {
	case st.Class == Read:
		if err := checkRead(d, toks, &st, maxRows); err != nil {
			return Statement{}, err
		}
	case st.Class == DDL || st.Class == Admin:
		if err := checkPrivileged(d, toks); err != nil {
			return Statement{}, err
		}
	}
	return st, nil
}

// checkForbidden refuses constructs that are never allowed: forbidden
// function calls, INTO OUTFILE/DUMPFILE and SONAME (native code loading).
// A MySQL "name"( counts as a call: with ANSI_QUOTES it is one.
func checkForbidden(d Dialect, toks []Token) error {
	for k, t := range toks {
		name := t.nameIn(d)
		if name == "" {
			continue
		}
		if isCall(toks, k) && isForbiddenFunc(name) {
			return refusef("forbidden function: %.64s", name)
		}
		if t.Kind != TokWord {
			continue
		}
		switch name {
		case "INTO":
			if k+1 < len(toks) && (toks[k+1].Text == "OUTFILE" || toks[k+1].Text == "DUMPFILE") && toks[k+1].Kind == TokWord {
				return refusef("INTO %s is not allowed (writes a file on the server)", toks[k+1].Text)
			}
		case "SONAME":
			return refuse("SONAME is not allowed (loads native code)")
		}
	}
	return nil
}

// isCall reports whether toks[k] is directly followed by '('.
func isCall(toks []Token, k int) bool {
	return k+1 < len(toks) && toks[k+1].Kind == TokPunct && toks[k+1].Text == "("
}

func isForbiddenFunc(name string) bool {
	if forbiddenFuncs.has(name) {
		return true
	}
	for _, p := range forbiddenFuncPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// dataModifying returns the lower-cased first data-modifying keyword in toks,
// or "". INSERT and REPLACE followed by '(' are string functions, UPDATE after
// FOR or KEY belongs to a locking clause or ON DUPLICATE KEY UPDATE, and
// REPLACE modifies data only as REPLACE INTO. INSERT, UPDATE and MERGE are
// non-reserved in PostgreSQL, so they can also be column names: see
// usedAsName. DELETE is reserved everywhere and always counts.
func dataModifying(toks []Token) string {
	for k, t := range toks {
		if k == 0 || t.Kind != TokWord {
			continue
		}
		next := ""
		if k+1 < len(toks) {
			next = toks[k+1].Text
		}
		prev := toks[k-1].Text
		switch t.Text {
		case "INSERT", "MERGE":
			if next != "(" && !usedAsName(toks, k) {
				return strings.ToLower(t.Text)
			}
		case "DELETE":
			return "delete"
		case "UPDATE":
			if prev != "FOR" && prev != "KEY" && !usedAsName(toks, k) {
				return "update"
			}
		case "REPLACE":
			if next == "INTO" {
				return "replace"
			}
		}
	}
	return ""
}

// nameFollowers are words that may follow a column name but never the
// INSERT, UPDATE or MERGE keyword of a statement (which is followed by INTO,
// OR, ONLY, a modifier or a table name).
var nameFollowers = newSet("FROM", "AS", "IS", "AND", "WHERE")

// usedAsName reports whether the INSERT, UPDATE or MERGE word at toks[k] is
// used as a name rather than as a statement keyword: it is qualified
// (t.merge), it ends the statement, or it is followed by punctuation (other
// than '(') or by a word in nameFollowers. Any other context counts as a
// statement, which errs on the side of the higher tier.
func usedAsName(toks []Token, k int) bool {
	if k > 0 && toks[k-1].Kind == TokPunct && toks[k-1].Text == "." {
		return true
	}
	if k+1 >= len(toks) {
		return true
	}
	next := toks[k+1]
	switch next.Kind {
	case TokPunct:
		return next.Text != "("
	case TokWord:
		return nameFollowers.has(next.Text)
	}
	return false
}

// checkShow refuses the MySQL/MariaDB SHOW forms that return credential
// material: SHOW CREATE USER prints the authentication string (password
// hash), and MariaDB's SHOW GRANTS prints IDENTIFIED BY PASSWORD '<hash>'.
// Other SHOW forms are left to the output caps and PII masking.
func checkShow(toks []Token) error {
	word := func(i int) string {
		if i < len(toks) && toks[i].Kind == TokWord {
			return toks[i].Text
		}
		return ""
	}
	switch {
	case word(1) == "CREATE" && word(2) == "USER":
		return refuse("SHOW CREATE USER is not allowed (it returns the password hash)")
	case word(1) == "GRANTS":
		return refuse("SHOW GRANTS is not allowed (MariaDB includes password hashes); query the privilege tables instead")
	}
	return nil
}

// checkRead applies the READ rules: no SELECT ... INTO, no locking clause, no
// procedure, no sequence advance, the shape rules of DESCRIBE and PRAGMA, and
// the top-level LIMIT for selects.
func checkRead(d Dialect, toks []Token, st *Statement, maxRows int) error {
	for k, t := range toks {
		if t.Kind != TokWord {
			continue
		}
		next := func(i int) string {
			if k+i < len(toks) && toks[k+i].Kind == TokWord {
				return toks[k+i].Text
			}
			return ""
		}
		switch t.Text {
		case "INTO":
			return refuse("SELECT ... INTO is not allowed (it writes a table, a variable or a file)")
		case "PROCEDURE":
			return refuse("PROCEDURE is not allowed in a read")
		case "LOCK":
			return refuse("locking reads (LOCK IN SHARE MODE) are not allowed")
		case "FOR":
			clause := []string{"FOR"}
			for i := 1; i <= 3; i++ {
				w := next(i)
				if w != "NO" && w != "KEY" && w != "UPDATE" && w != "SHARE" {
					break
				}
				clause = append(clause, w)
				if w == "UPDATE" || w == "SHARE" {
					return refusef("locking reads (%s) are not allowed", strings.Join(clause, " "))
				}
			}
		case "NEXT":
			if next(1) == "VALUE" && next(2) == "FOR" {
				return refuse("NEXT VALUE FOR advances a sequence; sequence changes are not allowed in a read")
			}
		}
	}
	for k, t := range toks {
		if name := t.nameIn(d); sequenceFuncs.has(name) && isCall(toks, k) {
			return refusef("%s advances a sequence; sequence changes are not allowed in a read", name)
		}
	}
	switch st.Kind {
	case "describe":
		return checkDescribe(toks)
	case "pragma":
		return checkPragma(toks)
	case "show":
		return checkShow(toks)
	}
	n, err := topLevelLimit(d, toks)
	if err != nil {
		return err
	}
	if maxRows > 0 && n > maxRows {
		return refusef("LIMIT %d exceeds the maximum of %d rows", n, maxRows)
	}
	st.Limit = n
	return nil
}

// checkDescribe accepts DESCRIBE|DESC table, db.table, optionally followed
// by a column name or pattern. Other forms are EXPLAIN in disguise.
func checkDescribe(toks []Token) error {
	bad := refuse("DESCRIBE accepts a table name only (DESCRIBE [db.]table [column])")
	rest := toks[1:]
	isName := func(t Token) bool {
		return t.Kind == TokQuotedIdent || t.Kind == TokWord && !describeStop.has(t.Text)
	}
	if len(rest) == 0 || !isName(rest[0]) {
		return bad
	}
	rest = rest[1:]
	if len(rest) >= 2 && rest[0].Text == "." && rest[0].Kind == TokPunct && isName(rest[1]) {
		rest = rest[2:]
	}
	if len(rest) == 1 && (isName(rest[0]) || rest[0].Kind == TokString) {
		rest = rest[1:]
	}
	if len(rest) != 0 {
		return bad
	}
	return nil
}

// checkPragma accepts PRAGMA [schema.]name and, for introspection pragmas,
// PRAGMA [schema.]name(arg). Assignments and other pragmas are refused.
func checkPragma(toks []Token) error {
	rest := toks[1:]
	for _, t := range rest {
		if t.Kind == TokPunct && t.Text == "=" {
			return refuse("PRAGMA with an assignment is not allowed")
		}
	}
	if len(rest) >= 2 && rest[1].Kind == TokPunct && rest[1].Text == "." {
		rest = rest[2:]
	}
	if len(rest) == 0 || rest[0].Kind != TokWord && rest[0].Kind != TokQuotedIdent {
		return refuse("PRAGMA needs a pragma name")
	}
	name := rest[0].Name()
	rest = rest[1:]
	switch {
	case len(rest) == 0 && (pragmaIntrospect.has(name) || pragmaSettings.has(name)):
		return nil
	case len(rest) == 3 && pragmaIntrospect.has(name) && rest[0].Text == "(" && rest[2].Text == ")" &&
		rest[1].Kind != TokPunct:
		return nil
	case pragmaSettings.has(name):
		return refusef("PRAGMA %s with an argument changes the setting; only the read form is allowed", name)
	}
	return refusef("PRAGMA %.64s is not allowed (only introspection and setting reads are)", name)
}

// checkPrivileged applies the DDL and ADMIN rules: no credentials in the
// statement, no SET of a guarded session setting, no ALTER SYSTEM, no
// CREATE EXTENSION, no ANALYZE that runs a statement, no VACUUM INTO.
func checkPrivileged(d Dialect, toks []Token) error {
	first := toks[0].Text
	second := ""
	if len(toks) > 1 {
		second = toks[1].Name()
	}
	credentialStmt := first == "SET" || first == "GRANT"
	for _, t := range toks {
		if t.Kind == TokWord && (t.Text == "USER" || t.Text == "ROLE" || t.Text == "MAPPING" || t.Text == "SERVER") {
			credentialStmt = true
		}
	}
	for _, t := range toks {
		if credentialStmt && t.Kind == TokWord && credentialWords.has(t.Text) {
			return refuse("statements that carry credentials (PASSWORD, IDENTIFIED) are not allowed: the audit log would record the secret")
		}
	}
	switch first {
	case "SET":
		for _, t := range toks[1:] {
			name := t.nameIn(d)
			if name == "" {
				continue
			}
			if sessionSettings.has(name) || hasAnyPrefix(name, sessionSettingPrefixes) {
				return refusef("SET of %.64s is not allowed (it would weaken the console's session guards)", name)
			}
		}
	case "ALTER":
		if second == "SYSTEM" {
			return refuse("ALTER SYSTEM is not allowed (server configuration)")
		}
	case "CREATE":
		for _, t := range toks[1:] {
			if t.Kind == TokWord && t.Text == "EXTENSION" {
				return refuse("CREATE EXTENSION is not allowed (extensions can load native code)")
			}
		}
	case "ANALYZE":
		if len(toks) > 1 {
			t := toks[1]
			// A MariaDB statement may also be parenthesised; PostgreSQL's
			// ANALYZE (VERBOSE) t option list is not a statement.
			if t.Kind == TokWord && analyzeStatement.has(t.Text) || d == MySQL && t.Text == "(" {
				return refuse("ANALYZE of a statement is not allowed (it runs the statement)")
			}
		}
	case "VACUUM":
		for _, t := range toks[1:] {
			if t.Kind == TokWord && t.Text == "INTO" {
				return refuse("VACUUM INTO is not allowed (writes a file)")
			}
		}
	}
	return nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
