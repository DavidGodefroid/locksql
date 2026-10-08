package sqlclass

import (
	"errors"
	"strings"
	"testing"
)

// corpusMaxRows is the max_rows used by every corpus case.
const corpusMaxRows = 200

// accepted is the class a case must get; refused cases set wantErr instead.
type corpusCase struct {
	sql       string
	wantClass Class
	wantKind  string // optional
	wantLimit int    // checked only when wantKind is "select"; other kinds must have Limit -1
	wantErr   string // non-empty: the statement must be refused with this substring
}

var allDialects = []Dialect{MySQL, Postgres, SQLite}

// commonCorpus applies to every dialect. It is ported from the prototype
// validator corpus (dbq tests/test_validator.py) and the plan's minimum set.
var commonCorpus = []corpusCase{
	// Accepted READ.
	{sql: "SELECT id FROM email WHERE id = 3 LIMIT 1", wantClass: Read, wantKind: "select", wantLimit: 1},
	{sql: "select id from email limit 10", wantClass: Read, wantKind: "select", wantLimit: 10},
	{sql: "SELECT id FROM t WHERE s = 'delete' LIMIT 5", wantClass: Read, wantKind: "select", wantLimit: 5},
	{sql: "SELECT id FROM t WHERE note = 'a; b -- c /* d */ @x := # \"' LIMIT 5", wantClass: Read},
	{sql: "SELECT id FROM t WHERE s = 'it''s' LIMIT 5", wantClass: Read},
	{sql: "WITH x AS (SELECT 1) SELECT * FROM x LIMIT 5", wantClass: Read, wantKind: "select", wantLimit: 5},
	{sql: "WITH x AS (SELECT id FROM t WHERE a = 1) SELECT * FROM x LIMIT 5", wantClass: Read},
	{sql: "SELECT id FROM t WHERE id IN (SELECT t_id FROM u LIMIT 3) LIMIT 5", wantClass: Read, wantKind: "select", wantLimit: 5},
	{sql: "SELECT id FROM a UNION SELECT id FROM b LIMIT 5", wantClass: Read, wantKind: "select", wantLimit: 5},
	{sql: "SELECT COUNT(*) FROM t LIMIT 1", wantClass: Read, wantKind: "select", wantLimit: 1},
	{sql: "SELECT COUNT(*) FROM t WHERE created_at > '2026-10-01' LIMIT 1", wantClass: Read},
	{sql: "SELECT id FROM t LIMIT 5;", wantClass: Read, wantKind: "select", wantLimit: 5},
	{sql: "  SELECT id FROM t LIMIT 5 ;  ", wantClass: Read},
	{sql: "SELECT id FROM other_db.t LIMIT 5", wantClass: Read},
	{sql: "SELECT id FROM t LIMIT 20 OFFSET 10", wantClass: Read, wantKind: "select", wantLimit: 20},
	{sql: "SELECT updated_at, deleted, insert_count FROM t LIMIT 5", wantClass: Read},
	{sql: "SELECT replace(name, 'a', 'b') FROM t LIMIT 5", wantClass: Read},
	{sql: "SELECT id FROM t LIMIT 200", wantClass: Read, wantKind: "select", wantLimit: 200},
	{sql: "SELECT id FROM t LIMIT 0", wantClass: Read, wantKind: "select", wantLimit: 0},
	{sql: "SELECT 1.5, .5, 1e3 LIMIT 1", wantClass: Read},
	{sql: "SELECT sleep_minutes FROM t LIMIT 1", wantClass: Read},
	{sql: "SELECT id FROM t WHERE x = 'café' LIMIT 1", wantClass: Read},
	{sql: "VALUES (1), (2) LIMIT 1", wantClass: Read, wantKind: "select", wantLimit: 1},

	// WRITE and DDL.
	{sql: "INSERT INTO t VALUES (1)", wantClass: Write, wantKind: "insert", wantLimit: -1},
	{sql: "UPDATE t SET a = 1", wantClass: Write, wantKind: "update", wantLimit: -1},
	{sql: "DELETE FROM t", wantClass: Write, wantKind: "delete"},
	{sql: "DELETE FROM t WHERE s = 'select'", wantClass: Write},
	{sql: "CREATE TABLE x (a int)", wantClass: DDL, wantKind: "create", wantLimit: -1},
	{sql: "DROP TABLE t", wantClass: DDL, wantKind: "drop"},
	{sql: "ALTER TABLE t ADD c int", wantClass: DDL, wantKind: "alter"},
	{sql: "ANALYZE t", wantClass: Admin, wantKind: "analyze"},

	// Refused: statement smuggling.
	{sql: "", wantErr: "empty"},
	{sql: "   ", wantErr: "empty"},
	{sql: ";", wantErr: "empty"},
	{sql: "SELECT 1 LIMIT 1; SELECT 2 LIMIT 1", wantErr: "one statement"},
	{sql: "SELECT 1 LIMIT 1; DROP TABLE t", wantErr: "one statement"},
	{sql: "SELECT 1 LIMIT 1;;", wantErr: "one statement"},
	{sql: "SELECT /* hi */ 1 LIMIT 1", wantErr: "comment"},
	{sql: "SELECT 1 LIMIT 1 -- x", wantErr: "comment"},
	{sql: "SELECT 1 */ LIMIT 1", wantErr: "comment"},
	{sql: "SELECT @v LIMIT 1", wantErr: "variable"},
	{sql: "SELECT @@version LIMIT 1", wantErr: "variable"},
	{sql: "SELECT (a := 1) LIMIT 1", wantErr: "assignment"},
	{sql: "SELECT (1 LIMIT 1", wantErr: "parenthes"},
	{sql: "SELECT 1) LIMIT 1", wantErr: "parenthes"},
	{sql: "SELECT 'unterminated LIMIT 1", wantErr: "unterminated"},
	{sql: "SELECT \"unterminated LIMIT 1", wantErr: "unterminated"},
	{sql: "SELECT id FROM t WHERE s = 'a\\'b' LIMIT 5", wantErr: "backslash"},
	{sql: "SELECT id FROM t WHERE s = 'a\\' LIMIT 5", wantErr: "backslash"},
	{sql: "SELECT 1 \\g", wantErr: "backslash"},

	// Refused: LIMIT rule.
	{sql: "SELECT id FROM t", wantErr: "LIMIT"},
	{sql: "SELECT COUNT(*) FROM t", wantErr: "LIMIT"},
	{sql: "SELECT id FROM t WHERE id IN (SELECT id FROM u LIMIT 3)", wantErr: "LIMIT"},
	{sql: "WITH x AS (SELECT 1 LIMIT 1) SELECT * FROM x", wantErr: "LIMIT"},
	{sql: "SELECT id FROM t LIMIT 500", wantErr: "exceeds"},
	{sql: "SELECT id FROM t LIMIT 201", wantErr: "exceeds"},
	{sql: "SELECT id FROM t LIMIT 1000 OFFSET 0", wantErr: "exceeds"},
	{sql: "SELECT id FROM t LIMIT 99999999999999999999999", wantErr: "LIMIT"},
	{sql: "SELECT id FROM t LIMIT 5 ORDER BY id", wantErr: "LIMIT"},
	{sql: "SELECT id FROM t LIMIT (5)", wantErr: "LIMIT"},
	{sql: "SELECT id FROM t LIMIT ALL", wantErr: "LIMIT"},
	{sql: "VALUES (1), (2)", wantErr: "LIMIT"},

	// Refused: EXPLAIN is issued by the console only.
	{sql: "EXPLAIN SELECT 1 LIMIT 1", wantErr: "EXPLAIN"},
	{sql: "explain analyze SELECT 1 LIMIT 1", wantErr: "EXPLAIN"},

	// Refused: SELECT ... INTO, locking reads.
	{sql: "SELECT * INTO newtab FROM t LIMIT 1", wantErr: "INTO"},
	{sql: "SELECT * FROM t LIMIT 1 FOR UPDATE", wantErr: "FOR UPDATE"},
	{sql: "SELECT * FROM t FOR SHARE LIMIT 1", wantErr: "FOR SHARE"},

	// Refused: FORBIDDEN functions, whatever the class (Classify ignores the tier).
	{sql: "SELECT SLEEP(1) LIMIT 1", wantErr: "SLEEP"},
	{sql: "SELECT sleep (1) LIMIT 1", wantErr: "SLEEP"},
	{sql: "INSERT INTO t SELECT sleep(1)", wantErr: "SLEEP"},
	{sql: "SELECT pg_sleep(1) LIMIT 1", wantErr: "PG_SLEEP"},
	{sql: "SELECT load_extension('x') LIMIT 1", wantErr: "LOAD_EXTENSION"},
	{sql: "SELECT BENCHMARK(1000000, MD5('a')) LIMIT 1", wantErr: "BENCHMARK"},
	{sql: "UPDATE t SET a = LOAD_FILE('/etc/hosts')", wantErr: "LOAD_FILE"},
	{sql: "SELECT dblink('x', 'y') LIMIT 1", wantErr: "DBLINK"},

	// Refused: statements that are never allowed or cannot be classified.
	{sql: "BEGIN", wantErr: "not allowed"},
	{sql: "COMMIT", wantErr: "not allowed"},
	{sql: "LOCK TABLES t READ", wantErr: "not allowed"},
	{sql: "FROBNICATE t", wantErr: "cannot be classified"},
	{sql: "(SELECT 1) LIMIT 1", wantErr: "cannot be classified"},
	{sql: "1", wantErr: "cannot be classified"},
}

// dialectCorpus holds the dialect-specific cases.
var dialectCorpus = map[Dialect][]corpusCase{
	MySQL: {
		{sql: "SELECT `update` FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT `update`, `set`, `drop` FROM t LIMIT 5", wantClass: Read},
		{sql: "SELECT `a``b` FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT \"delete\" LIMIT 1", wantClass: Read},
		{sql: "SELECT id FROM t LIMIT 10, 20", wantClass: Read, wantKind: "select", wantLimit: 20},
		{sql: "SELECT id FROM t LIMIT 0, 500", wantErr: "exceeds"},
		{sql: "SELECT INSERT('abc', 1, 1, 'x') LIMIT 1", wantClass: Read},
		{sql: "TABLE t LIMIT 5", wantClass: Read, wantKind: "select", wantLimit: 5},
		{sql: "SELECT /*!50000 SLEEP(1) */ 1 LIMIT 1", wantErr: "comment"},
		{sql: "SELECT /*+ MAX_EXECUTION_TIME(1) */ 1 LIMIT 1", wantErr: "comment"},
		{sql: "SELECT 1 LIMIT 1 # x", wantErr: "comment"},
		{sql: "SELECT * FROM t INTO OUTFILE '/tmp/x' LIMIT 1", wantErr: "OUTFILE"},
		{sql: "SELECT * FROM t LIMIT 1 INTO DUMPFILE '/tmp/x'", wantErr: "DUMPFILE"},
		{sql: "INSERT INTO t SELECT * FROM u INTO OUTFILE '/tmp/x'", wantErr: "OUTFILE"},
		{sql: "SELECT id INTO @v FROM t LIMIT 1", wantErr: "variable"},
		{sql: "SELECT id INTO v FROM t LIMIT 1", wantErr: "INTO"},
		{sql: "LOAD DATA INFILE 'x' INTO TABLE t", wantErr: "LOAD"},
		{sql: "LOAD XML INFILE 'x' INTO TABLE t", wantErr: "LOAD"},
		{sql: "SHOW CREATE TABLE t", wantClass: Read, wantKind: "show", wantLimit: -1},
		{sql: "SHOW TABLES", wantClass: Read, wantKind: "show"},
		{sql: "SHOW FULL COLUMNS FROM t", wantClass: Read, wantKind: "show"},
		{sql: "DESCRIBE t", wantClass: Read, wantKind: "describe", wantLimit: -1},
		{sql: "DESC t", wantClass: Read, wantKind: "describe"},
		{sql: "DESCRIBE db.t", wantClass: Read, wantKind: "describe"},
		{sql: "DESCRIBE `t` `c`", wantClass: Read, wantKind: "describe"},
		{sql: "DESCRIBE SELECT 1", wantErr: "DESCRIBE"},
		{sql: "DESC ANALYZE SELECT * FROM t", wantErr: "DESCRIBE"},
		{sql: "DESCRIBE FORMAT=JSON SELECT 1", wantErr: "DESCRIBE"},
		{sql: "INSERT INTO t VALUES (1)", wantClass: Write, wantKind: "insert"},
		{sql: "REPLACE INTO t VALUES (1)", wantClass: Write, wantKind: "replace"},
		{sql: "INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE a = 2", wantClass: Write},
		{sql: "WITH x AS (SELECT 1 AS id) DELETE FROM t WHERE id IN (SELECT id FROM x)", wantClass: Write, wantKind: "delete"},
		{sql: "ALTER TABLE t ADD c int", wantClass: DDL, wantKind: "alter"},
		{sql: "TRUNCATE t", wantClass: DDL},
		{sql: "RENAME TABLE a TO b", wantClass: DDL},
		{sql: "GRANT SELECT ON db.* TO 'u'@'h'", wantClass: Admin, wantKind: "grant"},
		{sql: "GRANT ALL ON *.* TO x", wantClass: Admin},
		{sql: "DROP USER `u`@`h`", wantClass: DDL},
		{sql: "DROP USER u@h", wantErr: "variable"},
		{sql: "SELECT 'a' @'b' LIMIT 1", wantErr: "variable"},
		{sql: "REVOKE SELECT ON db.* FROM x", wantClass: Admin},
		{sql: "KILL 42", wantClass: Admin},
		{sql: "OPTIMIZE TABLE t", wantClass: Admin},
		{sql: "CALL p()", wantClass: Admin, wantKind: "call"},
		{sql: "ANALYZE TABLE t", wantClass: Admin},
		{sql: "ANALYZE SELECT id FROM t LIMIT 5", wantErr: "ANALYZE"},
		{sql: "ANALYZE FORMAT=JSON DELETE FROM t", wantErr: "ANALYZE"},
		{sql: "ANALYZE (SELECT id FROM t LIMIT 5)", wantErr: "ANALYZE"},
		{sql: "ANALYZE TABLE t UPDATE HISTOGRAM ON c WITH 10 BUCKETS", wantClass: Admin, wantKind: "analyze"},
		{sql: "ANALYZE TABLE t DROP HISTOGRAM ON c", wantClass: Admin},
		{sql: "SELECT 1$x LIMIT 1", wantClass: Read},
		{sql: "SET SESSION sort_buffer_size = 1000000", wantClass: Admin, wantKind: "set"},
		{sql: "SET SESSION TRANSACTION READ WRITE", wantErr: "TRANSACTION"},
		{sql: "SET TRANSACTION READ WRITE", wantErr: "TRANSACTION"},
		{sql: "SET @a = 1", wantErr: "variable"},
		{sql: "SET SESSION max_statement_time = 0", wantErr: "MAX_STATEMENT_TIME"},
		{sql: "SET max_execution_time = 0", wantErr: "MAX_EXECUTION_TIME"},
		{sql: "SET NAMES gbk", wantErr: "NAMES"},
		{sql: "SET character_set_client = gbk", wantErr: "CHARACTER_SET_CLIENT"},
		{sql: "SET sql_mode = ''", wantErr: "SQL_MODE"},
		{sql: "SET ROLE ALL", wantErr: "ROLE"},
		{sql: "SET PASSWORD = 'x'", wantErr: "credential"},
		{sql: "CREATE USER u IDENTIFIED BY 'x'", wantErr: "credential"},
		{sql: "ALTER USER u IDENTIFIED BY 'x'", wantErr: "credential"},
		{sql: "SELECT password FROM users LIMIT 1", wantClass: Read},
		{sql: "CREATE FUNCTION f RETURNS INT SONAME 'x.so'", wantErr: "SONAME"},
		{sql: "DO SLEEP(1)", wantErr: "SLEEP"},
		{sql: "DO 1", wantErr: "not allowed"},
		{sql: "HANDLER t OPEN", wantErr: "not allowed"},
		{sql: "PREPARE s FROM 'DELETE FROM t'", wantErr: "not allowed"},
		{sql: "USE other", wantErr: "not allowed"},
		{sql: "SELECT * FROM t LIMIT 1 LOCK IN SHARE MODE", wantErr: "LOCK"},
		{sql: "SELECT GET_LOCK('a', 10) LIMIT 1", wantErr: "GET_LOCK"},
		{sql: "SELECT MASTER_POS_WAIT('a', 1) LIMIT 1", wantErr: "MASTER_POS_WAIT"},
		{sql: "SELECT `sleep`(1) LIMIT 1", wantErr: "SLEEP"},
		// With ANSI_QUOTES in sql_mode, "x" is an identifier: a double-quoted
		// name followed by '(' is a function call.
		{sql: "SELECT \"sleep\"(1) LIMIT 1", wantErr: "SLEEP"},
		{sql: "SELECT \"load_file\"('x') LIMIT 1", wantErr: "LOAD_FILE"},
		{sql: "SELECT \"LOAD_\"\"FILE\"('x') LIMIT 1", wantClass: Read}, // names LOAD_"FILE
		{sql: "SELECT \"sleep\" FROM t LIMIT 1", wantClass: Read},
		{sql: "SET \"sql_mode\" = ''", wantErr: "SQL_MODE"},
		{sql: "SELECT \"nextval\"(s) LIMIT 1", wantErr: "sequence"},
		{sql: "SELECT `nextval`(s) LIMIT 1", wantErr: "sequence"},
		// SHOW forms that return credential material.
		{sql: "SHOW CREATE USER u", wantErr: "CREATE USER"},
		{sql: "show create user `u`@`h`", wantErr: "CREATE USER"},
		{sql: "SHOW GRANTS", wantErr: "GRANTS"},
		{sql: "SHOW GRANTS FOR CURRENT_USER()", wantErr: "GRANTS"},
		{sql: "SHOW CREATE VIEW v", wantClass: Read, wantKind: "show"},
		{sql: "SELECT id FROM t LIMIT 5 PROCEDURE ANALYSE()", wantErr: "PROCEDURE"},
		{sql: "SELECT NEXTVAL(s) LIMIT 1", wantErr: "sequence"},
		{sql: "SELECT NEXT VALUE FOR s LIMIT 1", wantErr: "sequence"},
		{sql: "INSERT INTO t VALUES (NEXTVAL(s))", wantClass: Write},
		{sql: "SELECT ? LIMIT 1", wantErr: "parameter"},
		{sql: "SELECT $$x$$ LIMIT 1", wantClass: Read}, // $ is an identifier character in MySQL
		{sql: "PRAGMA table_info(t)", wantErr: "cannot be classified"},
		{sql: "ATTACH 'x.db' AS y", wantErr: "not allowed"},
		{sql: "SELECT 'x' \\G", wantErr: "backslash"},
	},
	Postgres: {
		{sql: "SELECT $$DROP TABLE x$$ LIMIT 1", wantClass: Read, wantKind: "select", wantLimit: 1},
		{sql: "SELECT $fn$ DELETE FROM t; $$ $fn$ LIMIT 1", wantClass: Read},
		{sql: "SELECT $a$x$a$ LIMIT 1", wantClass: Read},
		{sql: "SELECT $$unterminated LIMIT 1", wantErr: "unterminated"},
		{sql: "SELECT $1 LIMIT 1", wantErr: "parameter"},
		{sql: "SELECT E'it\\'s' LIMIT 1", wantClass: Read},
		{sql: "SELECT e'a\\\\b' LIMIT 1", wantClass: Read},
		{sql: "SELECT E'it\\' LIMIT 1", wantErr: "unterminated"},
		{sql: "SELECT 'it\\'s' LIMIT 1", wantErr: "backslash"},
		{sql: "SELECT \"drop\" FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT \"a\"\"b\" FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT id FROM t FETCH FIRST 5 ROWS ONLY", wantClass: Read, wantKind: "select", wantLimit: 5},
		{sql: "SELECT id FROM t ORDER BY id OFFSET 10 ROWS FETCH NEXT 3 ROWS ONLY", wantClass: Read, wantKind: "select", wantLimit: 3},
		{sql: "SELECT id FROM t FETCH FIRST ROW ONLY", wantClass: Read, wantKind: "select", wantLimit: 1},
		{sql: "SELECT id FROM t FETCH FIRST 500 ROWS ONLY", wantErr: "exceeds"},
		{sql: "SELECT id FROM t FETCH FIRST 5 ROWS WITH TIES", wantErr: "TIES"},
		{sql: "SELECT id FROM t OFFSET 5 LIMIT 5", wantClass: Read, wantKind: "select", wantLimit: 5},
		{sql: "SELECT id FROM t LIMIT 10, 20", wantErr: "LIMIT"},
		{sql: "TABLE t LIMIT 5", wantClass: Read, wantKind: "select", wantLimit: 5},
		{sql: "TABLE t", wantErr: "LIMIT"},
		{sql: "SHOW work_mem", wantClass: Read, wantKind: "show"},
		{sql: "SELECT a @> b, a <@ b, @ -5, t @@ q FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT @x LIMIT 1", wantErr: "variable"},
		{sql: "SELECT a # b, a::int FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT a ? 'k' FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT pg_sleep(1) LIMIT 1", wantErr: "PG_SLEEP"},
		{sql: "SELECT pg_sleep_for('1 s') LIMIT 1", wantErr: "PG_SLEEP_FOR"},
		{sql: "SELECT pg_catalog.pg_sleep(1) LIMIT 1", wantErr: "PG_SLEEP"},
		{sql: "SELECT \"pg_sleep\"(1) LIMIT 1", wantErr: "PG_SLEEP"},
		// PostgreSQL ends a number at '$': 1$$ is the integer 1 then a dollar quote.
		{sql: "SELECT 1$$ $$, pg_sleep(1) $$ LIMIT 1", wantErr: "unterminated dollar-quoted"},
		{sql: "SELECT 1$$ $$, pg_sleep(1), 2$$ $$ LIMIT 1", wantErr: "PG_SLEEP"},
		{sql: "SELECT 1.5$$ $$, pg_sleep(1), 2$$ $$ LIMIT 1", wantErr: "PG_SLEEP"},
		{sql: "SELECT 1e3$$ $$, pg_sleep(1), 2$$ $$ LIMIT 1", wantErr: "PG_SLEEP"},
		{sql: "SELECT 1$$x$$ LIMIT 1", wantClass: Read},
		{sql: "SELECT 1$1 LIMIT 1", wantErr: "$n"},
		{sql: "SELECT pg_read_file('x') LIMIT 1", wantErr: "PG_READ_FILE"},
		{sql: "SELECT pg_read_binary_file('x') LIMIT 1", wantErr: "PG_READ_BINARY_FILE"},
		{sql: "SELECT * FROM pg_ls_dir('.') LIMIT 1", wantErr: "PG_LS_DIR"},
		{sql: "SELECT lo_import('/etc/hosts') LIMIT 1", wantErr: "LO_IMPORT"},
		{sql: "SELECT lo_export(1, '/tmp/x') LIMIT 1", wantErr: "LO_EXPORT"},
		// Large objects: writes outside the classifier's sight, at any tier.
		{sql: "SELECT lo_unlink(1) LIMIT 1", wantErr: "LO_UNLINK"},
		{sql: "SELECT lo_create(0) LIMIT 1", wantErr: "LO_CREATE"},
		{sql: "SELECT lo_creat(-1) LIMIT 1", wantErr: "LO_CREAT"},
		{sql: "SELECT lo_open(1, 131072) LIMIT 1", wantErr: "LO_OPEN"},
		{sql: "SELECT lo_put(1, 0, 'x') LIMIT 1", wantErr: "LO_PUT"},
		{sql: "SELECT lo_get(1) LIMIT 1", wantErr: "LO_GET"},
		{sql: "SELECT lo_from_bytea(0, 'x') LIMIT 1", wantErr: "LO_FROM_BYTEA"},
		{sql: "SELECT lo_truncate(0, 0) LIMIT 1", wantErr: "LO_TRUNCATE"},
		{sql: "SELECT lo_write(0, 'x') LIMIT 1", wantErr: "LO_WRITE"},
		{sql: "SELECT loread(0, 10) LIMIT 1", wantErr: "LOREAD"},
		{sql: "SELECT lowrite(0, 'x') LIMIT 1", wantErr: "LOWRITE"},
		{sql: "SELECT lo_close(0) LIMIT 1", wantErr: "LO_CLOSE"},
		{sql: "SELECT pg_catalog.lo_unlink(oid) FROM pg_largeobject_metadata LIMIT 1", wantErr: "LO_UNLINK"},
		{sql: "SELECT \"lo_put\"(1, 0, 'x') LIMIT 1", wantErr: "LO_PUT"},
		{sql: "SELECT pg_advisory_lock(1) LIMIT 1", wantErr: "PG_ADVISORY_LOCK"},
		{sql: "SELECT pg_try_advisory_lock(1) LIMIT 1", wantErr: "PG_TRY_ADVISORY_LOCK"},
		{sql: "SELECT dblink_exec('c', 'DELETE FROM t') LIMIT 1", wantErr: "DBLINK_EXEC"},
		{sql: "SELECT query_to_xml('DELETE FROM t', true, true, '') LIMIT 1", wantErr: "QUERY_TO_XML"},
		{sql: "SELECT pg_terminate_backend(1) LIMIT 1", wantErr: "PG_TERMINATE_BACKEND"},
		{sql: "SELECT set_config('a','b',false) LIMIT 1", wantErr: "SET_CONFIG"},
		{sql: "SELECT nextval('s') LIMIT 1", wantErr: "sequence"},
		{sql: "COPY t TO '/tmp/x'", wantErr: "COPY"},
		{sql: "COPY t FROM PROGRAM 'x'", wantErr: "COPY"},
		{sql: "COPY t TO STDOUT", wantErr: "COPY"},
		{sql: "SET ROLE x", wantErr: "ROLE"},
		{sql: "SET SESSION AUTHORIZATION x", wantErr: "AUTHORIZATION"},
		{sql: "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE", wantErr: "CHARACTERISTICS"},
		{sql: "SET statement_timeout = 0", wantErr: "STATEMENT_TIMEOUT"},
		{sql: "SET \"statement_timeout\" = 0", wantErr: "STATEMENT_TIMEOUT"},
		{sql: "SET LOCAL search_path = evil", wantErr: "SEARCH_PATH"},
		{sql: "SET default_transaction_read_only = off", wantErr: "DEFAULT_TRANSACTION_READ_ONLY"},
		{sql: "SET work_mem = '64MB'", wantClass: Admin, wantKind: "set"},
		{sql: "VACUUM", wantClass: Admin, wantKind: "vacuum", wantLimit: -1},
		{sql: "VACUUM ANALYZE t", wantClass: Admin},
		{sql: "ANALYZE VERBOSE t", wantClass: Admin},
		{sql: "REINDEX TABLE t", wantClass: Admin},
		{sql: "CALL p(1)", wantClass: Admin},
		{sql: "GRANT SELECT ON t TO r", wantClass: Admin},
		{sql: "DELETE FROM t", wantClass: Write, wantKind: "delete"},
		{sql: "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", wantClass: Write, wantKind: "merge"},
		// INSERT, UPDATE and MERGE are non-reserved: as column names they do not make a write.
		{sql: "SELECT merge FROM t LIMIT 1", wantClass: Read, wantKind: "select", wantLimit: 1},
		{sql: "SELECT insert, update FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT t.merge, t.insert AS i FROM t WHERE update = 1 LIMIT 1", wantClass: Read},
		{sql: "SELECT id FROM t WHERE insert IS NULL AND update > 0 LIMIT 1", wantClass: Read},
		{sql: "WITH m AS (MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE RETURNING *) SELECT * FROM m LIMIT 1", wantClass: Write, wantKind: "merge"},
		{sql: "WITH RECURSIVE x AS (SELECT 1 AS id) CYCLE id SET c USING p UPDATE t SET a = 1", wantClass: Write, wantKind: "update"},
		{sql: "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", wantClass: Write, wantKind: "insert"},
		{sql: "INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET a = 2", wantClass: Write},
		{sql: "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d LIMIT 1", wantClass: Write, wantKind: "delete", wantLimit: -1},
		{sql: "WITH d AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM d", wantClass: Write, wantKind: "update"},
		{sql: "WITH d AS (INSERT INTO t VALUES (1) RETURNING id) SELECT id FROM d", wantClass: Write, wantKind: "insert"},
		{sql: "WITH x AS (SELECT 1) SELECT * FROM x FOR UPDATE LIMIT 1", wantErr: "FOR UPDATE"},
		{sql: "SELECT * FROM t LIMIT 1 FOR NO KEY UPDATE", wantErr: "FOR NO KEY UPDATE"},
		{sql: "SELECT * FROM t LIMIT 1 FOR KEY SHARE", wantErr: "FOR KEY SHARE"},
		{sql: "SELECT substring(s FROM 1 FOR 2) FROM t LIMIT 1", wantClass: Read},
		{sql: "TRUNCATE t", wantClass: DDL},
		{sql: "COMMENT ON TABLE t IS 'x'", wantClass: DDL, wantKind: "comment"},
		{sql: "CREATE ROLE r PASSWORD 'x'", wantErr: "credential"},
		{sql: "ALTER SYSTEM SET work_mem = '1GB'", wantErr: "ALTER SYSTEM"},
		{sql: "CREATE EXTENSION dblink", wantErr: "EXTENSION"},
		{sql: "DO $$BEGIN DELETE FROM t; END$$", wantErr: "not allowed"},
		{sql: "LOAD 'plugin'", wantErr: "not allowed"},
		{sql: "\\set x 1", wantErr: "backslash"},
		{sql: "DESCRIBE t", wantErr: "cannot be classified"},
		{sql: "SELECT (a := 1) LIMIT 1", wantErr: "assignment"},
	},
	SQLite: {
		{sql: "SELECT [order] FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT [delete], `update`, \"drop\" FROM t LIMIT 1", wantClass: Read},
		{sql: "SELECT [unterminated FROM t LIMIT 1", wantErr: "unterminated"},
		{sql: "SELECT id FROM t LIMIT 10, 20", wantClass: Read, wantKind: "select", wantLimit: 20},
		{sql: "ATTACH 'x.db' AS y", wantErr: "ATTACH"},
		{sql: "ATTACH DATABASE 'x.db' AS y", wantErr: "ATTACH"},
		{sql: "DETACH y", wantErr: "DETACH"},
		{sql: "SELECT load_extension('x') LIMIT 1", wantErr: "LOAD_EXTENSION"},
		{sql: "SELECT fts3_tokenizer('x') LIMIT 1", wantErr: "FTS3_TOKENIZER"},
		{sql: "PRAGMA table_info(t)", wantClass: Read, wantKind: "pragma", wantLimit: -1},
		{sql: "PRAGMA main.table_info(t)", wantClass: Read, wantKind: "pragma"},
		{sql: "PRAGMA index_list('t')", wantClass: Read},
		{sql: "PRAGMA journal_mode", wantClass: Read},
		{sql: "PRAGMA journal_mode = WAL", wantErr: "PRAGMA"},
		{sql: "PRAGMA journal_mode(WAL)", wantErr: "PRAGMA"},
		{sql: "PRAGMA query_only = 0", wantErr: "PRAGMA"},
		{sql: "PRAGMA query_only = false", wantErr: "PRAGMA"},
		{sql: "PRAGMA writable_schema", wantErr: "PRAGMA"},
		{sql: "PRAGMA wal_checkpoint", wantErr: "PRAGMA"},
		{sql: "SELECT * FROM pragma_table_info('t') LIMIT 5", wantClass: Read},
		{sql: "INSERT OR REPLACE INTO t VALUES (1)", wantClass: Write, wantKind: "insert"},
		{sql: "REPLACE INTO t VALUES (1)", wantClass: Write, wantKind: "replace"},
		{sql: "WITH x AS (SELECT 1 AS a) REPLACE INTO t SELECT a FROM x", wantClass: Write, wantKind: "replace"},
		{sql: "WITH x AS (SELECT 1 AS a) INSERT INTO t SELECT a FROM x", wantClass: Write, wantKind: "insert"},
		{sql: "WITH x AS (SELECT 1 AS a) INSERT OR IGNORE INTO t SELECT a FROM x", wantClass: Write, wantKind: "insert"},
		{sql: "WITH x AS (SELECT 1 AS a) UPDATE [t] SET a = 1", wantClass: Write, wantKind: "update"},
		{sql: "SELECT update FROM t LIMIT 1", wantClass: Read},
		{sql: "VACUUM", wantClass: Admin},
		{sql: "VACUUM INTO '/tmp/copy.db'", wantErr: "INTO"},
		{sql: "SELECT :name LIMIT 1", wantErr: "parameter"},
		{sql: "SELECT $name LIMIT 1", wantErr: "parameter"},
		{sql: "SELECT ?1 LIMIT 1", wantErr: "parameter"},
		{sql: "SELECT 1 LIMIT 1 # x", wantErr: "#"},
		{sql: "SHOW TABLES", wantErr: "cannot be classified"},
		{sql: "GRANT SELECT ON t TO x", wantErr: "cannot be classified"},
	},
}

func runCorpus(t *testing.T, d Dialect, cases []corpusCase) {
	t.Helper()
	for _, c := range cases {
		st, err := Classify(d, c.sql, corpusMaxRows)
		name := d.String() + ": " + c.sql
		if c.wantErr != "" {
			if err == nil {
				t.Errorf("%s: accepted as %v, want refusal containing %q", name, st.Class, c.wantErr)
				continue
			}
			var r *Refusal
			if !errors.As(err, &r) {
				t.Errorf("%s: error %T is not *Refusal", name, err)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: refusal %q does not contain %q", name, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: refused (%v), want %v", name, err, c.wantClass)
			continue
		}
		if st.Class != c.wantClass {
			t.Errorf("%s: class %v, want %v", name, st.Class, c.wantClass)
		}
		if c.wantKind != "" {
			if st.Kind != c.wantKind {
				t.Errorf("%s: kind %q, want %q", name, st.Kind, c.wantKind)
			}
			want := -1
			if c.wantKind == "select" {
				want = c.wantLimit
			}
			if st.Limit != want {
				t.Errorf("%s: limit %d, want %d", name, st.Limit, want)
			}
		}
		if strings.HasSuffix(st.SQL, ";") || st.SQL != strings.TrimSpace(st.SQL) {
			t.Errorf("%s: SQL %q keeps a trailing ';' or blanks", name, st.SQL)
		}
	}
}

func TestCorpusCommon(t *testing.T) {
	for _, d := range allDialects {
		runCorpus(t, d, commonCorpus)
	}
}

func TestCorpusDialect(t *testing.T) {
	for _, d := range allDialects {
		runCorpus(t, d, dialectCorpus[d])
	}
}

// FuzzLexNoPanic checks that neither the lexer nor the classifier panics,
// and that every error they return is a *Refusal. CI nightly runs it with
// -fuzz for 30 s; a plain `go test` runs the seed corpus only.
func FuzzLexNoPanic(f *testing.F) {
	for _, c := range commonCorpus {
		f.Add(c.sql)
	}
	for _, d := range allDialects {
		for _, c := range dialectCorpus[d] {
			f.Add(c.sql)
		}
	}
	f.Add("SELECT $")
	f.Add("SELECT $a")
	f.Add("SELECT E'")
	f.Add("SELECT [")
	f.Add("SELECT \xff\xfe LIMIT 1")
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range allDialects {
			if _, err := Lex(d, sql); err != nil {
				var r *Refusal
				if !errors.As(err, &r) {
					t.Fatalf("Lex(%v): error %T is not *Refusal", d, err)
				}
			}
			st, err := Classify(d, sql, corpusMaxRows)
			if err != nil {
				var r *Refusal
				if !errors.As(err, &r) {
					t.Fatalf("Classify(%v): error %T is not *Refusal", d, err)
				}
				continue
			}
			if st.Class == Read && st.Kind == "select" && (st.Limit < 0 || st.Limit > corpusMaxRows) {
				t.Fatalf("Classify(%v, %q): READ select with limit %d", d, sql, st.Limit)
			}
		}
	})
}
