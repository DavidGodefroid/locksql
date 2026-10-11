//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	_ "github.com/DavidGodefroid/locksql/internal/engine/sqlite"
	"github.com/DavidGodefroid/locksql/internal/pii"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// The canary suite seeds two masked columns with unique values, runs a
// generated corpus of reads through the full plan and run path, and fails
// when any answer the agent gets holds a canary, a piece of one or a
// reversible transform of one. A refusal or a server error is safe.
//
// Tables: canary(id, label, secret, doc) where secret holds CANARY-<id>
// and doc a JSON object {"token": "CANARY-<id>", "n": id}; both are under
// a mask rule. pal(id, name) holds no PII.

// canaryRows is the number of seeded rows: above the k-anonymity default
// so that a grouped read is not refused for its size alone.
const canaryRows = 20

// canaryAlphabet spells the random part of a canary. Its letters are no hex
// digit, no vowel and none that clusters in English or SQL ("nstr" in
// "constructors"), so that a run of 4 of them does not turn up by chance in
// a plan id, a number or a message.
const canaryAlphabet = "GJKQVWXZ"

// canaryPrefix starts every canary value. No query of the corpus spells it.
const canaryPrefix = "CANARY-"

// newCanaryID returns 43 random letters of canaryAlphabet, 3 bits each: a
// uuid's worth of randomness.
func newCanaryID() string {
	var b [43]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = canaryAlphabet[b[i]&7]
	}
	return string(b[:])
}

// canarySeed is one set of seeded values.
type canarySeed struct {
	secrets []string // canary.secret, row i+1
	tokens  []string // canary.doc token, row i+1
}

func newCanarySeed() canarySeed {
	var c canarySeed
	for range canaryRows {
		c.secrets = append(c.secrets, canaryPrefix+newCanaryID())
		c.tokens = append(c.tokens, canaryPrefix+newCanaryID())
	}
	return c
}

// statements returns the DDL and the inserts that seed the tables. jsonType
// is the engine's type for doc.
func (c canarySeed) statements(jsonType string) []string {
	out := []string{
		"CREATE TABLE canary (id INT PRIMARY KEY, label VARCHAR(40), secret VARCHAR(80), doc " + jsonType + ")",
		"CREATE TABLE pal (id INT PRIMARY KEY, name VARCHAR(40))",
	}
	var rows, pals []string
	for i := range canaryRows {
		rows = append(rows, fmt.Sprintf(`(%d, 'row%d', '%s', '{"token": "%s", "n": %d}')`, i+1, i+1, c.secrets[i], c.tokens[i], i+1))
		pals = append(pals, fmt.Sprintf("(%d, 'pal%d')", i+1, i+1))
	}
	return append(out,
		"INSERT INTO canary (id, label, secret, doc) VALUES "+strings.Join(rows, ", "),
		"INSERT INTO pal (id, name) VALUES "+strings.Join(pals, ", "))
}

// canaryDetector finds canary material in a text.
type canaryDetector struct {
	folded []string // looked up in the lower-cased text
	exact  []string // looked up as is (base64 is case-sensitive)
}

func newCanaryDetector(c canarySeed) canaryDetector {
	var d canaryDetector
	fold := func(s string) { d.folded = append(d.folded, strings.ToLower(s)) }
	b64 := func(s string) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
			d.exact = append(d.exact, strings.TrimRight(enc.EncodeToString([]byte(s)), "="))
		}
	}
	for _, p := range []string{canaryPrefix, strings.ToLower(canaryPrefix)} {
		fold(p)
		fold(reverse(p))
		fold(hex.EncodeToString([]byte(p)))
	}
	for _, v := range append(append([]string{}, c.secrets...), c.tokens...) {
		id := strings.TrimPrefix(v, canaryPrefix)
		for _, s := range []string{v, id, strings.ToLower(v), strings.ToLower(id)} {
			b64(s)
			fold(hex.EncodeToString([]byte(s)))
		}
		// Every substring of 4 letters or more of the id, read either way,
		// contains one of these 4-letter pieces; hex is twice as long.
		for _, s := range []string{id, reverse(id)} {
			for i := 0; i+4 <= len(s); i++ {
				fold(s[i : i+4])
				fold(hex.EncodeToString([]byte(s[i : i+4])))
				fold(hex.EncodeToString([]byte(strings.ToLower(s[i : i+4]))))
			}
			// A base64 text of 8 letters or more of the id holds one
			// 3-aligned piece of 6 letters: 8 characters of base64.
			for i := 0; i+6 <= len(s); i++ {
				for _, piece := range []string{s[i : i+6], strings.ToLower(s[i : i+6])} {
					d.exact = append(d.exact, base64.StdEncoding.EncodeToString([]byte(piece)))
				}
			}
		}
	}
	return d
}

// find returns the first canary material in text, or "".
func (d canaryDetector) find(text string) string {
	lower := strings.ToLower(text)
	for _, n := range d.folded {
		if strings.Contains(lower, n) {
			return n
		}
	}
	for _, n := range d.exact {
		if strings.Contains(text, n) {
			return n
		}
	}
	return ""
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// canaryDialect holds the spellings that differ between engines. Each
// template has one {e}: an expression over the canary row, aliased c.
type canaryDialect struct {
	sources  []string // expressions that read a canary column
	wrappers []string // scalar functions around a source
	aggs     []string // aggregate functions around a source
	windows  []string // window functions around a source
	extra    []string // whole statements
}

func canaryDialectFor(f engine.Flavor) canaryDialect {
	common := canaryDialect{
		sources: []string{"c.secret", "c.doc"},
		wrappers: []string{
			"{e}",
			"COALESCE({e}, 'x')",
			"NULLIF({e}, 'x')",
			"CASE WHEN c.id > 0 THEN {e} END",
			"UPPER({e})",
			"LOWER({e})",
			"SUBSTR({e}, 8, 12)",
			"SUBSTR({e}, 12)",
			"REPLACE({e}, '-', '_')",
			"TRIM({e})",
		},
		aggs: []string{"MAX({e})", "MIN({e})"},
		windows: []string{
			"FIRST_VALUE({e}) OVER (ORDER BY c.id)",
			"LAG({e}) OVER (ORDER BY c.id)",
			"LEAD({e}, 1) OVER (PARTITION BY c.id % 2 ORDER BY c.id)",
			"MAX({e}) OVER ()",
			"NTH_VALUE({e}, 2) OVER (ORDER BY c.id ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)",
		},
		extra: []string{
			"SELECT * FROM canary LIMIT 50",
			"SELECT c.* FROM canary c LIMIT 50",
			"SELECT p.*, c.* FROM pal p JOIN canary c ON c.id = p.id LIMIT 50",
			"SELECT t.* FROM (SELECT * FROM canary) t LIMIT 50",
			"WITH w AS (SELECT * FROM canary) SELECT * FROM w LIMIT 50",
			"SELECT name FROM pal UNION SELECT secret FROM canary LIMIT 50",
			"SELECT secret FROM canary UNION SELECT name FROM pal LIMIT 50",
			"SELECT secret AS name FROM canary WHERE id < 5 UNION ALL SELECT name FROM pal LIMIT 50",
			"SELECT secret FROM canary INTERSECT SELECT secret FROM canary LIMIT 50",
			"SELECT secret FROM canary EXCEPT SELECT name FROM pal LIMIT 50",
			"SELECT secret, COUNT(*) AS n FROM canary GROUP BY secret LIMIT 50",
			"SELECT DISTINCT secret FROM canary LIMIT 50",
			"SELECT label AS secret, secret AS label FROM canary LIMIT 50",
		},
	}
	switch f {
	case engine.FlavorMySQL, engine.FlavorMariaDB:
		common.sources = append(common.sources,
			"JSON_EXTRACT(c.doc, '$.token')",
			"JSON_UNQUOTE(JSON_EXTRACT(c.doc, '$.token'))",
			"JSON_VALUE(c.doc, '$.token')")
		if f == engine.FlavorMySQL {
			common.sources = append(common.sources, "c.doc->>'$.token'")
		}
		common.wrappers = append(common.wrappers,
			"CAST({e} AS CHAR(200))",
			"CONVERT({e}, CHAR)",
			"CAST({e} AS BINARY)",
			"CONCAT({e}, '')",
			"CONCAT(c.label, ':', {e})",
			"CONCAT_WS('|', c.label, {e})",
			"IFNULL({e}, 'x')",
			"IF(c.id > 0, {e}, NULL)",
			"ELT(1, {e})",
			"REVERSE({e})",
			"HEX({e})",
			"TO_BASE64({e})",
			"LPAD({e}, 60, '*')",
			"LEFT({e}, 20)",
			"RIGHT({e}, 20)",
			"MID({e}, 9, 10)",
			"SUBSTRING_INDEX({e}, '-', -1)",
			"INSERT({e}, 1, 7, '')",
			"GREATEST({e}, 'A')",
			"JSON_OBJECT('k', {e})",
			"JSON_ARRAY({e})",
			"JSON_QUOTE({e})",
			"CHAR_LENGTH({e})",
			// Error-based extraction: the value would ride in the message.
			"EXTRACTVALUE(1, CONCAT(0x5c, {e}))",
			"UPDATEXML(1, CONCAT(0x5c, {e}), 1)",
			"JSON_EXTRACT('{}', CONCAT('$.', {e}))",
			"CAST({e} AS SIGNED)",
		)
		common.aggs = append(common.aggs,
			"GROUP_CONCAT({e})",
			"GROUP_CONCAT({e} ORDER BY c.id SEPARATOR '|')",
			"JSON_ARRAYAGG({e})",
			"JSON_OBJECTAGG(c.id, {e})")
		common.extra = append(common.extra,
			"SELECT JSON_OBJECT('a', c.secret, 'b', c.doc) AS j FROM canary c LIMIT 50",
			"SELECT JSON_SEARCH(c.doc, 'one', 'C%') AS j FROM canary c LIMIT 50",
			"SELECT JSON_KEYS(c.doc) AS j FROM canary c LIMIT 50",
			"SELECT j.v FROM canary c, JSON_TABLE(c.doc, '$' COLUMNS (v VARCHAR(80) PATH '$.token')) j LIMIT 50",
			"WITH RECURSIVE r (n, v) AS (SELECT 1, CAST(secret AS CHAR(80)) FROM canary WHERE id = 1 UNION ALL SELECT n + 1, v FROM r WHERE n < 3) SELECT v FROM r LIMIT 50",
			"SELECT secret FROM canary ORDER BY id LIMIT 50 INTO @x",
			"SELECT @@hostname, (SELECT secret FROM canary LIMIT 1) AS s LIMIT 1",
		)
	case engine.FlavorPostgres:
		common.sources = append(common.sources,
			"c.doc->>'token'",
			"c.doc->'token'",
			"c.doc#>>'{token}'",
			"jsonb_extract_path_text(c.doc, 'token')")
		common.wrappers = append(common.wrappers,
			"CAST({e} AS text)",
			"({e})::varchar(200)",
			"CONCAT({e}, '')",
			"c.label || ':' || {e}",
			"CONCAT_WS('|', c.label, {e})",
			"format('%s', {e})",
			"REVERSE({e}::text)",
			"encode(convert_to({e}::text, 'UTF8'), 'hex')",
			"encode(convert_to({e}::text, 'UTF8'), 'base64')",
			"convert_to({e}::text, 'UTF8')",
			"LPAD({e}::text, 60, '*')",
			"LEFT({e}::text, 20)",
			"RIGHT({e}::text, 20)",
			"split_part({e}::text, '-', 2)",
			"OVERLAY({e}::text PLACING '' FROM 1 FOR 7)",
			"GREATEST({e}::text, 'A')",
			"json_build_object('k', {e})::text",
			"to_jsonb({e})",
			"jsonb_build_array({e})",
			"ARRAY[{e}::text]",
			"quote_literal({e})",
			"md5({e}::text) || {e}::text",
			"regexp_replace({e}::text, '(.)', '\\1 ', 'g')",
			"string_to_array({e}::text, '-')",
			"translate({e}::text, 'GJ', 'gj')",
			// Error-based extraction: the value would ride in the message.
			"CAST({e} AS int)",
			"({e})::text::numeric",
			"({e})::text::date",
			"({e})::text::jsonb",
			"({e})::text::regclass",
			"({e})::text::regproc",
			"({e})::text::uuid",
			"({e})::text::inet",
			"to_number({e}::text, '999')",
		)
		common.aggs = append(common.aggs,
			"string_agg({e}::text, ',')",
			"string_agg({e}::text, '|' ORDER BY c.id DESC)",
			"array_agg({e})::text",
			"json_agg({e})::text",
			"jsonb_object_agg(c.id, {e})",
			"MAX({e}::text)")
		common.extra = append(common.extra,
			"SELECT row_to_json(c)::text FROM canary c LIMIT 50",
			"SELECT to_jsonb(c) FROM canary c LIMIT 50",
			"SELECT c::text FROM canary c LIMIT 50",
			"SELECT (c).secret FROM canary c LIMIT 50",
			"SELECT c.label, j.* FROM canary c, jsonb_each_text(c.doc) j LIMIT 50",
			"SELECT j FROM canary c, jsonb_path_query(c.doc, '$.token') j LIMIT 50",
			"SELECT jsonb_pretty(c.doc) FROM canary c LIMIT 50",
			"SELECT unnest(ARRAY[c.secret, c.label]) FROM canary c LIMIT 50",
			"SELECT array_agg(c)::text FROM canary c LIMIT 50",
			"WITH RECURSIVE r (n, v) AS (SELECT 1, secret::text FROM canary WHERE id = 1 UNION ALL SELECT n + 1, v FROM r WHERE n < 3) SELECT v FROM r LIMIT 50",
			"SELECT (SELECT secret FROM canary LIMIT 1)::int",
			"SELECT secret FROM canary FOR UPDATE",
			"VALUES ((SELECT secret FROM canary LIMIT 1))",
			"TABLE canary LIMIT 50",
		)
	case engine.FlavorSQLite:
		common.sources = append(common.sources,
			"json_extract(c.doc, '$.token')",
			"c.doc->>'$.token'",
			"c.doc->'$.token'")
		common.wrappers = append(common.wrappers,
			"CAST({e} AS TEXT)",
			"CAST({e} AS BLOB)",
			"{e} || ''",
			"c.label || ':' || {e}",
			"IFNULL({e}, 'x')",
			"IIF(c.id > 0, {e}, NULL)",
			"HEX({e})",
			"printf('%s', {e})",
			"quote({e})",
			"unicode({e})",
			"SUBSTRING({e}, 9, 10)",
			"ltrim({e}, 'CANRY')",
			"rtrim({e}, 'Z')",
			"MAX({e}, 'A')",
			"json_object('k', {e})",
			"json_array({e})",
			"json_quote({e})",
			"json({e})",
			"instr({e}, 'G')",
		)
		common.aggs = append(common.aggs,
			"GROUP_CONCAT({e})",
			"GROUP_CONCAT({e}, '|')",
			"json_group_array({e})",
			"json_group_object(c.id, {e})")
		common.extra = append(common.extra,
			"SELECT j.value FROM canary c, json_each(c.doc) j LIMIT 50",
			"SELECT j.* FROM canary c, json_tree(c.doc) j LIMIT 50",
			"WITH RECURSIVE r (n, v) AS (SELECT 1, secret FROM canary WHERE id = 1 UNION ALL SELECT n + 1, v FROM r WHERE n < 3) SELECT v FROM r LIMIT 50",
			"SELECT secret FROM canary NOT INDEXED LIMIT 50",
		)
	}
	return common
}

// canaryShapes place a projection (one {e}, over a canary row aliased c)
// in the statement forms of the corpus.
var canaryShapes = []string{
	"SELECT {e} AS v FROM canary c LIMIT 50",
	"SELECT p.name, {e} AS v FROM canary c JOIN pal p ON p.id = c.id LIMIT 50",
	"SELECT p.name, {e} AS v FROM pal p LEFT JOIN canary c ON c.id = p.id LIMIT 50",
	"WITH w AS (SELECT {e} AS v FROM canary c) SELECT w.v FROM w LIMIT 50",
	"WITH c AS (SELECT * FROM canary) SELECT {e} AS v FROM c LIMIT 50",
	"SELECT d.v FROM (SELECT {e} AS v FROM canary c) d LIMIT 50",
	"SELECT p.name AS v FROM pal p UNION ALL SELECT {e} FROM canary c LIMIT 50",
	"SELECT {e} AS v FROM canary c UNION SELECT p.name FROM pal p LIMIT 50",
	"SELECT p.id, (SELECT {e} FROM canary c WHERE c.id = p.id) AS v FROM pal p LIMIT 50",
}

// canaryQueries generates the corpus for flavor f: every wrapper over every
// source in the plain shape, every wrapper over secret in every shape,
// every aggregate and window over every source in a few shapes, two
// wrappers deep over secret, and the dialect's whole statements.
func canaryQueries(f engine.Flavor) []string {
	d := canaryDialectFor(f)
	var out []string
	seen := map[string]bool{}
	add := func(q string) {
		if !seen[q] {
			seen[q] = true
			out = append(out, q)
		}
	}
	place := func(tmpl, expr string) string { return strings.ReplaceAll(tmpl, "{e}", expr) }
	for _, src := range d.sources {
		for _, w := range d.wrappers {
			add(place(canaryShapes[0], place(w, src)))
		}
	}
	for _, sh := range canaryShapes[1:] {
		for _, w := range d.wrappers {
			add(place(sh, place(w, "c.secret")))
		}
	}
	for _, src := range d.sources {
		for _, fn := range append(append([]string{}, d.aggs...), d.windows...) {
			for _, sh := range []string{canaryShapes[0], canaryShapes[3], canaryShapes[5], canaryShapes[8]} {
				add(place(sh, place(fn, src)))
			}
		}
	}
	for _, outer := range d.wrappers[1:] {
		for _, inner := range d.wrappers[1:] {
			add(place(canaryShapes[0], place(outer, place(inner, "c.secret"))))
		}
	}
	for _, q := range d.extra {
		add(q)
	}
	return out
}

// assertNoCanary runs the corpus for s's flavor through a console server
// on database db, under the canary mask rules of schema (db itself, but on
// PostgreSQL), and fails on any canary material in an answer. The
// statements that ran run again under the partial and email mask modes,
// which show a little of each value.
func assertNoCanary(t *testing.T, s engine.Session, db, schema string, seed canarySeed) {
	t.Helper()
	secret, doc := schema+".canary.secret", schema+".canary.doc"
	det := newCanaryDetector(seed)
	// The control: unmasked, the detector sees the seed.
	r, err := s.Run(context.Background(), db, read("SELECT secret, doc FROM canary WHERE id = 1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(r.Rows); det.find(string(raw)) == "" {
		t.Fatalf("the detector misses the raw seed: %s", raw)
	}
	var ran []string
	check := func(q string, run bool, answer string) {
		if n := det.find(answer); n != "" {
			stage := "plan"
			if run {
				stage = "run"
			}
			t.Errorf("%s: %s answer holds canary material %q: %s", q, stage, n, answer)
		}
		if run && strings.Contains(answer, `"rows":[[`) {
			ran = append(ran, q)
		}
	}
	queries := canaryQueries(s.Flavor())
	asAgent(t, s, db, pii.Rules{Mask: []string{secret, doc}}, queries, check)
	t.Logf("%d statements, %d returned rows", len(queries), len(ran))
	if len(ran) == 0 {
		t.Fatal("no statement of the corpus returned a row: the suite proves nothing")
	}
	modes := pii.Rules{Mask: []string{secret, doc}, Modes: map[string]string{secret: pii.ModePartial, doc: pii.ModeEmail}}
	asAgent(t, s, db, modes, ran, check)
}

func TestCanary(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		seed := newCanarySeed()
		path := filepath.Join(t.TempDir(), "canary.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range seed.statements("TEXT") {
			if _, err := db.Exec(q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		db.Close()
		e, err := engine.Get(config.EngineSQLite)
		if err != nil {
			t.Fatal(err)
		}
		s, err := e.Connect(context.Background(), config.Profile{Name: "it", Engine: config.EngineSQLite, Path: path,
			Tier: config.TierRead, Limits: config.DefaultLimits(false)}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		assertNoCanary(t, s, "main", "main", seed)
	})
	for _, m := range mysqlTargets() {
		t.Run(m.image(), func(t *testing.T) {
			srv := startMySQL(t, m)
			seed := newCanarySeed()
			admin := connectMySQL(t, m, srv, "rw", config.TierAdmin, 10*time.Second)
			seedCanary(t, admin, seed.statements("JSON"))
			assertNoCanary(t, connectMySQL(t, m, srv, "ro", config.TierRead, 5*time.Second), "app", "app", seed)
		})
	}
	for _, v := range pgVersions() {
		t.Run("postgres:"+v, func(t *testing.T) {
			srv := startPostgres(t, v)
			seed := newCanarySeed()
			admin := connectPG(t, srv, "postgres", config.TierAdmin, 10*time.Second)
			seedCanary(t, admin, append(seed.statements("jsonb"), "GRANT SELECT ON canary, pal TO ro", "ANALYZE canary, pal"))
			assertNoCanary(t, connectPG(t, srv, "ro", config.TierRead, 5*time.Second), "app", "public", seed)
		})
	}
}

// seedCanary runs the seed statements on an admin session and removes the
// tables at the end of the test: the containers are shared with the other
// tests, which list the tables.
func seedCanary(t *testing.T, admin engine.Session, stmts []string) {
	t.Helper()
	t.Cleanup(func() {
		drop := sqlclass.Statement{Class: sqlclass.DDL, Kind: "ddl", SQL: "DROP TABLE IF EXISTS canary, pal", Limit: -1}
		if _, err := admin.Run(context.Background(), "app", drop, 0); err != nil {
			t.Error(err)
		}
	})
	for _, q := range stmts {
		st := sqlclass.Statement{Class: sqlclass.DDL, Kind: "ddl", SQL: q, Limit: -1}
		if strings.HasPrefix(q, "INSERT") {
			st.Class, st.Kind = sqlclass.Write, "insert"
		}
		if _, err := admin.Run(context.Background(), "app", st, 0); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestCanaryDetector(t *testing.T) {
	seed := newCanarySeed()
	d := newCanaryDetector(seed)
	v := seed.secrets[3]
	id := strings.TrimPrefix(v, canaryPrefix)
	b64 := base64.StdEncoding.EncodeToString
	for _, leak := range []string{
		v, strings.ToLower(v), id[5:9], reverse(id)[10:14], strings.ToLower(id[20:24]),
		hex.EncodeToString([]byte(v)), strings.ToUpper(hex.EncodeToString([]byte(id[7:11]))),
		b64([]byte(v)), b64([]byte("x" + id)), b64([]byte("xy" + strings.ToLower(id))), b64([]byte(id[3:12])),
		seed.tokens[0][9:13], `{"token": "CANARY-`,
	} {
		if d.find("ok "+leak+" ok") == "" {
			t.Errorf("missed %q", leak)
		}
	}
	for _, clean := range []string{
		`{"plan_id":"3f9a0c1e2b7d4a65","summary":"read canary, 20 rows"}`,
		`{"columns":["v"],"rows":[["<redacted>"],[12345678],["2026-10-11"]]}`,
		"refused: an expression over the masked column canary.secret",
	} {
		if n := d.find(clean); n != "" {
			t.Errorf("false positive %q in %s", n, clean)
		}
	}
	// A plan answer echoes its statement: no statement may hold a run of
	// the alphabet.
	for _, f := range []engine.Flavor{engine.FlavorMariaDB, engine.FlavorMySQL, engine.FlavorPostgres, engine.FlavorSQLite} {
		for _, q := range canaryQueries(f) {
			for i := 0; i+4 <= len(q); i++ {
				if strings.Trim(strings.ToUpper(q[i:i+4]), canaryAlphabet) == "" {
					t.Errorf("%s: %q could match a canary", q, q[i:i+4])
				}
			}
		}
	}
}
