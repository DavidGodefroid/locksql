package mysql

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

func TestRegistered(t *testing.T) {
	for _, name := range []string{config.EngineMariaDB, config.EngineMySQL} {
		if _, err := engine.Get(name); err != nil {
			t.Error(err)
		}
	}
}

func TestParseGrants(t *testing.T) {
	mariaRO := []string{
		"GRANT USAGE ON *.* TO `ro`@`%` IDENTIFIED BY PASSWORD '*0123456789ABCDEF0123456789ABCDEF01234567'",
		"GRANT SELECT, SHOW VIEW ON `app`.* TO `ro`@`%`",
		"GRANT SELECT ON `other`.* TO `ro`@`%`",
	}
	cases := []struct {
		name  string
		lines []string
		tier  config.Tier
		want  string
	}{
		{"read-only account", mariaRO, config.TierRead, "[]"},
		{"all privileges", []string{"GRANT ALL PRIVILEGES ON *.* TO `rw`@`%` IDENTIFIED BY PASSWORD '*AB'"}, config.TierRead, "[ALL PRIVILEGES]"},
		{"all privileges at admin", []string{"GRANT ALL PRIVILEGES ON *.* TO `rw`@`%` WITH GRANT OPTION"}, config.TierAdmin, "[]"},
		{"write privileges at read", []string{"GRANT SELECT, INSERT, UPDATE, DELETE ON `app`.* TO `w`@`%`"}, config.TierRead, "[INSERT UPDATE DELETE]"},
		{"write privileges at write", []string{"GRANT SELECT, INSERT, UPDATE, DELETE ON `app`.* TO `w`@`%`"}, config.TierWrite, "[]"},
		{"ddl at write", []string{"GRANT CREATE, DROP, INDEX ON `app`.* TO `w`@`%`"}, config.TierWrite, "[CREATE DROP INDEX]"},
		{"ddl at ddl", []string{"GRANT CREATE, ALTER, DROP, INDEX, REFERENCES ON `app`.* TO `w`@`%`"}, config.TierDDL, "[]"},
		{"admin at ddl", []string{"GRANT PROCESS, SUPER ON *.* TO `w`@`%`"}, config.TierDDL, "[PROCESS SUPER]"},
		{"column privileges", []string{"GRANT SELECT (`a`, `b`), UPDATE (`c`) ON `app`.`t` TO `u`@`%`"}, config.TierRead, "[UPDATE]"},
		{"mysql dynamic privileges", []string{"GRANT APPLICATION_PASSWORD_ADMIN,AUDIT_ADMIN ON *.* TO `u`@`%`"}, config.TierRead, "[APPLICATION_PASSWORD_ADMIN AUDIT_ADMIN]"},
		{"grant option", []string{"GRANT SELECT ON `app`.* TO `u`@`%` WITH GRANT OPTION"}, config.TierRead, "[GRANT OPTION]"},
		{"role", []string{"GRANT `app_writer`@`%` TO `u`@`%`"}, config.TierRead, "[ROLE/PROXY: GRANT `app_writer`@`%`]"},
		{"proxy", []string{"GRANT PROXY ON ''@'' TO 'root'@'%' WITH GRANT OPTION"}, config.TierRead, "[ROLE/PROXY: GRANT PROXY ON ''@'']"},
		{"partial revoke", []string{"REVOKE INSERT ON `mysql`.* FROM `u`@`%`"}, config.TierRead, "[]"},
		{"duplicates", []string{"GRANT INSERT ON `a`.* TO `u`@`%`", "GRANT INSERT ON `b`.* TO `u`@`%`"}, config.TierRead, "[INSERT]"},
		{"lower case and spacing", []string{"grant show   databases, select on *.* to u@h"}, config.TierRead, "[]"},
	}
	for _, c := range cases {
		got := parseGrants(c.lines, c.tier)
		if fmt.Sprint(got) != c.want && !(c.want == "[]" && len(got) == 0) {
			t.Errorf("%s: got %q, want %s", c.name, got, c.want)
		}
		for _, e := range got {
			if strings.Contains(e, "IDENTIFIED") || strings.Contains(e, "*AB") {
				t.Errorf("%s: extra leaks a credential: %q", c.name, e)
			}
		}
	}
}

func TestValue(t *testing.T) {
	text := &gomysql.Field{Type: gomysql.MYSQL_TYPE_VAR_STRING, Charset: 45}
	blob := &gomysql.Field{Type: gomysql.MYSQL_TYPE_BLOB, Charset: binaryCharset}
	dec := &gomysql.Field{Type: gomysql.MYSQL_TYPE_NEWDECIMAL, Charset: binaryCharset}
	buf := []byte("abc")
	cases := []struct {
		v    gomysql.FieldValue
		f    *gomysql.Field
		want string
	}{
		{gomysql.NewFieldValue(gomysql.FieldValueTypeNull, 0, nil), text, "<nil> <nil>"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeSigned, uint64(1<<64-2), nil), text, "int64 -2"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeUnsigned, 7, nil), text, "int64 7"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeUnsigned, 1<<64-1, nil), text, "uint64 18446744073709551615"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeString, 0, buf), text, "string abc"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeString, 0, buf), blob, "[]uint8 [97 98 99]"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeString, 0, []byte("1.50")), dec, "string 1.50"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeString, 0, nil), blob, "[]uint8 []"},
		{gomysql.NewFieldValue(gomysql.FieldValueTypeString, 0, buf), nil, "string abc"},
	}
	for i, c := range cases {
		got := value(c.v, c.f)
		if s := fmt.Sprintf("%T %v", got, got); s != c.want {
			t.Errorf("case %d: %s, want %s", i, s, c.want)
		}
	}
	// The driver reuses its buffers: a []byte value must be a copy.
	b := value(gomysql.NewFieldValue(gomysql.FieldValueTypeString, 0, buf), blob).([]byte)
	buf[0] = 'X'
	if string(b) != "abc" {
		t.Error("value aliases the driver buffer")
	}
}

func TestTimeoutSQL(t *testing.T) {
	cases := []struct {
		f    engine.Flavor
		d    time.Duration
		want string
	}{
		{engine.FlavorMariaDB, 30 * time.Second, "SET SESSION max_statement_time = 30.000"},
		{engine.FlavorMariaDB, 1500 * time.Millisecond, "SET SESSION max_statement_time = 1.500"},
		{engine.FlavorMySQL, 10 * time.Second, "SET SESSION max_execution_time = 10000"},
		{engine.FlavorMySQL, time.Microsecond, "SET SESSION max_execution_time = 1"},
		{engine.FlavorMySQL, 0, ""},
	}
	for _, c := range cases {
		if got := timeoutSQL(c.f, c.d); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.f, c.d, got, c.want)
		}
	}
}

func TestConnectErrorHidesSecret(t *testing.T) {
	err := connectError(errors.New("dial: bad thing s3cr3t-pw near s3cr3t-pw"), "s3cr3t-pw")
	if strings.Contains(err.Error(), "s3cr3t-pw") || !strings.Contains(err.Error(), "***") {
		t.Errorf("err = %v", err)
	}
	err = connectError(&gomysql.MyError{Code: 1045, State: "28000", Message: "Access denied for user 'ro'@'x'"}, "pw")
	if !strings.Contains(err.Error(), "1045") {
		t.Errorf("err = %v", err)
	}
}

func TestLexSingle(t *testing.T) {
	if err := lexSingle("SELECT ';' FROM t WHERE a = 1"); err != nil {
		t.Errorf("quoted ';' refused: %v", err)
	}
	for _, q := range []string{"SELECT 1; SELECT 2", "SELECT 1;", "SELECT 1 /* x */ ; DROP TABLE t"} {
		if err := lexSingle(q); err == nil {
			t.Errorf("%q accepted", q)
		}
	}
}

func TestConnectRefusesOtherEngines(t *testing.T) {
	_, err := Engine{}.Connect(t.Context(), config.Profile{Engine: config.EngineSQLite}, nil)
	if err == nil {
		t.Error("sqlite profile accepted")
	}
}
