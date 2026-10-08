package setup

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseURL(t *testing.T) {
	cwd := t.TempDir()
	for _, c := range []struct {
		in   string
		want Target
	}{
		{"postgres://app@127.0.0.1:5433/shop", Target{Engine: "postgres", Host: "127.0.0.1", Port: 5433, User: "app", Database: "shop"}},
		{"postgresql://db.local/shop", Target{Engine: "postgres", Host: "db.local", Port: 5432, Database: "shop"}},
		{"mysql://root@localhost", Target{Engine: "mysql", Host: "localhost", Port: 3306, User: "root"}},
		{"mariadb://u@[::1]:3307/x", Target{Engine: "mariadb", Host: "::1", Port: 3307, User: "u", Database: "x"}},
		{"sqlite:///var/db/app.db", Target{Engine: "sqlite", Path: "/var/db/app.db"}},
		{"sqlite://./app.db", Target{Engine: "sqlite", Path: filepath.Join(cwd, "app.db")}},
	} {
		got, err := ParseURL(c.in, cwd)
		if err != nil || got != c.want {
			t.Errorf("ParseURL(%q) = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
}

func TestParseURLRefusesWithoutEcho(t *testing.T) {
	for _, in := range []string{
		"postgres://app:S3cretPw@h/db",
		"mysql://h/db?password=S3cretPw",
		"postgres://h/db?sslmode=require",
		"postgres://h/a/b",
		"oracle://h/db",
		"postgres://h/db#S3cretPw",
		"",
	} {
		_, err := ParseURL(in, "/")
		if err == nil {
			t.Errorf("ParseURL(%q) accepted", in)
			continue
		}
		if strings.Contains(err.Error(), "S3cretPw") {
			t.Errorf("ParseURL(%q) error echoes the secret: %v", in, err)
		}
	}
}

func TestParseURLSQLiteStrict(t *testing.T) {
	for _, in := range []string{"sqlite://user:pw@host/x.db", "sqlite://localhost/x.db", "sqlite://x.db"} {
		_, err := ParseURL(in, "/")
		if err == nil {
			t.Errorf("ParseURL(%q) accepted", in)
		} else if strings.Contains(err.Error(), "pw") {
			t.Errorf("error echoes input: %v", err)
		}
	}
	got, err := ParseURL("SQLITE:///var/x.db", "/")
	if err != nil || got.Path != "/var/x.db" {
		t.Fatalf("ParseURL upper-case = %+v, %v", got, err)
	}
}
