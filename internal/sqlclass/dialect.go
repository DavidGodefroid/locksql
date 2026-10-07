// Package sqlclass is locksql's first gate: a conservative, dialect-aware
// lexer and statement classifier. It does not build an AST. It refuses
// anything it cannot classify with certainty, and it never rewrites SQL.
package sqlclass

import "fmt"

// Dialect selects the lexing and classification rules.
type Dialect int

// Dialects. MySQL also covers MariaDB.
const (
	MySQL Dialect = iota
	Postgres
	SQLite
)

var dialectNames = [...]string{"mysql", "postgres", "sqlite"}

func (d Dialect) String() string {
	if d >= 0 && int(d) < len(dialectNames) {
		return dialectNames[d]
	}
	return fmt.Sprintf("Dialect(%d)", int(d))
}

// DialectFor maps a config engine name ("mariadb", "mysql", "postgres",
// "sqlite") to its dialect.
func DialectFor(engine string) (Dialect, error) {
	switch engine {
	case "mariadb", "mysql":
		return MySQL, nil
	case "postgres":
		return Postgres, nil
	case "sqlite":
		return SQLite, nil
	}
	return 0, fmt.Errorf("sqlclass: unknown engine %q", engine)
}

// Class is the privilege class of a statement. Its order matches the
// profile tiers: Read < Write < DDL < Admin.
type Class int

// Classes, in increasing order of privilege.
const (
	Read Class = iota
	Write
	DDL
	Admin
)

var classNames = [...]string{"read", "write", "ddl", "admin"}

func (c Class) String() string {
	if c >= 0 && int(c) < len(classNames) {
		return classNames[c]
	}
	return fmt.Sprintf("Class(%d)", int(c))
}
