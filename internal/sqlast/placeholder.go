package sqlast

import (
	"regexp"
	"strings"
)

// ValueKind tells a value typed by the human from a cell reference.
type ValueKind int

const (
	// ValueTyped is '${name}': the human types the value in the console.
	ValueTyped ValueKind = iota + 1
	// ValueRef is '${rN.R.C}': the value of a masked cell the console
	// returned (result N, row R, column C).
	ValueRef
)

// ValueUse is a placeholder literal compared with a PII column.
type ValueUse struct {
	Kind ValueKind
	// Name is "email" for '${email}', "r3.1.2" for '${r3.1.2}'.
	Name string
	// Column is the PII column the placeholder is compared with.
	Column Source
	// InList is set inside IN (...).
	InList bool
	Span   Span
}

var (
	typedRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	refRe   = regexp.MustCompile(`^r[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*$`)
)

// ParsePlaceholder reads the body of a string literal (without quotes).
// isPlaceholder reports the "${...}" shape; ok whether the name is valid.
func ParsePlaceholder(body string) (kind ValueKind, name string, isPlaceholder, ok bool) {
	if !strings.HasPrefix(body, "${") {
		return 0, "", false, false
	}
	if !strings.HasSuffix(body, "}") {
		return 0, "", true, false
	}
	n := body[2 : len(body)-1]
	switch {
	case refRe.MatchString(n):
		return ValueRef, n, true, true
	case typedRe.MatchString(n):
		return ValueTyped, n, true, true
	}
	return 0, "", true, false
}
