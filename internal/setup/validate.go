package setup

import (
	"net"
	"strings"
	"unicode"
)

// The validators below check the free-text parts of a profile, whether
// typed step by step or taken from a URL. Callers never quote the refused
// value: a misplaced password must not be echoed.

func validHost(s string) bool {
	if strings.ContainsAny(s, "@/") || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return false
	}
	return !strings.Contains(s, ":") || net.ParseIP(s) != nil
}

func validUser(s string) bool {
	return !strings.ContainsAny(s, "@:/") && strings.IndexFunc(s, unicode.IsSpace) < 0
}

func validDatabase(s string) bool {
	return !strings.ContainsAny(s, "/@;") && strings.IndexFunc(s, unicode.IsSpace) < 0
}
