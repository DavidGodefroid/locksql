// Package secrets reads database secrets from the human (no-echo prompt) or
// the OS keychain, and scrubs them from error strings. A secret is a []byte
// that lives only in console memory; callers Wipe it when done.
package secrets

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Redacted replaces every occurrence of a secret in a sanitised string.
const Redacted = "***"

// Sanitize returns err's message with every secret removed. Besides the raw
// value it removes the forms a driver might print: URL query, path and
// userinfo escaping, and Go/JSON string quoting. A nil err gives "".
func Sanitize(err error, secrets ...[]byte) string {
	if err == nil {
		return ""
	}
	return SanitizeString(err.Error(), secrets...)
}

// SanitizeString is Sanitize for a plain string.
func SanitizeString(s string, secrets ...[]byte) string {
	var forms []string
	seen := map[string]bool{}
	for _, sec := range secrets {
		if len(sec) == 0 {
			continue
		}
		raw := string(sec)
		quoted := strconv.Quote(raw)
		for _, f := range []string{
			raw,
			url.QueryEscape(raw),
			url.PathEscape(raw),
			strings.TrimPrefix(url.UserPassword("", raw).String(), ":"),
			quoted[1 : len(quoted)-1],
		} {
			if f != "" && !seen[f] {
				seen[f] = true
				forms = append(forms, f)
			}
		}
	}
	// Longest first, so a secret that contains another is removed whole.
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	for _, f := range forms {
		s = strings.ReplaceAll(s, f, Redacted)
	}
	return s
}

// Wipe overwrites b with zeros. Go may have copied the bytes elsewhere (string
// conversions, driver buffers), so this narrows the exposure, it does not
// end it.
func Wipe(b []byte) {
	clear(b)
}
