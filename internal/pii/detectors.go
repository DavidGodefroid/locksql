package pii

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Detector masks personal values found inside a text, in place.
type Detector interface {
	Name() string
	// Mask returns s with every value the detector recognises replaced by
	// its masked form (first character + "***" + "(length)").
	Mask(s string) string
}

// detectorOrder is the order detectors run in, whatever the order they are
// configured in: emails first (their digits are not phone numbers), the
// checksummed numbers next, phone numbers, the loosest pattern, last.
var detectorOrder = []string{"email", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn", "phone"}

var detectorFinders = map[string]func(string) []span{
	"email":   findEmails,
	"iban":    findIBANs,
	"card":    findCards,
	"be_niss": findNISS,
	"fr_nir":  findNIR,
	"nl_bsn":  findBSN,
	"us_ssn":  findSSN,
	"phone":   findPhones,
}

// Detectors returns the named detectors, de-duplicated, in their fixed run
// order. Names: email, phone, iban, card, be_niss, fr_nir, nl_bsn, us_ssn.
func Detectors(names []string) ([]Detector, error) {
	want := map[string]bool{}
	for _, n := range names {
		if _, ok := detectorFinders[n]; !ok {
			return nil, fmt.Errorf("pii: unknown detector %q (known: %s)", n, strings.Join(detectorOrder, ", "))
		}
		want[n] = true
	}
	var out []Detector
	for _, n := range detectorOrder {
		if want[n] {
			out = append(out, finderDetector{name: n, find: detectorFinders[n]})
		}
	}
	return out, nil
}

type finderDetector struct {
	name string
	find func(string) []span
}

func (d finderDetector) Name() string { return d.name }

func (d finderDetector) Mask(s string) string {
	spans := d.find(s)
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, sp := range spans {
		b.WriteString(s[last:sp.start])
		b.WriteString(maskText(s[sp.start:sp.end]))
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String()
}

// span is a byte range [start, end) of a recognised value.
type span struct{ start, end int }

// scanWindow is the slice of text handed to the regexp engine at a time.
// Go's regexp is much faster on short inputs, and the digit detectors run
// it once per candidate, so searching the whole remainder each time would
// make a long run of separated digits quadratic in practice.
const scanWindow = 1024

// scan returns the non-overlapping matches of re accepted by check, which
// may also shorten a match by returning a smaller end. A rejected match is
// retried one byte further, since RE2 has no look-around. maxLen is the
// longest match re can produce, or 0 when unbounded; when bounded, re only
// sees windows of scanWindow bytes, overlapping by maxLen so that no match
// is cut by a window edge.
func scan(s string, re *regexp.Regexp, maxLen int, check func(s string, start, end int) (int, bool)) []span {
	var out []span
	for pos := 0; pos < len(s); {
		sub := s[pos:]
		if maxLen > 0 && len(sub) > scanWindow {
			sub = sub[:scanWindow]
		}
		loc := re.FindStringIndex(sub)
		if loc == nil {
			if len(sub) == len(s)-pos {
				break
			}
			pos += scanWindow - maxLen // any match starting before this fits in the window
			continue
		}
		if len(sub) < len(s)-pos && loc[1] > len(sub)-maxLen {
			// The match may run past the window: search again from its start.
			from := pos + loc[0]
			sub = s[from:min(len(s), from+scanWindow)]
			loc = re.FindStringIndex(sub)
			pos = from
		}
		start, end := pos+loc[0], pos+loc[1]
		if e, ok := check(s, start, end); ok {
			out = append(out, span{start, e})
			pos = e
			continue
		}
		// Every digit detector refuses a value preceded by a digit, so the
		// rest of a digit run cannot start a match: skip it (this keeps a
		// long run of digits linear).
		pos = start + 1
		for pos < len(s) && isDigit(s[pos]) && isDigit(s[pos-1]) {
			pos++
		}
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// before and after return the byte around a range, or 0 at the edges.
func before(s string, i int) byte {
	if i > 0 {
		return s[i-1]
	}
	return 0
}

func after(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func digitsOf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// mod97 returns the decimal number s modulo 97, letters counting as 10..35
// (the IBAN rule).
func mod97(s string) int {
	m := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; isDigit(c) || c >= 'A' && c <= 'Z' {
			m = mod97step(m, c)
		}
	}
	return m
}

// --- email

// emailRe accepts any letter, digit or combining mark in the local part
// (jöhn, a decomposed rené) and any letter in the domain labels, so that a
// non-ASCII character cannot cut the address and leave its prefix in clear.
var emailRe = regexp.MustCompile(`[\p{L}\p{M}\p{N}._%+\-]+@[\p{L}0-9\-]+(?:\.[\p{L}0-9\-]+)*\.\p{L}{2,}`)

// findEmails accepts a match only at the start of a word, never the tail of
// a longer local part, or right where the previous address ended: an
// address glued to a masked one (a@b.com-c@d.org) is masked too.
func findEmails(s string) []span {
	last := -1
	return scan(s, emailRe, 0, func(s string, start, end int) (int, bool) {
		r, _ := utf8.DecodeLastRuneInString(s[:start])
		if start > 0 && start != last && emailLocalRune(r) {
			return 0, false
		}
		last = end
		return end, true
	})
}

func emailLocalRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || strings.ContainsRune("._%+-", r)
}

// --- IBAN (mod 97)

// ibanRe ignores case: an IBAN typed in lower case is still an IBAN.
var ibanRe = regexp.MustCompile(`(?i)[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?`)

func findIBANs(s string) []span {
	return scan(s, ibanRe, 44, func(s string, start, end int) (int, bool) {
		if isAlnum(before(s, start)) {
			return 0, false
		}
		// Try the whole match, then shorter prefixes cut at a space.
		for e := end; ; {
			if !isAlnum(after(s, e)) && ibanValid(s[start:e]) {
				return e, true
			}
			k := strings.LastIndexByte(s[start:e], ' ')
			if k < 0 {
				return 0, false
			}
			e = start + k
		}
	})
}

// ibanValid checks the length and the mod-97 rule on v, blanks ignored,
// without allocating: the first four characters move to the end.
func ibanValid(v string) bool {
	n := len(v) - strings.Count(v, " ")
	if n < 15 || n > 34 {
		return false
	}
	m, seen := 0, 0
	for pass := 0; pass < 2; pass++ {
		seen = 0
		for i := 0; i < len(v); i++ {
			if v[i] == ' ' {
				continue
			}
			seen++
			if (pass == 0) == (seen > 4) {
				m = mod97step(m, v[i])
			}
		}
	}
	return m == 1
}

func mod97step(m int, c byte) int {
	if isDigit(c) {
		return (m*10 + int(c-'0')) % 97
	}
	if c >= 'a' && c <= 'z' {
		c -= 'a' - 'A'
	}
	return (m*100 + int(c-'A') + 10) % 97
}

// --- payment card (Luhn)

var cardRe = regexp.MustCompile(`[0-9](?:[ \-]?[0-9]){12,18}`)

func findCards(s string) []span {
	return scan(s, cardRe, 37, func(s string, start, end int) (int, bool) {
		if isDigit(before(s, start)) {
			return 0, false
		}
		// Digits of the match and the offset after each, collected once.
		var digits [19]byte
		var ends [19]int
		n := 0
		for i := start; i < end && n < len(digits); i++ {
			if isDigit(s[i]) {
				digits[n], ends[n] = s[i], i+1
				n++
			}
		}
		for k := n; k >= 13; k-- {
			if !isDigit(after(s, ends[k-1])) && luhn(digits[:k]) {
				return ends[k-1], true
			}
		}
		return 0, false
	})
}

func luhn(d []byte) bool {
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if (len(d)-1-i)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// --- Belgian national number (NISS / INSZ, mod 97)

var nissRe = regexp.MustCompile(`[0-9]{2}[. ]?[0-9]{2}[. ]?[0-9]{2}[- ]?[0-9]{3}[. ]?[0-9]{2}`)

func findNISS(s string) []span {
	return scan(s, nissRe, 15, func(s string, start, end int) (int, bool) {
		if isDigit(before(s, start)) || isDigit(after(s, end)) {
			return 0, false
		}
		d := digitsOf(s[start:end])
		check := int(d[9]-'0')*10 + int(d[10]-'0')
		// Born before 2000: 97 - (first 9 digits mod 97); from 2000 on, the
		// same with a leading 2.
		if 97-mod97(d[:9]) == check || 97-mod97("2"+d[:9]) == check {
			return end, true
		}
		return 0, false
	})
}

// --- French NIR (mod 97, Corsica 2A/2B)

var nirRe = regexp.MustCompile(`[1-478] ?[0-9]{2} ?[0-9]{2} ?(?:[0-9]{2}|2[ABab]) ?[0-9]{3} ?[0-9]{3} ?[0-9]{2}`)

func findNIR(s string) []span {
	return scan(s, nirRe, 21, func(s string, start, end int) (int, bool) {
		if isAlnum(before(s, start)) || isDigit(after(s, end)) {
			return 0, false
		}
		c := strings.ToUpper(strings.ReplaceAll(s[start:end], " ", ""))
		body, key := c[:13], int(c[13]-'0')*10+int(c[14]-'0')
		switch body[5:7] {
		case "2A":
			body = body[:5] + "19" + body[7:]
		case "2B":
			body = body[:5] + "18" + body[7:]
		}
		if 97-mod97(body) == key {
			return end, true
		}
		return 0, false
	})
}

// --- Dutch BSN (11-proof)

var bsnRe = regexp.MustCompile(`[0-9]{9}|[0-9]{4}\.[0-9]{2}\.[0-9]{3}`)

func findBSN(s string) []span {
	return scan(s, bsnRe, 11, func(s string, start, end int) (int, bool) {
		if b := before(s, start); isDigit(b) || b == '.' {
			return 0, false
		}
		if a := after(s, end); isDigit(a) || a == '.' && isDigit(after(s, end+1)) {
			return 0, false
		}
		d := digitsOf(s[start:end])
		sum := 0
		for i := 0; i < 8; i++ {
			sum += int(d[i]-'0') * (9 - i)
		}
		sum -= int(d[8] - '0')
		if sum != 0 && sum%11 == 0 && d != "000000000" {
			return end, true
		}
		return 0, false
	})
}

// --- US SSN (format and area rules)

var ssnRe = regexp.MustCompile(`[0-9]{3}[- ][0-9]{2}[- ][0-9]{4}`)

func findSSN(s string) []span {
	return scan(s, ssnRe, 11, func(s string, start, end int) (int, bool) {
		if b := before(s, start); isDigit(b) || b == '-' {
			return 0, false
		}
		if a := after(s, end); isDigit(a) || a == '-' {
			return 0, false
		}
		v := s[start:end]
		if v[3] != v[6] {
			return 0, false
		}
		area, group, serial := v[0:3], v[4:6], v[7:11]
		if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
			return 0, false
		}
		return end, true
	})
}

// --- phone numbers (E.164, 00-international and national formats)

const phoneSeps = " ./-()"

// findPhones scans by hand: a phone number is digit groups joined by at most
// two separator characters. The longest prefix of groups that forms a valid
// number is masked.
func findPhones(s string) []span {
	var out []span
	for i := 0; i < len(s); i++ {
		c := s[i]
		plus := c == '+'
		if !plus && !isDigit(c) {
			continue
		}
		if b := before(s, i); isAlnum(b) || strings.IndexByte("+.-/,", b) >= 0 {
			// Inside a word, a number, a date or a version: skip the run.
			for i+1 < len(s) && isDigit(s[i+1]) {
				i++
			}
			continue
		}
		if end, ok := phoneAt(s, i, plus); ok {
			out = append(out, span{i, end})
			i = end - 1
			continue
		}
		for i+1 < len(s) && isDigit(s[i+1]) {
			i++
		}
	}
	return out
}

type phoneGroup struct {
	end    int    // byte offset after the group
	digits string // digits up to and including the group
	sep    string // separator that follows the group ("" at the end)
	length int    // digits in this group
}

func phoneAt(s string, i int, plus bool) (int, bool) {
	j := i
	if plus {
		j++
		if !isDigit(after(s, j)) {
			return 0, false
		}
	}
	var groups []phoneGroup
	digits := ""
	for len(groups) < 10 && len(digits) <= 17 {
		k := j
		for k < len(s) && isDigit(s[k]) {
			k++
		}
		if k == j {
			break
		}
		digits += s[j:k]
		g := phoneGroup{end: k, digits: digits, length: k - j}
		// A separator is one or two characters followed by a digit.
		n := 0
		for n < 2 && k+n < len(s) && strings.IndexByte(phoneSeps, s[k+n]) >= 0 {
			n++
		}
		if n > 0 && isDigit(after(s, k+n)) {
			g.sep = s[k : k+n]
			groups = append(groups, g)
			j = k + n
			continue
		}
		groups = append(groups, g)
		break
	}
	if len(groups) == 0 || isDateLike(groups) {
		return 0, false
	}
	for k := len(groups) - 1; k >= 0; k-- {
		g := groups[k]
		if isAlnum(after(s, g.end)) {
			continue
		}
		// Stopping before the next group is only fine across a blank.
		if g.sep != "" && !strings.Contains(g.sep, " ") {
			continue
		}
		if phoneValid(g.digits, plus, groups[0].length) {
			return g.end, true
		}
	}
	return 0, false
}

func phoneValid(d string, plus bool, firstGroup int) bool {
	switch {
	case plus:
		return len(d) >= 8 && len(d) <= 15 && d[0] != '0'
	case strings.HasPrefix(d, "00"):
		return len(d) >= 10 && len(d) <= 17 && d[2] != '0'
	case d[0] == '0':
		// National: 0 + area or mobile prefix. "0.123" and "0 12" are not.
		return len(d) >= 9 && len(d) <= 11 && d[1] != '0' && firstGroup >= 2
	}
	return false
}

// isDateLike rejects dd-mm-yyyy shapes ("01-02-2026 12:30").
func isDateLike(g []phoneGroup) bool {
	return len(g) >= 3 && g[0].length == 2 && g[1].length == 2 && g[2].length == 4 &&
		g[0].sep == g[1].sep && len(g[0].sep) == 1 && strings.IndexByte("-/.", g[0].sep[0]) >= 0
}
