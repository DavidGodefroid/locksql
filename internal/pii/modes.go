package pii

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/sqlast"
)

// Tokens is the token table of one console session (mask mode "hash"): a
// keyed HMAC of the value, so the same value always gives the same token
// within the session, and a random key per session, so tokens cannot be
// correlated across sessions. It remembers which value each token stands
// for, so that an agent may filter on a token (WHERE email = 'tok_...'):
// the console substitutes the value in the statement that runs. Only
// equality leaks: no order, no prefix, no length.
type Tokens struct {
	mu     sync.Mutex
	key    [32]byte
	values map[string]string
}

// maxTokens bounds the remembered values; tokens issued beyond it still
// mask, but cannot be filtered on.
const maxTokens = 200_000

var tokenRe = regexp.MustCompile(`^tok_[a-z2-7]{20}$`)

var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTokens returns a token table with a fresh random key.
func NewTokens() *Tokens {
	t := &Tokens{values: map[string]string{}}
	if _, err := rand.Read(t.key[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return t
}

// Token returns the token of value.
func (t *Tokens) Token(value string) string {
	m := hmac.New(sha256.New, t.key[:])
	m.Write([]byte(value))
	tok := "tok_" + strings.ToLower(tokenEncoding.EncodeToString(m.Sum(nil)))[:20]
	t.mu.Lock()
	if len(t.values) < maxTokens {
		t.values[tok] = value
	}
	t.mu.Unlock()
	return tok
}

// Lookup resolves a token issued in this session. isToken reports whether
// s has the token format at all.
func (t *Tokens) Lookup(s string) (value string, isToken, ok bool) {
	if !tokenRe.MatchString(s) {
		return "", false, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.values[s]
	return v, true, ok
}

// Redacted is the cell of a column masked in mode redact.
const Redacted = "<redacted>"

// MaskValue masks one non-NULL cell in mode.
func MaskValue(v any, mode string, tok *Tokens) any {
	switch mode {
	case ModeRedact:
		return Redacted
	case ModeHash:
		if tok == nil {
			return Redacted
		}
		return tok.Token(cellText(v))
	case ModeEmail:
		if s, ok := v.(string); ok {
			if at := strings.LastIndexByte(s, '@'); at > 0 && at < len(s)-1 && utf8.ValidString(s) {
				first, _ := utf8.DecodeRuneInString(s)
				return string(first) + "***@" + s[at+1:]
			}
		}
	}
	return maskCell(v)
}

func cellText(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	case time.Time:
		return x.Format(time.RFC3339Nano)
	}
	return fmt.Sprint(v)
}

// MaskOutputs masks res in place following the analysed outputs of its
// statement: each column whose resolved sources are under a rule is masked
// in the output's mode. As a second line of defence a column whose engine-
// reported origin matches a rule is masked too. The other text and integer
// cells go through the detectors.
//
// The result must have exactly the analysed columns, and the columns the
// analysis expects by name (plain references, aliases, star expansions)
// must carry that label: otherwise masking by position could hit the wrong
// column, and the result is refused.
func MaskOutputs(res *engine.Result, outs []sqlast.Output, r Rules, ds []Detector, tok *Tokens, origin bool) error {
	if len(res.Columns) != len(outs) {
		return fmt.Errorf("the result has %d columns where the statement was analysed with %d", len(res.Columns), len(outs))
	}
	modes := make([]string, len(outs))
	for i, c := range res.Columns {
		o := outs[i]
		if o.Label != "" && fold(o.Label) != fold(c.Label) {
			return fmt.Errorf("result column %d is labelled %q where %q was expected", i+1, c.Label, strings.ToLower(o.Label))
		}
		modes[i] = o.Mask
		if modes[i] == "" && origin && c.HasOrigin() {
			if m, ok := r.Mode(c.OriginDB, c.OriginTable, c.OriginColumn); ok {
				modes[i] = m
			}
		}
	}
	for _, row := range res.Rows {
		for i, v := range row {
			if v == nil || i >= len(modes) {
				continue
			}
			if modes[i] != "" {
				row[i] = MaskValue(v, modes[i], tok)
				continue
			}
			row[i] = detect(v, ds)
		}
	}
	return nil
}
