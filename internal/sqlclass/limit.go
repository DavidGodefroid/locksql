package sqlclass

import (
	"fmt"
	"strconv"
)

// topLevelLimit returns the row count of the top-level LIMIT (or, in
// PostgreSQL, FETCH FIRST|NEXT n ROWS ONLY) that must end a READ statement.
// A LIMIT inside parentheses (subquery, CTE) does not count.
func topLevelLimit(d Dialect, toks []Token) (int, error) {
	last := -1
	for k, t := range toks {
		if t.Depth == 0 && t.Kind == TokWord && (t.Text == "LIMIT" || d == Postgres && t.Text == "FETCH") {
			last = k
		}
	}
	if last < 0 {
		if d == Postgres {
			return 0, refuse("a top-level LIMIT n or FETCH FIRST n ROWS ONLY is required (use LIMIT 1 for aggregates)")
		}
		return 0, refuse("a top-level LIMIT n is required (use LIMIT 1 for aggregates)")
	}
	if toks[last].Text == "FETCH" {
		return fetchFirst(toks[last+1:])
	}
	tail := toks[last+1:]
	switch {
	case len(tail) == 1 && isCount(tail[0]):
		return count(tail[0])
	case len(tail) == 3 && isCount(tail[0]) && tail[1].Kind == TokWord && tail[1].Text == "OFFSET" && isCount(tail[2]):
		return count(tail[0])
	case d != Postgres && len(tail) == 3 && isCount(tail[0]) && tail[1].Text == "," && isCount(tail[2]):
		return count(tail[2]) // LIMIT offset, count
	}
	if d == Postgres {
		return 0, refuse("the top-level LIMIT must end the statement: LIMIT n | LIMIT n OFFSET m")
	}
	return 0, refuse("the top-level LIMIT must end the statement: LIMIT n | LIMIT m, n | LIMIT n OFFSET m")
}

// fetchFirst parses the tail of FETCH: FIRST|NEXT [n] ROW|ROWS ONLY.
func fetchFirst(tail []Token) (int, error) {
	words := make([]string, len(tail))
	for k, t := range tail {
		words[k] = t.Text
	}
	if len(tail) >= 2 && words[len(words)-2] == "WITH" && words[len(words)-1] == "TIES" {
		return 0, refuse("FETCH ... WITH TIES can return more rows than requested; use ONLY")
	}
	n, rest := 1, tail
	if len(rest) > 0 && (words[0] == "FIRST" || words[0] == "NEXT") {
		rest = rest[1:]
		if len(rest) > 0 && isCount(rest[0]) {
			var err error
			if n, err = count(rest[0]); err != nil {
				return 0, err
			}
			rest = rest[1:]
		}
		if len(rest) == 2 && (rest[0].Text == "ROW" || rest[0].Text == "ROWS") && rest[1].Text == "ONLY" &&
			rest[0].Kind == TokWord && rest[1].Kind == TokWord {
			return n, nil
		}
	}
	return 0, refuse("the top-level FETCH must end the statement: FETCH FIRST n ROWS ONLY")
}

func isCount(t Token) bool {
	if t.Kind != TokNumber || t.Text == "" {
		return false
	}
	for i := 0; i < len(t.Text); i++ {
		if !isDigit(t.Text[i]) {
			return false
		}
	}
	return true
}

func count(t Token) (int, error) {
	n, err := strconv.Atoi(t.Text)
	if err != nil {
		return 0, refuse(fmt.Sprintf("LIMIT value %.20s is out of range", t.Text))
	}
	return n, nil
}
