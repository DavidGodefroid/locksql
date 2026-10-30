package sqlclass

// ValuesRows is a floor on the rows an INSERT or REPLACE whose rows are a
// top-level VALUES list changes: the number of its row groups ("(...)" or
// MySQL's "ROW(...)", separated by commas), twice that on MySQL for a
// REPLACE or an ON DUPLICATE KEY UPDATE (a replaced or updated row counts
// two). EXPLAIN gives no estimate for VALUES on MySQL and SQLite. It is 0
// for any other statement, or one that does not lex.
func ValuesRows(d Dialect, sql string) int64 {
	toks, err := Lex(d, sql)
	if err != nil || len(toks) == 0 || toks[0].Kind != TokWord {
		return 0
	}
	first := toks[0].Text
	if first != "INSERT" && first != "REPLACE" {
		return 0
	}
	start := -1
	for i, t := range toks {
		if t.Depth == 0 && t.Kind == TokWord && (t.Text == "VALUES" || t.Text == "VALUE" && d == MySQL) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return 0
	}
	var n int64
	expect := true // a row group may start here
	i := start
	for ; i < len(toks); i++ {
		t := toks[i]
		open := t.Kind == TokPunct && t.Text == "(" && t.Depth == 1 // an opening parenthesis carries the depth it opens
		switch {
		case expect && open:
			n++
			expect = false
			continue
		case t.Depth != 0:
			continue
		case expect && t.Kind == TokWord && t.Text == "ROW" && d == MySQL:
			continue
		case t.Kind == TokPunct && t.Text == ")":
			continue
		case !expect && t.Kind == TokPunct && t.Text == ",":
			expect = true
			continue
		}
		break
	}
	if d == MySQL {
		double := first == "REPLACE"
		for _, t := range toks[i:] {
			double = double || t.Depth == 0 && t.Kind == TokWord && t.Text == "DUPLICATE"
		}
		if double {
			n *= 2
		}
	}
	return n
}
