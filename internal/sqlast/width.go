package sqlast

import (
	"strings"

	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// width bounds the size of a value. bytes is what the literals and the
// length arguments of the statement contribute; cols counts the
// contributions whose size only the data bounds: a base column, or the
// result of a concatenating aggregate. A value combining a column with
// itself n times has cols n.
//
// Every value the analyzer computes carries its width, through derived
// tables, CTEs and set operations, and is checked against maxValueBytes and
// maxValueCols where it is built (analyzer.value): reusing a value through
// query layers multiplies its width, so the reuse is bounded too.
type width struct{ cols, bytes int }

// numWidth is the width given to a number, a date or a boolean.
const numWidth = 32

// widthCeiling keeps the arithmetic far from overflow; any value above it
// is refused anyway.
const widthCeiling = 1 << 40

func (w width) plus(v width) width {
	return width{cols: min(w.cols+v.cols, widthCeiling), bytes: min(w.bytes+v.bytes, widthCeiling)}
}

func (w width) times(n int) width {
	return width{cols: min(w.cols*n, widthCeiling), bytes: min(w.bytes*n, widthCeiling)}
}

func (w width) max(v width) width {
	return width{cols: max(w.cols, v.cols), bytes: max(w.bytes, v.bytes)}
}

// check refuses a value that could exceed the size bound.
func (w width) check() error {
	if w.bytes > maxValueBytes {
		return refusef("the statement could build a value larger than %d bytes", maxValueBytes)
	}
	if w.cols > maxValueCols {
		return refusef("the statement could build a value wider than %d columns", maxValueCols)
	}
	return nil
}

// maxWidth is the element-wise maximum of ws: a value that is one of them,
// or bounded by its input. A call without arguments returns a number or a
// date.
func maxWidth(ws []width) width {
	if len(ws) == 0 {
		return width{bytes: numWidth}
	}
	out := ws[0]
	for _, w := range ws[1:] {
		out = out.max(w)
	}
	return out
}

// sumWidth is the width of the concatenation of ws.
func sumWidth(ws []width) width {
	var out width
	for _, w := range ws {
		out = out.plus(w)
	}
	return out
}

// literalWidth is the width of a literal: the length of a string (escapes
// are not decoded, so the text is at least as long as the value), nothing
// for NULL, and for anything else its text or a number's width.
func (an *analyzer) literalWidth(l *Literal) width {
	switch l.Kind {
	case LitNull:
		return width{}
	case LitString:
		if s, ok := StringValue(an.d, l.Text); ok {
			return width{bytes: len(s)}
		}
	}
	return width{bytes: max(numWidth, len(l.Text))}
}

// paddedTypes are the cast types that pad a value to their length:
// PostgreSQL char(n), MySQL BINARY(n).
var paddedTypes = newSet("CHAR", "CHARACTER", "BPCHAR", "NCHAR", "NATIONAL CHAR", "NATIONAL CHARACTER", "BINARY")

// castWidth is the width of CAST(x AS typ): x's, or the length of a type
// that pads to it.
func castWidth(typ string, x width) width {
	name, mod, ok := strings.Cut(typ, "(")
	if !ok || !paddedTypes[strings.Join(strings.Fields(name), " ")] {
		return x
	}
	digits, _, _ := strings.Cut(mod, ",")
	digits = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(digits), ")"))
	n := widthCeiling
	if len(digits) <= 12 {
		n = atoiSafe(digits)
		if n < 0 {
			n = widthCeiling
		}
	}
	return width{cols: x.cols, bytes: max(x.bytes, n)}
}

// escapeFuncs quote or encode their input: every byte may become two
// (HEX, a quote or a backslash doubled by JSON). escapeBuilders also join
// their arguments.
var (
	escapeFuncs    = newSet("HEX", "JSON_QUOTE", "TO_JSON", "TO_JSONB")
	escapeBuilders = newSet("JSON_OBJECT", "JSON_ARRAY", "JSON_BUILD_OBJECT", "JSONB_BUILD_OBJECT", "JSON_BUILD_ARRAY", "JSONB_BUILD_ARRAY")
)

// funcWidth is the width of a scalar function call, from the widths of its
// arguments. checkSizeArgs, checkReplaceArgs and checkFormat have already
// checked the literal arguments it reads.
func (an *analyzer) funcWidth(f *FuncCall, ws []width) width {
	switch {
	case f.Name == "REPEAT" && len(f.Args) == 2:
		s, _ := an.stringLiteral(f.Args[0])
		n, _ := lengthLiteral(f.Args[1])
		return width{bytes: len(s) * n}
	case (f.Name == "LPAD" || f.Name == "RPAD") && len(f.Args) >= 2:
		// The result has exactly n characters.
		n, _ := lengthLiteral(f.Args[1])
		return width{bytes: n}
	case (f.Name == "SPACE" || f.Name == "ZEROBLOB") && len(f.Args) == 1:
		n, _ := lengthLiteral(f.Args[0])
		return width{bytes: n}
	case f.Name == "CONCAT":
		return sumWidth(ws)
	case f.Name == "CONCAT_WS" && len(ws) > 0:
		// The separator sits between every two values.
		return ws[0].times(max(1, len(ws)-2)).plus(sumWidth(ws[1:]))
	case f.Name == "REPLACE" && len(f.Args) == 3:
		from := 1
		if s, ok := an.stringLiteral(f.Args[1]); ok && !strings.Contains(s, "\\") {
			if s == "" {
				return ws[0] // an empty pattern leaves the string unchanged
			}
			from = len(s)
		}
		return ws[0].times(max(1, ceilDiv(an.replacementLen(f), from)))
	case f.Name == "REGEXP_REPLACE" && len(f.Args) >= 3:
		// An empty match inserts the replacement at every position, and a
		// back-reference (\0, \&) copies the match.
		to := an.replacementLen(f)
		return ws[0].times(2*to + 2).plus(width{bytes: to})
	case f.Name == "TRANSLATE" && len(f.Args) == 3:
		return ws[0].times(max(1, an.replacementLen(f)))
	case an.formatArg(f.Name) && len(f.Args) > 0:
		return an.formatWidth(f, ws)
	case escapeFuncs[f.Name]:
		return maxWidth(ws).times(2).plus(width{bytes: 2})
	case escapeBuilders[f.Name]:
		return sumWidth(ws).times(2).plus(width{bytes: 4*len(ws) + 2})
	}
	return maxWidth(ws)
}

func ceilDiv(a, b int) int { return (a + b - 1) / b }

// replacementLen is the length of a replacing function's replacement
// literal (checkReplaceArgs keeps it one), or maxReplacement.
func (an *analyzer) replacementLen(f *FuncCall) int {
	if s, ok := an.stringLiteral(f.Args[replaceArg[f.Name]]); ok {
		return len(s)
	}
	return maxReplacement
}

// formatWidth is the width of a printf-style format: its literal text, and
// for every conversion the width or precision it pads to, or the argument
// it references (twice over for a quoting conversion: %L, %I, %q, %Q, %w).
// A PostgreSQL position (%1$s) may reference an argument many times. An
// argument no conversion references is counted once.
func (an *analyzer) formatWidth(f *FuncCall, ws []width) width {
	fs, _ := an.stringLiteral(f.Args[0])
	var out width
	refs := make([]int, len(ws))
	next := 1
	for i := 0; i < len(fs); i++ {
		if fs[i] != '%' {
			out.bytes++
			continue
		}
		i++
		if i < len(fs) && fs[i] == '%' {
			out.bytes++
			continue
		}
		pos, size := 0, 0
		for ; i < len(fs) && !isLetter(fs[i]); i++ {
			if fs[i] < '0' || fs[i] > '9' {
				continue
			}
			j := i
			for j < len(fs) && fs[j] >= '0' && fs[j] <= '9' {
				j++
			}
			n := atoiSafe(strings.TrimLeft(fs[i:j], "0"))
			if n < 0 {
				n = widthCeiling
			}
			if j < len(fs) && fs[j] == '$' {
				pos = n
			} else {
				size = max(size, n)
			}
			i = j - 1
		}
		// SQLite length modifiers (%lld) precede the conversion.
		for i < len(fs) && an.d == sqlclass.SQLite && fs[i] == 'l' {
			i++
		}
		k := next
		if pos > 0 {
			k = pos
		}
		next = k + 1
		var arg width
		if k < len(ws) {
			arg = ws[k]
			refs[k]++
		}
		if i < len(fs) && strings.IndexByte("LIqQw", fs[i]) >= 0 {
			arg = arg.times(2).plus(width{bytes: 3})
		}
		out = out.plus(width{cols: arg.cols, bytes: max(size, arg.bytes)})
	}
	for k := 1; k < len(ws); k++ {
		if refs[k] == 0 {
			out = out.plus(ws[k])
		}
	}
	return out
}

// aggWidth is the width of an aggregate or window function. A
// concatenating aggregate builds one value from all its rows: each of its
// arguments (and a MySQL SEPARATOR) is at most maxConcatArg bytes and one
// column, and its result counts as a column, whose size only the data
// bounds.
func (an *analyzer) aggWidth(f *FuncCall, ws []width) (width, error) {
	switch {
	case concatAggs[f.Name]:
		if f.Separator != nil {
			ws = append(ws, an.literalWidth(f.Separator))
		}
		for _, w := range ws {
			if w.bytes > maxConcatArg || w.cols > 1 {
				return width{}, refusef("%s: an argument that may exceed %d bytes is not allowed", strings.ToLower(f.Name), maxConcatArg)
			}
		}
		return width{cols: 1}, nil
	case identityAggs[f.Name]:
		return maxWidth(ws), nil
	case aggregates[f.Name]:
		return width{bytes: numWidth}, nil
	}
	// Window functions return one of their arguments, or a rank.
	return maxWidth(ws), nil
}
