package pii

import (
	"strings"

	kpii "github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// Propose returns the "db.table.column" patterns for the columns that look
// like personal data from their name or type (lockkit's multilingual name
// heuristics), sorted and de-duplicated. A name that would break the
// pattern syntax becomes '*'.
func Propose(cols []engine.ColumnInfo) []string {
	var out []string
	for _, c := range cols {
		if kpii.LooksPersonalColumn(c.Column, c.Type) {
			out = append(out, patternSeg(c.DB)+"."+patternSeg(c.Table)+"."+patternSeg(c.Column))
		}
	}
	return canonical(out)
}

// QuasiLimit is what masking a quasi-identifier costs, shown when the scan
// proposes one.
const QuasiLimit = "masking blocks range filters, LIKE and ORDER BY on this column"

// ProposeQuasi returns the "db.table.column" patterns for the columns that
// look like quasi-identifiers (birth date, postal code, gender) and not
// like personal data, sorted and de-duplicated.
func ProposeQuasi(cols []engine.ColumnInfo) []string {
	var out []string
	for _, c := range cols {
		if !kpii.LooksPersonalColumn(c.Column, c.Type) && kpii.LooksQuasi(c.Column) {
			out = append(out, patternSeg(c.DB)+"."+patternSeg(c.Table)+"."+patternSeg(c.Column))
		}
	}
	return canonical(out)
}

func patternSeg(s string) string {
	if s == "" || strings.ContainsAny(s, "*. \t\r\n\"'`") {
		return "*"
	}
	return s
}
