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

// nameProbe stands for sampled values that are all person names: a column
// whose name means "name" is reported with them, any other is not.
var nameProbe = []string{"Alice Dupont", "Bob Martin"}

// NameCandidates returns the columns whose values ProposeName needs: the
// text columns of tables (views left out: sampling one runs its query)
// whose name means "name" and that Propose leaves out. Without samples the
// column name alone never proposes one.
func NameCandidates(cols []engine.ColumnInfo) []engine.ColumnInfo {
	var out []engine.ColumnInfo
	for _, c := range cols {
		if c.View || c.Generated || kpii.LooksPersonalColumn(c.Column, c.Type) {
			continue
		}
		if !c.TypeLoose && !textType(c.Type) {
			continue
		}
		if kpii.LooksPersonNameColumn(c.Table, c.Column, nameProbe) {
			out = append(out, c)
		}
	}
	return out
}

// ProposeName returns the "db.table.column" pattern of c when its sampled
// values are person names (lockkit's LooksPersonNameColumn), "" otherwise.
func ProposeName(c engine.ColumnInfo, samples []string) string {
	if !kpii.LooksPersonNameColumn(c.Table, c.Column, samples) {
		return ""
	}
	return patternSeg(c.DB) + "." + patternSeg(c.Table) + "." + patternSeg(c.Column)
}

// textType reports a column type that holds text: char, varchar, text,
// citext, clob, string and their variants (PostgreSQL arrays excepted).
func textType(t string) bool {
	t = strings.ToLower(t)
	if strings.HasSuffix(t, "[]") {
		return false
	}
	for _, w := range []string{"char", "text", "clob", "string"} {
		if strings.Contains(t, w) {
			return true
		}
	}
	return false
}

func patternSeg(s string) string {
	if s == "" || strings.ContainsAny(s, "*. \t\r\n\"'`") {
		return "*"
	}
	return s
}
