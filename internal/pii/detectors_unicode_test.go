package pii

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
)

// maskCells runs cells through MaskResult as one column with no rule, the
// case the value detectors exist for.
func maskCells(t *testing.T, names []string, cells ...any) []any {
	t.Helper()
	ds, err := Detectors(names)
	if err != nil {
		t.Fatal(err)
	}
	res := &engine.Result{Columns: []engine.ResultColumn{{Label: "note"}}}
	for _, c := range cells {
		res.Rows = append(res.Rows, []any{c})
	}
	MaskResult(res, Rules{}, ds, true)
	out := make([]any, len(res.Rows))
	for i, row := range res.Rows {
		out[i] = row[0]
	}
	return out
}

// Issue #17: Unicode e-mail addresses, typographic spaces, national phone
// formats and float cells.
func TestDetectorsUnicodeAndFloats(t *testing.T) {
	const nbsp, nnbsp = "\u00a0", "\u202f"
	defaults := config.DefaultDetectors()

	// Each of these leaked on lockkit v0.1.0 (before lockkit#19).
	leaks := map[string]string{
		"tel +32" + nbsp + "475" + nbsp + "12 34 56":                "12 34 56",
		"tel 0475" + nnbsp + "12" + nnbsp + "34" + nnbsp + "56":     "56",
		"card 4111" + nbsp + "1111" + nbsp + "1111" + nbsp + "1111": "1111",
		"iban BE68" + nbsp + "5390" + nbsp + "0754" + nbsp + "7034": "7034",
	}
	for in, secret := range leaks {
		got, _ := maskCells(t, defaults, in)[0].(string)
		if got == in || strings.Contains(got, secret) {
			t.Errorf("default detectors: %q -> %q, %q still visible", in, got, secret)
		}
	}

	// Unicode e-mail addresses were already masked on lockkit v0.1.0;
	// kept as regression guards.
	for in, secret := range map[string]string{
		"josé@example.com":          "josé",
		"müller.hans@exämple.de":    "exämple",
		"josé.dupont@example.com":   "dupont",
		"write to renée@exämple.fr": "renée",
	} {
		got, _ := maskCells(t, defaults, in)[0].(string)
		if got == in || strings.Contains(got, secret) {
			t.Errorf("default detectors: %q -> %q, %q still visible", in, got, secret)
		}
	}

	if f := float64(4111111111111111); maskCells(t, defaults, f)[0] == f {
		t.Errorf("default detectors: float64(%.0f) not masked", f)
	}
	// An integral float goes through the integer path: masked exactly when
	// the same integer is. 32475123456 has no + or trunk 0, so the default
	// phone rule leaves it, as an integer or as text.
	for _, n := range []int64{4111111111111111, 32475123456, 475123456} {
		fi, ii := maskCells(t, defaults, float64(n))[0], maskCells(t, defaults, n)[0]
		if (fi == float64(n)) != (ii == n) {
			t.Errorf("float64(%d) -> %v but int64 -> %v", n, fi, ii)
		}
	}

	loose := append(append([]string{}, defaults...), "phone_loose")
	for _, in := range []string{"(415) 555-2671", "415-555-2671", "612 345 678"} {
		if got := maskCells(t, loose, in)[0]; got == in {
			t.Errorf("phone_loose: %q not masked", in)
		}
		if got := maskCells(t, defaults, in)[0]; got != in {
			t.Errorf("default detectors: %q -> %v, the default phone rule changed", in, got)
		}
	}

	// Negatives, with phone_loose too.
	for _, in := range []any{"page" + nbsp + "12 of the report", "1.5", "2026-01-02", 1.5, float64(2026)} {
		if got := maskCells(t, loose, in)[0]; got != in {
			t.Errorf("%v (%T) -> %v, want unchanged", in, in, got)
		}
	}
}
