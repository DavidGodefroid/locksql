package pii

import (
	"strings"
	"testing"
)

func detector(t *testing.T, name string) Detector {
	t.Helper()
	ds, err := Detectors([]string{name})
	if err != nil || len(ds) != 1 {
		t.Fatalf("Detectors(%s) = %v, %v", name, ds, err)
	}
	if ds[0].Name() != name {
		t.Fatalf("Name() = %s", ds[0].Name())
	}
	return ds[0]
}

func TestDetectorsUnknown(t *testing.T) {
	if _, err := Detectors([]string{"email", "dna"}); err == nil {
		t.Error("unknown detector accepted")
	}
	ds, err := Detectors([]string{"phone", "email", "phone"})
	if err != nil || len(ds) != 2 || ds[0].Name() != "email" {
		t.Errorf("Detectors = %v, %v (want email first, de-duplicated)", ds, err)
	}
}

func TestDetectorMasks(t *testing.T) {
	cases := []struct {
		det, in  string
		masked   []string // substrings that must disappear
		kept     []string // substrings that must stay
		contains string   // optional substring of the output
	}{
		{det: "email", in: `{"to":"jean.dupont@example.com","status":"sent"}`, masked: []string{"jean.dupont@example.com"}, kept: []string{`"status":"sent"`, `{"to":"`}, contains: "j***(23)"},
		{det: "email", in: "to jöhn@example.com.", masked: []string{"öhn", "@example"}, kept: []string{"to ", "."}, contains: "to j***(16)."},
		{det: "email", in: "rené.dupont@example.com", masked: []string{"ené", "dupont"}, contains: "r***(23)"},
		{det: "email", in: "john@exämple.com", masked: []string{"ohn", "exämple"}, contains: "j***(16)"},
		{det: "email", in: "rene\u0301.dupont@example.com", masked: []string{"ene", "\u0301", "dupont"}, contains: "r***(24)"}, // decomposed é
		{det: "email", in: "ÉLÈVE_42@école.fr", masked: []string{"LÈVE", "école"}, contains: "É***(17)"},
		{det: "be_niss", in: "ref 85073003328 ok", masked: []string{"85073003328"}, contains: "ref 8***(11) ok"},
		{det: "be_niss", in: "ref 85.07.30-033.28 ok", masked: []string{"033"}},
		{det: "be_niss", in: "ref 85 07 30 033 28 ok", masked: []string{"033"}},
		{det: "be_niss", in: "id 12345678901", kept: []string{"12345678901"}},
		{det: "be_niss", in: "id 850730033281", kept: []string{"850730033281"}}, // 12 digits: not a NISS
		{det: "iban", in: "pay BE68 5390 0754 7034 now", masked: []string{"5390"}, kept: []string{"pay ", " now"}, contains: "B***(19)"},
		{det: "iban", in: "BE68539007547034", masked: []string{"BE68539007547034"}},
		{det: "iban", in: "BE68 5390 0754 7035", kept: []string{"BE68 5390 0754 7035"}},
		{det: "iban", in: "pay be68 5390 0754 7034 now", masked: []string{"5390"}, kept: []string{"pay ", " now"}, contains: "b***(19)"},
		{det: "iban", in: "Be68539007547034", masked: []string{"539007547034"}},
		{det: "card", in: "card 4111 1111 1111 1111.", masked: []string{"1111"}, contains: "card 4***(19)."},
		{det: "card", in: "4111-1111-1111-1111", masked: []string{"1111"}},
		{det: "card", in: "4111 1111 1111 1112", kept: []string{"4111 1111 1111 1112"}},
		{det: "phone", in: "call +32 475 12 34 56 now", masked: []string{"475 12"}, contains: "call +***(16) now"},
		{det: "phone", in: "0475123456", masked: []string{"0475123456"}},
		{det: "phone", in: "0475/12.34.56 and 02 123 45 67", masked: []string{"0475", "123 45"}},
		{det: "phone", in: "0032475123456", masked: []string{"0032475123456"}},
		{det: "phone", in: "tel 0475123456 2026", masked: []string{"0475123456"}, kept: []string{" 2026"}},
		{det: "phone", in: "+33 6 12 34 56 78", masked: []string{"12 34"}},
		{det: "phone", in: "order 12345678901, 2026-10-07, 0.123456789, v1.2.3, 10.0.0.1", kept: []string{"12345678901", "2026-10-07", "0.123456789", "10.0.0.1"}},
		{det: "fr_nir", in: "nir 1 84 03 76 451 089 96", masked: []string{"451 089"}},
		{det: "fr_nir", in: "nir 184037645108996", masked: []string{"184037645108996"}},
		{det: "fr_nir", in: "nir 2 69 05 2A 001 123 07", masked: []string{"001 123"}},
		{det: "fr_nir", in: "nir 184037645108997", kept: []string{"184037645108997"}},
		{det: "nl_bsn", in: "bsn 111222333", masked: []string{"111222333"}},
		{det: "nl_bsn", in: "bsn 111222334", kept: []string{"111222334"}},
		{det: "us_ssn", in: "ssn 123-45-6789", masked: []string{"123-45-6789"}},
		{det: "us_ssn", in: "ssn 666-45-6789 000-12-3456 912-34-5678 123-00-4567 123-45-0000", kept: []string{"666-45-6789", "000-12-3456", "912-34-5678", "123-00-4567", "123-45-0000"}},
	}
	for _, c := range cases {
		got := detector(t, c.det).Mask(c.in)
		for _, m := range c.masked {
			if strings.Contains(got, m) {
				t.Errorf("%s.Mask(%q) = %q, still contains %q", c.det, c.in, got, m)
			}
		}
		for _, k := range c.kept {
			if !strings.Contains(got, k) {
				t.Errorf("%s.Mask(%q) = %q, lost %q", c.det, c.in, got, k)
			}
		}
		if c.contains != "" && !strings.Contains(got, c.contains) {
			t.Errorf("%s.Mask(%q) = %q, want it to contain %q", c.det, c.in, got, c.contains)
		}
	}
}

func TestAllDetectorsTogether(t *testing.T) {
	ds, err := Detectors([]string{"email", "phone", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn"})
	if err != nil {
		t.Fatal(err)
	}
	in := "a@b.example, BE68 5390 0754 7034 / +32 475 12 34 56 / 0475123456 / 85073003328 / 4111111111111111"
	out := in
	for _, d := range ds {
		out = d.Mask(out)
	}
	for _, leak := range []string{"a@b", "5390", "475 12", "0475123456", "85073003328", "4111111111111111"} {
		if strings.Contains(out, leak) {
			t.Errorf("output %q still contains %q", out, leak)
		}
	}
}

func TestMaskText(t *testing.T) {
	for in, want := range map[string]string{"": "***(0)", "é": "é***(1)", "Jean Dupont": "J***(11)", "\xffab": "�***(3)"} {
		if got := maskText(in); got != want {
			t.Errorf("maskText(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzDetectorsNoPanic(f *testing.F) {
	f.Add("+32 475 12 34 56 BE68 5390 0754 7034 a@b.c 4111 1111 1111 1111")
	f.Add("2 69 05 2A 001 123 07 111222333 123-45-6789 85.07.30-033.28")
	ds, _ := Detectors([]string{"email", "phone", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn"})
	f.Fuzz(func(t *testing.T, s string) {
		for _, d := range ds {
			s = d.Mask(s)
		}
	})
}

// Values that straddle a scan window edge are still found.
func TestDetectorsAcrossWindowEdges(t *testing.T) {
	values := map[string]string{
		"card":    "4111 1111 1111 1111",
		"iban":    "BE68 5390 0754 7034",
		"be_niss": "85.07.30-033.28",
		"fr_nir":  "1 84 03 76 451 089 96",
		"nl_bsn":  "111222333",
		"us_ssn":  "123-45-6789",
	}
	for name, v := range values {
		d := detector(t, name)
		for off := scanWindow - 50; off < scanWindow+10; off++ {
			in := strings.Repeat("x", off) + " " + v + " " + strings.Repeat("y", 3*scanWindow)
			if got := d.Mask(in); strings.Contains(got, v) {
				t.Errorf("%s at offset %d not masked", name, off)
			}
		}
	}
	// A long run of separated digits stays fast and finds a card at its end.
	in := strings.Repeat("1-", 100000) + " 4111 1111 1111 1111"
	if got := detector(t, "card").Mask(in); strings.Contains(got, "4111 1111") {
		t.Error("card after a digit run not masked")
	}
}
