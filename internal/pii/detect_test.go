package pii

import (
	"slices"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

func TestPropose(t *testing.T) {
	var cols []engine.ColumnInfo
	for _, c := range [][2]string{
		{"email", "varchar(255)"}, {"prenom", "varchar(50)"}, {"voornaam", "varchar(50)"},
		{"telefoon", "varchar(20)"}, {"street_name", "varchar(100)"},
		{"template_name", "varchar(50)"}, {"mail_id", "bigint"}, {"status", "varchar(10)"},
		{"ip_address", "inet"},
	} {
		cols = append(cols, engine.ColumnInfo{DB: "app", Table: "users", Column: c[0], Type: c[1]})
	}
	got := Propose(cols)
	want := []string{
		"app.users.email", "app.users.ip_address", "app.users.prenom",
		"app.users.street_name", "app.users.telefoon", "app.users.voornaam",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Propose = %v\nwant      %v", got, want)
	}
}

func TestProposeMore(t *testing.T) {
	sensitive := []string{
		"EmailAddress", "recipientName", "customer_name", "nom_client", "last_name", "lastname", "achternaam",
		"Nachname", "apellido", "mail_address", "courriel", "gsm", "mobile_number",
		"city", "iban", "niss", "national_id", "rijksregisternummer",
		"client_ip", "card_number", "password_hash",
		"phone_num", "tel_num", "card_num", "account_num", "card_no", "account_nr", "mobile_num",
	}
	neutral := []string{"id", "status", "table_name", "file_name", "template_name", "mail_id", "postal_handling_id",
		"created_at", "email_id", "email_verified_at", "nombre_lignes", "phone_type"}
	for _, c := range sensitive {
		if got := Propose([]engine.ColumnInfo{{DB: "d", Table: "t", Column: c, Type: "text"}}); len(got) != 1 {
			t.Errorf("Propose(%s) = %v, want a rule", c, got)
		}
	}
	for _, c := range neutral {
		if got := Propose([]engine.ColumnInfo{{DB: "d", Table: "t", Column: c, Type: "text"}}); len(got) != 0 {
			t.Errorf("Propose(%s) = %v, want none", c, got)
		}
	}
	// Types: network addresses always, binary only when the name suggests a document.
	typed := []engine.ColumnInfo{
		{DB: "d", Table: "t", Column: "origin", Type: "cidr"},
		{DB: "d", Table: "t", Column: "scan_pdf", Type: "bytea"},
		{DB: "d", Table: "t", Column: "checksum", Type: "varbinary(32)"},
	}
	if got := Propose(typed); !slices.Equal(got, []string{"d.t.origin", "d.t.scan_pdf"}) {
		t.Errorf("Propose(typed) = %v", got)
	}
	// Names that would break the pattern syntax become wildcards.
	if got := Propose([]engine.ColumnInfo{{DB: "my.db", Table: "t", Column: "email", Type: "text"}}); !slices.Equal(got, []string{"*.t.email"}) {
		t.Errorf("Propose(dotted) = %v", got)
	}
}

func TestProposeQuasi(t *testing.T) {
	quasi := []string{"birth_date", "dob", "date_naissance", "geboortedatum", "geburtsdatum", "zip_code",
		"postcode", "postal_code", "code_postal", "plz", "gender", "sex", "sexe", "geslacht", "geschlecht"}
	neutral := []string{"id", "email", "birth_date_verified", "zip_code_id", "status"}
	var cols []engine.ColumnInfo
	for _, c := range append(slices.Clone(quasi), neutral...) {
		cols = append(cols, engine.ColumnInfo{DB: "app", Table: "t", Column: c, Type: "varchar"})
	}
	got := ProposeQuasi(cols)
	for _, c := range quasi {
		if !slices.Contains(got, "app.t."+c) {
			t.Errorf("%s not proposed as a quasi-identifier", c)
		}
	}
	for _, c := range neutral {
		if slices.Contains(got, "app.t."+c) {
			t.Errorf("%s proposed as a quasi-identifier", c)
		}
	}
}

func TestQuasiNeverAlsoPII(t *testing.T) {
	var cols []engine.ColumnInfo
	for _, c := range []string{"birth_name", "birth_date", "email", "zip_code", "customer_name"} {
		cols = append(cols, engine.ColumnInfo{DB: "app", Table: "t", Column: c, Type: "varchar"})
	}
	pii, quasi := Propose(cols), ProposeQuasi(cols)
	for _, p := range quasi {
		if slices.Contains(pii, p) {
			t.Errorf("%s is in both lists", p)
		}
	}
	if !slices.Contains(pii, "app.t.birth_name") {
		t.Error("birth_name (a name) not proposed as PII")
	}
}
