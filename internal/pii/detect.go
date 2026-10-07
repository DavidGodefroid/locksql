package pii

import (
	"slices"
	"strings"
	"unicode"

	"github.com/DavidGodefroid/locksql/internal/engine"
)

// sensitiveTokens are column-name tokens that make a column personal data
// on their own (en, fr, nl, de, es).
var sensitiveTokens = set(
	// email
	"email", "emails", "courriel", "emailadres", "emailadresse", "correo",
	// phone
	"phone", "phones", "telephone", "tel", "telefoon", "telefon", "telefono", "gsm", "mobile", "mobiel",
	"handy", "cellphone", "msisdn", "fax", "phonenumber", "telefoonnummer", "telefonnummer", "portable",
	// person names
	"firstname", "lastname", "surname", "fullname", "givenname", "familyname", "middlename", "maidenname",
	"prenom", "voornaam", "achternaam", "familienaam", "vorname", "nachname", "familienname",
	"apellido", "apellidos",
	// address
	"address", "addresses", "addr", "adresse", "adres", "anschrift", "direccion", "domicilio",
	"street", "streetname", "rue", "straat", "strasse", "calle", "city", "ville", "stad", "woonplaats",
	"stadt", "ciudad", "zip", "zipcode", "postcode", "postalcode", "postleitzahl", "plz",
	"housenumber", "huisnummer", "hausnummer",
	// birth
	"birth", "birthdate", "birthday", "dob", "naissance", "geboorte", "geboortedatum", "geburt",
	"geburtsdatum", "geburtstag", "nacimiento",
	// bank and card
	"iban", "bic", "cardnumber", "creditcard", "cvv", "cvc",
	// national ids and documents
	"ssn", "niss", "nir", "bsn", "ssin", "rrn", "insz", "inss", "nationalid", "nationalnumber",
	"rijksregister", "rijksregisternummer", "passport", "passeport", "paspoort", "reisepass", "pasaporte",
	"dni", "nie",
	// network
	"ip", "ipaddress", "ipv4", "ipv6",
	// credentials (hashes included)
	"password", "passwd", "pwd", "secret", "token", "apikey", "otp",
)

// pairTokens are two consecutive tokens that make a column personal data
// together ("first_name", "mail_address", "card_number").
var pairTokens = map[[2]string]bool{
	{"mail", "address"}: true, {"mail", "addr"}: true, {"mail", "adres"}: true, {"mail", "adresse"}: true,
	{"phone", "number"}: true, {"card", "number"}: true, {"account", "number"}: true, {"bank", "account"}: true,
	{"national", "id"}: true, {"national", "number"}: true, {"national", "register"}: true,
	{"id", "card"}: true, {"identity", "card"}: true, {"tax", "id"}: true, {"social", "security"}: true,
	{"house", "number"}: true, {"postal", "code"}: true, {"code", "postal"}: true, {"api", "key"}: true,
	{"date", "naissance"}: true, {"fecha", "nacimiento"}: true, {"codigo", "postal"}: true,
}

func init() {
	// "phone_num", "card_no": short forms of number, which alone are neutral
	// ("email_num" counts emails).
	for _, owner := range []string{"phone", "tel", "mobile", "gsm", "fax", "card", "account"} {
		for _, n := range []string{"num", "no", "nr", "nb"} {
			pairTokens[[2]string{owner, n}] = true
		}
	}
}

// nameWords mean "name" and need an owner token next to them: "customer_name"
// and "nom_client" are personal, "template_name" and "file_name" are not.
var nameWords = set("name", "naam", "nom", "nombre")

var nameOwners = set(
	"first", "last", "full", "given", "family", "middle", "maiden", "birth", "nick", "display",
	"customer", "recipient", "client", "sender", "contact", "person", "user", "member", "employee",
	"patient", "owner", "holder", "beneficiary", "debtor", "creditor", "student",
	"klant", "kunde", "destinataire", "expediteur", "famille", "familie", "achter", "voor", "pila",
)

// nameSkip are stop words skipped when looking for a name owner
// ("nom_de_famille").
var nameSkip = set("de", "du", "des", "la", "le", "van", "der", "von", "del")

// neutralLast are last tokens that make a column metadata about personal
// data rather than the data itself ("email_id", "email_verified_at").
var neutralLast = set(
	"id", "ids", "uuid", "guid", "fk", "count", "nb", "num", "type", "types", "status", "kind", "flag",
	"enabled", "verified", "validated", "valid", "format", "length", "len", "at", "on", "sent",
	"optin", "consent", "lines", "lignes",
)

// documentTokens suggest that a binary column holds a document or a picture.
var documentTokens = set(
	"document", "documents", "doc", "docs", "file", "files", "pdf", "scan", "scans", "attachment",
	"attachments", "image", "images", "img", "photo", "photos", "picture", "pictures", "avatar",
	"signature", "content", "body", "blob", "upload", "fichier", "bestand", "datei",
)

// Propose returns the "db.table.column" patterns for the columns that look
// like personal data from their name or type, sorted and de-duplicated. A
// name that would break the pattern syntax becomes '*'.
func Propose(cols []engine.ColumnInfo) []string {
	var out []string
	for _, c := range cols {
		if sensitiveColumn(c.Column, c.Type) {
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

func sensitiveColumn(name, typ string) bool {
	typ = strings.ToLower(typ)
	toks := tokens(name)
	if len(toks) == 0 {
		return false
	}
	if base, _, _ := strings.Cut(typ, "("); base == "inet" || base == "cidr" || base == "macaddr" || base == "macaddr8" {
		return true
	}
	for i := 1; i < len(toks); i++ {
		if pairTokens[[2]string{toks[i-1], toks[i]}] {
			return true
		}
	}
	if neutralLast[toks[len(toks)-1]] && len(toks) > 1 {
		return false
	}
	if isBinaryType(typ) && slices.ContainsFunc(toks, func(t string) bool { return documentTokens[t] }) {
		return true
	}
	for i, t := range toks {
		if sensitiveTokens[t] {
			return true
		}
		if nameWords[t] && (ownerAt(toks, i, -1) || ownerAt(toks, i, +1)) {
			return true
		}
	}
	// Unsplit compounds such as "emailaddress" or "customername".
	joined := strings.Join(toks, "")
	for _, suffix := range []string{"email", "phone", "address", "firstname", "lastname", "fullname"} {
		if strings.HasSuffix(joined, suffix) && len(joined) > len(suffix) && len(toks) == 1 {
			return true
		}
	}
	return false
}

func ownerAt(toks []string, i, step int) bool {
	for j := i + step; j >= 0 && j < len(toks); j += step {
		if nameSkip[toks[j]] {
			continue
		}
		return nameOwners[toks[j]]
	}
	return false
}

func isBinaryType(typ string) bool {
	for _, b := range []string{"blob", "bytea", "binary", "varbinary", "image"} {
		if strings.Contains(typ, b) {
			return true
		}
	}
	return false
}

// tokens splits a column name on non-alphanumerics and camelCase, lowered,
// with accents removed from common Latin letters ("prénom" → "prenom").
func tokens(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) ||
				(unicode.IsUpper(rs[i-1]) && i+1 < len(rs) && unicode.IsLower(rs[i+1]))) {
				flush()
			}
			cur = append(cur, unaccent(unicode.ToLower(r)))
		default:
			flush()
		}
	}
	flush()
	return out
}

func unaccent(r rune) rune {
	switch r {
	case 'à', 'á', 'â', 'ä', 'ã', 'å':
		return 'a'
	case 'ç':
		return 'c'
	case 'è', 'é', 'ê', 'ë':
		return 'e'
	case 'ì', 'í', 'î', 'ï':
		return 'i'
	case 'ñ':
		return 'n'
	case 'ò', 'ó', 'ô', 'ö', 'õ':
		return 'o'
	case 'ù', 'ú', 'û', 'ü':
		return 'u'
	case 'ß':
		return 's'
	}
	return r
}

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}
