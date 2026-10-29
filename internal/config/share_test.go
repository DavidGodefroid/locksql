package config

import (
	"fmt"

	"bytes"
	"errors"
	"github.com/BurntSushi/toml"
	"reflect"
	"strings"
	"testing"
)

const shareSource = `[profiles.uat]
engine = "mariadb"
host = "db.uat.example.com"
user = "alice"
database = "app"
tls_ca = "/etc/ssl/corp.pem"
tls = "verify-full"
pii_rules = "shop"

[profiles.uat.limits]
max_rows = 300

[profiles.uat.ssh]
host = "bastion.example.com"
user = "deploy"
auth = "key"
key = "~/.ssh/id_ed25519"

[profiles.reporting]
engine = "postgres"
host = "db.internal"
credentials = "vault"
vault_path = "database/creds/reporting-ro"
detectors = []
write_functions = "allowlist"

[profiles.local]
engine = "sqlite"
path = "dev.db"

[profiles.sock]
engine = "mysql"
host = "/run/mysqld/mysqld.sock"
`

func mustParse(t *testing.T, data string) map[string]Profile {
	t.Helper()
	ps, err := ParseProfiles([]byte(data), "config.toml", "/srv/app")
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestExportProfileAllowList(t *testing.T) {
	ps := mustParse(t, shareSource)
	s, err := ExportProfile(ps["uat"], "shop", false)
	if err != nil {
		t.Fatal(err)
	}
	if s.User != "" {
		t.Errorf("user exported without --include-user: %q", s.User)
	}
	if got := strings.Join(s.NeedsLocal, ","); got != "tls_ca,ssh.key" {
		t.Errorf("needs_local = %s", got)
	}
	var b bytes.Buffer
	if err := EncodeShare(&b, Share{Format: ShareFormat, Profiles: map[string]SharedProfile{"uat": s}}); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"corp.pem", "id_ed25519", "alice", `"key":`, `"tls_ca":`} {
		if strings.Contains(b.String(), leak) {
			t.Errorf("export holds %q:\n%s", leak, b.String())
		}
	}
	if s.Limits.MaxRows != 300 || s.SSH.Host != "bastion.example.com" || s.PIIRules != "shop" || s.TLS != "verify-full" {
		t.Errorf("shared keys lost: %+v", s)
	}
	if s, _ := ExportProfile(ps["uat"], "shop", true); s.User != "alice" {
		t.Errorf("--include-user: user %q", s.User)
	}
	if s, _ := ExportProfile(ps["reporting"], "reporting", false); s.Detectors == nil || len(s.Detectors) != 0 {
		t.Errorf("empty detectors not kept: %#v", s.Detectors)
	}
	for _, n := range []string{"local", "sock"} {
		if _, err := ExportProfile(ps[n], n, false); !errors.Is(err, ErrNotShareable) {
			t.Errorf("%s: err = %v", n, err)
		}
	}
}

func TestExportRefusesSecrets(t *testing.T) {
	p := mustParse(t, shareSource)["uat"]
	p.User = "alice:hunter2@db"
	if _, err := ExportProfile(p, "shop", true); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
	p = mustParse(t, shareSource)["uat"]
	p.Database = "x password=hunter2"
	if _, err := ExportProfile(p, "shop", false); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
}

func shareOf(t *testing.T, includeUser bool) *Share {
	t.Helper()
	ps := mustParse(t, shareSource)
	s := &Share{Format: ShareFormat, Profiles: map[string]SharedProfile{}}
	for _, n := range []string{"uat", "reporting"} {
		sp, err := ExportProfile(ps[n], RuleSetOf(ps[n]), includeUser)
		if err != nil {
			t.Fatal(err)
		}
		s.Profiles[n] = sp
	}
	var b bytes.Buffer
	if err := EncodeShare(&b, *s); err != nil {
		t.Fatal(err)
	}
	d, err := DecodeShare(b.Bytes())
	if err != nil {
		t.Fatalf("round trip: %v\n%s", err, b.String())
	}
	return d
}

// An imported profile resolves to the source on the shared keys; local
// values come from --local or stay as they were.
func TestImportRoundTrip(t *testing.T) {
	s := shareOf(t, false)
	f, err := ParseConfigFile([]byte(`[profiles.mine]
engine = "postgres"
host = "db.mine"
`), "config.toml", "/home/b")
	if err != nil {
		t.Fatal(err)
	}
	skipped, err := f.Import(s, ImportOptions{Local: map[string]map[string]string{"uat": {"tls_ca": "/b/ca.pem", "ssh.key": "~/.ssh/b"}}})
	if err != nil || len(skipped) != 0 {
		t.Fatalf("skipped %v, err %v", skipped, err)
	}
	got := mustParse(t, string(f.TOML("")))
	src := mustParse(t, shareSource)
	if _, ok := got["mine"]; !ok {
		t.Error("local-only profile dropped")
	}
	for _, n := range []string{"uat", "reporting"} {
		a, b := src[n], got[n]
		// The import names the set the source used.
		if RuleSetOf(a) != RuleSetOf(b) {
			t.Errorf("%s: set %q, want %q", n, RuleSetOf(b), RuleSetOf(a))
		}
		a.User, a.TLSCA, b.TLSCA, a.PIIRules, b.PIIRules = "", "", "", "", ""
		if a.SSH != nil {
			if b.SSH == nil || b.SSH.Key != "~/.ssh/b" {
				t.Fatalf("%s: ssh.key not from --local: %+v", n, b.SSH)
			}
			sa, sb := *a.SSH, *b.SSH
			sa.Key, sb.Key = "", ""
			a.SSH, b.SSH = &sa, &sb
		}
		if n == "uat" && got[n].TLSCA != "/b/ca.pem" {
			t.Errorf("tls_ca = %q", got[n].TLSCA)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s:\nsource %+v\nimport %+v", n, a, b)
		}
	}

	// A second import changes nothing.
	before := f.TOML("")
	if _, err := f.Import(s, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, f.TOML("")) {
		t.Errorf("second import changed the file:\n%s\n---\n%s", before, f.TOML(""))
	}
}

func TestImportKeepsLocalValuesAndSkipsMissing(t *testing.T) {
	s := shareOf(t, false)
	f, err := ParseConfigFile([]byte(`[profiles.uat]
engine = "mariadb"
host = "old.example.com"
user = "bob"
tls = "verify-full"
tls_ca = "/b/ca.pem"
`), "config.toml", "/home/b")
	if err != nil {
		t.Fatal(err)
	}
	skipped, err := f.Import(s, ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// uat needs ssh.key, which nothing gives: skipped, the local profile kept.
	if len(skipped) != 1 || skipped[0].Profile != "uat" || !strings.Contains(skipped[0].Reason, "ssh.key") {
		t.Fatalf("skipped = %+v", skipped)
	}
	got := mustParse(t, string(f.TOML("")))
	if got["uat"].Host != "old.example.com" {
		t.Errorf("skipped profile changed: %+v", got["uat"])
	}
	if _, err := f.Import(s, ImportOptions{Local: map[string]map[string]string{"uat": {"ssh.key": "~/.ssh/b"}}}); err != nil {
		t.Fatal(err)
	}
	got = mustParse(t, string(f.TOML("")))
	if u := got["uat"]; u.User != "bob" || u.TLSCA != "/b/ca.pem" || u.Host != "db.uat.example.com" {
		t.Errorf("local values: %+v", u)
	}

	// --local accepts only local keys of profiles in the file.
	if _, err := f.Import(s, ImportOptions{Local: map[string]map[string]string{"uat": {"host": "evil"}}}); err == nil {
		t.Error("--local host accepted")
	}
	if _, err := f.Import(s, ImportOptions{Local: map[string]map[string]string{"nope": {"tls_ca": "x"}}}); err == nil {
		t.Error("--local of an unknown profile accepted")
	}
}

func TestImportReplace(t *testing.T) {
	s := shareOf(t, false)
	f, _ := ParseConfigFile([]byte("[profiles.mine]\nengine = \"postgres\"\nhost = \"db.mine\"\n"), "config.toml", "/b")
	if _, err := f.Import(s, ImportOptions{Replace: true, Only: []string{"reporting"}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.Names(), ","); got != "reporting" {
		t.Errorf("profiles after --replace: %s", got)
	}
	if _, err := f.Import(s, ImportOptions{Only: []string{"absent"}}); err == nil {
		t.Error("--profile of a profile not in the file accepted")
	}
}

func TestDecodeShareRefuses(t *testing.T) {
	ok := `{"locksql_config_format":1,"profiles":{"uat":{"engine":"mariadb","host":"db","detectors":[]}}}`
	if _, err := DecodeShare([]byte(ok)); err != nil {
		t.Fatalf("valid file refused: %v", err)
	}
	cases := map[string]string{
		"newer format":      `{"locksql_config_format":2,"profiles":{}}`,
		"no format":         `{"profiles":{}}`,
		"unknown top field": `{"locksql_config_format":1,"extra":1,"profiles":{"a":{"engine":"mariadb","host":"h","detectors":[]}}}`,
		"unknown key":       `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","password":"x","detectors":[]}}}`,
		"unknown limit":     `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","limits":{"max_rowz":1},"detectors":[]}}}`,
		"unknown pii field": `{"locksql_config_format":1,"pii":{"s":{"mask":[{"column":"a.b.c","x":1}],"allow":[]}}}`,
		"local key in file": `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","tls_ca":"/x","detectors":[]}}}`,
		"bad needs_local":   `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","needs_local":["host"],"detectors":[]}}}`,
		"bad name":          `{"locksql_config_format":1,"profiles":{"../x":{"engine":"mariadb","host":"h","detectors":[]}}}`,
		"bad set":           `{"locksql_config_format":1,"pii":{"../x":{"mask":[],"allow":[]}}}`,
		"bad pii_rules":     `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","pii_rules":"A/B","detectors":[]}}}`,
		"newline injection": `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h\"]\n[profiles.x]","detectors":[]}}}`,
		"nul":               `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h\u0000","detectors":[]}}}`,
		"dsn with password": `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"u:secretpw@h","detectors":[]}}}`,
		"trailing data":     ok + ` {}`,
		"wrong type":        `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","port":"x","detectors":[]}}}`,
		"empty":             `{"locksql_config_format":1,"profiles":{}}`,
		"not json":          `[profiles.a]`,
	}
	for name, data := range cases {
		_, err := DecodeShare([]byte(data))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "secretpw") {
			t.Errorf("%s: error quotes the value: %v", name, err)
		}
	}
}

// Values the shell or a template would expand are kept as text: nothing
// in an import is expanded, and the writer quotes everything.
func TestImportWritesValuesVerbatim(t *testing.T) {
	data := `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"$(id)` + "`id`" + `~$HOME","database":"x\"y","detectors":[]}}}`
	s, err := DecodeShare([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := ParseConfigFile(nil, "config.toml", "/b")
	if _, err := f.Import(s, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	got := mustParse(t, string(f.TOML("")))
	if got["a"].Host != "$(id)`id`~$HOME" || got["a"].Database != `x"y` {
		t.Errorf("values changed: %+v", got["a"])
	}
}

// Every key a config file can hold survives the writer: a key added to
// rawProfile and forgotten in ConfigFile.TOML would be dropped from the
// profiles an import does not touch, a silent policy change.
func TestConfigFileWritesEveryKey(t *testing.T) {
	var fill func(v reflect.Value)
	fill = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			v.SetString("v")
		case reflect.Int, reflect.Int64:
			v.SetInt(7)
		case reflect.Float64:
			v.SetFloat(1.5)
		case reflect.Bool:
			v.SetBool(true)
		case reflect.Slice:
			v.Set(reflect.ValueOf([]string{"v"}))
		case reflect.Pointer:
			v.Set(reflect.New(v.Type().Elem()))
			fill(v.Elem())
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				fill(v.Field(i))
			}
		}
	}
	var r rawProfile
	fill(reflect.ValueOf(&r).Elem())
	f := &ConfigFile{profiles: map[string]rawProfile{"p": r}}
	var back rawFile
	if _, err := kconfigDecode(f.TOML(""), &back); err != nil {
		t.Fatalf("%v\n%s", err, f.TOML(""))
	}
	if !reflect.DeepEqual(back.Profiles["p"], r) {
		t.Errorf("keys lost by the writer:\nwrote %+v\nread  %+v\n%s", r, back.Profiles["p"], f.TOML(""))
	}
}

func kconfigDecode(data []byte, into any) (any, error) {
	md, err := toml.Decode(string(data), into)
	if err == nil && len(md.Undecoded()) > 0 {
		err = fmt.Errorf("unknown key %q", md.Undecoded()[0].String())
	}
	return nil, err
}

// Every profile key is either shared or listed as personal or local here:
// a key added to Profile must be placed on purpose, else an import would
// drop it on the other machine.
func TestEveryProfileKeyIsPlaced(t *testing.T) {
	notShared := map[string]bool{"name": true, "path": true, "user": true, "tls_ca": true, "tls_cert": true, "tls_key": true, "proxy_command": true}
	shared := map[string]bool{}
	st := reflect.TypeOf(SharedProfile{})
	for i := 0; i < st.NumField(); i++ {
		shared[strings.Split(st.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	pt := reflect.TypeOf(Profile{})
	for i := 0; i < pt.NumField(); i++ {
		k := strings.Split(pt.Field(i).Tag.Get("json"), ",")[0]
		if !shared[k] && !notShared[k] {
			t.Errorf("profile key %q is neither shared nor excluded", k)
		}
	}
}

// proxy_command is a command of this machine: never exported, never taken
// from a shared file, nor from --local; an import keeps the local one, and
// skips a profile that needs one and has none.
func TestProxyCommandStaysLocal(t *testing.T) {
	src := mustParse(t, `[profiles.k8s]
engine = "postgres"
host = "db"
proxy_command = ["kubectl", "exec", "-i", "db-0", "--", "nc", "localhost", "5432"]
`)
	sp, err := ExportProfile(src["k8s"], "k8s", false)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_ = EncodeShare(&b, Share{Format: ShareFormat, Profiles: map[string]SharedProfile{"k8s": sp}})
	if strings.Contains(b.String(), "kubectl") || !strings.Contains(strings.Join(sp.NeedsLocal, ","), "proxy_command") {
		t.Fatalf("export:\n%s", b.String())
	}
	s, err := DecodeShare(b.Bytes())
	if err != nil {
		t.Fatalf("needs_local proxy_command refused: %v", err)
	}
	// A command in the shared file is refused.
	bad := strings.Replace(b.String(), `"engine": "postgres",`, `"engine": "postgres", "proxy_command": ["sh", "-c", "id"],`, 1)
	if _, err := DecodeShare([]byte(bad)); err == nil {
		t.Error("proxy_command in a shared file accepted")
	}

	// No local command: skipped.
	f, _ := ParseConfigFile(nil, "config.toml", "/b")
	skipped, err := f.Import(s, ImportOptions{})
	if err != nil || len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "proxy_command") {
		t.Fatalf("skipped %+v, err %v", skipped, err)
	}
	// --local cannot give a command.
	if _, err := f.Import(s, ImportOptions{Local: map[string]map[string]string{"k8s": {"proxy_command": "sh"}}}); err == nil {
		t.Error("--local proxy_command accepted")
	}
	// The local command is kept.
	f, err = ParseConfigFile([]byte(`[profiles.k8s]
engine = "postgres"
host = "old"
proxy_command = ["docker", "exec", "-i", "pg", "nc", "localhost", "5432"]
`), "config.toml", "/b")
	if err != nil {
		t.Fatal(err)
	}
	if skipped, err := f.Import(s, ImportOptions{}); err != nil || len(skipped) != 0 {
		t.Fatalf("skipped %+v, err %v", skipped, err)
	}
	got := mustParse(t, string(f.TOML("")))["k8s"]
	if strings.Join(got.ProxyCommand, " ") != "docker exec -i pg nc localhost 5432" || got.Host != "db" {
		t.Errorf("k8s = %+v", got)
	}
}
