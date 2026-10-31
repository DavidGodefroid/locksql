package config

import (
	"fmt"
	"strings"
	"testing"
)

// Canary secrets: a token pasted in the wrong key, and a URL with userinfo.
const (
	canaryToken = "glsa_CanarySecretToken123"
	canaryURL   = "https://user:glsa_Canary@h"
)

// noEcho reports an error that quotes a canary or does not name its key.
func noEcho(t *testing.T, what, key string, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("%s: accepted", what)
	case strings.Contains(err.Error(), "glsa_Canary"):
		t.Errorf("%s: error quotes the value: %v", what, err)
	case !strings.Contains(err.Error(), key):
		t.Errorf("%s: error does not name %s: %v", what, key, err)
	}
}

// TestErrorsDoNotEchoValues: a secret in any key of a profile never
// appears in the error, which still names the key.
func TestErrorsDoNotEchoValues(t *testing.T) {
	both := []string{canaryToken, canaryURL}
	mysql := "engine=\"mysql\"\nhost=\"db\"\n"
	vault := "engine=\"postgres\"\nhost=\"db\"\ncredentials=\"vault\"\n"
	cases := []struct {
		key, body string // body holds %s, the canary
		canaries  []string
	}{
		{"tier", mysql + "tier=%q\n", both},
		{"engine", "engine=%q\nhost=\"db\"\n", both},
		{"tls", mysql + "tls=%q\n", both},
		{"credentials", mysql + "credentials=%q\n", both},
		{"write_functions", mysql + "write_functions=%q\n", both},
		{"detectors", mysql + "detectors=[\"email\", %q]\n", both},
		{"limits.statement_timeout", mysql + "[profiles.p.limits]\nstatement_timeout=%q\n", both},
		{"limits.idle_timeout", mysql + "[profiles.p.limits]\nidle_timeout=%q\n", both},
		{"limits.max_session", mysql + "[profiles.p.limits]\nmax_session=%q\n", both},
		{"credentials_ttl", mysql + "credentials_ttl=%q\n", both},
		{"pii_rules", mysql + "pii_rules=%q\n", both},
		{"tls_server_name", mysql + "tls=\"verify-full\"\ntls_server_name=%q\n", both},
		{"vault_path", vault + "vault_path=%q\n", []string{canaryURL, "-" + canaryToken, "/" + canaryToken, "a " + canaryToken}},
		{"host", "engine=\"mysql\"\nhost=%q\n", []string{canaryURL}},
		{"user", mysql + "user=%q\n", []string{canaryURL}},
		{"database", mysql + "database=%q\n", []string{canaryURL}},
		{"tls_ca", mysql + "tls=\"verify-full\"\ntls_ca=%q\n", []string{canaryURL}},
		{"proxy_command[1]", mysql + "proxy_command=[\"nc\", %q]\n", []string{canaryURL, "--token=" + canaryToken}},
		{"ssh.credentials", mysql + "[profiles.p.ssh]\nhost=\"b\"\nuser=\"u\"\nauth=\"password\"\ncredentials=%q\n", both},
	}
	for _, c := range cases {
		for _, v := range c.canaries {
			body := "[profiles.p]\n" + fmt.Sprintf(c.body, v)
			_, err := ParseProfiles([]byte(body), "t.toml", t.TempDir())
			noEcho(t, c.key+" = "+v, c.key, err)
		}
	}
	if _, err := ParseTier(canaryToken); err == nil || strings.Contains(err.Error(), "glsa_Canary") {
		t.Errorf("ParseTier: %v", err)
	}
}

// TestDecodeShareDoesNotEchoValues: the same for a shared configuration.
func TestDecodeShareDoesNotEchoValues(t *testing.T) {
	for _, v := range []string{canaryToken, canaryURL} {
		for key, data := range map[string]string{
			"needs_local":       `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","needs_local":[%q],"detectors":[]}}}`,
			"PII rule set name": `{"locksql_config_format":1,"pii":{%q:{"mask":[],"allow":[]}}}`,
			"pii_rules":         `{"locksql_config_format":1,"profiles":{"a":{"engine":"mariadb","host":"h","pii_rules":%q,"detectors":[]}}}`,
		} {
			_, err := DecodeShare(fmt.Appendf(nil, data, v))
			noEcho(t, key+" = "+v, key, err)
		}
	}
}

// TestImportDoesNotEchoProfileNames: a --profile or --local naming no
// profile of the file is named by the flag, never quoted back.
func TestImportDoesNotEchoProfileNames(t *testing.T) {
	s := shareOf(t, false)
	f, err := ParseConfigFile([]byte("[profiles.mine]\nengine = \"postgres\"\nhost = \"db.mine\"\n"), "config.toml", "/home/b")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{canaryToken, canaryURL + "/path?token=glsa_Canary"} {
		_, err := f.Import(s, ImportOptions{Only: []string{"uat", v}})
		noEcho(t, "--profile "+v, "--profile 2", err)
		_, err = f.Import(s, ImportOptions{Local: map[string]map[string]string{v: {"tls_ca": "x"}}})
		noEcho(t, "--local "+v, "--local", err)
	}
}
