package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandHome(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"~/x.pem", "/home/locksql/x.pem"},
		{"~/.ssh/db-ca.pem", "/home/locksql/.ssh/db-ca.pem"},
		{"~", "/home/locksql"},
		{"/etc/ssl/ca.pem", "/etc/ssl/ca.pem"},
		{"certs/ca.pem", "certs/ca.pem"},
		{"~other/x.pem", "~other/x.pem"}, // another account's home: as is
		{"", ""},
	} {
		want := tc.want
		if strings.HasPrefix(tc.in, "~/") {
			want = filepath.FromSlash(want) // filepath.Join's separator
		}
		if got := ExpandHome(tc.in, "/home/locksql"); got != want {
			t.Errorf("ExpandHome(%q) = %q, want %q", tc.in, got, want)
		}
	}
}

func TestFileKeys(t *testing.T) {
	p := Profile{TLSCA: "~/ca.pem", TLSKey: "~/k.pem", TLSCert: "~/c.pem",
		SSH: &SSHProfile{Auth: SSHAuthKey, Key: "~/.ssh/id"}}
	var keys []string
	for _, f := range p.FileKeys() {
		keys = append(keys, f.Key+"="+f.Path)
	}
	if got, want := strings.Join(keys, " "), "tls_ca=~/ca.pem tls_cert=~/c.pem tls_key=~/k.pem ssh.key=~/.ssh/id"; got != want {
		t.Errorf("FileKeys = %q, want %q", got, want)
	}
	p.SSH.Auth = SSHAuthAgent
	p.TLSCert, p.TLSKey = "", ""
	if got := p.FileKeys(); len(got) != 1 || got[0].Key != "tls_ca" {
		t.Errorf("FileKeys without client cert, ssh agent = %+v, want tls_ca only", got)
	}
}

func TestCheckFiles(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "x.pem"), []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFiles(Profile{TLSCA: "~/x.pem"}, home); err != nil {
		t.Errorf("present ~/x.pem: %v", err)
	}
	if err := CheckFiles(Profile{}, home); err != nil {
		t.Errorf("no file key: %v", err)
	}
	err := CheckFiles(Profile{TLSCA: "~/.ssh/db-ca.pem"}, home)
	want := "tls_ca: " + filepath.Join(home, ".ssh/db-ca.pem") + " not found in the console's home (" + home + ")"
	if err == nil || err.Error() != want {
		t.Errorf("missing tls_ca: %v, want %q", err, want)
	}
	err = CheckFiles(Profile{TLSCA: "~/x.pem", TLSCert: "~/c.pem", TLSKey: "~/x.pem"}, home)
	if err == nil || !strings.HasPrefix(err.Error(), "tls_cert: ") {
		t.Errorf("missing tls_cert: %v", err)
	}
	abs := filepath.Join(home, "none.pem")
	if err := CheckFiles(Profile{TLSKey: abs}, home); err == nil || err.Error() != "tls_key: "+abs+" not found" {
		t.Errorf("missing absolute tls_key: %v", err)
	}
}
