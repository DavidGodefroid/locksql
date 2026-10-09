package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnknownKeyAccepted(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	kh := filepath.Join(t.TempDir(), ".ssh", "known_hosts")
	asked := 0
	cb, err := KnownHosts(kh, func(host, keyType, fp string) bool {
		asked++
		if !strings.HasPrefix(fp, "SHA256:") || keyType != "ssh-ed25519" {
			t.Errorf("confirm(%q, %q, %q)", host, keyType, fp)
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := Open(t.Context(), Options{Profile: sshProfile(s, "key", path), HostKey: cb})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
	st, err := os.Stat(kh)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts: %v %v", st, err)
	}
	// Second connection: the key is now known, no question.
	cb, _ = KnownHosts(kh, func(string, string, string) bool { asked++; return false })
	tun, err = Open(t.Context(), Options{Profile: sshProfile(s, "key", path), HostKey: cb})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
	if asked != 1 {
		t.Errorf("asked %d times", asked)
	}
}

func TestUnknownKeyRefused(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	kh := filepath.Join(t.TempDir(), "known_hosts")
	cb, _ := KnownHosts(kh, func(string, string, string) bool { return false })
	if _, err := Open(t.Context(), Options{Profile: sshProfile(s, "key", path), HostKey: cb}); err == nil {
		t.Fatal("connected to an untrusted host")
	}
	if _, err := os.Stat(kh); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("known_hosts written after a refusal: %v", err)
	}
}

func TestChangedKeyRefused(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, acceptKey(pub))
	kh := filepath.Join(t.TempDir(), "known_hosts")
	cb, _ := KnownHosts(kh, func(string, string, string) bool { return true })
	tun, err := Open(t.Context(), Options{Profile: sshProfile(s, "key", path), HostKey: cb})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
	// Same address, new host key: point the known_hosts line at another
	// server's key by rewriting it with that server's address.
	other := newTestServer(t, acceptKey(pub))
	data, _ := os.ReadFile(kh)
	host := sshProfile(s, "key", path)
	otherProf := sshProfile(other, "key", path)
	line := strings.Replace(string(data), knownAddr(host), knownAddr(otherProf), 1)
	os.WriteFile(kh, []byte(line), 0o600)
	cb, _ = KnownHosts(kh, func(string, string, string) bool { t.Error("asked about a changed key"); return true })
	_, err = Open(t.Context(), Options{Profile: otherProf, HostKey: cb})
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Errorf("err = %v, want ErrHostKeyChanged", err)
	}
}
