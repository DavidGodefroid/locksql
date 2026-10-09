package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/DavidGodefroid/locksql/internal/config"
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

// ecdsaToo makes the test server offer an ECDSA host key besides its
// Ed25519 one.
func ecdsaToo(t *testing.T, cfg *ssh.ServerConfig) *ssh.ServerConfig {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(signer)
	return cfg
}

func TestRecordedKeyTypeIsNegotiated(t *testing.T) {
	path, pub := writeKey(t, t.TempDir(), "", 0o600)
	s := newTestServer(t, ecdsaToo(t, acceptKey(pub)))
	prof := sshProfile(s, "key", path)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownAddr(prof)}, s.hostKey.PublicKey())
	if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, _ := KnownHosts(kh, func(string, string, string) bool { t.Error("asked"); return true })
	if tun, err := Open(t.Context(), Options{Profile: prof, HostKey: cb}); err == nil {
		tun.Close()
		t.Fatal("expected a failure without HostKeyAlgorithms (Go prefers ECDSA)")
	} else if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("err = %v", err)
	}
	algs, err := HostKeyAlgorithms(kh, prof)
	if err != nil || len(algs) != 1 || algs[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("algs = %v, %v", algs, err)
	}
	tun, err := Open(t.Context(), Options{Profile: prof, HostKey: cb, HostKeyAlgorithms: algs})
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
}

func TestHostKeyAlgorithmsNothingRecorded(t *testing.T) {
	prof := config.SSHProfile{Host: "bastion", Port: 22}
	for _, kh := range []string{filepath.Join(t.TempDir(), "absent"), ""} {
		if kh == "" {
			kh = filepath.Join(t.TempDir(), "empty")
			os.WriteFile(kh, nil, 0o600)
		}
		algs, err := HostKeyAlgorithms(kh, prof)
		if err != nil || len(algs) == 0 || algs[0] != ssh.KeyAlgoED25519 {
			t.Fatalf("algs = %v, %v", algs, err)
		}
		for _, a := range algs {
			if strings.Contains(a, "cert") {
				t.Errorf("certificate algorithm %s", a)
			}
		}
	}
}

func TestAppendKeepsFileWellFormed(t *testing.T) {
	_, pub := writeKey(t, t.TempDir(), "", 0o600)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	first := knownhosts.Line([]string{"first.example:22"}, pub)
	os.WriteFile(kh, []byte(first), 0o600) // no trailing newline
	if err := appendLine(kh, knownhosts.Line([]string{"second.example:22"}, pub)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(kh)
	if lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n"); len(lines) != 2 || lines[0] != first {
		t.Fatalf("file = %q", data)
	}
	if _, err := knownhosts.New(kh); err != nil {
		t.Fatal(err)
	}
}

func TestHostIsLowercased(t *testing.T) {
	prof := config.SSHProfile{Host: "Bastion.Example.COM", Port: 22}
	if got, want := knownAddr(prof), "bastion.example.com"; got != want {
		t.Errorf("knownAddr = %q, want %q", got, want)
	}
	_, pub := writeKey(t, t.TempDir(), "", 0o600)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(kh, []byte(knownhosts.Line([]string{"bastion.example.com"}, pub)+"\n"), 0o600)
	cb, _ := KnownHosts(kh, func(string, string, string) bool { t.Error("asked"); return false })
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22}
	if err := cb("Bastion.Example.COM:22", addr, pub); err != nil {
		t.Fatal(err)
	}
}
