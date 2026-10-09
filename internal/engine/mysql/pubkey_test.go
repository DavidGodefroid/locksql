package mysql

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// salt is the 20-byte scramble of handshakeWith.
const salt = "abcdefghijklmnopqrst"

// handshakeWith is handshakeV10 with another default auth plugin.
func handshakeWith(plugin string) []byte {
	p := handshakeV10()
	return append(p[:len(p)-len("mysql_native_password\x00")], []byte(plugin+"\x00")...)
}

func readPacket(c net.Conn) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint32(append(h[:3:3], 0)))
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}

// pubKeyServer plays an attacker who stripped TLS and asks for the
// password through RSA with its own key: either a caching_sha2_password
// full authentication or an auth switch to sha256_password. It decrypts
// whatever the client sends with that key.
type pubKeyServer struct {
	ln        net.Listener
	key       *rsa.PrivateKey
	sha256    bool
	mu        sync.Mutex
	recovered []string
	done      sync.WaitGroup
}

func (f *pubKeyServer) serve() {
	pubDER, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.done.Add(1)
		go func() {
			defer f.done.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			plugin := "caching_sha2_password"
			if _, err := c.Write(packet(0, handshakeWith(plugin))); err != nil {
				return
			}
			if _, err := readPacket(c); err != nil {
				return
			}
			seq := byte(2)
			if f.sha256 {
				sw := append([]byte{0xfe}, []byte("sha256_password\x00"+salt+"\x00")...)
				if _, err := c.Write(packet(seq, sw)); err != nil {
					return
				}
				if _, err := readPacket(c); err != nil { // the public key request
					return
				}
				seq += 2
			} else {
				if _, err := c.Write(packet(seq, []byte{0x01, 0x04})); err != nil { // full auth
					return
				}
				if _, err := readPacket(c); err != nil { // the public key request
					return
				}
				seq += 2
			}
			if _, err := c.Write(packet(seq, append([]byte{0x01}, pemKey...))); err != nil {
				return
			}
			enc, err := readPacket(c)
			if err != nil || len(enc) == 0 {
				return
			}
			plain, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, f.key, enc, nil)
			if err != nil {
				return
			}
			for i := range plain {
				plain[i] ^= salt[i%len(salt)]
			}
			f.mu.Lock()
			f.recovered = append(f.recovered, string(plain))
			f.mu.Unlock()
		}()
	}
}

// An attacker who strips TLS must not get the password by asking for it
// encrypted with its own RSA key.
func TestRefusesPublicKeyAuthWithoutTLS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, sha256 := range []bool{false, true} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f := &pubKeyServer{ln: ln, key: key, sha256: sha256}
		go f.serve()
		addr := ln.Addr().(*net.TCPAddr)
		p := config.Profile{
			Name: "t", Engine: config.EngineMySQL, Host: "127.0.0.1", Port: addr.Port, User: "u",
			Tier: config.TierRead, Limits: config.DefaultLimits(false),
		}
		const secret = "S3cr3t-pa55word"
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = Engine{}.Connect(ctx, p, []byte(secret), nil)
		cancel()
		ln.Close()
		f.done.Wait()
		if err == nil || !strings.Contains(err.Error(), "unencrypted") {
			t.Errorf("sha256=%v: connect error = %v, want the unencrypted-auth refusal", sha256, err)
		}
		for _, r := range f.recovered {
			if bytes.Contains([]byte(r), []byte(secret)) {
				t.Errorf("sha256=%v: the attacker recovered the password", sha256)
			}
		}
	}
}
