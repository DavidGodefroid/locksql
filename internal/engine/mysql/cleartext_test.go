package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// fakeServer is a local MySQL-protocol stub that offers no TLS, accepts
// the client's handshake response, then asks for an auth switch to
// mysql_clear_password. It records every byte the client sends.
type fakeServer struct {
	ln   net.Listener
	mu   sync.Mutex
	got  bytes.Buffer
	done sync.WaitGroup
}

func packet(seq byte, payload []byte) []byte {
	h := make([]byte, 4)
	binary.LittleEndian.PutUint32(h, uint32(len(payload)))
	h[3] = seq
	return append(h, payload...)
}

func handshakeV10() []byte {
	caps := uint32(gomysqlProtocol41 | gomysqlSecureConn | gomysqlPluginAuth | 1)
	var p bytes.Buffer
	p.WriteByte(10)
	p.WriteString("8.4.0-fake\x00")
	p.Write([]byte{1, 0, 0, 0})
	p.WriteString("abcdefgh")
	p.WriteByte(0)
	p.Write([]byte{byte(caps), byte(caps >> 8)})
	p.WriteByte(0x21)
	p.Write([]byte{2, 0})
	p.Write([]byte{byte(caps >> 16), byte(caps >> 24)})
	p.WriteByte(21)
	p.Write(make([]byte, 10))
	p.WriteString("ijklmnopqrst\x00")
	p.WriteString("mysql_native_password\x00")
	return p.Bytes()
}

const (
	gomysqlProtocol41 = 0x00000200
	gomysqlSecureConn = 0x00008000
	gomysqlPluginAuth = 0x00080000
)

func (f *fakeServer) serve(t *testing.T) {
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
			if _, err := c.Write(packet(0, handshakeV10())); err != nil {
				return
			}
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			f.mu.Lock()
			f.got.Write(buf[:n])
			f.mu.Unlock()
			if err != nil {
				return
			}
			sw := append([]byte{0xfe}, []byte("mysql_clear_password\x00")...)
			if _, err := c.Write(packet(2, sw)); err != nil {
				return
			}
			rest, _ := io.ReadAll(c)
			f.mu.Lock()
			f.got.Write(rest)
			f.mu.Unlock()
		}()
	}
}

func TestRefusesClearTextAuthSwitchWithoutTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{ln: ln}
	go f.serve(t)
	defer func() { ln.Close(); f.done.Wait() }()

	addr := ln.Addr().(*net.TCPAddr)
	p := config.Profile{
		Name: "t", Engine: config.EngineMySQL, Host: "127.0.0.1", Port: addr.Port, User: "u",
		Tier: config.TierRead, Limits: config.DefaultLimits(false),
	}
	const secret = "S3cr3t-pa55word"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = Engine{}.Connect(ctx, p, []byte(secret))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("clear text")) {
		t.Fatalf("connect error = %v, want the clear-text refusal", err)
	}
	ln.Close()
	f.done.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if bytes.Contains(f.got.Bytes(), []byte(secret)) {
		t.Fatal("the password reached the server in clear text")
	}
}
