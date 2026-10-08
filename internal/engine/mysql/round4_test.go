package mysql

import (
	"bytes"
	"context"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locksql/internal/config"
)

// TestRefusesSplitGreetingForgedOK plays an attacker who pads the greeting
// to a 0xffffff-byte packet, so that go-mysql joins it with the next packet,
// and makes that continuation packet start with 0x00. A guard framing
// packets one by one would take it for an OK, stop looking, and let the
// auth switch to mysql_clear_password through.
func TestRefusesSplitGreetingForgedOK(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got bytes.Buffer
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				g := handshakeV10()
				g = append(g, make([]byte, 0xffffff-len(g))...)
				if _, err := c.Write(append(packet(0, g), packet(1, []byte{0x00})...)); err != nil {
					return
				}
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				mu.Lock()
				got.Write(buf[:n])
				mu.Unlock()
				if err != nil {
					return
				}
				sw := append([]byte{0xfe}, []byte("mysql_clear_password\x00")...)
				if _, err := c.Write(packet(3, sw)); err != nil {
					return
				}
				rest, _ := io.ReadAll(c)
				mu.Lock()
				got.Write(rest)
				mu.Unlock()
			}()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	p := config.Profile{
		Name: "t", Engine: config.EngineMySQL, Host: "127.0.0.1", Port: addr.Port, User: "u",
		Tier: config.TierRead, Limits: config.DefaultLimits(false),
	}
	const secret = "S3cr3t-pa55word"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := Engine{}.Connect(ctx, p, []byte(secret))
	if err == nil {
		s.Close()
		t.Error("connect succeeded")
	}
	ln.Close()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if bytes.Contains(got.Bytes(), []byte(secret)) {
		t.Fatal("the password reached the server in clear text")
	}
}

func TestFromNames(t *testing.T) {
	cases := []struct {
		q             string
		rels, aliases string
		ok            bool
	}{
		{"SELECT small.label FROM v_def AS small LIMIT 5", "V_DEF", "SMALL", true},
		{"SELECT label FROM app.v_def small LIMIT 5", "V_DEF", "SMALL", true},
		{"SELECT b.id FROM big b JOIN small ON small.id = b.id, other.t AS x WHERE 1", "BIG SMALL T", "B X", true},
		{"SELECT id FROM big LEFT JOIN small USING (id) ORDER BY id", "BIG SMALL", "", true},
		{"SELECT id FROM big PARTITION (p0) AS p USE INDEX (i) LIMIT 1", "BIG", "P", true},
		{"SELECT 1 FROM DUAL", "", "", true},
		{"SELECT id FROM (big JOIN small USING (id))", "", "", false},
	}
	for _, c := range cases {
		rels, aliases, ok := fromNames(c.q)
		if ok != c.ok {
			t.Errorf("%s: ok = %v", c.q, ok)
			continue
		}
		if !ok {
			continue
		}
		set := func(s string) map[string]bool {
			m := map[string]bool{}
			for _, w := range strings.Fields(s) {
				m[w] = true
			}
			return m
		}
		if !reflect.DeepEqual(rels, set(c.rels)) || !reflect.DeepEqual(aliases, set(c.aliases)) {
			t.Errorf("%s: rels %v aliases %v", c.q, rels, aliases)
		}
	}
}
