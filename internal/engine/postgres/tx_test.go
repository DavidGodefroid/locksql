package postgres

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/sqlclass"
)

// fakeServer speaks just enough of the PostgreSQL protocol for a session to
// connect and run statements; it records every statement text it receives
// and answers each with one int4 row (value 1).
type fakeServer struct {
	mu   sync.Mutex
	stmt []string
}

func (f *fakeServer) record(q string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stmt = append(f.stmt, q)
}

func (f *fakeServer) statements() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.stmt...)
}

func (f *fakeServer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, s := net.Pipe()
	go f.serve(s)
	return c, nil
}

func (f *fakeServer) serve(c net.Conn) {
	defer c.Close()
	be := pgproto3.NewBackend(c, c)
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 2}})
	tx := byte('I')
	be.Send(&pgproto3.ReadyForQuery{TxStatus: tx})
	if be.Flush() != nil {
		return
	}
	row := func() {
		be.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
			{Name: []byte("n"), DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1}}})
	}
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			f.record(m.String)
			switch q := strings.ToUpper(m.String); {
			case strings.HasPrefix(q, "BEGIN"):
				tx = 'T'
			case q == "COMMIT" || q == "ROLLBACK":
				tx = 'I'
			}
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: tx})
		case *pgproto3.Parse:
			f.record(m.Query)
			be.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Bind:
			be.Send(&pgproto3.BindComplete{})
		case *pgproto3.Describe:
			row()
		case *pgproto3.Execute:
			be.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("1")}})
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		case *pgproto3.Sync:
			be.Send(&pgproto3.ReadyForQuery{TxStatus: tx})
		case *pgproto3.Terminate:
			return
		}
		if be.Flush() != nil {
			return
		}
	}
}

// TestRunRollsBackReads checks that a read ends its READ ONLY transaction
// with ROLLBACK: a session-level SET made inside it (a planted function
// calling set_config(..., false)) must not outlive the statement. A write
// still commits.
func TestRunRollsBackReads(t *testing.T) {
	for _, tc := range []struct {
		class      sqlclass.Class
		sql, begin string
		end        string
	}{
		{sqlclass.Read, "SELECT lower(1)", "BEGIN READ ONLY", "ROLLBACK"},
		{sqlclass.Write, "UPDATE t SET a = 1", "BEGIN", "COMMIT"},
	} {
		f := &fakeServer{}
		p := config.Profile{Engine: config.EnginePostgres, Host: "db.internal", Port: 5432, User: "u",
			TLS: config.TLSDisable, Tier: config.TierWrite}
		sess, err := Engine{}.Connect(t.Context(), p, []byte("pw"), f.dial)
		if err != nil {
			t.Fatal(err)
		}
		before := len(f.statements())
		if _, err := sess.Run(t.Context(), "", sqlclass.Statement{Class: tc.class, SQL: tc.sql}, 10); err != nil {
			t.Fatalf("%s: %v", tc.sql, err)
		}
		got := f.statements()[before:]
		want := []string{tc.begin, tc.sql, tc.end}
		if strings.Join(got, " | ") != strings.Join(want, " | ") {
			t.Errorf("%s: statements = %q, want %q", tc.sql, got, want)
		}
		sess.Close()
	}
}
