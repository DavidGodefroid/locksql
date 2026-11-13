package console

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kconsole "github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/locksql/internal/config"
	audit "github.com/DavidGodefroid/locksql/internal/sqlaudit"
)

// lockedBuffer is a bytes.Buffer safe for the Terminal's writes and the
// test's reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// questionTerminal is a Terminal over a pipe that records its questions
// in a file; answer waits for the next question, returns its file and
// types reply.
func questionTerminal(t *testing.T) (term *Terminal, out *lockedBuffer, answer func(reply string) string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	out = &lockedBuffer{}
	term = NewTerminal(r, out)
	qpath := filepath.Join(t.TempDir(), "uat.question")
	term.SetQuestionFile(qpath)
	answer = func(reply string) string {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(qpath); err == nil {
				if _, err := w.WriteString(reply + "\n"); err != nil {
					t.Error(err)
				}
				return string(b)
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("no question file written")
		return ""
	}
	return term, out, answer
}

// The host and the fingerprint of an unknown host key are printed as
// context of the trust question, so that a human answering from the hub
// or the mobile app sees which key they trust (#213), for the [yes/N]
// prompt and for the production one; the terminal shows them as before.
func TestHostKeyContextInQuestionFile(t *testing.T) {
	const fp = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	for _, production := range []bool{false, true} {
		term, out, answer := questionTerminal(t)
		log, err := audit.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p := uatProfile()
		p.Production = production
		p.SSH = &config.SSHProfile{Host: "bastion.example.com", Port: 22, User: "deploy"}
		st := &starter{io: term, log: log, profile: p}
		reply := "yes"
		if production {
			reply = fp[len(fp)-8:]
		}
		got := make(chan string, 1)
		go func() { got <- answer(reply) }()
		ok := st.confirmHostKey(context.Background(), p, "/home/u/.ssh/known_hosts", "bastion.example.com:22", "ssh-ed25519", fp)
		q := <-got
		if !ok {
			t.Fatalf("production=%v: key not trusted with %q", production, reply)
		}
		prompt, above := kconsole.ParseQuestion(q)
		wantPrompt := "Trust this key and add it to /home/u/.ssh/known_hosts? [yes/N]"
		if production {
			wantPrompt = "Type the last 8 characters of the fingerprint to trust it:"
		}
		if !strings.Contains(prompt, wantPrompt) {
			t.Errorf("production=%v: prompt %q, want %q", production, prompt, wantPrompt)
		}
		ctxt := strings.Join(above, "\n")
		for _, want := range []string{
			"The authenticity of bastion.example.com:22 can't be established.",
			"ssh-ed25519 key fingerprint is " + fp,
		} {
			if !strings.Contains(ctxt, want) {
				t.Errorf("production=%v: question context %q lacks %q", production, ctxt, want)
			}
		}
		if strings.Contains(ctxt, reply+"\n") || strings.HasSuffix(ctxt, "\n"+reply) {
			t.Errorf("production=%v: answer in the question context %q", production, ctxt)
		}
		s := out.String()
		if !strings.Contains(s, "The authenticity of bastion.example.com:22 can't be established.") ||
			!strings.Contains(s, "ssh-ed25519 key fingerprint is "+fp+"\n") {
			t.Errorf("production=%v: terminal output lost the host key lines: %q", production, s)
		}
		if i, j := strings.Index(s, "fingerprint is"), strings.Index(s, wantPrompt); i < 0 || j < i {
			t.Errorf("production=%v: host key lines not above the prompt: %q", production, s)
		}

		// The next question, a secret one, carries neither the host key
		// context nor the answer typed to the trust question.
		got = make(chan string, 1)
		go func() { got <- answer("s3cret") }()
		v, err := term.AskSecret(context.Background(), "Password for deploy@bastion.example.com: ")
		q = <-got
		if err != nil || string(v) != "s3cret" {
			t.Fatalf("production=%v: AskSecret = %q, %v", production, v, err)
		}
		if _, above := kconsole.ParseQuestion(q); above != nil {
			t.Errorf("production=%v: secret question has context %q", production, above)
		}
		if strings.Contains(q, "s3cret") || strings.Contains(q, reply) {
			t.Errorf("production=%v: an answer reached the question file: %q", production, q)
		}
	}
}
