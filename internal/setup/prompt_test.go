package setup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type script struct {
	answers []string
	out     []string
}

func (s *script) Println(l string) { s.out = append(s.out, l) }
func (s *script) Ask(_ context.Context, p string, _ time.Duration) (string, bool) {
	s.out = append(s.out, p)
	if len(s.answers) == 0 {
		return "", false // Ctrl-D
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return a, true
}

func TestPromptURLWithDefaults(t *testing.T) {
	s := &script{answers: []string{"postgres://app@127.0.0.1:5432/shop", "", "", "", ""}}
	a, err := Prompt(context.Background(), s, "/", nil)
	want := Answers{Target: Target{Engine: "postgres", Host: "127.0.0.1", Port: 5432, User: "app", Database: "shop"}, Name: "dev", Tier: "read", Keychain: true}
	if err != nil || a != want {
		t.Fatalf("Prompt = %+v, %v", a, err)
	}
}

func TestPromptStepByStep(t *testing.T) {
	// URL empty, engine 2 (mysql), host default, port default, user, database, name, tier, production, keychain
	s := &script{answers: []string{"", "2", "", "", "root", "", "uat", "write", "y", "n"}}
	a, err := Prompt(context.Background(), s, "/", []string{"dev"})
	want := Answers{Target: Target{Engine: "mysql", Host: "127.0.0.1", Port: 3306, User: "root"}, Name: "uat", Tier: "write", Production: true}
	if err != nil || a != want {
		t.Fatalf("Prompt = %+v, %v", a, err)
	}
}

func TestPromptReasksAndDefaultsAroundTakenNames(t *testing.T) {
	s := &script{answers: []string{"postgres://app:pw@h/db", "postgres://h/db", "", "admin", "", "", ""}}
	a, err := Prompt(context.Background(), s, "/", []string{"dev"})
	if err != nil || a.Name != "dev2" || a.Tier != "read" {
		t.Fatalf("Prompt = %+v, %v", a, err)
	}
	if strings.Contains(strings.Join(s.out, "\n"), ":pw@") {
		t.Fatal("the password was echoed")
	}
}

func TestPromptAbortWritesNothing(t *testing.T) {
	s := &script{answers: []string{"postgres://h/db"}}
	if _, err := Prompt(context.Background(), s, "/", nil); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}
}
