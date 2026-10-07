package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

type fakeEngine struct{}

func (fakeEngine) Connect(context.Context, config.Profile, []byte) (Session, error) { return nil, nil }

func TestRegistry(t *testing.T) {
	Register("fake-test", fakeEngine{})
	if _, err := Get("fake-test"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(Names(), "fake-test") {
		t.Fatalf("Names = %v", Names())
	}
	if _, err := Get("nope"); err == nil {
		t.Fatal("unknown engine accepted")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate Register did not panic")
		}
	}()
	Register("fake-test", fakeEngine{})
}
