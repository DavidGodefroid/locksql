//go:build unix

package main

import (
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
)

func TestCompleteSpec(t *testing.T) {
	bad := []profileSpec{
		{engine: "oracle"},
		{engine: "sqlite"},
		{engine: "sqlite", path: "a.db", host: "h"},
		{engine: "postgres", path: "a.db"},
		{engine: "postgres", port: 70000},
		{engine: "postgres", credentials: "env"},
		{engine: "postgres", name: "a.b"},
		{engine: "postgres", host: "h\nx"},
	}
	for _, s := range bad {
		if _, err := completeSpec(s); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	s, err := completeSpec(profileSpec{engine: "mariadb", user: `we"ird\`})
	if err != nil {
		t.Fatal(err)
	}
	if s.name != "dev" || s.host != "127.0.0.1" || s.port != 3306 || s.credentials != "ask" {
		t.Errorf("defaults %+v", s)
	}
	profiles, err := config.ParseProfiles([]byte(s.toml()), "t", t.TempDir())
	if err != nil {
		t.Fatalf("%v\n%s", err, s.toml())
	}
	if profiles["dev"].User != `we"ird\` {
		t.Errorf("user %q", profiles["dev"].User)
	}
}
