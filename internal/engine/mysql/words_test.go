package mysql

import "testing"

func TestWordIn(t *testing.T) {
	for _, c := range []struct {
		text, name string
		want       bool
	}{
		{"update 1log set x = 1", "1log", true},
		{"update shop.1log set x = 1", "1log", true},
		{"update `shop`.`rc_my` set x = 1", "rc_my", true},
		{"update \"rc_my\" set x = 1", "rc_my", true},
		{"update rc_my2 set x = 1", "rc_my", false},
		{"update xrc_my set x = 1", "rc_my", false},
		{"update t set rc_my_note = 1", "rc_my", false},
		{"insert into t values ('rc_my')", "rc_my", true}, // refuses more, never less
	} {
		if got := wordIn(c.text, c.name); got != c.want {
			t.Errorf("wordIn(%q, %q) = %v", c.text, c.name, got)
		}
	}
}

func TestQualified(t *testing.T) {
	for _, c := range []struct {
		text string
		want bool
	}{
		{"update mysql.user set x = 1", true},
		{"update `mysql` . `user` set x = 1", true},
		{"update t set user = 1", false},
		{"update app.user set x = 1", false},
	} {
		if got := qualified(c.text, "mysql", "user"); got != c.want {
			t.Errorf("qualified(%q) = %v", c.text, got)
		}
	}
}
