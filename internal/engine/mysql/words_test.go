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

func TestQualifier(t *testing.T) {
	for _, c := range []struct {
		text string
		want bool
	}{
		{"update other.t set x = 1", true},
		{"update `other` . `t` set x = 1", true},
		{"update \"other\".t set x = 1", true},
		{"update t set x = 'other'", false},
		{"update another.t set x = 1", false},
		{"update other_x.t set x = 1", false},
		{"update t set other = 1", false},
		{"update other\r.t set x = 1", true},
		{"update other\f.t set x = 1", true},
		{"update other\v.t set x = 1", true},
		{"update other\r\n. t set x = 1", true},
		{"update `oth``er`.t set x = 1", true},
	} {
		if got := qualifier(matchText(c.text), "other") || qualifier(matchText(c.text), "oth`er"); got != c.want {
			t.Errorf("qualifier(%q) = %v", c.text, got)
		}
	}
}

func TestQualifiedBlanks(t *testing.T) {
	for _, q := range []string{"UPDATE other\r.rc_oth SET x = 1", "UPDATE other\f.rc_oth SET x = 1", "UPDATE other\v.\vrc_oth SET x = 1", "UPDATE `other`\r\n.`rc_oth` SET x = 1"} {
		if !qualified(matchText(q), "other", "rc_oth") || !qualifier(matchText(q), "other") {
			t.Errorf("%q: not qualified", q)
		}
	}
	if !qualified(matchText("UPDATE `a``b`.t SET x = 1"), "a`b", "t") {
		t.Error("a schema with a doubled backtick")
	}
}
