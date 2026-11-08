package config

import (
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
)

// limits.tickets_per_window, limits.ticket_window and limits.max_pending
// reach the hub client's limits; unset, its defaults apply (#150).
func TestTicketLimitsParse(t *testing.T) {
	parse := func(t *testing.T, limits string) Limits {
		t.Helper()
		body := "[profiles.app]\nengine=\"sqlite\"\npath=\"app.db\"\n[profiles.app.limits]\n" + limits
		ps, err := ParseProfiles([]byte(body), "config.toml", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return ps["app"].Limits
	}
	if got := parse(t, "").TicketLimits(); got != hubclient.DefaultLimits() {
		t.Errorf("unset: %+v, want the defaults %+v", got, hubclient.DefaultLimits())
	}
	l := parse(t, "tickets_per_window = 60\nticket_window = \"10m\"\nmax_pending = 40\n")
	if l.TicketsPerWindow != 60 || l.TicketWindow != 10*time.Minute || l.MaxPending != 40 {
		t.Fatalf("parsed %+v", l)
	}
	want := hubclient.Limits{MaxPending: 40, RateN: 60, RateWindow: 10 * time.Minute, RateTotal: hubclient.RateTotal}
	if got := l.TicketLimits(); got != want {
		t.Errorf("TicketLimits %+v, want %+v", got, want)
	}
}

func TestTicketLimitsInvalid(t *testing.T) {
	for _, c := range []struct{ name, limits, want string }{
		{"negative rate", "tickets_per_window = -1\n", "limits.tickets_per_window"},
		{"negative pending", "max_pending = -3\n", "limits.max_pending"},
		{"window not a duration", "ticket_window = \"soon\"\n", "limits.ticket_window"},
		{"negative window", "ticket_window = \"-5m\"\n", "limits.ticket_window"},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := "[profiles.app]\nengine=\"sqlite\"\npath=\"app.db\"\n[profiles.app.limits]\n" + c.limits
			_, err := ParseProfiles([]byte(body), "config.toml", t.TempDir())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want one naming %s", err, c.want)
			}
		})
	}
}

// Raising a ticket limit or shortening the window lets an agent ask the
// human more often: a loosening, reviewed. Lowering is free; an approved
// policy from before the limits existed (0) compares as the default.
func TestTicketLimitsDiff(t *testing.T) {
	p := Profile{Name: "uat", Engine: EngineSQLite, Path: "/x", Limits: DefaultLimits(false)}
	a := NewPolicy(p, nil, nil)
	field := func(changes []Change, f string) *Change {
		for i := range changes {
			if changes[i].Field == f {
				return &changes[i]
			}
		}
		return nil
	}
	for _, c := range []struct {
		name, field string
		set         func(*Limits)
		loosens     bool
	}{
		{"more tickets", "limits.tickets_per_window", func(l *Limits) { l.TicketsPerWindow = 60 }, true},
		{"fewer tickets", "limits.tickets_per_window", func(l *Limits) { l.TicketsPerWindow = 10 }, false},
		{"default tickets", "limits.tickets_per_window", func(l *Limits) { l.TicketsPerWindow = hubclient.RateN }, false},
		{"shorter window", "limits.ticket_window", func(l *Limits) { l.TicketWindow = time.Minute }, true},
		{"longer window", "limits.ticket_window", func(l *Limits) { l.TicketWindow = time.Hour }, false},
		{"more pending", "limits.max_pending", func(l *Limits) { l.MaxPending = 50 }, true},
		{"fewer pending", "limits.max_pending", func(l *Limits) { l.MaxPending = 5 }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := a
			c.set(&b.Profile.Limits)
			if Fingerprint(b) == Fingerprint(a) {
				t.Errorf("%s: not in the fingerprint", c.field)
			}
			ch := Diff(a, b)
			got := field(ch, c.field)
			if got == nil || got.Loosens != c.loosens {
				t.Fatalf("%+v, want %s loosens=%v", ch, c.field, c.loosens)
			}
			// Back to the approved value: the reverse direction.
			if back := field(Diff(b, a), c.field); back == nil || back.Loosens && c.loosens {
				t.Errorf("reverse %+v", back)
			}
		})
	}
	if ch := Diff(a, a); len(ch) != 0 {
		t.Errorf("no change reported %+v", ch)
	}
}
