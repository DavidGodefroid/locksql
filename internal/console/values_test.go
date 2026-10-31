package console

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locksql/internal/config"
	"github.com/DavidGodefroid/locksql/internal/engine"
	"github.com/DavidGodefroid/locksql/internal/ipc"
)

// typedQ holds a placeholder: refused, no value is typed in lockhub.
const typedQ = "SELECT id, email, note FROM users WHERE email = '${email}' LIMIT 5"

// A placeholder in a write is refused at plan time: it would run as the
// literal text '${...}', and no value is ever prompted for.
func TestPlaceholderInWriteRefused(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p)
	for _, q := range []string{
		"UPDATE users SET email = '${email}' WHERE id = 7",
		"UPDATE users SET note = 'x' WHERE email = '${r1.1.2}'",
		"DELETE FROM users WHERE email = '${email}'",
		"INSERT INTO users (id, email) VALUES (9, '${email}')",
		"INSERT INTO users (id, email) VALUES (9, \"${email}\")",
	} {
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		if resp.Error != nil && !strings.Contains(resp.Error.Message, "only allowed in read statements") {
			t.Errorf("%s: refusal %q", q, resp.Error.Message)
		}
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran")
	}
	// A plain string that merely holds "${" further in is not a placeholder.
	h.plan(t, "UPDATE users SET note = 'cost: ${x}' WHERE id = 1", false)
}

// While mask rules exist, a write cannot plant a value the agent chose into
// a masked column: read back, it would come as a reference to a known
// value, usable as a lookup without the k-anonymity check.
func TestWritePlantingRefused(t *testing.T) {
	p := uatProfile()
	p.Tier = config.TierWrite
	h := newHarness(t, p)
	for _, q := range []string{
		"UPDATE users SET email = 'victim@x.com' WHERE id = 1",
		"INSERT INTO users (id, email) VALUES (99, 'victim@x.com')",
		"UPDATE users SET email = note WHERE id = 1",
		"UPDATE users SET email = CONCAT('vic', 'tim@x.com') WHERE id = 1",
		"INSERT INTO users (id, email) SELECT 99, note FROM users WHERE id = 1",
	} {
		resp := h.call(t, ipc.MethodQueryPlan, ipc.PlanParams{DB: "app", SQL: q})
		wantCode(t, resp, ipc.CodeRefused)
		if resp.Error != nil && (!strings.Contains(resp.Error.Message, "cannot receive values the agent chose") || strings.Contains(resp.Error.Message, "victim")) {
			t.Errorf("%s: refusal %q", q, resp.Error.Message)
		}
	}
	if h.sess.runCount() != 0 {
		t.Fatal("a statement ran")
	}
	// NULL into a masked column, and any value into another column, pass.
	h.sess.result = engine.Result{}
	h.plan(t, "UPDATE users SET email = NULL WHERE id = 1", false)
	h.plan(t, "UPDATE users SET note = 'victim@x.com' WHERE id = 1", false)
	h.plan(t, "INSERT INTO users (id, note) VALUES (99, 'x')", false)
}
