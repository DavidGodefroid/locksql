# The console: unmasking, keys and clear results

What you can switch in the console while it runs. The console is started by lockhub (`lox add`, `lox run`); see [usage.md](usage.md#2-start-the-console).

## `--allow-unmask`

An agent can ask for unmasked PII output (`locksql plan --unmask`, or
`unmask` in the MCP `locksql_plan` tool) only when the human allowed it in
the console: `--allow-unmask` at start (from the lock's settings in `lox
up`), or `:unmask` while it runs (confirmed with `y` at the console's
terminal; `:unmask` again turns it off). Without it, the console refuses
every unmask request before anything runs and audits the refusal. It is
console-only: no client or config file can turn it on, and each change is
audited (`unmask` record). With it, each unmasked query is still decided by
the human in lockhub, shown as `PII: UNMASKED` in red. The console then
prints the clear result, so you see exactly what the agent received (the
audit log still holds no row data).

## Console keys and status line

The console runs its own line editor, so one key and two commands switch
its behaviour while it runs, without a restart, and a status row fixed at
the bottom of the terminal always shows the state: the profile and tier, whether results
are shown in clear, `unmask allowed`, the open plans and what awaits
`:review`. The switches are console-only (no client, config file or
environment variable can set them) and each change is audited.

| Key | Typed | Effect |
|---|---|---|
| Ctrl-P Ctrl-Q | | detach (`lox attach`'s key): the console keeps running; the Ready box shows it, and so does each question asked after the console served (a reconnect, a loosened policy) |
| Ctrl-O | `:results` | results masked ⇄ shown here in clear |
| | `:unmask` | unmasked output off ⇄ allowed (allowing asks for `y`) |
| | `:revoke` | end every active grant (`:revoke ID`: one) |

## Clear results (Ctrl-O)

Ctrl-O (or the console's `--show-results`, which `lox run` does not pass) prints in
the console, in clear, the result of each masked query it runs, as an
aligned table, so you see who the rows are while the agent still gets the
masked cells. The cells the agent got masked are yellow and carry their
reference (`‹r1.1.2›`); the output caps apply as for the agent. Off by
default. The console warns when it goes on (in red on production), the
status row reads `results clear`, every approval screen says `result:
shown here in clear`, and `locksql status` reports `show results on`. The
audit log still holds no row data. Unavailable when the console runs in a
desktop terminal (security levels 1 and 2): the agent's account can read
that window, so `--show-results` is refused and Ctrl-O leaves the results
masked.
