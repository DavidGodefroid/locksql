# Configuring locksql

Profiles, PII rule sets, sharing a configuration and the company's [managed configuration](#managed-configuration). Setting a project up: [docker.md](docker.md); what each setting does at run time: [usage.md](usage.md).

## Profiles

Profiles live in `.locksql/config.toml` at the project root (found by walking
up from the current directory) and in `<user config dir>/locksql/config.toml`.
A project profile wins over a user profile of the same name. No file ever
holds a secret: keys named like `password`, `passwd`, `pwd`, `secret` or
`token`, and DSNs with an embedded password, are refused.

> **Breaking change (v0.15).** locksql no longer enforces transport
> security: the `tls*` settings are passed to the driver, a profile with no
> `tls` setting gets the drivers' default `prefer` whatever the host (it
> was `verify-full` for a remote host since v0.4), `production = true` no
> longer requires TLS, and no authentication method is refused because of
> the TLS mode. A plaintext connection gets one warning at session start.
> To keep verifying the server certificate, set `tls = "verify-full"`.

```toml
[profiles.uat]
engine      = "mariadb"             # mariadb | mysql | postgres | sqlite
host        = "db.uat.example.com"  # or path = "app.db" for sqlite
port        = 3306                  # default 3306, or 5432 for postgres
user        = ""                    # empty: asked at console start
database    = ""                    # empty: chosen per query (--db)
credentials = "ask"                 # ask | keychain | vault
tls         = "verify-full"         # disable | prefer (default) | require | verify-ca | verify-full, as libpq's sslmode
tls_ca      = ""                    # optional PEM bundle replacing the system roots; "~/db-ca.pem" is in the console account's home
credentials_ttl = "20m"             # optional: ask for the secret again
tier        = "read"                # read | write | ddl | admin
production  = false
detectors   = ["email", "phone", "iban", "card", "be_niss"]

[profiles.uat.limits]
statement_timeout   = "30s"
explain_rows_warn   = 100000
explain_rows_refuse = 1000000
max_rows            = 200
max_cell_chars      = 200
max_output_bytes    = 65536
k_anonymity         = 5
explain_cost_refuse = 0             # engine cost units; 0 = off
idle_timeout        = "20m"         # the connection closes after this long idle
max_session         = "4h"          # ... and after this long in all
grant_max_duration  = "1h"          # the longest grant; "0" turns grants off
grant_max_statements = 200          # a grant's budget at most: statements,
grant_max_rows      = 10000         # rows returned
grant_max_bytes     = 1048576       # and bytes returned
tickets_per_window  = 30            # tickets a human decides per window
ticket_window       = "5m"
max_pending         = 30            # tickets pending at once
```

With `credentials = "vault"` the console runs `vault read -format=json
<vault_path>` at every connection, as the console account and with its
environment (`VAULT_ADDR`), and connects with the `username` and `password`
of the secret. The console asks for the Vault token at start and keeps it in
memory for the session. Nothing is stored. See
[Credentials from HashiCorp Vault](usage.md#credentials-from-hashicorp-vault).

```toml
[profiles.reporting]
engine      = "postgres"
host        = "db.internal"
tls         = "verify-full"
credentials = "vault"
vault_path  = "database/creds/reporting-ro"   # or a KV secret: "secret/data/reporting"
```

A database reachable only from a bastion gets an `ssh` table: the console
opens the SSH connection itself, with no local listening port, and verifies
the bastion against the console account's `~/.ssh/known_hosts` (asking on
first use, refusing a changed key). `host` is then the database as seen from
the bastion; the bastion-to-database leg is protected by `tls` only, unless
the database runs on the bastion itself. See
[Reaching a remote server through SSH](usage.md#reaching-a-remote-server-through-ssh).
A database that publishes no port (an internal Docker network, a server
bound to its container's loopback) is reached with `proxy_command`, an argv
whose stdin and stdout carry the connection, such as
`["docker", "exec", "-i", "shop-db", "socat", "-", "TCP:127.0.0.1:3306"]`;
see [Databases that publish no port](usage.md#databases-that-publish-no-port).

```toml
[profiles.prod]
engine      = "postgres"
host        = "db.internal"         # as seen from the bastion
tls         = "verify-full"
production  = true

[profiles.prod.ssh]
host        = "bastion.example.com"
port        = 22                    # default 22
user        = "deploy"
auth        = "key"                 # key | agent | password
key         = "~/.ssh/id_ed25519"   # auth = "key" only; the console account's home
credentials = "ask"                 # passphrase or SSH password; default: the profile's
```

<details>
<summary>All profile keys</summary>

| Key | Default | Notes |
|---|---|---|
| `engine` | required | `mariadb`, `mysql`, `postgres`, `sqlite` |
| `host`, `port` | required host; port 3306 / 5432 | a host starting with `/` is a Unix socket (MariaDB/MySQL) |
| `path` | required for sqlite | relative to the project root; the file is never created |
| `user` | asked at start | with `credentials = "vault"`: the secret's `username`; set it only for a secret without one |
| `database` | none | the only database served (and scanned for PII); empty: every database the account can see, chosen per query with `--db` |
| `credentials` | `ask` | `keychain` (not in a container) offers to save the secret after the first successful login; `locksql forget --profile P` removes it. `vault` reads the login from `vault_path` at every connection |
| `vault_path` | required with `credentials = "vault"` | the Vault path read with `vault read`, such as `database/creds/<role>` or `secret/data/<name>`; any change is a loosening |
| `credentials_ttl` | none | a duration of at least `1m` (`"20m"`, `"1h"`): the connection is closed and the secret asked again once it is that old |
| `tier` | `read` | highest statement class allowed |
| `production` | `false` | stricter limits, production banner at console start, and the typed profile name when its policy is first approved or loosened |
| `detectors` | `email`, `phone`, `iban`, `card` | also `be_niss`, `fr_nir`, `nl_bsn`, `us_ssn` and `phone_loose`; `[]` disables them. `phone` masks `+` and 8 to 15 digits, `00` and 10 to 17 digits, or a national number with a trunk 0 (9 to 11 digits, a first group of at least 2 digits); `phone_loose` adds national numbers without a trunk 0 (`(415) 555-2671`, `612 345 678`: 9 to 11 digits in at least two groups, the first of 2 to 4) and also masks some grouped amounts (`123 456 789`). Every detector reads U+00A0, U+202F and U+2009 as a space and full-width digits as digits |
| `pii_rules` | the profile name, in lower case | the PII rule set, `pii/<set>.toml`; 1 to 64 lower-case letters, digits, `_`, `-` or `.`; profiles on isomorphic databases share a set by naming it; any change is a loosening |
| `limits.statement_timeout` | 30s (production 10s) | |
| `limits.explain_rows_warn` | 100 000 (production 20 000) | |
| `limits.explain_rows_refuse` | 1 000 000 (production 200 000) | |
| `limits.max_rows` | 200 | upper bound for `LIMIT n` and for returned rows |
| `limits.max_cell_chars` | 200 | longer cells are cut with `…` |
| `limits.max_output_bytes` | 65 536 | output is cut with a marker |
| `limits.k_anonymity` | 5 (production 10) | a PII filter, a group or an aggregate of a PII column covering fewer rows warns on the approval screen (it no longer refuses); lowering it is a loosening |
| `limits.reference_probe` | 5 | no effect: cell references are not supported; kept so that existing configs load (raising it is still recorded as a loosening) |
| `limits.idle_timeout` | 20m (production 10m), or `max_session` when that is shorter | the database connection and the SSH tunnel close after this long without activity; the console keeps running, and the next request asks a connect ticket in `lox run` ([usage](usage.md)); at least `1m` and at most `max_session`; raising it is a loosening |
| `limits.max_session` | 4h (production 2h) | the console session ends after this long in all; at most `24h`; raising it is a loosening |
| `limits.tickets_per_window`, `limits.ticket_window` | 30 per `5m` | tickets a human decides that the console opens per window at most; a ticket an auto rule of `lox run` decides (`read = auto`) leaves this count, and a safety cap of 300 tickets per window counts every one ([Ticket limits](usage.md#ticket-limits)); more tickets or a shorter window is a loosening |
| `limits.max_pending` | 30 | tickets pending a decision at once at most; raising it is a loosening |
| `limits.explain_cost_refuse` | 0 (off) | refuse plans above this total cost, in the engine's own units; SQLite reports no cost and is not checked |
| `ssh.host`, `ssh.port`, `ssh.user` | required host and user; port 22 | the bastion; not with sqlite or a Unix socket `host` |
| `ssh.auth` | required | `key`, `agent` (`SSH_AUTH_SOCK` of the console) or `password` |
| `ssh.key` | required with `auth = "key"` | private key of the console account, mode 0600 |
| `tls_ca`, `tls_cert`, `tls_key` | none | PEM files read by the console account ([TLS to the database](usage.md#tls-to-the-database)) |
| `ssh.credentials` | the profile's `credentials` (`ask` when that is `vault`) | `ask` or `keychain` for the passphrase or SSH password; `locksql forget --profile P` removes it too |
| `proxy_command` | none | argv run without a shell, as the console account, once per connection; its stdin and stdout carry it (`docker exec`, `kubectl exec`, `ssh ... socat`). Not with `ssh`, sqlite or a Unix socket `host`; any change is a loosening |

In every file key (`tls_ca`, `tls_cert`, `tls_key`, `ssh.key`), a leading
`~/` is the console account's home (`/home/locksql` in the image); the
console checks each file right after the policy review, before any secret
is asked.

</details>

## PII rules

PII column rules live in named rule sets, one file per set: `pii/<set>.toml`
next to the config, so `.locksql/pii/<set>.toml` inside a project and
`<user config dir>/locksql/pii/<set>.toml` (`~/.config/locksql/pii/` on
Linux) elsewhere. Each profile uses the set named by its `pii_rules` key,
by default its own name, so a profile never sees the rules of an unrelated
database. Profiles that point at isomorphic databases share a set on
purpose:

```toml
[profiles.shop-dev]
pii_rules = "shop"
[profiles.shop-prod]
pii_rules = "shop"        # rules added from either console reach both
production = true
[profiles.billing]        # no pii_rules: the set "billing", its own
```

`locksql pii` and `:pii` act on the set of the profile in use, and the
approval screen shows the set next to the profile. The console warns at start
when a profile without `pii_rules` shares its set by accident: with a
profile whose name differs only by case, with a profile whose `pii_rules`
names it, or because it is named `default`. `pii_rules` is read at
start; pointing a profile at another set is a loosening, approved again at
the next start.

The single `pii.toml` of earlier versions becomes the set `default` at the
first start (moved to `pii/default.toml`, with a one-time notice). The
profiles approved before keep using it until they get a `pii_rules` key;
any other profile uses its own set.

A set file:

```toml
[[mask]]
column = "app.users.email"            # db.table.column (schema.table.column on PostgreSQL), * per segment
mode   = "email"                      # j***@example.com
[[mask]]
column = "app.users.customer_ref"
mode   = "partial"                    # j***(12)
[[mask]]
column = "*.*.recipient_reference"    # <redacted> (default)
[[allow]]                             # explicit exception: never mask
column = "app.templates.name"
[[mask]]                              # '*' prefix/suffix inside a segment:
column = "*.*.*email*"                # contact_email, email_backup, Email
```

| Mode | Output | Notes |
|---|---|---|
| `redact` (default) | `<redacted>` | a rule without `mode` is `redact`; no masked cell carries a reference to its value |
| `partial` | `j***(12)` | first character and length |
| `email` | `j***@example.com` | first character and domain; other values as `partial` |

A column covered by several rules with different modes is redacted. Changing
a mode is a loosening unless the new mode is `redact`.

`mode = "hash"` is no longer a mode: a rules file that uses it is rejected
(`[[mask]] entry N: pii rule: unknown mode (want redact, partial or email)`).

On PostgreSQL the first segment is the schema (`public.users.email`).

## Share a configuration with your team

`locksql config export` writes the profiles of your user config (or of the
project with `--project`) and the PII rule sets they use to one JSON file;
`locksql config import FILE` applies it on another machine:

```sh
locksql config export --output team.json                 # all profiles, their PII rule sets
locksql config import team.json --dry-run                # show what would change
locksql config import team.json --local uat.ssh.key=~/.ssh/id_ed25519
```

- **Never exported:** secrets (none is in a config file; a value that looks
  like one fails the export), `user` (unless `--include-user`), files of one
  machine (`tls_ca`, `tls_cert`, `tls_key`, `ssh.key`: listed in
  `needs_local`, given on import with `--local NAME.KEY=VALUE`),
  `proxy_command` (a command line: kept from your own config, never
  imported), SQLite and
  Unix-socket profiles, approved policies, the audit log and console flags.
  `--no-pii` leaves the rule sets out.
- **Import:** a strict format (unknown fields, newer formats and invalid
  values are refused, nothing is written); imported profiles replace those
  of the same name but keep your `user` and local files; rule sets are
  merged (a mode conflict keeps `redact`); `--replace` replaces the
  profiles and the imported sets instead. A backup (`*.bak`) is kept.
- **Loosening:** any change that loosens the policy (new profile or host,
  higher tier, higher limits, a removed mask rule, a new allow
  rule, another rule set, ...) is refused unless you pass `--allow-loosen`,
  and the console still asks you to approve it at its next start.

The file describes your databases: keep it in a private repository.

## Managed configuration

A company can bound every locksql of a machine with one file its admin
installs: `/etc/lockfamily/managed.toml` (Linux) or `/Library/Application
Support/lockfamily/managed.toml` (macOS), owned by root and writable by root
only, optionally signed (the family's format, signing and deployment:
lockfamily [`docs/managed.md`](https://github.com/DavidGodefroid/lockfamily/blob/main/docs/managed.md)).
A user may tighten what it allows, never loosen it. locksql reads its
`[locksql]` section:

```toml
version = 1
organisation = "Acme"

[locksql.bounds]
tier = "write"
tls = "verify-full"
credentials = ["vault", "ask"]
hosts = ["*.db.acme.internal"]
detectors = ["fr_nir"]
auto = { ddl = "deny" }
limits = { max_rows = 500, max_session = "2h" }

[[locksql.bounds.pii_mask]]
column = "crm.customers.email"
mode = "email"

[locksql.defaults]
limits = { max_rows = 100, max_session = "2h" }

[locksql.profiles.prod-erp]
engine = "postgres"
host = "erp.db.acme.internal"
database = "erp"
production = true
credentials = "vault"
vault_path = "database/creds/erp-ro"
```

The precedence is: the hard-coded floor > the managed bounds and profiles >
the project file > the user file > the managed defaults > the built-in
defaults. The merged result is checked against the bounds at the console's
start and at every policy poll (every 2 s): a profile beyond them is refused
with no prompt (no human can approve past it), one line each, audited
`refused-managed`:

```
blocked by company policy: locksql.bounds.tier = write (profile dev: tier = ddl)
```

A managed file that cannot be read (badly owned, invalid, badly signed) is a
refusal to start, never ignored. Once the console serves, a stricter file is
applied at the next poll: the policy in force is replaced by the files'
policy when that one is within the new bounds, else the session ends. The
start screen shows `Managed by <organisation> (sha256:…)`, the approved
policy records `managed_sha256` and every audit record `managed`.

### Bounds

`[locksql.bounds]` takes these keys; each is optional. "Looser" is what the
bound refuses.

| Key | Type | Looser |
|---|---|---|
| `production` | `true` | `production = false` |
| `tier` | `read`, `write`, `ddl` or `admin` (a ceiling) | a higher tier |
| `tls` | a TLS mode (a floor) | a weaker mode (`disable` < `prefer` < `require` < `verify-ca` < `verify-full`); SQLite has none |
| `credentials` | allowed modes (`["vault", "ask"]`) | a mode outside the list |
| `engine` | allowed engines (`["postgres"]`) | an engine outside the list |
| `hosts` | host patterns (`*.db.acme.internal`, `path.Match` syntax, case-insensitive) on `host` and `ssh.host` | a host no pattern matches |
| `write_functions` | `"allowlist"` | the denylist |
| `credentials_ttl` | a duration (a ceiling) | longer, or none (the secret kept for the session) |
| `auto.connect`, `auto.read`, `auto.write`, `auto.ddl`, `auto.unmask` | `deny`, `ask` or `auto` (a ceiling) | toward `auto` |
| `limits.statement_timeout`, `limits.max_rows`, `limits.max_cell_chars`, `limits.max_output_bytes`, `limits.explain_rows_refuse` | a ceiling | higher, or 0 (unlimited) |
| `limits.k_anonymity` | a floor | lower |
| `limits.idle_timeout`, `limits.max_session` | a duration (a ceiling) | longer |
| `limits.grant_max_duration` | a duration, or `0` (grants off) | longer, or grants on under `0` |
| `limits.grant_max_statements`, `limits.grant_max_rows`, `limits.grant_max_bytes` | a ceiling | higher |
| `detectors` | detectors every profile runs | added to every profile, never removed |
| `[[pii_mask]]` | `column = "db.table.column"`, `mode = "redact"`, `"partial"` or `"email"` (as `[[mask]]` in a rule set) | masks added to every profile's rules, whatever its `pii_rules` |

- `credentials`, `engine` and `hosts` are allowlists: a value outside one is
  refused naming the key (`blocked by company policy:
  locksql.bounds.hosts does not allow db.other.com (profile dev: host +
  db.other.com)`).
- `[family] vault = { required = true }` acts as `credentials = ["vault"]`
  on every network profile, cited as `family.vault.required`.
- A managed mask takes its mode over a rule of the same column in the rule
  set. A user `[[allow]]` that could clear a managed mask (`*.*.email` over
  `crm.customers.email`) is refused at load; a user may add mask rules,
  never remove or weaken a managed one.
- A bound on a duration or a size is never clamped silently: a profile
  beyond it is refused, and you lower it in the config file.

### Defaults and profiles

- `[locksql.defaults]` takes the keys of a profile, `limits.*` included. A
  key a profile leaves unset takes it, before the built-in defaults; a value
  of the config file wins (within the bounds). The `limits` table is merged
  key by key, `ssh` and `auto` are taken whole. A default beyond the bounds
  is a load error.
- `[locksql.profiles.<name>]` has exactly the keys of `[profiles.<name>]`,
  is served as written (with the defaults), and wins as a whole: a project
  or user profile of its name is refused (`profile "prod-erp" is provided
  by the company's managed configuration and cannot be redefined in the
  project config: rename yours`). A managed profile beyond the bounds is a
  load error.

### Commands

- `locksql managed show`: the file's path, organisation, fingerprint and
  signature, then the active bounds, defaults and managed profile names.
  `no managed configuration` (exit 0) when there is none; a refused file
  prints the error (exit 3).
- `locksql managed check [--profile NAME]`: the profiles of the config
  files against the bounds, as the console checks them at start, without a
  connection or a credential: one `blocked by company policy: …` line per
  violation (exit 3), else `ok: N profiles within the company policy
  (…)` (exit 0). `lox` runs it before it starts the lock.
- `locksql doctor` has a `managed` line: the file as above, `no managed
  configuration`, or the error that refuses it.
