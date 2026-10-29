# How the PII analysis works

This note is for contributors: it explains how the console decides what
a statement may do with personal data and which cells it masks, and where
the code lives. The rules themselves, with their reasons, are in
[security-model.md](security-model.md); the user's view is in
[usage.md](usage.md).

The design in one sentence: **a read is parsed in full, every output
column is traced back to the base columns it comes from, and masking is
decided on those sources, never on the column's label.** What cannot be
traced is refused.

## The pipeline

A `query.plan` request goes through these steps in the console
(`internal/console/handlers.go`, `readpath.go`):

1. **Classify** (`internal/sqlclass`). A lexer per dialect splits the
   statement outside literals and comments, refuses several statements,
   comments, variables, bind parameters and unbalanced quotes, and gives it
   a class (read, write, ddl, admin) compared with the profile's tier.
   Reads must be `SELECT`, `WITH ... SELECT` or `EXPLAIN SELECT` with a
   `LIMIT` within `max_rows`.
2. **Parse** (`sqlast.Parse`, `parser.go`). A hand-written recursive-descent
   parser for the read grammar of MariaDB/MySQL, PostgreSQL and SQLite
   builds an AST (`ast.go`). It is fail-closed: a construct outside the
   supported grammar is a refusal, not a guess. Nesting is bounded
   (`maxDepth`).
3. **Analyze** (`sqlast.Analyze`, `analyze.go`), with an `Env`: a
   `Catalog` that resolves table names from the session's column catalog
   (`console/readpath.go`), `Rule`, which says whether a base column is
   under a mask rule and in which mode, and `Value`, which resolves
   placeholders and cell references. The result is an `Analysis` (below).
4. **Weigh.** The console runs `EXPLAIN` on the statement and on each
   k-anonymity count, and `internal/weight` turns the plans into a verdict.
5. **Count.** Before the approval prompt (after any placeholder values,
   which an `IN` list mixing them with literals needs), the k-anonymity
   counts run (`console.kCount`). Fewer than `k_anonymity` rows is a
   warning, never a refusal.
6. **Approve.** The human sees the statement, the PII columns it touches
   (`Analysis.Uses`), the masked outputs, the counts and, just above the
   prompt, a `▲ k-anonymity` warning for each count under k. In auto mode
   the statement runs and the warning goes to the console and the audit.
7. **Run and mask** (`pii.MaskOutputs`, `modes.go`). The rows are masked
   column by column from the analysis, then go through the value
   detectors, then through the output caps (`internal/render`).

A write never reaches `sqlast`: the human's approval is its gate, and
`pii.PlanCheck` and `pii.AliasViolation` (`mask.go`) refuse a write whose
`RETURNING` list or data-modifying CTE would move a rule column under
another label, or that copies a rule column into another column or plants
an agent value into one. Its result, if any, is masked by origin and by
name (`pii.MaskResult`).

## Provenance

The core of `analyze.go` is `Prov`, the provenance of a value:

| Field | Meaning |
|---|---|
| `Sources` | the base columns (`db.table.column`, `Source`) the value derives from |
| `Kind` | how: `KindConst` (no column), `KindCount` (a row count), `KindIdentity` (a value of one source: a plain reference, through aliases, subqueries, CTEs and set operations, `ANY_VALUE`, or `MIN`/`MAX` of an unmasked column), `KindAggregate`, `KindExpr` |
| `Sensitive` | a source is under a mask rule and the value reveals source values (identity, aggregate or expression) |
| `Modes` | the mask modes of the sensitive sources |
| `Lit` | some values may be literals of the statement (`UNION ALL SELECT 'x'`) |
| `w` | a bound on the value's size (`width.go`) |

The analyzer walks the query with scopes (`scope`, `relation`, `column`):

- **Base tables** resolve through the catalog; an unknown table or column
  is refused. A view's columns are `Source{View: true}`: rules match them
  by column name only, since the analyzer does not see through a view.
- **Derived tables, CTEs and set operations** pass the provenance of their
  columns up. A `UNION` merges the provenance of its arms column by column.
  A recursive CTE is analysed to a fixpoint: the analyzer re-runs its body
  in "dry" mode until the columns' provenance stops changing, and refuses
  one that does not converge.
- **`*` and `USING`/`NATURAL` joins** expand to the columns the engine will
  return, in its order, so that each output position has a known
  provenance.
- **Expressions** combine the provenance of their operands. A function
  must be on the per-dialect allowlist (`funcs.go`): pure functions on
  values, the usual aggregates and window functions, nothing that reads
  files, opens connections, sleeps, locks, changes the session or reads
  server metadata. `COUNT` gives `KindCount`; `ANY_VALUE` keeps identity, and so
  do `MIN` and `MAX` of an unmasked column; `MIN` and `MAX` of a PII column,
  whose result depends on how the values order, and other aggregates give
  `KindAggregate`.

Each output column becomes an `Output` with its provenance, the label the
engine must report (an alias or a plain column name, or `""` when the
engine names it) and its mask (`maskOf`): none when it is not sensitive;
the rule's mode for an identity value under one mode; `redact` for an
aggregate, an expression or several modes.

## The usage rules

With masking on (every plan but an approved unmask), the analyzer also
refuses what would turn a masked column into an oracle. The checks are in
`filter`, `comparison`, `inFilter`, `joinEquality`, `setOpCompare`,
`orderItem` and `call`; the refusal messages say what to write instead.

- **Filters** (`WHERE`, `HAVING`, `ON`). A PII column may only appear in a
  positive atom reached through `AND`: equality with a literal (`=`,
  `IN (literals)`, `IS NULL`) in `WHERE` or `HAVING`, or equality with
  another PII column (a join).
  Under `NOT`, `OR` or `XOR`, or with `<>`, `NOT IN`, `IS NOT NULL`, the
  atom could select rows the k-anonymity counts do not cover. `LIKE`,
  ranges and functions over a PII column are refused: they compare it
  character by character.
- **Joins** must pair two plain PII columns: a PII column joined with an
  unmasked one would copy its values where no mask applies.
- **Set operations.** `INTERSECT`, `EXCEPT` and the duplicate removal of
  `UNION` are equality tests: a PII column may meet only PII columns there.
- **Ordering and windows.** `ORDER BY`, `PARTITION BY`, `DISTINCT ON` and
  `FILTER` over a PII column are refused (they rank values).
- **`EXPLAIN`** of a statement that filters, groups or aggregates PII is
  refused: the planner's row estimates would answer the question the
  counts guard.

## k-anonymity counts

A filter, grouping, `DISTINCT` or aggregate on a PII column needs row counts, planned
by the analyzer (`KCheck`) and run by the console before the approval
prompt (`console.kCount`):

- `kCheck` builds `SELECT COUNT(*)` from the statement's own `FROM`,
  `WHERE`, `GROUP BY` and `HAVING` text (the smallest group for a grouped
  query). A correlated subquery, a recursive CTE or a `SELECT` without
  `FROM` cannot be counted on its own and is refused.
- `constFilter` adds, for each constant compared with a PII column, a count
  of that value's subjects in the column's own base table, so that a join
  cannot inflate it. An `IN` list counts each value apart and checks the
  smallest.
- When every compared value is a placeholder (`'${name}'`, typed by the
  human) or a cell reference (`'${r1.2.3}'`), the agent chose none of them:
  the filter skips the counts and the console warns instead
  (`console/warnings.go`). `Analysis.Replacements` substitutes the values
  into the statement that runs; the agent never sees them.

A count under `k_anonymity` (or one that cannot run) does not refuse the
statement. `kCount` returns it as a warning: the console prints it in the
approval frame, adds it to the audit record's `warnings`, and the human
decides. Before v0.5.2 it was a refusal (`E_K_ANON`, now retired). The
agent learns nothing of a count: its answer is the same either way, and in
auto mode `query.run` levels its response time from the counts on. The
structural rules that make a count meaningful (equality only, `AND` only,
no self-comparison, no view column under a constant filter) still refuse.

`PIIFilter` marks a statement whose row estimates must stay on the
console; `LitFilter` marks one that compares a PII column with a literal
the agent wrote, whose results then carry no cell references.

## Masking the result

`pii.MaskOutputs` (`modes.go`) checks the result against the analysis
before it masks anything: the column count must match and every labelled
output must carry its expected label, or the result is dropped, since
masking by position could hit the wrong column. Then, per column:

- the analysed mask applies (`redact`, `partial`, `email`; `rules.go`);
- as a second line of defence, a column whose engine-reported origin
  (`OriginColumns`, when the driver reports one) matches a rule is masked
  even if the analysis did not mask it;
- every other text or integer cell, and every integral float (`|f| <
  1e19`, a PostgreSQL `float4`/`float8`), goes through the value detectors
  (lockkit's `pii` package: email with Unicode local parts and domains,
  IBAN and card with their checksums, Belgian, French, Dutch and US
  national numbers, phone numbers, typographic spaces and full-width
  digits), which mask what they find inside the text.

A `redact` cell of a plain column whose every source is under a rule
(`referenceable`) gets a reference (`<redacted:r1.2.3>`) to its value,
which only the console keeps (`console/refs.go`). Any other masked cell
gets plain `<redacted>`: the agent might know the value behind it (a
literal, an unmasked `UNION` arm, an aggregate) and could look up a row
with it without the counts.

## The rules and where they come from

Rules live in named rule sets (`pii.Rules`), one file per set:
`pii/<set>.toml` next to the config (`pii.SetPath`). A profile's set is its
`pii_rules` key, by default its own name in lower case
(`config.RuleSetOf`); the console resolves it once at start
(`console.resolveRuleSet`) and stores it in the approved policy
(`Profile.PIIRules`), so `config.Diff` reports a switch of set as a
loosening. The legacy single `pii.toml` is moved once to the set `default`
(`pii.MigrateLegacy`), and the profiles approved before keep that set until
they name one. A set file holds `[[mask]]` patterns
`db.table.column` (any segment may be `*`, or a name with a leading or
trailing `*` such as `*email*`) with an optional mode, and
`[[allow]]` patterns that beat every mask. At every start the console
scans the schema and proposes rules for columns whose names look personal
(`detect.go`: tokens in English, French, Dutch, German and Spanish), and
quasi-identifiers apart. Adding a rule is a tightening any client may ask
for; removing one is a loosening the human confirms.

## Where to start

- A bypass: add the statement to `internal/sqlast/adversarial_test.go` (or
  the classifier corpus, `internal/sqlclass/corpus_test.go`) and make it
  refuse.
- A legitimate statement refused: find the refusal text in `analyze.go`
  or `parser.go`; extend the grammar or the allowlist only where the
  provenance stays exact.
- A masking question: `internal/pii/modes.go` and its tests, then the
  console's `readpath.go`.

Known limits (views renaming rule columns, differencing attacks across
queries, best-effort detectors) are listed in the security model's
[limitations](security-model.md#out-of-scope-and-limitations).
