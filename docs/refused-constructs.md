# Most refused constructs

locksql refuses what it cannot parse or prove with certainty. This list
ranks the refused constructs users hit most, so that grammar work starts
with them. It is fed by the anonymised reports of `locksql stats --export`
(see [Refusal statistics](usage.md#refusal-statistics)) attached to GitHub
issues, and worked top-down.

## Process

1. A user runs `locksql stats --export > refusals.json` as the console
   account, reads the file, and attaches it to an issue labelled
   `refusal-stats`. The export holds counts, refusal codes, engines and
   statement shapes only: no literal, identifier, comment or message.
2. A maintainer adds the report's `by_construct` and `shapes` counts to the
   table below, one row per construct and engine (a construct is a code and
   the token the check stopped at, or a shape when the token says too
   little). The `Reports` column counts the issues it came from, so that one
   heavy user does not outrank many.
3. Rows are ranked by `Reports`, then `Refusals`. Constructs refused on
   purpose (the security model's PII rules, `E_FORBIDDEN`,
   `E_TIER`) are listed under *Refused by design* with the rewrite users
   should be taught instead, and never "fixed".
4. A construct is worked from the top. Supporting it ships with:
   - the parser and analyser change, fail-closed for every variant not
     covered;
   - adversarial provenance tests in `internal/sqlast/adversarial_test.go`:
     the new construct must not hide a PII column behind an alias, an
     expression, a set operation or a subquery, nor open a predicate
     oracle;
   - a classifier corpus entry in `internal/sqlclass/corpus_test.go` per
     dialect it applies to;
   - an integration test on the engines it concerns.
5. A shipped row moves to *Done* with the release that supports it.

## Ranking

| Rank | Code | Construct | Engines | Reports | Refusals | Status |
|---|---|---|---|---|---|---|
| | | *(no report yet)* | | | | |

## Refused by design

| Code | Construct | Rewrite to teach |
|---|---|---|

## Done

| Construct | Release |
|---|---|
