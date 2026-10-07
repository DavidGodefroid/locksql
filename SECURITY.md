# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub security advisories:
open <https://github.com/DavidGodefroid/locksql/security/advisories/new>
(the "Report a vulnerability" button on the repository's Security tab).

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Please include:

- the locksql version (`locksql version`) and your OS;
- the database engine and version, if relevant;
- the steps or input needed to reproduce the issue, and its impact.

Never include real credentials or real personal data in a report.

You will get an acknowledgement within a week. Fixes are released as soon as
possible, and the advisory is published with credit to the reporter unless
you ask otherwise.

## Scope

The threat model is in [docs/security-model.md](docs/security-model.md).
Issues of interest include, among others:

- a way for a client (CLI or MCP) to run a statement without the human's
  approval, or to loosen the policy without confirmation;
- a secret reaching argv, the environment, a file, a log, the socket or an
  error message;
- a statement that the classifier accepts in a lower class than it belongs
  to, or a forbidden construct that it accepts;
- unmasked personal data in a result where a rule or detector should apply;
- client-controlled text that can spoof the console's approval screen.

Attacks that require running code as the same OS user as the console are out
of scope, as documented in the threat model.

## Supported versions

Only the latest release receives security fixes.
