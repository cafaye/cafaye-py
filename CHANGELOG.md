# Changelog

All notable changes to `cafaye-py` are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**`tests/test_tenant_isolation.py` — 362 cross-tenant negative tests, and the
enumeration they are negative about.** D18 measured cafaye-py at **zero**
cross-tenant negative tests. This is that number, and it follows darkroom-09's
pattern: enumerate every account-scoped entry point, negative-test each one, make
the scoping load-bearing.

cafaye-py is a **client SDK**, not a service — there is no route table and no
database in this repository, so the account-scoped surface here is the *service
methods* and the enumeration says so rather than inventing a server to test:

| | count | entry points |
|---|---|---|
| **account-scoped** | **8** | across **5** distinct paths |
| … per face (`IdentityService` + `AsyncIdentityService`) | **16** | call sites |
| read | 1 | `get_oidc_client` |
| list | 2 | `list_oidc_clients`, `list_api_keys` |
| create | 2 | `register_oidc_client`, `mint_api_key` |
| delete | 3 | `revoke_oidc_client`, `revoke_api_key`, `revoke_api_key(reason=…)` |
| update | **0** | see the finding below |
| **credential-scoped** | **2** | `get_current_user`, `introspect_api_key` |

**Absence, never 403.** core's rule, quoted in `_errors.CafayeNotFoundError`:
*"404 is correct there, 403 is not allowed to leak existence."* Four classes hold
that line, 128 tests in all:

- the scope parameter reaches the path, **and only the path** — a client that
  dropped `account_id` would let the service fall back to the caller's own
  membership and return the **wrong tenant's rows with a 200**. Not a 403, not an
  error: a success carrying somebody else's data, in an SDK, and invisible to a
  mock transport that answers any URL.
- a 404 arrives as `CafayeNotFoundError` and is never a `CafayeForbiddenError`.
- **every observable** of the raised error is byte-identical for another tenant's
  row and for a row that never existed: message, type, title, detail, instance,
  status, code, trace id, extensions, per-field errors. Compared against a
  *constant* response body, so any difference is attributable to the client — the
  only party in this repository.
- **no tenant is served from another's answer.** `AGENTS.md`'s "no caching of
  anything" and tenant isolation are the same rule; a cache keyed on `client_id`
  without the account returns the wrong rows with a 200 and the right model. Every
  id in the file is deliberately **shared** between the two tenants so that bug is
  reachable.

**No 403 was found on the account-scoped surface, and that is now a measurement
rather than an assumption** — asserted three ways: an AST walk proving no service
file mentions 403, a check that `_errors._STATUS_CLASSES` is the only
status-to-class mapping in the package, and a check that `CafayeForbiddenError`
and `CafayeNotFoundError` are siblings rather than one an ancestor of the other.
A 403 the *service* sends about the caller's own credential — `DELETE /v1/session`
is documented to answer 403 to a scoped API token — is asserted to pass through
**unlaundered**: laundering is the defect, honesty is not.

**The enumeration cannot go stale.** The counts are the deliverable, so the counts
get a walk: an AST walk of `_services/identity.py` compares every
`/v1/accounts/` path against the enumeration, in **both** directions, and a second
walk keys on the *signature* (`account_id` in the parameters) rather than on a
list of names, on both faces.

**`gate.yml` — the gate is declared, not discovered.** The repository root now
says what gates it, against `cafaye/core`'s `schemas/gate.schema.json`: the
entrypoint, the arguments, the mise task, what the gate needs from the machine,
the CI workflow it is reached from, and seven proofs over the gate's own output
— three of them countable. Two things follow that are easy to undo by accident, so
they are stated here as well as in the file:

- A floor is a ratchet. `no-skip` sits at the **exact** measured count, because
  cafaye-py's unit tier has no `skipif`, no `importorskip` and no environment
  variable anywhere under `tests/`, so the difference between that number and one
  less is one test that did not run. `suite` sits below it, so adding a test costs
  no edit. The exact number is 586 as declared and **948 as of the entry below**,
  which raised it; the gap between the two floors is 368, and the drift is named
  in `gate.yml` rather than left for a reader to notice.
- `no-skip`'s negative lookahead is what makes a skip a red rather than a
  decrement. Measured on the 586-test suite: one test made to skip produced
  `585 passed, 1 skipped`, 100.00% coverage, `prime: unit tier GREEN` and
  **exit 0** from the gate — and `gate-check --prove` was still red, naming
  `gate.proof-missing` on that proof alone. Re-measured on the 948-test suite for
  the raise, and it behaves the same: `947 passed` trips the floor, and
  `585 passed, 1 skipped` cannot match the pattern at all.

**The declaration was proven red five times before it was trusted**, and each
proof is recorded in `gate.yml` with its findings. The headline: `bin/prime`
replaced by a stub whose whole body is `exit 0` produced **seven**
`gate.proof-missing` failures. Before this file existed, it would have produced
none.

### Changed

**`gate.yml`: `no-skip`'s floor raised 586 → 948.** This packet added 362 tests,
and the floor was 586 *exactly* — cafaye-py's unit tier has no `skipif`, no
`importorskip` and no environment variable anywhere under `tests/`, so 586 was the
whole suite and 585 was one test that did not run. Leaving it at 586 would have
loosened the only proof standing between a silently-shrunk suite and a green badge
by 362, without anybody deciding to. `AGENTS.md`'s rule is "when you delete a
test, lower nothing and raise nothing"; nothing was deleted, and the direction
here is a raise.

`suite`'s floor is **left at 580** and the drift is now named in its own comment:
it was a deliberate six-test margin against 586 and is now 368 against 948. It is
the permissive half of the pair — `no-skip` carries the exact count, so a deletion
is still caught to the test — and putting two floors at the same number is the
case the `no-skip` comment warns about.

Both verified against the declared patterns, not assumed: `947 passed` trips
`no-skip` (floor 948), `585 passed, 1 skipped` trips it too, and
`1 failed, 947 passed` cannot match it at all.

### Findings

**`update 0` — the account-scoped surface has no update verb, so "update" cannot
be negative-tested at the account path.** Read off the table: identity declares no
`PATCH` and no `PUT`, at any path. The account-scoped mutations are two creates
and three deletes, and all five are covered. This is a measurement with a name
(`TestTheUpdateSlotIsEmpty`), not a gap in the packet — and **not** evidence that
nothing updates tenant data, because the updates that exist (an API key's
`last_used_at`, a revoke reason) are fields on a row this client can only write by
replacing the whole row through a delete and a create.

**`revoke_api_key` is two entry points, and one of them is undeclared.** With a
`reason` it POSTs to `…/api-keys/{key_id}/revoke`; without one it DELETEs
`…/api-keys/{key_id}`. Two methods, two paths, two requests, one Python method —
and it is the **only** account-scoped operation whose wire shape is absent from
`IDENTITY_OPERATIONS`. A scoping property the table cannot check is asserted
against the document instead. Enumerating by method name alone would have counted
seven and left the second wire shape untested.

### Fixed

**`mypy --warn-unreachable` caught a branch that cannot be taken in the new
helper**, and it is gone rather than kept with a `pragma`: `_invoke`'s
`if account_id is not None`, where `account_id` is a plain `str` and no call path
passes `None`. `warn_return_any` also flagged two functions, because `mypy`
resolves `from conftest import …` as `Any` (`conftest.py` is not a member of the
`tests` package, so there is no module to read the annotation off); fixed by
naming the type on the local, which keeps the check doing its job on the rest of
the file instead of being switched off.

**`mise run gate` was a dead command, and the fleet's spelling did not exist.**
`mise.toml`'s `[tasks.gate]` read `run = "./bin/gate"`, and there is no
`bin/gate` in this repository — it printed `sh: ./bin/gate: No such file or
directory` and mise reported `ERROR task failed`. So the one gate spelling mise
advertised was broken, `mise run prime` failed with "task not found", and the
only correct command in the repository was the one nothing pointed a developer
at: README, AGENTS.md and CI all said `./bin/prime`, and `mise.toml` — the file
you run `mise install` next to — said something else. Both tasks now resolve to
`./bin/prime`. `mise run prime` is the fleet's spelling and is new here;
`mise run gate` is kept as an alias, because one gate under two names is one
gate and not two.

### Known gaps

- **CI runs `./bin/live`, not `./bin/prime --live`.** Both reach the same file,
  but the composition is only exercised by hand, so nothing in CI has ever run
  `bin/prime` with a live credential. Recorded in `gate.yml` rather than
  papered over; the fix is a one-word change to the workflow and which side it
  should move is a manager's call.
- **cafaye-py has no drift guard against `cafaye/core`.** Unlike `muse`, it does
  not vendor core's schemas and has no `../core` requirement in `gate.yml`,
  because there is nothing here to drift. The cost is that nothing in this
  repository would notice if core changed a convention this client documents in
  a comment. Named in `REPORT-cafaye-py-10-gate.md`; not fixed, because the fix
  is a design decision rather than a declaration.
- `bin/gate-self-test`, which would make the five red proofs above reproducible
  on demand the way `bin/red-proofs` does for the test-level ones. courier and
  darkroom ship one; cafaye-py does not yet.

## [0.1.0] — 2026-09-30

The first release. Hand-written, typed, sync and async from one implementation,
with `identity`'s twenty operations and an error model that survives a problem
type nobody has written yet.

### Added

**The client.** `Cafaye` and `AsyncCafaye`, one runtime dependency (`httpx`),
`py.typed`. Base-URL precedence is explicit and tested in all three directions —
argument, then `$CAFAYE_BASE_URL`, then the documented default — and
`base_url_sources` names which one answered.

**Both auth models.** A scoped API token, a bearer JWT, and a session token,
discriminated from the credential's own shape the way identity's
`internal/httpapi/apikeys.go` discriminates. A session contributes both the
bearer header and the `__Host-session` cookie, because identity documents how it
resolves a request carrying both. The credential is attached per request, so
`set_token` rotates one without rebuilding the client.

**RFC 9457 problem → typed exception.** A distinct class per reserved code, with
`type` and `detail` preserved, and a **typed fallback**: a code this client has
never seen produces a `CafayeProblemError` carrying it. `code` chooses the class
and `status` breaks the tie.

**The three ways a request can fail, kept apart.** A problem document, a
protocol fault in either direction, and no response at all. A timeout is not a
DNS failure and both are queryable through `reason`; a cancellation is not
classified at all, because "timeout" is the answer most likely to be retried and
a task being torn down is the one case where retrying is wrong.

**Twenty `identity` operations**, declared once and exposed by two classes with
the same twenty names, compared method by method and token by token so a
conditional branch on one face and not the other fails the suite.

**The credential-leak test.** Adversarial rather than innocent: every failure
path is fed a service that has deliberately echoed the credential back. It walks
`str`, `repr`, every own attribute, the cause chain, the formatted traceback, the
client's own `repr`, and every captured log record — and every response model's
`__repr__`.

**A named gate.** `bin/prime`, in bash, under `set -euo pipefail`, reading
`${PIPESTATUS[0]}` — because a piped gate's status under zsh is the status of
`tail`, and that has already produced one false green in this fleet. Two tiers:
a unit tier that always runs, and an env-gated tier that is *demanded* rather
than skipped.

**100% line and branch coverage**, with `source = ["src/cafaye"]` set so an
unimported module is a failure rather than an absence, and a type checker
(`mypy --strict --warn-unreachable`) that treats a branch which cannot be taken as
the finding it is.

### Fixed

Six defects found by the tests this release shipped with, and recorded rather
than quietly repaired. Each has a regression test; two have a red proof in
`.red/` proving the test is the thing that catches it.

- **`httpx` does not substitute `{name}` path placeholders.** It percent-encodes
  the braces and turns the whole parameter mapping into a query string, so nine
  of the twenty operations were requesting
  `/v1/accounts/%7Baccount_id%7D/api-keys`. A mock transport never noticed,
  because a mock answers any URL. `.red/06`.
- **The redactor's `\b` anchors were backwards.** `\bcafaye_` asserts a
  word/non-word transition, so it matched a bare token and a token after a `/`,
  `?` or space, and silently failed on a token preceded by any word character —
  `xcafaye_…`, `1cafaye_…`, `prefix_cafaye_…`. A credential concatenated onto
  something is the ordinary case, not the exotic one. `.red/05`.
- **`POST /v1/session` returned `None`.** The declaration table had no model for
  it, so a successful login decoded to nothing.
- **`_Model.from_response` called a method no model has.** The one method every
  model inherited was an `AttributeError` with no message.
- **A streaming response was reported as a network failure.**
  `Response.json()` raises `ResponseNotRead`, which is not a `ValueError`, so it
  escaped as a `CafayeNetworkError` with `reason="unknown"` — a client-side
  fault described as the network having failed.
- **A cancellation was classified as a timeout**, contradicting the module's own
  docstring, and a handler for an unread response raised the exception it was
  handling.

### Known gaps

- The env-gated tier has never been run. It needs a cafaye deployment and a
  scoped credential, and this packet had neither. `REPORT-cafaye-py-01.md` says
  so in its first line.
- `identity` is the only service with a client. The other five are declared for
  base-URL resolution and have no operations here.
- This client's surface is identity's *current* `openapi/v1.yaml`; `cafaye-ts`
  holds a vendored copy from an older commit and so has sixteen operations where
  this one has twenty.

[Unreleased]: https://github.com/cafaye/cafaye-py/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cafaye/cafaye-py/releases/tag/v0.1.0
