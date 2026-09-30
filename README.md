# cafaye-py

The cafaye Python client. Hand-written, typed, sync and async from one
implementation, and structurally unable to log a credential.

```python
from cafaye import Cafaye

cafaye = Cafaye(base_url="https://identity.cafaye.com", token="cafaye_…")
user = cafaye.identity.get_current_user()
print(user.email)
```

One runtime dependency (`httpx`). Twenty `identity` operations, reached through
one property. A failure is a typed exception, not a status code to inspect.

---

## Five minutes

**Install.**

```console
$ pip install cafaye-py          # from a checkout: pip install .
$ mise install                    # if you are working in this repository
```

**Point it somewhere.** Highest of three sources, in this order:

| source | example |
| --- | --- |
| the `base_url` argument | `Cafaye(base_url="https://identity.example.test")` |
| `$CAFAYE_BASE_URL` | `export CAFAYE_BASE_URL=https://identity.example.test` |
| the documented default | `https://identity.cafaye.com` — `servers[0]` of identity's OpenAPI document |

Each one wins in turn and each is tested proving the others did not. The default
is never a loopback address, and a value that is set and malformed is refused
with the name of the source that was wrong.

Which source answered is not a thing you have to infer:

```python
cafaye.base_url_sources["identity"]
# 'the `base_url` argument' | '$CAFAYE_BASE_URL' | 'the documented default'
```

**Give it a credential.** cafaye has two auth models and a client that supports
only one is useless for half its users. cafaye-py supports both and works out
which one it has, from the shape:

| you pass | it is | it goes out as |
| --- | --- | --- |
| `cafaye_…` (32 bytes after the prefix) | a scoped API token | `Authorization: Bearer …` |
| a JWS compact serialization | a service JWT | `Authorization: Bearer …` |
| anything else | a session token | `Authorization: Bearer …` **and** `Cookie: __Host-session=…` |

The prefix is the discriminator because identity's own
`internal/httpapi/apikeys.go` says so: *"THE PREFIX IS THE DISCRIMATOR, and that
is the second thing the `cafaye_` prefix buys."* A session contributes both forms
because identity's document says how it resolves a request carrying both — *"An
`Authorization: Bearer` header is preferred over the cookie when both are
present, because a client holding both has said which one it means."* The
tie-break is the server's, not this client's.

An unrecognised value is treated as a session, and that direction is chosen
deliberately: a session misread as a JWT loses a cookie it did not strictly need,
while a JWT misread as a session publishes itself onto the wrong surface.

**Rotate it.** The credential is attached per request, not per client:

```python
cafaye.set_token(new_token)  # takes effect on the next call
cafaye.set_token(None)  # and this removes it
cafaye.credential_kind  # what it decided, never the value
```

**Use it.**

```python
cafaye.identity.get_current_user()
cafaye.identity.mint_api_key(account_id="acc_1", name="ci", scopes=["invoices:read"])
cafaye.identity.delete_session()
```

**Close it.** It is a context manager, and so is the async one.

```python
with Cafaye(base_url=…, token=…) as cafaye:
    cafaye.identity.get_current_user()

async with AsyncCafaye(base_url=…, token=…) as cafaye:
    await cafaye.identity.get_current_user()
```

---

## Async

`httpx` ships a sync and an async client over one transport, and this package
writes the request lifecycle **once**, as a generator that yields the request it
wants sent and receives the response back:

```python
pending = exchange.send(None)  # build
response = transport.send(pending)  # I/O   <- the only line that differs
value = exchange.send(response)  # map or raise
```

So there are two classes — `Cafaye` and `AsyncCafaye` — with the same twenty
operation names, the same options, the same credential rules and the same error
model. `tests/test_branches.py` compares the two service classes **method by
method, token by token**, with only layout, docstrings and the four names that
are supposed to differ (`async`, `await`, `_perform`, `_aperform`) removed. A
conditional branch written on one face and forgotten on the other fails there,
and three such branches existed when that test was written.

Async tests are synchronous tests that call `asyncio.run`, deliberately: an async
test plugin brings a loop fixture, a session scope, a marker and a third runtime
dependency into a package whose selling point is one runtime dependency.

---

## Errors

Every non-2xx response from every cafaye service is
`application/problem+json` (RFC 9457), so one shape means one place to turn a
failure into a value a caller can catch by type.

```
CafayeError                        kind: problem | protocol | network | configuration
├── CafayeProblemError             a problem document arrived
│   ├── CafayeUnauthenticatedError    401 unauthorized
│   ├── CafayeForbiddenError          403 forbidden
│   ├── CafayeNotFoundError           404 not_found
│   ├── CafayeRateLimitedError        429 rate_limited
│   ├── CafayeConflictError           409 conflict
│   │   └── CafayeIdempotencyKeyReusedError   409 idempotency_key_reused
│   └── CafayeValidationError         422 validation_failed
├── CafayeProtocolError          an HTTP response that is not what the contract says
├── CafayeNetworkError           no HTTP response at all
│   └── CafayeTimeoutError        the network failure was a timeout
└── CafayeConfigurationError     the options were wrong; no request was made
```

```python
from cafaye import CafayeError, CafayeRateLimitedError

try:
    cafaye.identity.list_api_keys(account_id="acc_1", limit=50)
except CafayeRateLimitedError as error:
    print(error.retry_after)  # from the problem document
except CafayeError as error:
    print(error.kind, error.status, error.code, error.trace_id)
```

`CafayeProblemError` is instantiable and **is** the typed fallback. A service
that adds a code next month produces a `CafayeProblemError` carrying that code,
not a `KeyError` — and the handler above works against every failure this package
can produce, including the ones nobody has seen yet. `.red/03-unknown-problem-type.txt`
is the recorded proof, with the fallback line removed.

`code` chooses the class and `status` breaks the tie, because `code` is
documented as the machine-readable contract and `status` is one response's
opinion about itself. A service that answers 403 with `code: "forbidden"` is a
`CafayeForbiddenError` even if the number drifts, and a service that omits `code`
entirely is still mapped from the number.

A **timeout is not a DNS failure** and they do not collapse.
`CafayeTimeoutError` extends `CafayeNetworkError`, so
`except CafayeNetworkError: retry()` catches both, and `error.reason`
(`timeout` / `dns` / `connection` / `tls` / `protocol` / `unknown`) tells them
apart. Classification is by **type and errno**, never by message: httpx raises
`ConnectError("All connection attempts failed")` for *both* a refused connection
and a name that did not resolve, so the difference that matters is one level down.

A **cancellation is not classified at all.** There is no `NetworkFailureReason`
for one, and its absence is a decision: the obvious place to put it is `timeout`,
which is the answer most likely to be retried, and a task being torn down is the
one case where retrying is wrong. The caller's own `CancelledError` comes back
untouched, so `Task.cancelling()` bookkeeping stays consistent.

**A 2xx with no body, where the operation declares one, is a
`CafayeProtocolError`** rather than a `None`. `get_current_user() -> User`
returning `None` would put a `None` check in front of every caller for a case the
annotation says is impossible. This is this package's own rule rather than the
brief's, and it follows the same principle the brief states for the
problem-shaped case: *a typed client that quietly returns the wrong shape is
worse than one that stops.*

---

## The threat model

> **Who can see what, and therefore what this client refuses to do.**
>
> A Python process is the least hostile place a credential lives, and the most
> exposed. The credential is a string in memory; the moment it becomes a
> `str`, a `repr`, an f-string or a `__dict__` entry it is one `traceback` away
> from a log file, a crash reporter, a support ticket or a terminal somebody is
> looking over your shoulder. `logger.error("request failed", exc_info=True)`
> prints the whole cause chain with no configuration at all.
>
> So this package refuses three things outright. It **emits nothing**: no
> `logging`, no `print`, no telemetry, in any module — a debug-level log is a
> level somebody turns off in production and pastes into a bug report, so the
> only way to *guarantee* the invariant is to have nothing to guarantee it about.
> It **never builds a string out of caller- or service-supplied text without a
> redactor first**, and the redactor is all-or-nothing: a string comes back
> unchanged or comes back as one marker, never half-redacted, so a pattern with
> a gap in it can only cause a false negative for "this string is clean" and
> never a leak. And it **redacts every `__repr__` that could hold a secret** —
> the client's, and all seven credential-bearing models'.
>
> What it explicitly does **not** do is hide the credential from you. A
> `Session` from `POST /v1/session` still has `.token`, an `IssuedApiKey` still
> has `.token`, and `dataclasses.asdict(session)` still contains it. That has to
> be so — it is the whole point of those operations — and a package that made
> the credential unreadable would have broken every caller that legitimately
> needed it. The boundary is: **this client will not print a credential
> accidentally, and it will not stop you printing one on purpose.** A structured
> log payload built from a `Session` is yours to keep.
>
> Finally, the credential is a constructor argument and a keyword, never an
> environment variable read by this package and never a command-line argument it
> suggests. It is not read from `.env`, it is not logged, it is not written to
> disk, and `.env` is in `.gitignore` for the same reason. A token passed on a
> command line is in the process listing for as long as the process lives; this
> client does not make that easy to do by accident, and cannot prevent you doing
> it on purpose.

`tests/test_credential_leak.py` is the deliverable, and it is adversarial
rather than innocent: every failure path is fed a service that has
**deliberately put the credential into the response** — a problem `detail` that
echoes it, an extension member that echoes it, a `Set-Cookie` that echoes it, an
HTML 502 that echoes it, and a transport that rejects with an error whose message
echoes it. An innocent `assert TOKEN not in message` passes just as well when
those are all absent, and proves nothing when they are present.

It also walks every **response model**'s `__repr__`, because a test that checks
the client's `repr` is not a test that checks the result's — and that gap was
real: two of the seven models were unprotected until the walk was written.

---

## The operations, and how they map to `cafaye-ts`

The two clients are one product, and a divergence between them is a defect in the
platform rather than in either client. Same credential rules, same error model,
same `kind`/`status`/`code`, same operation identity in an exception's
`operation`.

The one systematic difference is the naming convention: Python is snake_case and
the documents' `operationId`s are camelCase, so `get_current_user` here is
`getCurrentUser` there. A camelCase method name in a Python client would be a
defect rather than a parity win. The table, from identity's `openapi/v1.yaml`:

| this client | `cafaye-ts` | HTTP | path |
| --- | --- | --- | --- |
| `register_user` | `registerUser` | POST | `/v1/users` |
| `create_session` | `createSession` | POST | `/v1/session` |
| `delete_session` | `deleteSession` | DELETE | `/v1/session` |
| `complete_second_factor` | `completeSecondFactor` | POST | `/v1/session/mfa` |
| `get_mfa_status` | `getMFAStatus` | GET | `/v1/mfa` |
| `disable_mfa` | `disableMFA` | DELETE | `/v1/mfa` |
| `start_mfa_enrollment` | `startMFAEnrollment` | POST | `/v1/mfa/enrollments` |
| `confirm_mfa_enrollment` | `confirmMFAEnrollment` | POST | `/v1/mfa/enrollments/{enrollment_id}/confirm` |
| `regenerate_mfa_recovery_codes` | `regenerateMFARecoveryCodes` | POST | `/v1/mfa/recovery-codes` |
| `get_current_user` | `getCurrentUser` | GET | `/v1/me` |
| `register_oidc_client` | `registerOIDCClient` | POST | `/v1/accounts/{account_id}/oidc-clients` |
| `list_oidc_clients` | `listOIDCClients` | GET | `/v1/accounts/{account_id}/oidc-clients` |
| `get_oidc_client` | `getOIDCClient` | GET | `/v1/accounts/{account_id}/oidc-clients/{client_id}` |
| `revoke_oidc_client` | `revokeOIDCClient` | DELETE | `/v1/accounts/{account_id}/oidc-clients/{client_id}` |
| `mint_api_key` | `mintAPIKey` | POST | `/v1/accounts/{account_id}/api-keys` |
| `list_api_keys` | `listAPIKeys` | GET | `/v1/accounts/{account_id}/api-keys` |
| `revoke_api_key` | `revokeAPIKey` | DELETE | `/v1/accounts/{account_id}/api-keys/{key_id}` |
| `introspect_api_key` | `introspectAPIKey` | POST | `/v1/introspections` |
| `liveness` | `liveness` | GET | `/healthz` |
| `readiness` | `readiness` | GET | `/readyz` |

`tests/test_identity.py` states this table independently and asserts the client's
declaration table against it, so a change to one is a change to both.

### Two places the clients differ, on purpose

**`CafayeProblemError`'s constructor.** `cafaye-ts` takes
`(message, {type, title, status, …})` — a members bag. This one takes
`(message, *, type, title, status, …)` — keyword-only. The reason is that nobody
outside this package constructs a `CafayeProblemError`: they are *raised*, never
built, so the constructor is not part of the shape a caller sees. The
caller-visible surface is the **attributes** — `type`, `title`, `detail`,
`instance`, `code`, `traceId`, `errors`, `extensions`, `operation` — and those
match. Putting a positional bag in Python would lose the per-field types and the
per-parameter documentation for a constructor nobody calls.

This client's `CafayeProblemError` also carries a `content_type` that the
TypeScript one does not. It is the one field that distinguishes "a cafaye service
said no" from "a proxy handed me an error page that happened to be JSON", and
`CafayeProtocolError` already carries it in both clients, so the two error types
now read the same way.

**The base URL's fallback.** `cafaye-ts` resolves in five steps and **throws**
when nothing is configured, citing *"a default would be a guess, and a guess about
which deployment to send a customer's credentials to is the one kind of guess this
package refuses to make."* This one has a documented default, because its brief
specifies `explicit → CAFAYE_BASE_URL → the documented default` and that default
is `servers[0]` read out of a committed document — a fact from the contract
rather than a guess about a deployment.

Both clients keep the property that actually matters: **nothing can resolve to a
loopback address**, and both expose the source that answered. Whether a
credential-carrying client should default to a public SaaS host at all is a real
platform question this repository does not settle, and it is recorded in
`REPORT-cafaye-py-01.md` rather than answered here.

### MD6: hand-written, not generated

Go generates its client from the OpenAPI documents. **This one is hand-written**
and does not reach for a generator: `openapi-python-client` and its relatives
each impose a runtime dependency, a pydantic v1/v2 split, or a model layer that
does not match the problem. The sameness that matters is the shape a caller
sees, not the mechanism that produced it, so the two clients match in method
names, error model, auth precedence and naming — and differ in how they were
built, which is invisible from the outside.

The consequence a consumer sees is the same either way: construct `Cafaye`,
reach every operation through a property, and a generator upgrade can never break
your code.

The response models are frozen dataclasses rather than a validation layer, and
**an unknown member is dropped**. A validating model raises on a field the
client does not know about, or silently keeps it, and either way *your* code
fails because *identity* added a field. A client that breaks the day the API
grows is a client that has made the service's release calendar its own problem.

---

## The gate

```console
$ ./bin/prime           # the whole thing
$ ./bin/prime --fast    # the frozen install only
$ ./bin/prime --live    # and demand the env-gated tier
$ mise run prime        # the same file, by the fleet's spelling
```

`bin/prime` is the one command: frozen install, `ruff format --check`, `ruff
check`, `mypy`, the test suite, and a coverage check that re-reads
`coverage.xml` and `fail_under` independently rather than trusting that pytest
was asked to enforce them.

It is **bash**, and that is load-bearing: `${PIPESTATUS[0]}` does not exist in
zsh, which is this machine's default shell, so a gate piped into `tail` exits 0
under zsh no matter what the gate decided. `set -euo pipefail` plus an explicit
`${PIPESTATUS[0]}` is the mechanism, and it only exists in bash.

### It is declared, not discovered

`gate.yml` at the repository root states what gates this repository, against
`cafaye/core`'s `schemas/gate.schema.json`. Read it before changing `bin/prime`,
`mise.toml` or `.github/workflows/ci.yml` — the checker reads all three.

Three things in it are load-bearing here:

- **`proof[].no-skip` must not match a line that says `skipped`.** That
  negative lookahead is the only thing between a green exit code and a suite
  that quietly stopped running part of itself. Measured: with one test made to
  skip, the gate printed `585 passed, 1 skipped`, coverage was still 100.00%, it
  printed `prime: unit tier GREEN`, and it **exited 0**. The declaration was red
  anyway, naming `gate.proof-missing` on `no-skip` alone.
- **`proof[].minimum` is a ratchet.** `580` is below the suite's 586 so adding
  a test does not need an edit first; `586` on `no-skip` is exact, because with
  no `skipif` anywhere under `tests/` the difference between 586 and 585 is one
  test that did not run. Deleting a test takes it under.
- **`external.selfContained: false`** because `bin/prime` exits 127 without `uv`
  on PATH and installs this repository's locked closure from PyPI on a cold
  checkout.

Check it with core's checker, which this repository does not vendor:

```console
$ ../core/harness/bin/gate-check .          # the declaration against the tree
$ ../core/harness/bin/gate-check --prove .  # and the gate itself
```

One warning is expected and correct: `gate.requirement-unproven` on `mise`,
because the checker refuses to run `mise install` to see whether a toolchain is
there — an answer that depended on the machine would be red on a laptop and
green on CI. It is reported and never acted on.

### Two tiers

The **unit tier** needs no credential, no network and no deployment. It is the
default and it is what the gate is.

The **env-gated tier** (`bin/live`, `live/`) talks to a real deployment, and it
is **demanded rather than skipped**: `bin/prime --live` and the `live` CI job
both treat a missing credential as a **failure**, with a sentence explaining
why. A CI job whose live tier quietly reported "0 tests ran, all green" would be
indistinguishable from one that genuinely found nothing wrong, and the badge
above both is the same green. Every run of the gate prints which tier did not
run, in those words.

`bin/red-proofs` reproduces the red proofs in `.red/`. It is **not** part of the
gate — each proof requires deliberately breaking the code — and it verifies that
it restored the tree by diffing, because a harness that leaves the tree modified
is worse than no harness.

## What is not here

Nothing that composes two services, refreshes a token, retries, paginates
automatically, or caches. Each is a place to put a policy the platform should
own, and putting one here would make the fleet's current shape a thing your
application depends on. `page.next_cursor` is opaque and this client does not
parse it; pass it back unexamined.

## Licence

MIT. See `LICENSE`.
