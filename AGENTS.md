# AGENTS.md

The rules the hand-written half of this package has, and why. `cafaye-ts` has a
file with this name; this one exists because the two halves of the same product
should be able to disagree about *mechanism* and never about *shape*.

## THE ONE INVARIANT

> **Never log a token, a cookie, or a JWT.**

Not in a log record, not in an exception message, not in a serialised form, not
in a `repr()`, not in a traceback, not in a `__str__`.

This is why the client is hand-written (MD6), and it is why there is exactly one
runtime dependency. A generator cannot hold an invariant; a hand-written
credential path can, and the test that proves it is
`tests/test_credential_leak.py`.

Concretely, in this repository:

- **No module imports `logging`, `warnings` or `subprocess`.** The leak test
  walks the AST of `src/cafaye/` and fails on any of them, and on any call to
  `print` or to a logger. A library that logs nothing cannot leak a credential
  by logging.
- **Every string built from caller- or service-supplied text goes through
  `redact_text` first.** The redactor is all-or-nothing: unchanged, or one
  marker. No partial redaction, because partial redaction invites a reader to add
  one more pattern and a pattern with a gap in it ships a credential.
- **Every model that can hold a secret overrides `__repr__`.** Seven of the
  thirteen do: `Session`, `MfaChallenge`, `StartedEnrollment`,
  `ConfirmedEnrollment`, `RecoveryCodesResponse`, `OIDCClientWithSecret`,
  `IssuedApiKey`. The walk that keeps that true is in the leak test, not in a
  checklist.
- **A credential is never in a message that quotes the offending value.** How
  many characters were wrong is diagnosis; which ones is a fingerprint.

What this does **not** do is hide the credential from a caller. `Session.token`
is readable, because that is what the operation is for. The boundary is: this
package will not print a credential *accidentally*, and it will not stop you
printing one *on purpose*.

## NEVER ADD A GENERATOR

MD6 ruled it. `openapi-python-client` and its relatives each impose a runtime
dependency, a pydantic v1/v2 split, or a model layer that does not match the
problem. The sameness that matters across the SDKs is the shape a caller sees,
not the mechanism that produced it.

The corollary: **do not add a second model layer, and do not add a runtime
dependency to make this tree look like `cafaye-ts`.** One dependency, `httpx`.

## NEVER COMPOSE, RETRY, REFRESH, PAGE OR CACHE

Each is a place to put a policy the platform should own, and putting one here
makes the fleet's *current* shape a thing a consumer's application depends on.

- No auto-pagination. `page.next_cursor` is opaque; pass it back unexamined.
- No retry. `CafayeNetworkError.reason` exists so a *caller* can decide, and a
  retry loop inside the client cannot know whether the caller's deadline, its
  idempotency story or its shutdown sequence allows it.
- No token refresh. `set_token` is the whole API.
- No caching of anything.

## TWO CLASSES, NOT ONE WITH A FLAG

`Cafaye` and `AsyncCafaye`. The alternative — one class whose methods return
either a value or a coroutine — fails at the `await`, several frames from the
line that mixed them up, with an `AttributeError` about a value not being
awaitable, which is a diagnosis that costs an hour.

The check that keeps them honest is in `tests/test_branches.py`: the two service
classes are compared **method by method, token by token**, with only layout,
docstrings and `async`/`await`/`_perform`/`_aperform` removed. Three conditional
branches were unreachable on the async face when that test was written.

## A BRANCH THAT CANNOT BE TAKEN IS A BUG

`mypy` runs with `--warn-unreachable` and coverage runs at `fail_under = 100`
with `branch = true`. Both are here to say the same thing: "cannot happen" is a
finding, not a style note.

That is why `credentials.py` has no `isinstance(token, str)` check, why
`_decode` has one `ResponseNotRead` guard and not two, and why
`_client._is_problem_media_type` and `_errors._is_problem_media_type` are
compared against each other by a test instead of left to drift.

Adding a `pragma: no cover` is a decision, and it needs a sentence saying which
invariant makes the branch unreachable. There are three in the tree and each one
says.

## THE DECLARATION TABLE IS THE SINGLE SOURCE OF TRUTH

`IDENTITY_OPERATIONS` in `_services/identity.py` says what each of identity's
twenty operations is: its `operationId`, its HTTP method, its path, and its
response model. The twenty methods name the same model again, and `_declared()`
checks the two against each other on every call.

The duplication is deliberate. A `cast` at every call site would document the
annotation without checking it, and a table with no `model` column would no longer
describe the service. The cost is one comparison per call and the benefit is that
a method which says `-> User` and decodes with something else is a loud error
rather than a wrong value.

`_declared` compares with `_same_decoder`, not `is`, because every
`from_response` is a `classmethod` and Python builds a fresh bound method on each
access. An identity check there is a check that is always red and therefore checks
nothing.

## PATH PARAMETERS ARE SUBSTITUTED HERE

`httpx` does **not** substitute `{name}` in a path. Given
`https://x/v1/accounts/{account_id}` and `params={"account_id": "a"}` it
produces `https://x/v1/accounts/%7Baccount_id%7D?account_id=a`.

So `_resolve_path` completes the path and returns the rest as the query, and the
split is **derived** rather than declared: anything named in the path is a path
parameter, everything else is a query parameter. A second list per operation
would be a second place to forget.

## TEST DISCIPLINE

- **No network.** Every request goes through `httpx.MockTransport`. A suite that
  reaches the internet fails on somebody else's outage and can be made to
  exfiltrate.
- **No sleeps. No raised retries. No loosened assertions.** If something is
  flaky, fix the flake or report it.
- **Assert on the request, not only on the response.** A mock answers any URL,
  which is how a path-parameter bug survived 148 passing tests.
- **Red proofs are kept.** `.red/` is not a scratch directory. `bin/red-proofs`
  reproduces them, and it verifies it restored the tree by diffing.

## THE GATE IS ONE COMMAND

`./bin/prime`. CI runs `./bin/prime`, not a re-implementation of it in YAML — a
CI job that runs something other than the local gate proves nothing about the
local gate, and the two drift within a month.

It is bash, and that is load-bearing. `${PIPESTATUS[0]}` does not exist in zsh,
so a gate piped into `tail` exits 0 under zsh regardless of what the gate
decided, and that has already produced one false green in this fleet.

## A TIER THAT IS NOT RUN IS SAID OUT LOUD

`bin/prime` prints which tier did not run on every invocation, in those words.
The env-gated tier is *demanded* (`--live`), never silently skipped, and a
missing credential is a failure there rather than a pass.

A CI job whose live tier quietly reported "0 tests ran, all green" would be
indistinguishable from one that genuinely found nothing wrong. The badge above
both is the same green, and a green badge is a claim.
