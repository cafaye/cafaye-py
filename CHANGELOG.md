# Changelog

All notable changes to `cafaye-py` are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing. The next change goes here.

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
