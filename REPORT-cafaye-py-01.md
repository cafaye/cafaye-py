# REPORT — cafaye-py-01-resume

**The env-gated tier was not run. 0 tests were skipped as unavailable; 1 test
file (5 tests) could not run at all, because `bin/prime --live` needs a cafaye
deployment and a scoped credential and this packet had neither.** The unit tier is
the tier that ran: 586 passed, 0 failed, 100.00% line and branch coverage, and
`./bin/prime` exited 0.

Everything below is in `cafaye-py` on branch `rescue/cafaye-py-01-partial`, which
is not yet pushed — see "The push" at the end.

---

## 1. What I inherited, and what was actually true

The packet said the tree was red with one failing test. **It was red with
thirteen**, and the log named one of them. `git show 629dd3e` is the manager's
snapshot of a tree that existed only uncommitted, so there is no earlier commit
to diff against; these are the numbers as measured, not as reported.

```
$ uv run pytest -p no:cacheprovider --no-cov -q --maxfail=0
13 failed, 134 passed in 1.47s
```

The thirteen fell into three clusters, and **only one of them was in the source**:

| cluster | count | where the bug was |
| --- | --- | --- |
| network failures all classified `reason="unknown"` | 11 | `tests/conftest.py` |
| `delete_session() got an unexpected keyword argument 'token'` | 1 | the test |
| `CafayeProblemError.__init__() takes 2 positional arguments but 3 were given` | 1 | the test |

**`responding_with` returned an exception instead of raising it.**
`httpx.MockTransport` type-checks its handler's return value and raises
`TypeError("Cannot use an async handler in a sync Client")` for anything that is
not a `Response`. So a handler that *returned* an exception produced a
`TypeError`, and eleven tests about `classify_network_failure` were all
greenly asserting that a `TypeError` is `reason="unknown"`. The suite had never
exercised the classifier it was built to prove. One fixture bug, and it is worth
recording that `-p no:cacheprovider --no-cov` plus the default `-x` hid the
scale: `-x` stops at the first failure, so the log's "1 failed" was the first of
thirteen.

**`delete_session` takes no token, and the test said otherwise.** The document
settles it. `identity/openapi/v1.yaml` at `e500262`, `deleteSession`:

```yaml
    delete:
      operationId: deleteSession
      summary: Log out
      security:
        - sessionCookie: []
        - bearerToken: []
      responses:
        '204': {…}
```

No `requestBody`, no query parameters. There is nowhere on the wire for a
per-call credential to go, so the only defensible signature is
`delete_session() -> None` with the credential attached by `attach_credential`
from the client that holds it. The sibling client agrees from the same document:
`cafaye-ts`'s generated `DeleteSessionData` is
`{ body?: never; path?: never; query?: never; url: '/v1/session' }`.

What matters more than the signature: identity-08 documents that this route
answers **403 to a scoped API token**, because a machine credential has no
session to end. A signature that accepted a token would have let a caller hand
over exactly the credential this route refuses, and the 403 would have arrived
with no obvious cause. **I changed the test, not the client, and the test now
asserts the signature** so the question cannot be reopened silently.

**The third one was a cross-client shape divergence, not a plain bug.** The test
called `CafayeProblemError("a problem", {"type": …, "title": …, "status": …})` —
a members bag as the second positional argument. That is `cafaye-ts`'s
constructor, transcribed. See §5 for the decision I made about it.

## 2. The two design questions I was asked to answer

**`delete_session`: no token argument.** Decided above, on the document's
evidence, with the sibling client's generated type as corroboration. The code
was right and the test was wrong, and the report says which.

**MD7: both spellings are accepted, and neither wins.** `internal/apikeys/claims.go`
says it outright: the claim is emitted **twice** — as `scopes` and as `scope` —
*"and that is not a typo, not a compatibility shim somebody forgot to remove, and
not this service having an opinion about the specification. The fleet does not
agree on the name"*, with `core/docs/openapi-conventions.md:134` requiring
`scopes` and `guard/src/middleware/jwt.ts:32` reading `scope`, both recorded in
MD7 as open.

So `Introspection` carries **both**, each optional, and **neither is derived from
the other**:

```python
>>> Introspection.from_response({"active": True, "scopes": "invoices:read"})
Introspection(active=True, …, scopes='invoices:read', scope=None, …)
>>> Introspection.from_response({"active": True, "scope": "invoices:read"})
Introspection(active=True, …, scopes=None, scope='invoices:read', …)
```

identity holds a test that the two cannot drift, and this client does **not**
assume that: it reports what it was given, because a service emitting two
different values would be a finding and merging them here would hide it.
`None` is "the service did not say", which is a different and answerable question
from "the service said nothing". A client that picked a winner would hide half the
claim from whichever side of MD7 turns out to be right, and the cost of being
wrong is a rotation of every credential already in a customer's hand.

## 3. What the original brief asked for, item by item

| # | the brief asked for | state | evidence |
| --- | --- | --- | --- |
| 1 | `Cafaye` client class, base-URL precedence explicit and tested in all three directions | **already done** | `tests/test_base_url.py` |
| 2 | both auth models, the decision tested in both directions | **already done** | `tests/test_credentials.py` |
| 3 | RFC 9457 → typed exception, one class per type, **typed fallback** | **already done** | `tests/test_errors.py` |
| 4 | sync and async from one implementation | **already done** | `tests/test_client.py` |
| 5 | typed service clients, starting with `identity` | **already done, but with a bug** — see below | `tests/test_identity.py` |
| 6 | the credential-leak test, real and not a grep, error path included | **already done**; **extended** | `tests/test_credential_leak.py` |
| 7 | threat model in the README, one paragraph | **built** | `README.md` |
| 8 | modern Python pinned in `mise.toml` + `.python-version` | **already done** | `mise.toml` |
| 9 | real `pyproject.toml`, `requires-python` justified | **already done** | `pyproject.toml` |
| 10 | `py.typed` | **already done** | `src/cafaye/py.typed` |
| 11 | type-checked in the gate, with a stated choice of checker | **already configured, never run** | `pyproject.toml` |
| 12 | formatted/linted with stable configuration | **already configured, never run** | `pyproject.toml` |
| 13 | `--cov-fail-under` **and `source=`** set | **already done, never run** | `pyproject.toml` |
| 14 | a README a Python developer can act on in five minutes | **built** (it was the word "placeholder") | `README.md` |
| 15 | a `CHANGELOG.md` | **built** (absent) | `CHANGELOG.md` |
| 16 | the gate green | **built and green** | `bin/prime` |
| 17 | `REPORT-cafaye-py-01.md` with three red proofs and a "could not verify" section | **this file** | — |
| 18 | say clearly in the report that pantry must be flipped by a second packet | **§7** | — |

**What was already satisfied:** 1, 2, 3, 4, 8, 9, 10, and 6's original form.
Those were genuinely good and I left them alone except where the gate found a
problem inside them.

**What I built:** 7, 11 (made it run), 12 (made it run), 13 (made it run), 14,
15, 16, 17, 18. Plus `AGENTS.md`, `bin/live`, `bin/check-coverage`,
`bin/red-proofs`, `.github/workflows/ci.yml`, and five test files.

## 4. Six defects, and how each was found

Four were in the source and two in the tests. The order is the order they were
found, and the last one is the most interesting.

**(a) `create_session` returned `None`.** The declaration table had no `model` for
`POST /v1/session`, so a successful login decoded to nothing and a caller with a
valid session token in hand had nowhere to read it out of. No test covered the
operation, which is how it survived. The decoder is now `_session_or_challenge`,
dispatching on the one member the document promises is absent: *"The `202` body
carries **no `token` key at all** — not an empty one — so a client that reads
`token` finds nothing and is unambiguous about it."* That sentence is the
discriminator, and using it means the rule is the document's rather than a
heuristic of ours.

**(b) `_Model.from_response` called a method no model has.** The one method every
model inherited was `return cls.from_mapping(body)`, and `from_mapping` is a
module-level function that takes a body and returns a mapping — not a classmethod.
Any code calling it on the base class got an `AttributeError` with no message.
Unreachable from the twenty models, which all override it, which is how 78%
coverage and a green suite had not found it.

**(c) `httpx` does not substitute `{name}` path placeholders.** This is the worst
one. `PendingRequest`'s docstring claimed it did — *"httpx substitutes `{name}`
placeholders in the path from the same mapping it builds the query from, which is
why one dict carries both"* — and httpx does not:

```python
>>> c.build_request("GET", "https://x.test/v1/accounts/{account_id}/api-keys",
...                 params={"account_id": "acc_1"}).url
URL('https://x.test/v1/accounts/%7Baccount_id%7D/api-keys?account_id=acc_1')
```

The braces are percent-encoded, the identifier is in the query string where
nothing reads it, and the request goes to a route that does not exist. **Nine of
the twenty operations have a path parameter.** A mock transport never noticed,
because a mock answers any URL, and the previous suite asserted on
`request.url.path` for three operations and read the braces as correct.

`_resolve_path` now completes the path and returns the rest as the query, and the
split is **derived rather than declared**: anything named in the path is a path
parameter, everything else is a query parameter. A second list per operation would
be a second place to forget. Writing the test also surfaced that `_run` was
merging the JSON body into the same mapping, so every POST went out as
`?json={"code":"123456"}` with an empty body.

**(d) The redactor's `\b` anchors were backwards.** `CREDENTIAL_SHAPES` began
`\bcafaye_` and `\beyJ`. A word boundary asserts a word/non-word transition, so it
matched a bare token and a token after a `/`, `?` or space — and silently failed
on a token preceded by **any** word character:

```
alone        True
after x      False        <- xcafaye_...  not redacted
in a url     True
after a digit False       <- 1cafaye_...  not redacted
jwt after x  False
```

A credential concatenated onto something is not the exotic case, it is the
ordinary one: a proxy URL with it in the path, a log line that interpolated it
into an identifier, a cursor that embedded it. identity chose a seven-character
prefix precisely so a leaked credential is recognisable at sight, and the word
boundary discarded that for the shapes that matter most. Both `\b` are gone, with
a negative test alongside the positive ones — because a pattern loose enough to
match any occurrence of the letters "cafaye" would satisfy every positive case
and be useless.

**(e) A cancellation was classified as `timeout`,** contradicting `_errors.py`'s
own docstring. It is now `cancellation_in_chain()`, which returns the caller's own
`CancelledError` for the client to re-raise untouched. There is deliberately **no
`NetworkFailureReason`** for it: "timeout" is the answer most likely to be
auto-retried, and a task being torn down is the one case where retrying is wrong.

**(f) `Session.__repr__` printed the session token.** Four models were
unprotected, not one. `StartedEnrollment`, `OIDCClientWithSecret` and
`IssuedApiKey` redacted from the start, so a reader reasonably concluded the
models were handled — and `test_credential_leak.py` drove the client through every
path it has **without ever printing a response model**, because a test that
checks the client's `repr` is not a test that checks the result's. A login
returned a session token that any `print`, debugger frame or failed assertion put
on screen in full. `MfaChallenge` holds *"a one-time credential … valid for ten
minutes and single-use"*; `ConfirmedEnrollment` and `RecoveryCodesResponse` hold
the recovery codes, which are the account's way back in.

The hole was in the *test*, and it is now closed by a rule rather than by
remembering seven models: the leak test walks every model's `repr` with a
credential planted in the **fields that hold one by meaning**, and
`every_string_in` gained a dataclass arm — it used to append `str(value)` (clean,
for a redacted repr) and stop, never reaching the field underneath, while a
structured logger *does* descend there.

## 5. Where I changed a test, and why

Three, and each is recorded because "changed a test" is a thing a reader of a
diff should be able to check.

1. **`delete_session(token=...)` → `delete_session()`**, on the document's
   evidence. The test now also asserts the signature. §2.
2. **The reload test**, which could not run at all. It now constructs against the
   real constructor, and is paired with a test for what the class docstring
   actually claims. It then got worse: `importlib.reload(cafaye._errors)`
   rebinds that module's names but not the ones `cafaye/__init__.py` re-exported
   at import time, so after it ran, every `from cafaye import
   CafayeProtocolError` in the suite compared against a class the client no longer
   raised and `pytest.raises` **stopped catching**. A suite that is order-
   dependent and says nothing about it. It now loads a genuine second copy of
   `_errors.py` under a second name — the real two-copies-in-one-dependency-tree
   scenario rather than a proxy for it — and has no global side effect.
3. **A test of mine, written three times and wrong three times**, on the
   credential models: the first version planted the fake credential in *every*
   declared field, which puts one in `Introspection.sub` — a **user id**. A
   service that put a credential there would be broken, but a client that refused
   to print it would be hiding a field it is supposed to show. The second version
   asserted that a structured logger walking the *fields* finds nothing, which is
   false by design: the model has to hand the credential over, that is what
   `POST /v1/session` is for. The third states the actual property in both
   directions, including the sharp edge:

   > A redacted `repr` protects against **accidental** printing: a debugger
   > frame, an f-string, a traceback with locals, a failed assertion. It cannot
   > protect against a caller who walks the fields on purpose.

   `dataclasses.asdict(session)` **does** contain the token, and there is a test
   that says so out loud, because a caller who believes it is safe to put a
   `Session` in a structured log payload is wrong and the rule is theirs to keep.

**The `CafayeProblemError` constructor.** `cafaye-ts` takes
`(message, {type, title, status, …})`. This one takes
`(message, *, type, title, status, …)`. I kept the keyword-only form and stated
the divergence in the README. Nobody outside this package constructs a
`CafayeProblemError` — they are *raised*, never built — so the constructor is not
the shape a caller sees. The caller-visible surface is the **attributes**, and
those match. A positional members bag in Python would lose the per-field types and
per-parameter documentation for a constructor nobody calls. This client's
`CafayeProblemError` also carries a `content_type` the TypeScript one does not;
it is the field that distinguishes "a cafaye service said no" from "a proxy
handed me an error page that happened to be JSON", and `CafayeProtocolError`
already carries it in both clients.

## 6. The red proofs

Five, in `.red/`, reproducible with `./bin/red-proofs`. The method is the same
for all of them: patch one line, run one test, record the output, put the line
back, and **verify the restore by diffing** — a harness that leaves the tree
modified is worse than no harness, because the next reader cannot tell which
state the tree was in. `.red/01-import-red.txt` is the previous worker's genuine
red proof and is untouched.

**Auth precedence** — `.red/02-base-url-precedence.txt`, with
`(_present(explicit), SOURCE_ARGUMENT)` → `(None, SOURCE_ARGUMENT)`:

```
>       assert resolved.url == EXPLICIT
E       AssertionError: assert 'https://from....example.test' == 'https://expl....example.test'
E
E         - https://explicit.example.test
E         + https://from-env.example.test

1 failed in 0.03s
# pytest exit status: 1  (non-zero is the point: this is a red proof)
```

**The unknown problem type** — `.red/03-unknown-problem-type.txt`, with the
`or CafayeProblemError` replaced by `KeyError`, which is literally the failure
the brief names:

```
>       assert type(error) is CafayeProblemError
E       AssertionError: assert <class 'TypeError'> is CafayeProblemError
E       +  where <class 'TypeError'> = type(TypeError('KeyError() takes no keyword arguments'))

1 failed in 0.02s
```

The test stays red and the failure is *not a `CafayeError` at all*, which is the
whole point: the common handler in the README does not catch it.

**The credential leak** — `.red/04-credential-leak.txt`, with the redactor turned
into a pass-through (the "careful implementation" the module docstring argues
against — replace what you recognise, return the rest):

```
FAILED tests/test_credential_leak.py::TestTheErrorPaths::test_a_problem_detail_that_echoes_the_token
1 failed, 3 passed in 0.05s
```

**The word-boundary redactor bug** — `.red/05-redactor-word-boundary.txt`, with
`\bcafaye_` put back:

```
FAILED tests/test_redact.py::TestStructuralShapesAreRemovedWithoutTheClientKnowingThem::
  test_a_token_concatenated_onto_something_is_still_a_token[after-a-letter]
1 failed, 14 passed in 0.07s
```

**The path-parameter substitution** — `.red/06-path-parameter-substitution.txt`,
with `_resolve_path` bypassed:

```
FAILED tests/test_identity.py::TestTheRequestEachOperationMakes::
  test_a_path_parameter_is_substituted_and_never_reaches_the_body_or_query
1 failed in 0.04s
```

The last two are the ones worth keeping: a red proof for a bug that is *already
fixed* is the only evidence that the regression test covering it is the thing that
catches it, rather than a test that happens to pass.

## 7. The gate, the two tiers, and what the green means

`./bin/prime` is one named command: frozen install, `ruff format --check`,
`ruff check`, `mypy`, the test suite, and a coverage check that re-reads
`coverage.xml` and `fail_under` **independently** rather than trusting that
pytest was asked to enforce them.

It is bash, and that is load-bearing. `${PIPESTATUS[0]}` does not exist in zsh,
which is this machine's default shell, so a gate piped into `tail` exits 0 under
zsh no matter what the gate decided. That mistake has already produced one false
green in this fleet.

```console
$ bash -c './bin/prime 2>&1 | tail -5; echo "GATE EXIT (PIPESTATUS[0])=${PIPESTATUS[0]}"'
prime: unit tier GREEN (frozen install, format, lint, types, tests, coverage).
prime: env-gated tier NOT RUN (0 tests skipped as unavailable, 0 not requested).
    It needs a live cafaye deployment and a credential, so it is not part of
    the default gate. Run 'bin/prime --live' to demand it. It is never skipped
    silently: this line is in the output of every green run.
GATE EXIT (PIPESTATUS[0])=0
```

I also checked that it **fails** when it should, in both directions, because a
gate nobody has seen go red is not known to go red:

| what I did | exit |
| --- | --- |
| nothing | `0` |
| put the `\bcafaye_` bug back | `1` |
| `./bin/prime --live` with no deployment | `1`, with `$CAFAYE_LIVE_BASE_URL is not set` |

**The two tiers.** The unit tier needs no credential, no network and no
deployment, and it is the default. The env-gated tier (`bin/live`, `live/`) talks
to a real deployment and is **demanded, never skipped**: `--live` and the `live`
CI job both treat a missing credential as a **failure** with a sentence saying
why, and the CI job has deliberately no `continue-on-error` and no
`if: secrets.X != ''` guard. A live tier that quietly reported "0 tests ran, all
green" would be indistinguishable from one that genuinely found nothing wrong,
and the badge above both is the same green. The gate prints which tier did not
run on **every** invocation.

**The numbers, separately, as asked:**

| tier | result |
| --- | --- |
| unit (`bin/prime`) | **586 passed, 0 failed, 100.00% line and branch coverage** |
| env-gated (`bin/prime --live`) | **NOT RUN** — 0 passed, 0 failed, 5 collected, 0 skipped-as-unavailable |
| `leak`-marked subset | 60 passed |

## 8. Findings for the platform, not settled here

1. **Should a credential-carrying client default to a public SaaS host at all?**
   This client does, because its brief specifies a documented default and that
   default is `servers[0]` out of a committed document. `cafaye-ts` throws when
   nothing is configured, citing *"a guess about which deployment to send a
   customer's credentials to is the one kind of guess this package refuses to
   make."* Both keep the property that matters — nothing can resolve to a
   loopback address — and both expose which source answered. This is a platform
   question, recorded rather than answered.

2. **The two clients hold different vintages of identity's document.** This
   client reads the current `openapi/v1.yaml` (`e500262`) and has twenty
   operations. `cafaye-ts` holds vendored bytes from `35c2576` and has sixteen —
   the four `api-keys` routes and `introspectAPIKey` landed in `bff6333`.
   `cafaye-ts` re-vendoring is that repository's decision and not this one's to
   make. The obvious next packet is aligning them, and the operation table in
   `README.md` is where a reader would notice.

3. **The other five services are declared but not implemented.** `SERVICE_NAMES`
   and `DEFAULT_BASE_URLS` name all six so base-URL resolution is complete and
   `Cafaye(base_url=…).billing` raises rather than half-working, but only
   `identity` has operations. `test_client.py` asserts that the service-module
   list is exactly `["identity"]`, so the second one is a red test rather than a
   silent gap.

4. **A `# pragma: no cover` is a decision and needs a sentence.** There are three
   in the tree, each naming the invariant that makes its branch unreachable. A
   fourth would mean the rule is being used to hide rather than to record.

5. **`pantry` has `cafaye-py` as `blockedBy: planned` because the directory was
   not a repository.** This packet does not change that. **A second packet is
   needed to flip the row, and it cannot be flipped here** — it is a pantry
   change, pantry has its own gate, and I have not touched pantry.

## What I could not verify

Not an empty section, and ordered by how much it would cost to be wrong.

1. **The env-gated tier has never run. Zero of its five tests have ever been
   executed.** They type-check and they are the only tier that would catch
   identity changing a field name, and I have no way to know whether they pass.
   `live/test_live_contract.py` is written against the *documents*, so it is
   correct about shapes and untested about reality. **The first person with a
   deployment should expect it to need work.**

2. **Whether the credential-leak test catches a leak in a path neither face
   reaches.** It walks the client, the exceptions, the models, the redactor, the
   cause chain, the traceback, the log records, the client's own `repr`, and
   every model's. It does **not** walk `httpx`'s internals, so a credential that
   leaked inside httpx before this package saw the response is outside its
   reach.

3. **CI on Python 3.11, 3.12 and 3.13.** The matrix is declared; I only ever ran
   3.14.7. `mypy` analyses against `python_version = "3.11"` so a 3.12-only
   construct would be caught statically, but the *suite* has not run on 3.11.

4. **CI on Linux.** Everything was run on Darwin. Three platform-dependent things
   are covered by construction — the errno tables list both Darwin and Linux
   values, and the errno test uses a plain `Exception` with an `errno` attribute
   precisely so it does not depend on `OSError`'s subclass mapping, which differs
   — but the suite has not been run there.

5. **`uvx pip-audit` in the CI workflow has never been run.** I put it there
   because the alternative is a CI job with no dependency check at all, and an
   unrun step in a workflow is a claim. It may need a `--requirement` shape
   adjustment on first execution.

6. **The `.red/*.patch` files are not `git apply`-able as written.** They record
   the before/after as a labelled diff for a human, and `bin/red-proofs`
   reproduces each proof by direct string substitution, which is why it verifies
   exactly one occurrence before substituting. The header of each proof says
   "or edit the line as the comment says" for that reason.

7. **Nothing has been pushed.** The packet said the manager creates the remote
   and that I should not create an org repository. `git remote -v` is empty, so
   the tree is on `rescue/cafaye-py-01-partial` with eight commits and no
   upstream. The first push has to be
   `git push -u git@github.com:cafaye/cafaye-py.git rescue/cafaye-py-01-partial:worker/cafaye-py-01`,
   which is not a force-push and is a first publication rather than a rewrite. It
   has not been done here, and the branch is therefore unpublished.

8. **`version = "0.1.0"` in `pyproject.toml` and the `0.1.0` entry in
   `CHANGELOG.md` are unbuilt and untagged.** The changelog is written in the past
   tense and dated today, which is a claim about a release that does not exist
   yet. If the fleet's convention is to date a changelog entry at tag time rather
   than at merge time, that line is wrong and should be moved to `[Unreleased]`.

9. **I could not measure whether the six defects I fixed were the *only* latent
   ones.** Nine of twenty operations were sending requests to a URL that does not
   exist, and that was invisible to 148 passing tests. A mock transport answers
   any URL, and this suite uses only mock transports. The two things I would want
   before trusting that number are the live tier (§8.1) and one run against a
   real deployment of the credential attachment.

## The push

Not done, per the packet: the manager creates the remote, and I should not push
until the gate is green. The gate is green and has been verified green **and**
verified red. The push command is in §8.7 and is a first publication, not a
force-push.
