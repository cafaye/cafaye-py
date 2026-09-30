# REPORT-cafaye-py-10-gate — declaring the gate, so `bin/prime` means something here

`worker/cafaye-py-10-gate`, on `3908488`. One repository's `gate.yml`, against
`cafaye/core`'s `schemas/gate.schema.json`, plus the defect the measurement found.

**Not pushed.** Committed on the worker branch for the manager.

---

## 1. What was wrong, before anything was declared

The packet's premise is that `bin/prime` exists here and nothing says what it is
worth. Measuring it turned up something the packet did not predict: **the one
gate spelling this repository advertised did not work.**

```console
$ mise tasks
gate       The gate: format, lint, typecheck, the full test suite, the coverage check
test       The test suite with coverage, no gate
typecheck  mypy over the package and the tests

$ mise run gate
[gate] $ ./bin/gate
sh: ./bin/gate: No such file or directory
[gate] ERROR task failed

$ mise run prime
mise ERROR ...   # no such task
```

`mise.toml`'s `[tasks.gate]` read `run = "./bin/gate"`. There is no `bin/gate`
in this repository — `bin/` holds `check-coverage`, `live`, `prime` and
`red-proofs`, and it has held those four since 0.1.0.

So the position was:

| | before this packet |
|---|---|
| `README.md`, `AGENTS.md`, `CHANGELOG.md` | `./bin/prime` — correct |
| CI's `unit` job | `./bin/prime` — correct |
| `mise.toml`'s only gate task | `./bin/gate` — **a file that does not exist** |
| the fleet's spelling, `mise run prime` | **no such task** |

A developer who read the README ran the right command. A developer who ran
`mise tasks`, or who read the header of the file you run `mise install` next to,
got a dead command. `core`'s own `gate.yml` names this exact defect class — "in
the newest repository — a task named `gate` whose `run` string names a file that
does not exist" — which is a fair description of what was here.

**Fixed in `mise.toml`, two lines.** `[tasks.prime]` and `[tasks.gate]` both run
`./bin/prime` and nothing else. `mise run prime` is the fleet's spelling and is
new here; `mise run gate` is kept as an alias, on `core`'s own precedent — "one
gate under two names is not two gates" — because a repository that renamed its
task without keeping the old spelling breaks every muscle memory and every doc
that names it.

I fixed it rather than declaring around it. The alternative was to write a
`gate.yml` that names no mise task, take `gate.task-undeclared`, and put a dead
command in the report. That would have been accurate and useless: the packet's
subject is what `bin/prime` means, and a declaration that cannot mention the one
tool developers use to find commands does not answer it.

### The second difference, recorded and not resolved

CI's `live` job runs `./bin/live`. **Nothing in CI runs `./bin/prime --live`.**
Both reach the same file — `bin/prime --live` calls `bin/live` at the end — but
the composition is only ever exercised by hand.

This is a real gap and it is in `gate.yml` and in the CHANGELOG rather than
smoothed over. It is also not a false green: `bin/live` exits **1** with a
sentence naming the missing variable rather than exiting 0 having run nothing, so
the `live` job's green means the tier ran. The fix is one word in the workflow
(`./bin/prime --live` for `./bin/live`), and which side should move is a
manager's call, so I have not moved it.

---

## 2. The declaration

`gate.yml`, seven proofs over the gate's own output. Full reasoning is in the
file; the shape:

| id | matches | floor |
|---|---|---|
| `frozen-install` | `^==> uv sync --frozen` | — |
| `type-check` | `^Success: no issues found` | — |
| `coverage-gate` | `^    fail_under = 100   actual = 100\.00%   ok$` | — |
| `suite` | `^=+ ([0-9]+) passed` | **580** |
| `no-skip` | `^=+ (?!.*skipped)([0-9]+) passed` | **586** |
| `unit-tier-green` | `^prime: unit tier GREEN` | — |
| `env-tier-not-run` | `^prime: env-gated tier NOT RUN \(0 tests skipped as unavailable, 0 not requested\)\.$` | — |

`command: [bin/prime]`, `miseTask: prime`, `entrypoint: bin/prime`,
`timeoutSeconds: 1800`, `external.selfContained: false` with a toolchain
requirement and a network requirement, `ci.workflow:
.github/workflows/ci.yml`, `ci.invokes: [bin/prime]`.

**On the two floors.** `suite` is six below the measured 586 so adding a test
needs no edit; `no-skip` is 586 **exactly**, because cafaye-py's unit tier has no
`skipif`, no `importorskip` and no environment variable anywhere under `tests/` —
so 586 is the whole suite and 585 means one test did not run. The overlap is
deliberate and `gate.yml` says so: whenever a run skips, `no-skip` subsumes
`suite`, and that is what makes a skip a red rather than a decrement.

**On `bin/prime` rather than `mise run prime` as the command.** Measured, not
taste. Both run the same file, but `./bin/prime` is what the README, AGENTS.md
and CI all say, and CI installs uv with `astral-sh/setup-uv@v5` rather than mise
— so declaring `mise` would describe a gate this repository's own CI does not
run. `miseTask` is declared alongside and cross-checked against the entrypoint,
which is the division the format is for.

---

## 3. The suite, measured, counts reported separately

From a real run of `./bin/prime` on this worktree:

| | |
|---|---|
| **PASSED** | **586** |
| **FAILED** | **0** |
| **SKIPPED** | **0** |
| **XFAILED / XPASSED** | **0** |
| **ERRORS** | **0** |
| coverage | 100.00% line **and** branch, `fail_under = 100` |
| mypy | clean, 22 source files, strict + `--warn-unreachable` |
| ruff | 25 files formatted, `ruff check` clean |
| wall clock | 58s from an empty `.venv`; 13s warm |

`586 collected / 586 passed / 0 skipped`, by file:

```
 22  tests/test_base_url.py          63  tests/test_credential_leak.py
 88  tests/test_branches.py          27  tests/test_credentials.py
120  tests/test_client.py            69  tests/test_errors.py
 93  tests/test_identity.py          52  tests/test_models.py
 52  tests/test_redact.py                    -------------------------
                                        586
```

### The tier that did not run, and the variables that gate it

**The env-gated tier has never been run and was not run by this packet.** It has
never been run, full stop — `REPORT-cafaye-py-01.md` says so in its first line,
and nothing in this packet changed that.

Two environment variables gate it, and both must be set or the tier **fails**:

- **`CAFAYE_LIVE_BASE_URL`** — a cafaye identity deployment.
- **`CAFAYE_LIVE_TOKEN`** — a scoped, short-lived credential. Read-only scopes
  are enough; nothing in `live/` creates or destroys anything.

Verified here, and it is a failure rather than a skip:

```console
$ ./bin/live
live: $CAFAYE_LIVE_BASE_URL is not set, so the env-gated tier cannot run.
live: this is a failure and not a skip. Run 'bin/prime --live' only when
live: a deployment and a scoped credential are actually available, or the
live: green badge above this line is a claim about a tier nobody checked.
$ echo $?
1
```

`live/test_live_contract.py` holds **5 tests** (4 in
`TestTheDocumentStillSaysWhatTheClientExpects`, 1 in
`TestBothFacesReachTheSameDeployment`). Collecting them without the environment
raises at import time, by design, with a message that says so — measured:

```
live/test_live_contract.py:79: RuntimeError: The env-gated tier was demanded
and it cannot run: $CAFAYE_LIVE_BASE_URL and $CAFAYE_LIVE_TOKEN are not both set.
```

So: **0 of 5 env-gated tests executed. 586 of 586 unit-tier tests executed.**
No network socket was opened to anything but the mock transport, and no
credential of any kind was present, requested, printed or logged during this
packet — the gate log written by `--prove` is the only artefact, and it contains
`env-gated tier NOT RUN`, which is the line saying the tier did not run.

---

## 4. Proven red, five times

A gate that has never been observed red is not a gate. Every case below was run
against `gate-check --prove` on this worktree, and **every one ended with the
tree byte-identical to how it was found** — verified with `git status
--porcelain` and `diff`, not asserted.

| # | what was broken | what the checker said | exit |
|---|---|---|---|
| 1 | `bin/prime` replaced by a stub whose body is `exit 0` | **7 ×** `gate.proof-missing` | 1 |
| 2 | `gate.command` → `[bin/prime, --fast]`, nothing broken | **6 ×** `gate.proof-missing` | 1 |
| 3 | one test made to skip | `gate.proof-missing` on `no-skip` **alone** | 1 |
| 4 | `no-skip` floor 586 → 587, suite unchanged | `gate.floor: proof 'no-skip' reported 586 and the declaration's floor is 587` | 1 |
| 5 | one test made to fail | `gate.nonzero` + 5 × `gate.proof-missing` | 1 |

**Case 1 is the packet's own scenario, run literally.** A checker replaced by a
function that unconditionally exits 0 produced seven failures — every proof in
the file vanished. Before this declaration existed it would have produced none.
That is the whole argument for the file, measured rather than asserted.

**Case 3 is the one that earned its keep.** The gate printed:

```
======================== 585 passed, 1 skipped in 3.15s =========================
    fail_under = 100   actual = 100.00%   ok
prime: unit tier GREEN (frozen install, format, lint, types, tests, coverage).
```

and **exited 0.** Coverage was unaffected, because the skip was one case of a
parametrised test whose lines its four siblings still covered. `suite` passed at
585 against its floor of 580. The single finding was `gate.proof-missing` on
`no-skip`. A green badge over a suite that is quietly one test smaller, caught by
the one proof written to catch it.

**Case 5 corrected a claim I had reasoned about rather than measured.** I had
written into `gate.yml` that a failing run's summary line cannot match
`^=+ ([0-9]+) passed`, on the grounds that `-x` is in `addopts` so the line reads
`1 failed, N passed` and the digits are followed by ` failed`. The measurement
agrees — the line is `======== 1 failed, 586 passed in 5.62s ========` — but the
declaration now carries the measurement, and the reasoning is gone.

**Case 4 is a sensitivity test, not a broken build,** and it is labelled that way
in `gate.yml`: the suite was untouched and green; the declaration's floor was
raised by one and the checker named the exact shortfall. The ratchet is read.

### What was not done to any of them

No assertion was weakened, no skip marker added, no sleep introduced, no retry
count raised, no threshold lowered. Case 3 took one test out of the run and case
5 added one that fails; neither touched the suite's own assertions. The only
number changed in any file this packet was `minimum`, in case 4, and it was
raised.

One note for whoever picks this up: the first attempt at case 5 used
`assert 1 == 2`, which the gate itself rejected — `PLR0133` from ruff and
`comparison-overlap` from mypy, before pytest ran at all. That is the gate
working, not the gate being difficult. The file had to be named `test_*.py` as
well or pytest never collected it, and that first attempt reported a green
`586 passed` while silently running nothing new. Both are recorded here because
they are the kind of thing that gets reported as a working proof.

---

## 5. Checker results

```
$ ../core/harness/bin/gate-check .            # static
OK  …: 0 failure(s), 1 warning(s)

$ ../core/harness/bin/gate-check --prove .    # runs the gate
OK  …: 0 failure(s), 1 warning(s)
```

**The one warning is expected and is the correct behaviour.**
`gate.requirement-unproven` on the `mise` requirement: the checker refuses to run
`mise install` to find out whether a toolchain is present, because an answer that
depended on what happened to be on PATH would be red on a laptop and green on CI.
It is reported and never acted on. The other requirement is satisfied by
`bin/prime`, a repository-relative path, which the checker *can* resolve and did.

`gate.yml` parses under PyYAML as well as core's restricted reader — checked,
because a plain YAML scalar may not contain `": "` and a document core accepts
while every other parser refuses is a document with two dialects.

---

## 6. Files

| file | |
|---|---|
| `gate.yml` | **new.** The declaration, its measured provenance, and the five red proofs. |
| `mise.toml` | **fixed.** `[tasks.gate]` pointed at a file that does not exist; `[tasks.prime]` added. |
| `README.md` | a "It is declared, not discovered" section under *The gate*. |
| `AGENTS.md` | *THE GATE IS ONE COMMAND* now says declared, and says what not to undo. |
| `CHANGELOG.md` | Added / Fixed / Known gaps under `[Unreleased]`. |

Nothing under `src/`, `tests/` or `live/` was modified. Nothing in `core` was
touched. The gate was run 9 times and every run is recorded above.

---

## 7. Open for the manager

1. **`./bin/live` vs `./bin/prime --live` in CI.** A one-word change either way.
   Recorded, not decided.
2. **cafaye-py has no drift guard against `cafaye/core`.** Unlike `muse`, it
   vendors none of core's schemas, so there is no `../core` requirement to
   declare and nothing here would notice core changing a convention this client
   documents in a comment. It is the only artefact in the fleet with that
   property. The fix is a design decision, not a declaration, so I have not
   started it.
3. **`bin/gate-self-test`.** courier and darkroom ship one that breaks the
   declaration N ways and asserts core's checker catches each. The five red
   proofs above are reproducible only from this report. Shipping a self-test is a
   second gate and belongs in its own packet — core's `AGENTS.md` is explicit
   that it must be a CI step of its own, not part of `bin/prime`.
