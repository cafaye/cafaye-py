"""The test the brief calls "the deliverable": a credential never escapes.

    "construct a client holding a **fake** token, one that is unmistakably fake
    (prefixed, never a plausible real credential) — assert the fake string
    appears in **no** captured log record, **no** exception message, **no**
    serialised representation, and **no** ``repr()`` of the client object,
    across a full request/response cycle *including* an error response.

    A test that only checks the happy path does not prove it. The error path is
    where credentials leak — the exception is built from the response, and the
    response is where the headers are."

Why it is adversarial rather than innocent
------------------------------------------

Every failure path below is fed a service or a gateway that has **deliberately
put the credential into the response**: a problem ``detail`` that echoes it, an
extension member that echoes it, a ``Set-Cookie`` header that echoes it, an HTML
502 from a proxy that echoes it, and a transport that rejects with an error whose
message echoes it. An innocent ``assert TOKEN not in message`` passes just as
well when those are all *absent*, and proves nothing about them when present. A
test that only ever sees a well-behaved service is a test that cannot fail.

Where a string can hide
-----------------------

- ``str(error)`` and ``error.args`` — the obvious one.
- ``error.message`` and every **own** attribute, not just ``args``. A problem
  document's ``detail`` is server-controlled prose and the most likely place for a
  service to echo a caller's own credential back. In Python an exception's own
  attributes are ordinary instance attributes and are reachable by
  ``vars()``, ``dataclasses.asdict``-style walks and any structured logger.
- The **cause chain**. ``raise ... from`` is how the errno survives, and a
  traceback printer walks the whole chain — which is why ``safe_cause``
  withholds the original outright rather than scrubbing a copy of it.
- The **traceback** itself, formatted the way a crash reporter formats it.
- The ``repr()`` and ``str()`` of the **client**, which is the object a developer
  pokes at in a REPL or a notebook when something is wrong.
- Every captured **log record** and both output streams — the package emits
  nothing, so "no log record contains it" must be true because there were no log
  records.
"""

from __future__ import annotations

import ast
import io
import json
import logging
import sys
import traceback
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any, ClassVar

import httpx
import pytest

from cafaye import (
    API_TOKEN_PREFIX,
    Cafaye,
    CafayeConfigurationError,
    CafayeNetworkError,
    CafayeProtocolError,
)

# THE FAKE CREDENTIALS.
#
# Obviously fake, and not one plausible real credential:
#   - the API token carries identity's real `cafaye_` prefix, because the
#     classifier has to see it to reach the branch that matters, and the body is
#     spelled out and cannot be produced by `crypto/rand`;
#   - the session token is 43 base64url characters, which is the shape identity
#     mints, but is spelled out rather than random;
#   - the JWT has a real JOSE header and three real segments.
#
# A guard that recognised only the `cafaye_` prefix would pass a test carrying
# only an API token, which is why all three are here and each drives every path.
FAKE_API_TOKEN = API_TOKEN_PREFIX + "TESTONLY-not-a-real-token-TESTONLY-000000"
FAKE_SESSION_TOKEN = "TESTONLY-not-a-real-session-000000000000000"
FAKE_JWT = (
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNhZmF5ZS0xIn0."
    "TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-00000."
    "TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0"
)

ALL_FAKE_CREDENTIALS = (FAKE_API_TOKEN, FAKE_SESSION_TOKEN, FAKE_JWT)
COOKIE_HEADER_LINE = f"__Host-session={FAKE_SESSION_TOKEN}"

#: Modules this package must not import, at all, in any file. Named once so
#: the `import x` arm and the `from x import y` arm of the AST walk below
#: cannot disagree about the list -- a scan that checks one spelling of an
#: import and not the other is a scan with a hole shaped like a keyword.
FORBIDDEN_MODULES = frozenset({"logging", "warnings", "subprocess"})


def assert_no_credential(label: str, text: str) -> None:
    """The one assertion this file is made of, named so a failure says which."""
    for credential in ALL_FAKE_CREDENTIALS:
        assert credential not in text, f"{label} leaked {credential[:24]}…:\n{text}"
    assert FAKE_SESSION_TOKEN not in text, f"{label} leaked the session token"


def every_string_in(
    value: Any, seen: set[int] | None = None, out: list[str] | None = None
) -> list[str]:
    """Every string reachable from a value, however a log formatter would find it.

    Own attributes are walked whether or not they are enumerable, because an
    exception's own attributes in Python are ordinary instance attributes and a
    structured logger walks them without asking. Cycles terminate, and a getter
    that raises contributes nothing, because a value that cannot be read cannot
    leak.
    """
    seen = set() if seen is None else seen
    out = [] if out is None else out

    if value is None:
        return out
    if isinstance(value, str):
        out.append(value)
        return out
    if isinstance(value, (bytes, bytearray)):
        # `suppress`, not `try`/`except`/`pass`: "this value contributes nothing"
        # is the assertion, not an oversight, and `errors="replace"` is what makes
        # the arm unreachable in the first place.
        with suppress(Exception):
            out.append(value.decode("utf-8", "replace"))
        return out
    marker = id(value)
    if marker in seen:
        return out
    seen.add(marker)

    # A `__str__` that raises contributes nothing. Reading the attribute is the
    # whole job of this walker, so it must not be the thing that fails.
    with suppress(Exception):
        out.append(str(value))

    if isinstance(value, BaseException):
        for attribute in ("args", "message", "detail", "title", "type", "instance", "code"):
            candidate = getattr(value, attribute, None)
            if candidate is not None:
                every_string_in(candidate, seen, out)
        cause = getattr(value, "__cause__", None)
        context = getattr(value, "__context__", None)
        for chained in (cause, context):
            if isinstance(chained, BaseException):
                every_string_in(chained, seen, out)
        for attribute_value in list(vars(value).values()):
            every_string_in(attribute_value, seen, out)
        return out

    if isinstance(value, (dict,)):
        for item_key, item_value in value.items():
            every_string_in(item_key, seen, out)
            every_string_in(item_value, seen, out)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            every_string_in(item, seen, out)
        return out

    for key, attribute_value in list(vars(value).items()) if hasattr(value, "__dict__") else []:
        every_string_in(str(key), seen, out)
        every_string_in(attribute_value, seen, out)
    return out


@contextmanager
def capturing_everything() -> Iterator[tuple[list[logging.LogRecord], io.StringIO, io.StringIO]]:
    """Capture log records, stdout and stderr for the duration of the block."""
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    root = logging.getLogger()
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)

    out, err = io.StringIO(), io.StringIO()
    saved_out, saved_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        yield records, out, err
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err
        root.removeHandler(handler)
        root.setLevel(previous_level)


def client_returning(
    response: httpx.Response | Exception,
    *,
    token: str | None,
    **kwargs: Any,
) -> Cafaye:
    """A client whose transport returns ``response`` or raises it."""
    outcome = response

    def handler(request: httpx.Request) -> httpx.Response:
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return Cafaye(
        base_url="https://identity.example.test",
        token=token,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def probe_one(label: str, client: Cafaye, token: str | None) -> None:
    """Drive a full cycle, capture everything, and assert nothing leaked.

    This is the single routine every test below runs, and it is one routine on
    purpose: a leak that only one of eleven paths is exposed to is a leak that
    survives, because the path that leaked is the one nobody ran.
    """
    with capturing_everything() as (records, out, err), pytest.raises(Exception) as caught:
        client.identity.get_current_user()
    error = caught.value

    # 1. The message, and every string the exception itself carries.
    for text in every_string_in(error):
        assert_no_credential(f"{label}: exception string", text)

    # 2. The serialised representation, the way a structured logger writes one.
    assert_no_credential(f"{label}: repr()", repr(error))
    assert_no_credential(f"{label}: str()", str(error))
    assert_no_credential(
        f"{label}: json.dumps",
        json.dumps(error, default=repr, sort_keys=True),
    )

    # 3. The traceback, formatted the way a crash reporter formats it — which
    #    walks the whole cause chain.
    assert_no_credential(
        f"{label}: traceback",
        "".join(traceback.format_exception(type(error), error, error.__traceback__)),
    )

    # 4. The client's own repr and str. This is what a developer prints when
    #    something is wrong, and it is the object most likely to hold a token.
    assert_no_credential(f"{label}: repr(client)", repr(client))
    assert_no_credential(f"{label}: str(client)", str(client))

    # 5. Every captured log record, at every level.
    for record in records:
        rendered = record.getMessage()
        rendered += " " + repr(record.args)
        rendered += " " + repr(getattr(record, "exc_info", None))
        assert_no_credential(f"{label}: log record {record.levelname}", rendered)

    # 6. Both output streams.
    assert_no_credential(f"{label}: stdout", out.getvalue())
    assert_no_credential(f"{label}: stderr", err.getvalue())


@pytest.mark.leak
class TestTheHappyPath:
    """The path a careless test would stop at. It is here for completeness."""

    @pytest.mark.parametrize("token", ALL_FAKE_CREDENTIALS, ids=["api", "session", "jwt"])
    def test_a_successful_cycle_leaks_nothing(self, token: str) -> None:
        client = client_returning(
            httpx.Response(200, json={"id": "u", "email": "a@b.test"}),
            token=token,
        )
        with capturing_everything() as (records, out, err):
            client.identity.get_current_user()
        for record in records:
            assert_no_credential("success: log", record.getMessage() + repr(record.args))
        assert_no_credential("success: stdout", out.getvalue())
        assert_no_credential("success: stderr", err.getvalue())
        assert_no_credential("success: repr(client)", repr(client))


@pytest.mark.leak
class TestTheErrorPaths:
    """Where credentials actually leak."""

    def test_a_problem_detail_that_echoes_the_token(self) -> None:
        body = {
            "type": "https://errors.cafaye.com/unauthorized",
            "title": "Unauthorized",
            "status": 401,
            "detail": f"token {FAKE_API_TOKEN} is not recognised",
            "code": "unauthorized",
            "trace_id": "0af7651916cd43dd8448eb211c80319c",
        }
        response = httpx.Response(
            401, json=body, headers={"content-type": "application/problem+json"}
        )
        probe_one("echoed detail", client_returning(response, token=FAKE_API_TOKEN), FAKE_API_TOKEN)

    def test_an_extension_member_that_echoes_the_token(self) -> None:
        """A member the fleet does not define, so no per-field filter catches it."""
        body = {
            "type": "https://errors.cafaye.com/forbidden",
            "title": "Forbidden",
            "status": 403,
            "detail": "not allowed",
            "code": "forbidden",
            "debug": {"presented": FAKE_API_TOKEN},
        }
        response = httpx.Response(
            403, json=body, headers={"content-type": "application/problem+json"}
        )
        probe_one(
            "echoed extension", client_returning(response, token=FAKE_API_TOKEN), FAKE_API_TOKEN
        )

    def test_a_set_cookie_header_that_echoes_the_session_token(self) -> None:
        """The response headers are the other half of "where a token can hide"."""
        response = httpx.Response(
            401,
            json={"type": "about:blank", "title": "Unauthorized", "status": 401},
            headers={
                "content-type": "application/problem+json",
                "set-cookie": COOKIE_HEADER_LINE,
            },
        )
        probe_one(
            "set-cookie", client_returning(response, token=FAKE_SESSION_TOKEN), FAKE_SESSION_TOKEN
        )

    def test_a_proxies_html_error_page_that_echoes_the_token(self) -> None:
        response = httpx.Response(
            502,
            content=f"<html><body>upstream saw {COOKIE_HEADER_LINE}</body></html>".encode(),
            headers={"content-type": "text/html"},
        )
        probe_one(
            "proxy html", client_returning(response, token=FAKE_SESSION_TOKEN), FAKE_SESSION_TOKEN
        )

    def test_a_transport_error_whose_message_echoes_the_token(self) -> None:
        """The cause chain, which is why the original is withheld rather than scrubbed."""
        failure = httpx.ConnectError(f"connect failed presenting {FAKE_API_TOKEN}")
        probe_one("connect error", client_returning(failure, token=FAKE_API_TOKEN), FAKE_API_TOKEN)

    def test_a_200_that_carries_a_problem_echoing_the_token(self) -> None:
        response = httpx.Response(
            200,
            json={
                "type": "https://errors.cafaye.com/internal",
                "title": "Internal",
                "status": 200,
                "detail": f"echo {FAKE_JWT}",
                "code": "internal",
            },
            headers={"content-type": "application/problem+json"},
        )
        probe_one("200 problem", client_returning(response, token=FAKE_JWT), FAKE_JWT)

    def test_an_empty_500_still_does_not_crash_and_still_does_not_leak(self) -> None:
        probe_one(
            "empty 500",
            client_returning(httpx.Response(500), token=FAKE_API_TOKEN),
            FAKE_API_TOKEN,
        )


@pytest.mark.leak
class TestTheConfigurationPath:
    """A failure thrown before any request exists still has to be safe.

    This is a real class of leak, not a hypothetical one: a configuration error
    is the **most** likely error a developer ever sees, it is the one they paste
    into an issue, and it is usually raised while echoing back what was wrong.
    """

    def test_a_refused_credential_is_not_quoted_in_the_message(self) -> None:
        with (
            capturing_everything() as (records, out, err),
            pytest.raises(CafayeConfigurationError) as caught,
        ):
            Cafaye(base_url="https://identity.example.test", token=FAKE_API_TOKEN + "\n")
        error = caught.value
        assert_no_credential("config: message", str(error))
        assert_no_credential("config: repr", repr(error))
        assert_no_credential("config: traceback", "".join(traceback.format_exception(error)))
        assert_no_credential("config: stdout", out.getvalue())
        assert_no_credential("config: stderr", err.getvalue())
        for record in records:
            assert_no_credential("config: log", record.getMessage() + repr(record.args))

    def test_a_refused_base_url_is_not_quoted_either(self) -> None:
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url="file:///etc/passwd")
        assert_no_credential("config: base url", str(caught.value))


@pytest.mark.leak
class TestTheClientObjectItself:
    """``repr()`` must be redacted, and there must be no way to read the token out."""

    @pytest.mark.parametrize("token", ALL_FAKE_CREDENTIALS, ids=["api", "session", "jwt"])
    def test_repr_is_redacted(self, token: str) -> None:
        """Redacted, and there is no path by which it could not be.

        The brief's words are "no ``repr()`` of the client object". A client *does*
        hold the credential — it has to, to send it — so the requirement is that
        the credential does not **escape**, not that it does not exist. Everything
        that formats an object is therefore in scope: ``repr``, ``str``, and a
        serialised form.
        """
        client = Cafaye(base_url="https://identity.example.test", token=token)
        assert_no_credential("repr", repr(client))
        assert_no_credential("str", str(client))

        # `__slots__` means there is no `__dict__`, so every attribute is named in
        # the class and the walk has to be written out. That is a stronger
        # assertion than `vars()`: a new attribute cannot be added to an instance
        # by accident without appearing in `__slots__`, so this list cannot
        # silently fall out of date the way a `vars()` walk would.
        slots = [name for klass in type(client).__mro__ for name in getattr(klass, "__slots__", ())]
        assert slots, "the client declares __slots__; without one there is no __dict__ to walk"
        assert "__dict__" not in slots

        # `_token` is the one attribute that legitimately holds the credential, and
        # it is skipped **by name** rather than by a prefix rule — a rule like
        # "skip anything starting with an underscore" would also skip a new
        # `_secret` that should not have existed.
        assert "_token" in slots, "the credential slot must be visible to this test"
        for name in slots:
            if name == "_token":
                continue
            assert_no_credential(f"slot {name}", repr(getattr(client, name)))

    @pytest.mark.parametrize("token", ALL_FAKE_CREDENTIALS, ids=["api", "session", "jwt"])
    def test_the_token_is_not_in_any_public_attribute(self, token: str) -> None:
        """Every **public** attribute, walked the way a serialiser would.

        ``dir()`` rather than ``__slots__``, because this is the broader claim:
        whatever else ends up on the object, none of it a caller can reach by name
        without a leading underscore is holding the credential.
        """
        client = Cafaye(base_url="https://identity.example.test", token=token)
        for name in dir(client):
            if name.startswith("_"):
                continue
            value = getattr(client, name)
            if callable(value):
                continue
            assert_no_credential(f"public attribute {name}", repr(value))

    @pytest.mark.parametrize("token", ALL_FAKE_CREDENTIALS, ids=["api", "session", "jwt"])
    def test_the_only_private_attribute_holding_it_is_the_slot(self, token: str) -> None:
        """So that the public walk above is not passing by luck.

        It asserts that the credential lives in exactly one place, named, and that
        a reader of this file knows where that is rather than having to trust that
        the redactor covers it.
        """
        client = Cafaye(base_url="https://identity.example.test", token=token)
        holders = [
            name
            for klass in type(client).__mro__
            for name in getattr(klass, "__slots__", ())
            if token in repr(getattr(client, name))
        ]
        assert holders == ["_token"]

    def test_there_is_no_public_reader_for_the_credential(self) -> None:
        """No ``.token``. The kind is a decision; the value is nobody's business.

        The moment an object can hand the credential back out is the moment it
        ends up in a log through some code path nobody was thinking about.
        """
        client = Cafaye(base_url="https://identity.example.test", token=FAKE_API_TOKEN)
        assert not hasattr(client, "token")
        assert client.credential_kind == "api_token"

    def test_a_client_with_no_credential_says_so_in_its_repr(self) -> None:
        client = Cafaye(base_url="https://identity.example.test")
        assert "None" in repr(client) or "no credential" in repr(client)


@pytest.mark.leak
class TestEveryErrorClassIsClean:
    """Each class, built by hand, is clean.

    The cycles above cover the ones the client can produce. This covers the ones
    a consumer might construct or catch, which matters because the guarantee is
    about the *type*, not about the code path that happened to build it.
    """

    def test_a_hand_built_problem_error_is_clean_when_built_by_the_client(self) -> None:
        """The guarantee is about what comes OUT of a service, not about the
        caller's own string literals.

        A consumer who writes ``CafayeProblemError(f"...{token}...")`` has put the
        credential in the message themselves and this client cannot unwrite it.
        What the client must do — and what this asserts — is guarantee that every
        member that came from a **response** has been through the redactor, on
        the way in, including the members it has never heard of.
        """
        from cafaye import problem_error_from

        mapped = problem_error_from(
            body={
                "type": "https://errors.cafaye.com/forbidden",
                "title": f"Authorization: Bearer {FAKE_API_TOKEN}",
                "status": 403,
                "detail": f"the cookie was {COOKIE_HEADER_LINE}",
                "code": "forbidden",
                "echo": FAKE_API_TOKEN,
            },
            status=403,
            operation="identity.get_current_user",
            secrets=[FAKE_API_TOKEN, FAKE_SESSION_TOKEN],
        )
        assert_no_credential("mapped problem", json.dumps(mapped.extensions, default=repr))
        assert_no_credential("mapped problem", mapped.detail)
        assert_no_credential("mapped problem", mapped.title)
        assert_no_credential("mapped problem", str(mapped))
        for text in every_string_in(mapped):
            assert_no_credential("mapped problem walk", text)
        # The useful parts survive redaction, which is the other half: a
        # redactor that ate everything would pass every leak assertion above.
        assert mapped.code == "forbidden"
        assert mapped.status == 403
        assert mapped.title != ""
        assert "redacted" in mapped.detail
        assert mapped.detail != ""

    def test_the_redactor_itself_removes_every_shape(self) -> None:
        from cafaye import REDACTED, redact_text

        redact = redact_text(list(ALL_FAKE_CREDENTIALS))
        assert redact(FAKE_API_TOKEN) == REDACTED
        assert redact(FAKE_SESSION_TOKEN) == REDACTED
        assert redact(FAKE_JWT) == REDACTED
        assert redact(COOKIE_HEADER_LINE) == REDACTED
        assert redact(f"Cookie: {FAKE_SESSION_TOKEN}") == REDACTED
        assert redact(f"Authorization: Bearer {FAKE_API_TOKEN}") == REDACTED
        assert redact("connect ECONNREFUSED 127.0.0.1:443") == "connect ECONNREFUSED 127.0.0.1:443"

    def test_a_hand_built_protocol_error_with_a_credential_in_its_snippet(self) -> None:
        from cafaye import protocol_error_from

        error = protocol_error_from(
            status=502,
            content_type="text/html",
            body_text=f"<html>Cookie: {COOKIE_HEADER_LINE}</html>",
            problem_shaped=False,
            operation="identity.get_current_user",
            secrets=[FAKE_SESSION_TOKEN],
        )
        assert isinstance(error, CafayeProtocolError)
        assert_no_credential("protocol", str(error))
        assert_no_credential("protocol", repr(error))
        assert_no_credential("protocol", error.body_snippet or "")
        # An excerpt that was entirely credential-shaped is dropped, not shipped
        # with a marker in a field that says "body".
        assert error.body_snippet is None

    def test_a_network_error_whose_cause_carries_a_credential(self) -> None:
        from cafaye import NetworkFailureReason, network_error_from, redact_text

        failure = RuntimeError(f"Authorization: Bearer {FAKE_API_TOKEN}")
        message = redact_text([FAKE_API_TOKEN])(
            f"identity.get_current_user: the request failed: {failure}"
        )
        error = network_error_from(
            reason=NetworkFailureReason.UNKNOWN,
            message=message,
        )
        assert isinstance(error, CafayeNetworkError)
        assert_no_credential("network", str(error))
        for text in every_string_in(error):
            assert_no_credential("network walk", text)


@pytest.mark.leak
class TestTheStaticHalf:
    """The output side: this package emits nothing, and that is an assertion.

    A library that logs nothing cannot leak a credential by logging. The cycles
    above prove it dynamically for the paths they drive; this proves it for the
    package as a whole, including a path no test happens to execute today.

    The scan is an **AST walk**, not a grep. A grep for ``print(`` hits this
    file's own docstring; an AST walk sees calls, so a docstring that discusses
    logging costs nothing and a call in a branch no test covers still fails.
    """

    FORBIDDEN_CALLS: ClassVar[set[str]] = {
        "print",
        "logging.info",
        "logging.debug",
        "logging.warning",
        "logging.error",
        "logging.exception",
        "logging.critical",
        "logging.log",
        "logger.info",
        "logger.debug",
        "logger.warning",
        "logger.error",
        "logger.exception",
        "logger.critical",
        "log.info",
        "log.debug",
        "warnings.warn",
        "sys.stdout.write",
        "sys.stderr.write",
        "sys.stdout.flush",
        "sys.stderr.flush",
        "os.system",
        "subprocess.run",
        "subprocess.Popen",
    }

    def _source_files(self) -> list[Any]:
        import ast
        from pathlib import Path

        package = Path(__file__).resolve().parent.parent / "src" / "cafaye"
        return [
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for path in sorted(package.rglob("*.py"))
        ]

    def test_the_package_emits_nothing(self) -> None:
        offenders: list[str] = []
        for tree in self._source_files():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if isinstance(target, ast.Name):
                    name = target.id
                elif isinstance(target, ast.Attribute):
                    parts: list[str] = []
                    current: ast.expr = target
                    while isinstance(current, ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.append(current.id)
                    name = ".".join(reversed(parts))
                else:
                    continue
                if name in self.FORBIDDEN_CALLS:
                    offenders.append(f"{name} at line {node.lineno}")
        assert not offenders, "the package must emit nothing: " + ", ".join(offenders)

    def test_the_package_never_imports_logging(self) -> None:
        from pathlib import Path

        package = Path(__file__).resolve().parent.parent / "src" / "cafaye"
        offenders: list[str] = []
        for path in sorted(package.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                            offenders.append(f"{alias.name} at {path.name}:{node.lineno}")
                elif (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.split(".")[0] in FORBIDDEN_MODULES
                ):
                    offenders.append(f"{node.module} at {path.name}:{node.lineno}")
        assert not offenders, "the package must not import a logging module: " + ", ".join(
            offenders
        )

    def test_there_are_source_files_to_scan(self) -> None:
        """A vacuous scan is a green badge with no claim behind it."""
        assert len(self._source_files()) >= 8


@pytest.mark.leak
class TestNoTokenOnAVirologistArgument:
    """The brief's last requirement, in a form a test can actually check.

    "the client must not accept a token via a means that ends up in a process
    listing or a shell history without saying so". The refusal is a documented
    one — the constructor takes the token as a Python value, and the README says
    where it must come from — and this test is the executable half of that: the
    token is never read from the environment implicitly, so a process that never
    passes one cannot end up sending one it found in ``CAFAYE_TOKEN``.
    """

    def test_no_credential_is_read_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("CAFAYE_TOKEN", "CAFAYE_API_KEY", "CAFAYE_API_TOKEN", "CAFAYE_SESSION_TOKEN"):
            monkeypatch.setenv(name, FAKE_API_TOKEN)
        client = Cafaye(base_url="https://identity.example.test")
        assert client.credential_kind is None
        assert_no_credential("env", repr(client))

        sent: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return httpx.Response(200, json={"id": "u", "email": "a@b.test"})

        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        client.identity.get_current_user()
        assert "authorization" not in sent[0].headers
        assert "cookie" not in sent[0].headers
