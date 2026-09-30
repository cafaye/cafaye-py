"""The branches the happy-path tables do not reach.

``test_identity.py`` and ``test_client.py`` drive all twenty operations through
both faces. That is a parity claim about the *documented* path of each one, and a
documented path is not the whole of a method: five of them have a conditional
branch, and a branch only one face exercises is precisely the drift the parity
claim is supposed to rule out.

So this file names the branches and drives each one on both faces. Three were
unreachable on the async face until this file existed — ``create_session`` with a
second factor, ``mint_api_key`` with an expiry, and ``revoke_api_key`` with a
reason — which is the whole argument for writing them down rather than trusting
the happy path.

The rest of the file is the other half of the same idea. A suite that only drives
the documented path leaves the defensive branches unreached, and an unreached
branch is an unverified one: ``_body_text``'s fallback, the classifier's
errno-only paths, the redactor's recursion into a list, the two
``pragma: no cover`` guards. Each is a decision somebody wrote down, and each is
now a test.
"""

from __future__ import annotations

import inspect
import io
import json
import socket
import ssl
import textwrap
import tokenize
from typing import Any

import httpx
import pytest

from cafaye import (
    AsyncCafaye,
    Cafaye,
    CafayeError,
    CafayeNetworkError,
    CafayeProtocolError,
    CafayeTimeoutError,
    NetworkFailureReason,
    redact_text,
)
from cafaye._base_url import _is_absolute_http_url
from cafaye._client import (
    _body_text,
    _drain,
    _internal_bug,
    _resolve_path,
    _start,
)
from cafaye._errors import (
    _is_problem_media_type,
    _redact_value,
    cancellation_in_chain,
    cause_chain,
    classify_network_failure,
)
from conftest import BASE, async_client, json_response, run, sync_client


def _chained(outside: Exception, inside: BaseException) -> Exception:
    """An httpx error with a platform error chained onto it, as httpx itself does."""
    try:
        raise inside  # noqa: TRY301 - the raise IS the mechanism being faked
    except BaseException as exc:
        outside.__cause__ = exc
        return outside


class _NeverRead(httpx.SyncByteStream):
    """A stream that refuses to be read, standing in for a streaming response."""

    def __iter__(self) -> Any:
        raise httpx.ResponseNotRead()

    def close(self) -> None:
        return None


class TestTheConditionalBranchesOfBothFaces:
    """Five operations have a conditional branch, and each is driven on both."""

    def test_create_session_with_a_second_factor(self) -> None:
        """The 202 path, and the only way a caller supplies a TOTP code at login."""
        body = {"mfa_required": True, "challenge": "c", "expires_at": "x"}
        sync, sync_sent = sync_client(json_response(202, body))
        asynchronous, async_sent = async_client(json_response(202, body))

        from_sync = sync.identity.create_session(
            email="a@b.test", password="pw", second_factor="123456"
        )
        from_async = run(
            asynchronous.identity.create_session(
                email="a@b.test", password="pw", second_factor="123456"
            )
        )

        assert from_sync == from_async
        assert json.loads(sync_sent[0].content) == {
            "email": "a@b.test",
            "password": "pw",
            "second_factor": "123456",
        }
        assert sync_sent[0].content == async_sent[0].content

    def test_create_session_without_a_second_factor_omits_the_key_entirely(self) -> None:
        """A key sent as ``null`` is a different request from no key at all, and a
        service with ``additionalProperties: false`` would reject the first."""
        body = {"token": "t", "expires_at": "x"}
        sync, sync_sent = sync_client(json_response(200, body))
        asynchronous, async_sent = async_client(json_response(200, body))

        sync.identity.create_session(email="a@b.test", password="pw")
        run(asynchronous.identity.create_session(email="a@b.test", password="pw"))
        assert "second_factor" not in json.loads(sync_sent[0].content)
        assert sync_sent[0].content == async_sent[0].content

    @pytest.mark.parametrize(
        ("expires_in", "expected"),
        [(None, None), (3600, 3600)],
        ids=["without-an-expiry", "with-an-expiry"],
    )
    def test_mint_api_key_with_and_without_an_expiry(
        self, expires_in: int | None, expected: int | None
    ) -> None:
        issued = {"id": "k", "name": "n", "account_id": "a", "token": "cafaye_x"}
        sync, sync_sent = sync_client(json_response(201, issued))
        asynchronous, async_sent = async_client(json_response(201, issued))
        kwargs: dict[str, Any] = {"account_id": "a", "name": "n", "scopes": ["invoices:read"]}
        if expires_in is not None:
            kwargs["expires_in"] = expires_in

        assert sync.identity.mint_api_key(**kwargs) == run(
            asynchronous.identity.mint_api_key(**kwargs)
        )
        decoded: dict[str, Any] = json.loads(sync_sent[0].content)
        assert decoded.get("expires_in") == expected
        assert sync_sent[0].content == async_sent[0].content

    @pytest.mark.parametrize(
        ("reason", "method", "suffix"),
        [(None, "DELETE", ""), ("rotated", "POST", "/revoke")],
        ids=["plain-delete", "with-a-reason"],
    )
    def test_revoke_api_key_with_and_without_a_reason(
        self, reason: str | None, method: str, suffix: str
    ) -> None:
        """Two different routes, and the branch selects between them."""
        sync, sync_sent = sync_client(httpx.Response(204))
        asynchronous, async_sent = async_client(httpx.Response(204))
        kwargs: dict[str, Any] = {"account_id": "a", "key_id": "k"}
        if reason is not None:
            kwargs["reason"] = reason

        sync.identity.revoke_api_key(**kwargs)
        run(asynchronous.identity.revoke_api_key(**kwargs))

        assert sync_sent[0].method == method
        assert sync_sent[0].url.path == f"/v1/accounts/a/api-keys/k{suffix}"
        assert sync_sent[0].url == async_sent[0].url
        assert sync_sent[0].content == async_sent[0].content

    @pytest.mark.parametrize(
        ("limit", "cursor"),
        [(None, None), (10, None), (None, "opaque"), (10, "c")],
        ids=["neither", "limit", "cursor", "both"],
    )
    def test_pagination_parameters_on_both_faces(
        self, limit: int | None, cursor: str | None
    ) -> None:
        body = {"data": [], "page": {"has_more": False}}
        sync, sync_sent = sync_client(json_response(200, body))
        asynchronous, async_sent = async_client(json_response(200, body))

        assert sync.identity.list_api_keys(account_id="a", limit=limit, cursor=cursor) == run(
            asynchronous.identity.list_api_keys(account_id="a", limit=limit, cursor=cursor)
        )
        assert sync_sent[0].url == async_sent[0].url

    def test_start_mfa_enrollment_with_an_explicit_method_on_both_faces(self) -> None:
        body = {
            "enrollment_id": "e",
            "secret": "s",
            "provisioning_uri": "u",
            "method": "totp",
            "digits": 6,
            "period_seconds": 30,
            "algorithm": "SHA1",
            "expires_at": "x",
        }
        sync, sync_sent = sync_client(json_response(200, body))
        asynchronous, async_sent = async_client(json_response(200, body))
        sync.identity.start_mfa_enrollment(method="totp")
        run(asynchronous.identity.start_mfa_enrollment(method="totp"))
        assert sync_sent[0].content == async_sent[0].content

    def test_the_async_face_has_no_branch_the_sync_face_lacks(self) -> None:
        """The claim, checked against the source rather than against a list.

        ``_client.py`` says "one implementation, two faces" and
        ``_services/identity.py`` says the parity test "asserts the two faces
        expose the same twenty names and the same twenty declarations". This is
        the stronger version: it compares the two classes **method by method**,
        token by token, so a conditional branch written on one face and forgotten
        on the other is a failure here rather than a surprise in production. Three
        such branches existed an hour ago.

        Tokenised, not whitespace-normalised, because whitespace normalisation is
        not enough: ``ruff format`` wraps the sync face's ``mint_api_key``
        differently from the async one purely because the async signature is a
        line longer, and a text comparison reports that as a difference in the
        code. Three things are dropped, and only three, each with a reason:

        - layout tokens, which are formatting;
        - string tokens, which are the docstrings the async face replaces with a
          one-line cross-reference rather than repeating forty lines of prose;
        - the names ``async`` and ``await``, which are the one *intended*
          difference.
        """
        from cafaye._services.identity import AsyncIdentityService, IdentityService

        layout = frozenset(
            {
                tokenize.NEWLINE,
                tokenize.NL,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.ENDMARKER,
                tokenize.COMMENT,
            }
        )
        ignored = layout | {tokenize.STRING}
        #: The only differences between the two faces that are supposed to exist.
        face_only = {"async", "await", "_perform", "_aperform"}

        def tokens_of(cls: type) -> dict[str, list[tuple[int, str]]]:
            out: dict[str, list[tuple[int, str]]] = {}
            for name, member in vars(cls).items():
                if name.startswith("_") or not callable(member):
                    continue
                source = textwrap.dedent(inspect.getsource(member))
                raw = list(tokenize.generate_tokens(io.StringIO(source).readline))
                kept: list[tuple[int, str]] = []
                for position, token in enumerate(raw):
                    if token.type in ignored:
                        continue
                    if token.type == tokenize.NAME and token.string in face_only:
                        continue
                    # A trailing comma is layout, and `ruff format` leaves one on
                    # a multi-line signature and not on a single-line one. The
                    # lookahead skips layout tokens: on the multi-line form the
                    # next *raw* token after the comma is a newline rather than a
                    # bracket, so a one-token lookahead misses it.
                    following = next(
                        (later.string for later in raw[position + 1 :] if later.type not in layout),
                        "",
                    )
                    if token.string == "," and following in {")", "]", "}"}:
                        continue
                    kept.append((token.type, token.string))
                out[name] = kept
            return out

        assert tokens_of(IdentityService) == tokens_of(AsyncIdentityService)


class TestTheBodyExcerptFallbacks:
    """``_body_text``: "no excerpt" and "no excerpt available" are different."""

    def test_a_string_body_is_used_directly(self) -> None:
        """A gateway returning a bare error string. It is already text, and
        re-reading it from the response would go through a decode that can fail for
        no reason."""
        assert _body_text("already text", httpx.Response(500)) == "already text"

    def test_an_undecodable_body_is_replaced_rather_than_lost(self) -> None:
        """``httpx`` decodes with replacement, so the excerpt is still shown.

        Worth stating as a fact rather than left implied, because the alternative —
        an excerpt that vanishes because one byte in it was not UTF-8 — is exactly
        the case where a developer most needs to see it. And the
        ``UnicodeDecodeError`` handler that used to sit next to this one was
        unreachable for the same reason, which is what coverage reported.
        """
        response = httpx.Response(500, content=b"\xff\xfe\x00not utf-8")
        excerpt = _body_text(None, response)
        assert "not utf-8" in excerpt
        assert "\ufffd" in excerpt

    def test_a_decodable_body_is_read_as_text(self) -> None:
        response = httpx.Response(500, content=b"<html>502</html>")
        assert _body_text(None, response) == "<html>502</html>"

    def test_a_response_nobody_read_has_no_excerpt_at_all(self) -> None:
        """``httpx.ResponseNotRead`` — the one failure ``response.text`` raises.

        The answer is an **empty** excerpt, and the empty string is the finding.
        The fallback that was here first was ``repr(response.content)``, which
        raises the very exception being handled, because ``.content`` on a
        streaming response nobody read is the access that failed in the first
        place. So the handler traded one ``ResponseNotRead`` for another, one
        frame later.
        """
        assert _body_text(None, httpx.Response(500, stream=_NeverRead())) == ""

    def test_an_empty_excerpt_becomes_no_body_snippet(self) -> None:
        """``None`` says "there is nothing to show", and it is the same answer for an
        empty excerpt as for one redaction emptied."""
        client, _ = sync_client(httpx.Response(500, headers={"content-type": "text/html"}))
        with pytest.raises(CafayeProtocolError) as caught:
            client.identity.get_current_user()
        assert caught.value.body_snippet is None
        assert caught.value.content_type == "text/html"

    def test_a_body_nobody_read_decodes_to_nothing_rather_than_raising(self) -> None:
        """The bug this guards, at the only level at which it is reachable.

        ``Response.json()`` goes through ``self.content``, so a streaming response
        raises ``ResponseNotRead`` -- which is **not** a ``ValueError``. It escaped
        ``_decode``, was caught by ``_perform``'s blanket ``except Exception``, and
        came back out as a ``CafayeNetworkError`` with ``reason="unknown"``: a
        client-side fault described as the network having failed, which sends
        somebody to the wrong dashboard at three in the morning.

        Tested on ``_decode`` directly, and that is not a shortcut. It is genuinely
        unreachable through the client: ``httpx.Client.send`` calls
        ``response.read()`` for any request that is not itself streaming, so a
        streaming *response* cannot reach ``_finish`` at all, and this package
        never makes a streaming request. The guard is for a caller who supplies a
        transport of their own -- which is what the ``transport=`` option on the
        constructor is for -- and a guard for that is worth having even when this
        package's own lifecycle cannot reach it.
        """
        from cafaye._client import _decode

        assert _decode(httpx.Response(200, stream=_NeverRead())) is None


class TestTheClassifierOnEveryShapeItPromises:
    """A pure function, so every shape is reachable without a socket, a DNS server
    or a timer."""

    @pytest.mark.parametrize(
        ("inside", "reason"),
        [
            (TimeoutError("t"), NetworkFailureReason.TIMEOUT),
            (TimeoutError("t"), NetworkFailureReason.TIMEOUT),
            (socket.gaierror(-2, "no such name"), NetworkFailureReason.DNS),
            (socket.gaierror(-3, "temporary"), NetworkFailureReason.DNS),
            (ssl.SSLError("handshake"), NetworkFailureReason.TLS),
            (ssl.SSLCertVerificationError("no"), NetworkFailureReason.TLS),
            (ConnectionRefusedError(61, "refused"), NetworkFailureReason.CONNECTION),
            (ConnectionResetError(54, "reset"), NetworkFailureReason.CONNECTION),
            (ConnectionAbortedError(53, "aborted"), NetworkFailureReason.CONNECTION),
            # `BrokenPipeError` is a `ConnectionError` but **not** any of the three
            # above, so it needs its own arm — and this is the test that says the
            # arm is not redundant.
            (BrokenPipeError(32, "pipe"), NetworkFailureReason.CONNECTION),
        ],
        ids=[
            "timeout-error",
            "socket-timeout",
            "dns-2",
            "dns-3",
            "ssl",
            "ssl-verify",
            "refused",
            "reset",
            "aborted",
            "broken-pipe",
        ],
    )
    def test_a_shaped_cause_is_classified(
        self, inside: BaseException, reason: NetworkFailureReason
    ) -> None:
        failure = _chained(httpx.ConnectError("All connection attempts failed"), inside)
        assert classify_network_failure(failure)[0] is reason

    @pytest.mark.parametrize(
        "errno",
        [-2, -3, -5, -6, -8],
    )
    def test_a_dns_errno(self, errno: int) -> None:
        self._assert_bare_errno(errno, NetworkFailureReason.DNS)

    @pytest.mark.parametrize(
        "errno",
        [32, 51, 54, 60, 61, 65, 101, 104, 110, 113],
    )
    def test_a_connection_errno(self, errno: int) -> None:
        """Split across Darwin and Linux, because the numbers do not agree.

        A TLS errno is deliberately **not** in this set: retrying a certificate
        failure is how an outage becomes an incident.
        """
        self._assert_bare_errno(errno, NetworkFailureReason.CONNECTION)

    def _assert_bare_errno(self, errno: int, reason: NetworkFailureReason) -> None:
        """A number with no shape at all, which is what the errno lists are for.

        Some platforms and some wrappers report a numeric code and nothing else —
        no ``gaierror``, no ``SSLError``, just an int. So classification is by
        **type and errno**, and the two lists are the codes.

        The carrier is a plain ``Exception`` with an ``errno`` attribute and
        deliberately **not** an ``OSError``: ``OSError(60, "...")`` is a
        ``TimeoutError`` on both Darwin and Linux, so constructing one would
        exercise the type arm above rather than the errno arm, and this test would
        pass or fail depending on the machine it ran on.
        """

        class JustANumberError(Exception):
            def __init__(self, code: int) -> None:
                super().__init__("no shape, just a number")
                self.errno = code

        failure = _chained(httpx.ConnectError("wrapped"), JustANumberError(errno))
        assert classify_network_failure(failure) == (reason, errno)

    def test_an_errno_outside_every_list_is_still_reported(self) -> None:
        """The number is kept even when it means nothing here. Withholding it
        would cost the caller the one datum they had."""

        class JustANumberError(Exception):
            def __init__(self) -> None:
                super().__init__("?")
                self.errno = 9999

        failure = _chained(httpx.ConnectError("wrapped"), JustANumberError())
        reason, errno = classify_network_failure(failure)
        assert errno == 9999
        assert reason is NetworkFailureReason.CONNECTION

    def test_a_transport_error_with_nothing_to_go_on(self) -> None:
        reason, errno = classify_network_failure(
            httpx.ConnectError("All connection attempts failed")
        )
        assert reason is NetworkFailureReason.CONNECTION
        assert errno is None

    def test_something_that_is_not_an_httpx_error_at_all(self) -> None:
        """``unknown`` is an answer, not a shrug. Calling it ``connection`` would be
        a lie to whatever is deciding whether to retry."""
        reason, errno = classify_network_failure(RuntimeError("a custom transport"))
        assert reason is NetworkFailureReason.UNKNOWN
        assert errno is None

    def test_the_walk_terminates_on_a_cycle(self) -> None:
        """An unbounded walk over a structure the caller controls is a way to hang
        this package inside somebody's error handler."""
        first = RuntimeError("a")
        second = RuntimeError("b")
        first.__cause__ = second
        second.__cause__ = first
        assert classify_network_failure(first)[0] is NetworkFailureReason.UNKNOWN
        assert len(cause_chain(first)) < 8

    def test_the_walk_stops_at_eight(self) -> None:
        deepest: BaseException = ValueError("innermost")
        for index in range(30):
            outer = RuntimeError(f"level {index}")
            outer.__cause__ = deepest
            deepest = outer
        assert len(cause_chain(deepest)) == 8
        assert len(cause_chain(deepest, limit=3)) == 3

    def test_an_unsupported_scheme_is_a_protocol_fault(self) -> None:
        assert (
            classify_network_failure(httpx.UnsupportedProtocol("no scheme"))[0]
            is NetworkFailureReason.PROTOCOL
        )

    def test_a_cancellation_is_not_classified_at_all(self) -> None:
        """There is deliberately no ``NetworkFailureReason`` for one.

        The obvious place to put it is ``TIMEOUT``, and that is the most damaging
        answer available: a caller whose handler retries every timeout would have
        retried a request that was being torn down, and a runtime shutting down
        would have kept re-issuing work against a service that is already going
        away. So it is asked as a separate question, and the answer is "not a
        network failure" — the caller's own ``CancelledError``, re-raised untouched
        so ``Task.cancelling()`` bookkeeping stays consistent.
        """
        import asyncio

        failure = _chained(httpx.ReadError("read failed"), asyncio.CancelledError())
        found = cancellation_in_chain(failure)
        assert found is not None
        assert isinstance(found, asyncio.CancelledError)
        assert found is failure.__cause__
        assert cancellation_in_chain(httpx.ReadError("read failed")) is None


class TestTheMediaTypeTest:
    def test_absent_is_not_the_problem_type(self) -> None:
        assert _is_problem_media_type(None) is False

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("application/problem+json", True),
            ("application/problem+json; charset=utf-8", True),
            ("APPLICATION/PROBLEM+JSON", True),
            ("  application/problem+json  ", True),
            ("application/json", False),
            ("text/html", False),
            ("application/problem+jsonx", False),
        ],
    )
    def test_the_charset_parameter_does_not_change_the_answer(
        self, value: str, expected: bool
    ) -> None:
        """A service behind a proxy that rewrote the charset parameter is common,
        and a mislabelled content type is the one case the body check cannot help
        with — which is why both signals are read."""
        assert _is_problem_media_type(value) is expected

    def test_both_copies_of_the_test_agree(self) -> None:
        """``_errors`` and ``_client`` each hold this rule, and they are compared.

        Two copies of a three-line function is a duplication a reviewer would
        normally reject. It is here because ``_client`` imports ``_errors`` and a
        module that imports its own importer is a cycle dressed up as a
        convenience — so the duplication is the cheaper of the two, and this test
        is what stops the cheaper option from quietly becoming the wrong one.
        """
        from cafaye._client import _is_problem_media_type as client_copy

        for value in (None, "application/problem+json", "text/html", "application/json"):
            assert _is_problem_media_type(value) == client_copy(value)


class TestTheRedactorRecursesIntoEveryContainer:
    @pytest.mark.parametrize(
        "value",
        [
            ["a string", 7],
            ("a tuple", None),
            [[["nested three levels"]]],
            [{"a": ["b", {"c": ["d"]}]}],
        ],
        ids=["list", "tuple", "deep", "mixed"],
    )
    def test_every_string_inside_a_container_is_redacted(self, value: object) -> None:
        rendered = repr(_redact_value(redact_text(), value))
        assert "cafaye_" not in rendered
        assert "eyJ" not in rendered

    def test_a_string_stays_a_string_and_a_number_stays_a_number(self) -> None:
        """The shape of the extension member a service sent is preserved, because
        the point of keeping extensions is that the error stays legible."""
        redact = redact_text()
        assert _redact_value(redact, "clean") == "clean"
        assert _redact_value(redact, 7) == 7
        assert _redact_value(redact, None) is None
        assert _redact_value(redact, True) is True

    def test_a_mapping_keeps_its_keys_as_strings(self) -> None:
        """A structured logger will index by whatever the keys are, so a non-string
        key is normalised rather than left to be a ``TypeError`` downstream."""
        assert _redact_value(redact_text(), {7: "x"}) == {"7": "x"}

    def test_the_shape_of_a_credential_inside_a_container_is_preserved(self) -> None:
        from cafaye import REDACTED

        assert _redact_value(redact_text(), ["cafaye_x", "clean"]) == [REDACTED, "clean"]


class TestTheUnreachableGuardsAreUnreachable:
    """The two ``pragma: no cover`` arms, driven directly.

    Both are statements about the contract rather than reachable paths, and the
    alternative to proving that is leaving them as comments in a file where a
    reader cannot tell a comment from a lie.
    """

    def test_a_lifecycle_that_never_asks_for_a_request(self) -> None:
        def never_yields() -> Any:
            return None
            yield  # pragma: no cover - the `yield` is what makes this a generator

        with pytest.raises(CafayeError) as caught:
            _start(never_yields())
        assert "ended without asking for a request" in str(caught.value)
        assert "bug in cafaye-py" in str(caught.value)

    def test_a_lifecycle_that_asks_for_two_requests(self) -> None:
        from cafaye._client import PendingRequest

        def twice() -> Any:
            yield PendingRequest(method="GET", url="https://x", headers={})
            yield PendingRequest(method="GET", url="https://x", headers={})
            return None  # pragma: no cover - the second yield raises first

        # Primed first: `Generator.send(non_None)` on a generator that has not
        # started is a `TypeError` about the priming convention rather than about
        # the bug under test.
        exchange = twice()
        _start(exchange)
        with pytest.raises(CafayeError) as caught:
            _drain(exchange, httpx.Response(200))
        assert "more than one request" in str(caught.value)
        assert "bug in cafaye-py" in str(caught.value)

    def test_the_internal_bug_error_carries_a_kind_because_it_must(self) -> None:
        """``kind`` is documented as present on every error, so even an internal
        invariant violation has to pick one.

        It picks ``CONFIGURATION``, and that is a precedent rather than a
        classification: the four kinds describe *the caller's request* failing, and
        ``cafaye-ts`` reports its own internal lookup miss the same way. A fifth
        kind would put this client's error vocabulary one member ahead of every
        other cafaye SDK's, and the two clients being one product is worth more
        than a more precise enum.
        """
        from cafaye import ErrorKind

        error = _internal_bug("Something impossible happened.")
        assert error.kind is ErrorKind.CONFIGURATION
        assert error.status is None
        assert "bug in cafaye-py" in str(error)


class TestAUrlThatCannotEvenBeSplit:
    def test_an_ipv6_url_missing_its_bracket_is_refused(self) -> None:
        """``urlsplit`` raises rather than returning a half-parsed value, and the
        refusal has to survive that.

        Letting the ``ValueError`` escape would surface as a ``ValueError`` from
        the standard library's URL parser inside a constructor whose whole job is to
        explain configuration mistakes clearly.
        """
        from cafaye import CafayeConfigurationError

        assert _is_absolute_http_url("http://[::1") is False
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url="http://[::1")
        assert caught.value.source == "the `base_url` argument"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https://x.test", True),
            ("http://x.test", True),
            ("HTTPS://X.TEST", True),
            ("https://x.test/cafaye", True),
            ("x.test", False),
            ("ftp://x.test", False),
            ("https://", False),
            ("", False),
            ("://x", False),
        ],
    )
    def test_only_an_absolute_http_url_is_accepted(self, value: str, expected: bool) -> None:
        """A bare host is refused rather than completed.

        ``identity.example.com`` concatenated with ``/v1/me`` is
        ``identity.example.test/v1/me``, which is not a URL at all, and the
        resulting failure names neither the typo nor the cause.
        """
        assert _is_absolute_http_url(value) is expected


class TestTheAsyncFaceIsWiredTheSameWay:
    def test_the_deadline_reaches_the_async_pool_too(self) -> None:
        asynchronous = AsyncCafaye(
            base_url=BASE,
            timeout=7.0,
            transport=httpx.MockTransport(lambda _r: httpx.Response(204)),
        )
        assert asynchronous._client.timeout.read == 7.0

    def test_a_bad_deadline_is_refused_before_the_pool_exists(self) -> None:
        from cafaye import CafayeConfigurationError

        with pytest.raises(CafayeConfigurationError):
            AsyncCafaye(base_url=BASE, timeout=float("inf"))

    def test_the_two_faces_reject_the_same_base_urls(self) -> None:
        from cafaye import CafayeConfigurationError

        for bad in ("not a url", "x.test", "ftp://x.test"):
            with pytest.raises(CafayeConfigurationError):
                Cafaye(base_url=bad)
            with pytest.raises(CafayeConfigurationError):
                AsyncCafaye(base_url=bad)

    def test_a_network_failure_on_the_async_face_has_no_empty_context_either(self) -> None:
        """The context-chain rule is not a sync-only property, and it is the one
        that stops ``traceback`` from rendering the credential."""
        failure = _chained(
            httpx.ConnectError("[Errno 61] Connection refused"),
            ConnectionRefusedError(61, "refused"),
        )
        asynchronous, _ = async_client(failure)
        with pytest.raises(CafayeNetworkError) as caught:
            run(asynchronous.identity.get_current_user())
        assert caught.value.__context__ is None
        assert caught.value.errno == 61

    def test_a_timeout_on_the_async_face_is_its_own_class(self) -> None:
        asynchronous, _ = async_client(httpx.PoolTimeout("t"))
        with pytest.raises(CafayeTimeoutError) as caught:
            run(asynchronous.identity.get_current_user())
        assert caught.value.reason == NetworkFailureReason.TIMEOUT

    def test_a_cancellation_on_the_async_face_is_not_wrapped(self) -> None:
        import asyncio

        failure = _chained(httpx.ReadError("read failed"), asyncio.CancelledError())
        asynchronous, _ = async_client(failure)
        with pytest.raises(asyncio.CancelledError):
            run(asynchronous.identity.get_current_user())

    def test_a_protocol_error_on_the_async_face_says_the_same_thing(self) -> None:
        sync, _ = sync_client(
            httpx.Response(
                502, content=b"<html>bad gateway</html>", headers={"content-type": "text/html"}
            )
        )
        asynchronous, _ = async_client(
            httpx.Response(
                502, content=b"<html>bad gateway</html>", headers={"content-type": "text/html"}
            )
        )
        with pytest.raises(CafayeProtocolError) as sync_error:
            sync.identity.get_current_user()
        with pytest.raises(CafayeProtocolError) as async_error:
            run(asynchronous.identity.get_current_user())
        assert str(sync_error.value) == str(async_error.value)
        assert sync_error.value.body_snippet == async_error.value.body_snippet


class TestThePathResolverIsWhereTheUrlIsDecided:
    def test_both_faces_pass_the_path_rather_than_a_built_url(self) -> None:
        """If one face assembled its own URL, the two would diverge on exactly the
        operations with a path parameter — which is nine of twenty, and the
        substitution happens in ``_exchange``.

        The full token-level comparison of the two faces is the real check and is
        in the class above. This says *where* the URL is decided, which a token
        comparison cannot.
        """
        from cafaye._services.identity import AsyncIdentityService, IdentityService

        for cls in (IdentityService, AsyncIdentityService):
            source = inspect.getsource(cls._run)
            assert "self._client._exchange" in source, cls.__name__
            assert "path=operation.path" in source, cls.__name__

    def test_a_url_with_no_placeholders_and_no_parameters_is_unchanged(self) -> None:
        assert _resolve_path("https://x/v1/me", None) == ("https://x/v1/me", {})
