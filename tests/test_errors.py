"""RFC 9457 problem documents become typed exceptions, with a typed fallback.

The brief: "Map it to typed exceptions — a distinct exception class per problem
type, with ``type`` and ``detail`` preserved — and a **typed fallback** for a
``type`` this client has never seen. The fallback is the load-bearing part: a
client that raises ``KeyError`` on a problem type added next month is a client
that breaks the day the API grows, and the reason it breaks is that nobody wrote
the fallback."

So there is a test per reserved code, a test per fallback shape, and a test that
a code from **next month** is handled without the client knowing about it.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from cafaye import (
    CafayeConflictError,
    CafayeConfigurationError,
    CafayeError,
    CafayeForbiddenError,
    CafayeIdempotencyKeyReusedError,
    CafayeNetworkError,
    CafayeNotFoundError,
    CafayeProblemError,
    CafayeProtocolError,
    CafayeRateLimitedError,
    CafayeTimeoutError,
    CafayeUnauthenticatedError,
    CafayeValidationError,
    is_cafaye_error,
)
from conftest import async_client, json_response, problem_response, sync_client

# core's reserved list, from `docs/openapi-conventions.md`, and the class each one
# must produce. Stated as data so the test for one code is the same test as the
# test for the others, and adding a code to the table adds a test.
RESERVED_CODES = [
    ("unauthorized", 401, CafayeUnauthenticatedError),
    ("forbidden", 403, CafayeForbiddenError),
    ("not_found", 404, CafayeNotFoundError),
    ("conflict", 409, CafayeConflictError),
    ("idempotency_key_reused", 409, CafayeIdempotencyKeyReusedError),
    ("validation_failed", 422, CafayeValidationError),
    ("rate_limited", 429, CafayeRateLimitedError),
]


def call_and_catch(response: httpx.Response) -> BaseException:
    client, _ = sync_client(response)
    with pytest.raises(Exception) as caught:  # noqa: B017 - narrowed by the asserts
        client.identity.get_current_user()
    return caught.value


class TestOneClassPerReservedCode:
    @pytest.mark.parametrize(
        ("code", "status", "expected"),
        RESERVED_CODES,
        ids=[code for code, _, _ in RESERVED_CODES],
    )
    def test_the_code_produces_its_class(self, code: str, status: int, expected: type) -> None:
        error = call_and_catch(problem_response(code, status))
        assert isinstance(error, expected)
        assert type(error) is expected, "the most specific class, not a superclass of it"

    @pytest.mark.parametrize(
        ("code", "status", "expected"),
        RESERVED_CODES,
        ids=[code for code, _, _ in RESERVED_CODES],
    )
    def test_the_problem_document_survives_onto_the_exception(
        self, code: str, status: int, expected: type
    ) -> None:
        """``type`` and ``detail`` preserved, per the brief."""
        error = call_and_catch(
            problem_response(code, status, detail="the specific thing that went wrong")
        )
        assert isinstance(error, CafayeProblemError)
        assert error.type == f"https://errors.cafaye.com/{code}"
        assert error.detail == "the specific thing that went wrong"
        assert error.title == "Something went wrong"
        assert error.code == code
        assert error.status == status
        assert error.instance == "/v1/me"
        assert error.trace_id == "0af7651916cd43dd8448eb211c80319c"
        assert error.kind == "problem"

    @pytest.mark.parametrize(
        ("code", "status", "expected"),
        RESERVED_CODES,
        ids=[code for code, _, _ in RESERVED_CODES],
    )
    def test_every_problem_error_is_one_base_class(
        self, code: str, status: int, expected: type
    ) -> None:
        """So one ``except CafayeError`` catches all of them."""
        error = call_and_catch(problem_response(code, status))
        assert isinstance(error, CafayeError)
        assert is_cafaye_error(error)
        assert error.status == status

    @pytest.mark.parametrize(
        ("code", "status", "expected"),
        RESERVED_CODES,
        ids=[code for code, _, _ in RESERVED_CODES],
    )
    def test_the_message_carries_the_operation(self, code: str, status: int, expected: type) -> None:
        """The log line names which call failed, which is half of diagnosing it."""
        error = call_and_catch(problem_response(code, status))
        assert "identity.get_current_user" in str(error)


class TestTheTypedFallback:
    """The load-bearing part, and the reason this file exists.

    Four shapes, chosen because each is a different way the fallback can fail:

    1. a reserved code with no class of its own (``internal``, ``unavailable``);
    2. a code that is not in the reserved list at all;
    3. a problem with no ``code`` and an unrecognised status;
    4. a code whose status contradicts it.
    """

    def test_a_reserved_code_with_no_class_of_its_own(self) -> None:
        error = call_and_catch(problem_response("internal", 500))
        assert type(error) is CafayeProblemError
        assert error.code == "internal"
        assert error.status == 500

    def test_a_reserved_code_for_a_service_outage(self) -> None:
        error = call_and_catch(problem_response("unavailable", 503))
        assert type(error) is CafayeProblemError
        assert error.code == "unavailable"
        assert error.status == 503

    def test_a_code_this_client_has_never_heard_of(self) -> None:
        """Not ``KeyError``. Not a bare ``Exception``. A typed problem error.

        This is the whole argument in one test: cafaye adds ``account_locked``
        next month, this client is not updated, and the consumer's
        ``except CafayeProblemError`` still catches it with ``code`` intact.
        """
        error = call_and_catch(problem_response("quantum_entangled", 418))
        assert type(error) is CafayeProblemError
        assert error.code == "quantum_entangled"
        assert error.type == "https://errors.cafaye.com/quantum_entangled"
        assert error.status == 418
        assert isinstance(error, CafayeError)

    def test_a_problem_with_no_code_and_an_unrecognised_status(self) -> None:
        body = {
            "type": "about:blank",
            "title": "Teapot",
            "status": 418,
            "detail": "short and stout",
        }
        error = call_and_catch(json_response(418, body, content_type="application/problem+json"))
        assert type(error) is CafayeProblemError
        assert error.code is None
        assert error.status == 418

    def test_a_problem_with_no_code_at_all(self) -> None:
        body = {"type": "about:blank", "title": "Nope", "status": 500}
        error = call_and_catch(json_response(500, body, content_type="application/problem+json"))
        assert type(error) is CafayeProblemError
        assert error.code is None
        assert error.title == "Nope"


class TestTheCodeChoosesTheClassAndTheStatusBreaksTheTie:
    def test_the_code_wins_when_the_status_drifts(self) -> None:
        """core calls ``type`` the machine-readable contract; RFC 9457 makes
        ``status`` advisory.

        So a 403 carrying ``code: "forbidden"`` is a ``CafayeForbiddenError`` even
        if the number drifts, and the reported status is still what the service
        actually sent.
        """
        error = call_and_catch(problem_response("forbidden", 418))
        assert isinstance(error, CafayeForbiddenError)
        assert error.status == 418

    def test_the_status_is_used_when_there_is_no_code(self) -> None:
        body = {
            "type": "https://errors.cafaye.com/whatever",
            "title": "Not found",
            "status": 404,
            "detail": "",
        }
        error = call_and_catch(json_response(404, body, content_type="application/problem+json"))
        assert isinstance(error, CafayeNotFoundError)
        assert error.code is None

    def test_the_body_status_is_preferred_over_the_http_status(self) -> None:
        """The body repeats the status, and the body is the contract.

        An HTTP 422 carrying ``code: "conflict"`` and ``status: 409`` is a service
        with its two facts out of step; the body is what the document promises, so
        the body wins and ``conflict`` is what a caller catching by type gets.
        """
        error = call_and_catch(
            json_response(
                422,
                {
                    "type": "https://errors.cafaye.com/conflict",
                    "title": "Conflict",
                    "status": 409,
                    "detail": "the body says 409, the HTTP line says 422",
                    "code": "conflict",
                },
                content_type="application/problem+json",
            )
        )
        assert isinstance(error, CafayeConflictError)
        assert error.status == 409


class TestProblemMembersAndExtensions:
    def test_a_422_carries_its_per_field_failures(self) -> None:
        error = call_and_catch(
            problem_response(
                "validation_failed",
                422,
                errors=[{"field": "email", "code": "invalid_format"}],
            )
        )
        assert isinstance(error, CafayeValidationError)
        assert error.errors is not None
        assert [(entry.field, entry.code) for entry in error.errors] == [
            ("email", "invalid_format")
        ]

    def test_a_422_with_no_errors_array_still_has_the_attribute(self) -> None:
        """An empty tuple, not ``None``.

        On a 422 the field errors are the point of the response, so "this one had
        none" is a statement about a malformed body rather than an absence — and
        ``None`` would be indistinguishable from a 403, which never has them.
        """
        error = call_and_catch(problem_response("validation_failed", 422))
        assert isinstance(error, CafayeValidationError)
        assert error.errors == ()
        assert error.errors is not None

    def test_an_unknown_member_lands_in_extensions(self) -> None:
        """A client that kept only the known set would drop a field added yesterday."""
        error = call_and_catch(
            problem_response("conflict", 409, retry_after_seconds=30, remediation={"url": "/v1/x"})
        )
        assert error.extensions["retry_after_seconds"] == 30
        assert error.extensions["remediation"] == {"url": "/v1/x"}

    def test_known_members_are_not_duplicated_into_extensions(self) -> None:
        error = call_and_catch(problem_response("not_found", 404))
        for member in ("type", "title", "status", "detail", "instance", "code", "trace_id"):
            assert member not in error.extensions


class TestNonProblemFailures:
    """The brief: "an HTTP 500 with a non-problem body still produces a typed,
    useful error rather than a crash"."""

    def test_a_500_with_an_html_body_is_a_typed_error(self) -> None:
        response = httpx.Response(
            500,
            content=b"<html><body><h1>502 Bad Gateway</h1></body></html>",
            headers={"content-type": "text/html; charset=utf-8"},
        )
        error = call_and_catch(response)
        assert type(error) is CafayeProtocolError
        assert error.kind == "protocol"
        assert error.status == 500
        assert error.content_type == "text/html; charset=utf-8"
        assert error.problem_shaped is False

    def test_the_body_snippet_is_kept_because_it_is_the_only_diagnosis(self) -> None:
        response = httpx.Response(
            502,
            content=b"<html>upstream connect error</html>",
            headers={"content-type": "text/html"},
        )
        error = call_and_catch(response)
        assert error.body_snippet is not None
        assert "upstream connect error" in error.body_snippet

    def test_a_500_with_an_empty_body_is_still_typed(self) -> None:
        error = call_and_catch(httpx.Response(500))
        assert type(error) is CafayeProtocolError
        assert error.status == 500
        assert error.content_type is None

    def test_a_500_whose_body_is_not_json_at_all_is_still_typed(self) -> None:
        error = call_and_catch(
            httpx.Response(500, content=b"\x00\x01\x02not json", headers={"content-type": "application/json"})
        )
        assert type(error) is CafayeProtocolError

    def test_a_200_carrying_a_problem_document_is_not_a_success(self) -> None:
        """The brief: "a problem-shaped body with a 200 is not a success."

        Handing a caller a ``Problem`` where its annotation promised a ``User``
        is worse than stopping: the first produces a ``TypeError`` three frames
        from the mistake, the second produces a diagnosis at the mistake.
        """
        error = call_and_catch(
            httpx.Response(
                200,
                json={
                    "type": "https://errors.cafaye.com/internal",
                    "title": "Internal",
                    "status": 200,
                    "detail": "a service that should not have answered 200 at all",
                    "code": "internal",
                },
                headers={"content-type": "application/problem+json"},
            )
        )
        assert type(error) is CafayeProtocolError
        assert error.status == 200
        assert error.problem_shaped is True

    def test_a_200_labelled_problem_json_is_not_a_success_even_if_the_body_is_empty(self) -> None:
        error = call_and_catch(httpx.Response(200, headers={"content-type": "application/problem+json"}))
        assert type(error) is CafayeProtocolError
        assert error.problem_shaped is False

    def test_an_empty_204_is_a_success_with_no_body(self) -> None:
        """``DELETE /v1/session`` answers 204, and there is nothing to return."""
        client, _ = sync_client(httpx.Response(204))
        assert client.identity.delete_session(token="x") is None


class TestIsCafayeError:
    def test_it_recognises_this_packages_errors(self) -> None:
        assert is_cafaye_error(call_and_catch(problem_response("internal", 500)))

    def test_it_rejects_something_that_is_not_a_cafaye_error(self) -> None:
        assert not is_cafaye_error(ValueError("nope"))
        assert not is_cafaye_error(None)
        assert not is_cafaye_error("a string")

    def test_it_recognises_a_class_from_another_copy_of_the_package(self) -> None:
        """Two copies in one dependency tree give two constructors.

        ``isinstance`` returns false across the boundary and the failure looks
        like a bug in the consumer's error handling, which is the worst place to
        go looking for the cause. So the marker is a dunder name, which both
        copies resolve to the same string, checked with ``getattr`` rather than
        ``isinstance``.
        """

        class ForeignCafayeError(Exception):
            __cafaye_error__ = True

        assert is_cafaye_error(ForeignCafayeError("from another copy")) is True

    def test_the_marker_is_not_in_the_instances_own_attributes(self) -> None:
        """A marker in ``vars()`` is a marker in somebody's structured log line."""
        error = call_and_catch(problem_response("internal", 500))
        assert "__cafaye_error__" not in vars(error)
        serialised = json.dumps(error, default=lambda value: repr(value))
        assert "cafaye_error" not in serialised


class TestNetworkFailures:
    """The failure shapes httpx actually produces.

    Every one of these is built by raising a real ``OSError``/``ssl`` error and
    chaining it onto the httpx exception, which is precisely what httpx's own
    transport does. Classifying by **message** instead would make these tests
    pass while classifying a real DNS failure as a connection failure, because on
    a real one the outer message is the equally useless ``All connection
    attempts failed``.
    """

    @staticmethod
    def _chained(outside: Exception, inside: BaseException) -> Exception:
        try:
            raise inside
        except BaseException as exc:
            outside.__cause__ = exc
            return outside

    def test_a_connection_refusal(self) -> None:
        failure = self._chained(
            httpx.ConnectError("[Errno 61] Connection refused"),
            ConnectionRefusedError(61, "Connection refused"),
        )
        client, _ = sync_client(failure)
        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        error = caught.value
        assert error.kind == "network"
        assert error.status is None
        assert error.reason == "connection"
        assert error.errno == 61

    def test_a_dns_failure_is_not_the_same_problem_as_a_timeout(self) -> None:
        import socket

        failure = self._chained(
            httpx.ConnectError("[Errno -2] Name or service not known"),
            socket.gaierror(-2, "Name or service not known"),
        )
        client, _ = sync_client(failure)
        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        assert caught.value.reason == "dns"
        assert caught.value.reason != "timeout"

    def test_a_temporary_dns_failure_is_still_dns(self) -> None:
        import socket

        failure = self._chained(
            httpx.ConnectError("[Errno -3] Temporary failure in name resolution"),
            socket.gaierror(-3, "Temporary failure in name resolution"),
        )
        client, _ = sync_client(failure)
        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        assert caught.value.reason == "dns"

    def test_a_certificate_failure_is_neither_dns_nor_connection(self) -> None:
        """It is a configuration fault, and retrying it is how an outage becomes
        an incident."""
        import ssl

        failure = self._chained(
            httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]"),
            ssl.SSLCertVerificationError("certificate verify failed"),
        )
        client, _ = sync_client(failure)
        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        assert caught.value.reason == "tls"

    def test_a_timeout_is_a_network_error_that_is_also_its_own_class(self) -> None:
        client, _ = sync_client(httpx.ReadTimeout("timed out"))
        with pytest.raises(CafayeTimeoutError) as caught:
            client.identity.get_current_user()
        error = caught.value
        # A subclass, so `except CafayeNetworkError: retry()` catches both, and a
        # caller who cares can still separate them without knowing that httpx
        # reports a read timeout as `ReadTimeout` and a name failure as
        # `ConnectError` with a `gaierror` cause.
        assert isinstance(error, CafayeNetworkError)
        assert error.reason == "timeout"
        assert error.status is None

    @pytest.mark.parametrize(
        "failure",
        [
            httpx.ReadTimeout("t"),
            httpx.ConnectTimeout("t"),
            httpx.WriteTimeout("t"),
            httpx.PoolTimeout("t"),
        ],
        ids=["read", "connect", "write", "pool"],
    )
    def test_all_four_httpx_timeouts_are_timeouts(self, failure: Exception) -> None:
        client, _ = sync_client(failure)
        with pytest.raises(CafayeTimeoutError):
            client.identity.get_current_user()

    def test_a_cancellation_propagates_rather_than_becoming_a_network_error(self) -> None:
        """``CancelledError`` is a ``BaseException`` for a reason.

        Wrapping it in a ``CafayeNetworkError`` would convert "this coroutine is
        being torn down" into "this network failed", which is how a cancelled
        task turns into a retried request during shutdown.
        """
        import asyncio

        failure = self._chained(
            httpx.ReadError("read failed"),
            asyncio.CancelledError(),
        )
        client, _ = async_client(failure)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(client.identity.get_current_user())

    def test_an_unclassifiable_failure_says_unknown_rather_than_guessing(self) -> None:
        """A custom transport that raises its own error is by definition not one
        of httpx's shapes. ``unknown`` is an answer; calling it ``connection``
        would be a lie to something deciding whether to retry."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise RuntimeError("something else entirely")

        client, _ = sync_client(handler)
        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        assert caught.value.reason == "unknown"

    def test_a_refused_scheme_is_a_protocol_fault_not_a_connection_one(self) -> None:
        """A redirect to a non-http scheme is a protocol fault, and following it
        is how a credential reaches a host nobody vetted."""
        failure = httpx.UnsupportedProtocol("Request URL is missing an 'http://' scheme.")
        client, _ = sync_client(failure)
        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        assert caught.value.reason == "protocol"


class TestConfigurationErrors:
    def test_a_negative_timeout_is_refused_before_any_request_exists(self) -> None:
        from cafaye import Cafaye as _Cafaye

        with pytest.raises(CafayeConfigurationError, match="timeout"):
            _Cafaye(base_url="https://a.example.test", timeout=-1)

    def test_a_non_finite_timeout_is_refused(self) -> None:
        from cafaye import Cafaye as _Cafaye

        for bad in (float("nan"), float("inf")):
            with pytest.raises(CafayeConfigurationError, match="timeout"):
                _Cafaye(base_url="https://a.example.test", timeout=bad)


class TestIsCafayeErrorAcrossTheBoundary:
    """The cross-copy test, done properly rather than by pretending.

    A second *installed* copy of this package cannot be produced inside one
    interpreter without a subprocess, so the assertion here is about the
    mechanism: the brand is looked up by name through ``globals()``, so a module
    loaded twice — which is what ``importlib.reload`` does — agrees with itself.
    """

    def test_reloading_the_module_still_agrees_with_itself(self) -> None:
        import importlib

        import cafaye._errors as errors_module

        reloaded = importlib.reload(errors_module)
        error = reloaded.CafayeProblemError(
            "a problem",
            {"type": "about:blank", "title": "t", "status": 500},
        )
        assert reloaded.is_cafaye_error(error)

    def test_a_plain_exception_is_never_mistaken_for_one(self) -> None:
        values: list[Any] = [None, 1, "x", b"x", [], {}, ValueError("x"), KeyboardInterrupt]
        for value in values:
            assert not is_cafaye_error(value)