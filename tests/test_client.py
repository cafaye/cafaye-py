"""The client itself: the lifecycle, the two faces, and the seams between them.

``_client.py``'s docstring makes a specific claim -- "``tests/test_client.py``
asserts the two faces agree on every outcome rather than trusting this comment" --
and this is that file. The claim is the brief's: "``httpx`` supports both from one
implementation. Provide both; do not write two clients."

The way the package honours that is one **generator** for the whole lifecycle, with
the two faces differing on exactly one line::

    pending = exchange.send(None)  # build
    response = transport.send(pending)  # I/O   <- the only line that differs
    value = exchange.send(response)  # map or raise

So the thing worth testing is not that both faces work. It is that they are the
same code, because a lifecycle written twice is a lifecycle that drifts. This file
drives all twenty operations through both faces and compares what came out, and
then drives the failure paths through both and compares the exception classes.
"""

from __future__ import annotations

import json
from typing import Any, cast

import httpx
import pytest

from cafaye import (
    DEFAULT_TIMEOUT,
    AsyncCafaye,
    Cafaye,
    CafayeConfigurationError,
    CafayeNetworkError,
    CafayeTimeoutError,
)
from cafaye._client import _resolve_path
from conftest import BASE, async_client, json_response, problem_response, run, sync_client

#: Every operation, with the arguments it needs and the body that answers it. One
#: table, so "the two faces agree on every operation" is a loop rather than
#: twenty pairs of near-identical tests.
CALLS: list[tuple[str, tuple[Any, ...], dict[str, Any] | None, str | None]] = [
    ("register_user", ("a@b.test", "pw"), {"id": "u", "email": "a@b.test"}, "User"),
    ("create_session", ("a@b.test", "pw"), {"token": "t", "expires_at": "x"}, "Session"),
    ("delete_session", (), None, None),
    ("complete_second_factor", ("c", "123456"), {"token": "t", "expires_at": "x"}, "Session"),
    ("get_current_user", (), {"id": "u", "email": "a@b.test"}, "User"),
    ("get_mfa_status", (), {"enabled": True, "method": "totp"}, "MfaStatus"),
    # 204, and the body it *sends* is a separate concern -- the table records the
    # response, and the request body is asserted in `test_identity.py`.
    ("disable_mfa", ("123456",), None, None),
    ("start_mfa_enrollment", (), {"enrollment_id": "e", "secret": "s"}, "StartedEnrollment"),
    (
        "confirm_mfa_enrollment",
        ("e", "123456"),
        {"enabled": True, "recovery_codes": ["a"]},
        "ConfirmedEnrollment",
    ),
    (
        "regenerate_mfa_recovery_codes",
        (),
        {"recovery_codes": ["a"], "issued_at": "x"},
        "RecoveryCodesResponse",
    ),
    ("list_oidc_clients", ("acc",), {"data": [], "page": {"has_more": False}}, "_Page"),
    ("get_oidc_client", ("acc", "cli"), {"id": "r", "client_id": "cid"}, "OIDCClient"),
    (
        "register_oidc_client",
        ("acc", "n", ["u"], ["g"], ["openid"]),
        {"id": "r"},
        "OIDCClientWithSecret",
    ),
    ("revoke_oidc_client", ("acc", "cli"), None, None),
    ("mint_api_key", ("acc", "n", ["invoices:read"]), {"id": "k", "token": "t"}, "IssuedApiKey"),
    ("list_api_keys", ("acc",), {"data": [], "page": {"has_more": False}}, "_Page"),
    ("revoke_api_key", ("acc", "k"), None, None),
    ("introspect_api_key", ("t",), {"active": True, "scope": "invoices:read"}, "Introspection"),
    ("liveness", (), {"status": "ok"}, "Health"),
    ("readiness", (), {"status": "ok", "deps": "db"}, "Health"),
]

#: The `**kwargs` each operation actually takes, because the table above passes
#: positionally and a call with a wrong keyword is a different test.
KEYWORDS: dict[str, str] = {
    "register_user": "email, password",
    "create_session": "email, password",
    "complete_second_factor": "challenge, code",
    "disable_mfa": "code",
    "confirm_mfa_enrollment": "enrollment_id, code",
    "start_mfa_enrollment": "",
    "regenerate_mfa_recovery_codes": "",
    "list_oidc_clients": "account_id",
    "get_oidc_client": "account_id, client_id",
    "register_oidc_client": "account_id, name, redirect_uris, grant_types, scopes",
    "revoke_oidc_client": "account_id, client_id",
    "mint_api_key": "account_id, name, scopes",
    "list_api_keys": "account_id",
    "revoke_api_key": "account_id, key_id",
    "introspect_api_key": "token",
    "get_current_user": "",
    "get_mfa_status": "",
    "delete_session": "",
    "liveness": "",
    "readiness": "",
}

#: The value each positional argument above is bound to, as a keyword.
BOUND: dict[str, tuple[str, ...]] = {
    "register_user": ("email", "password"),
    "create_session": ("email", "password"),
    "complete_second_factor": ("challenge", "code"),
    "disable_mfa": ("code",),
    "confirm_mfa_enrollment": ("enrollment_id", "code"),
    "list_oidc_clients": ("account_id",),
    "get_oidc_client": ("account_id", "client_id"),
    "register_oidc_client": ("account_id", "name", "redirect_uris", "grant_types", "scopes"),
    "revoke_oidc_client": ("account_id", "client_id"),
    "mint_api_key": ("account_id", "name", "scopes"),
    "list_api_keys": ("account_id",),
    "revoke_api_key": ("account_id", "key_id"),
    "introspect_api_key": ("token",),
}


def _kwargs_for(name: str, args: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip(BOUND.get(name, ()), args, strict=True))


def _response_for(body: dict[str, Any] | None) -> httpx.Response:
    return httpx.Response(204) if body is None else json_response(200, body)


class TestTheTwoFacesAgreeOnEveryOperation:
    """The claim in ``_client.py``'s docstring, as twenty comparisons.

    Value **and** request. A face that returned the right value from the wrong URL
    would pass a value-only comparison, and "the two faces are the same code" is a
    claim about the request as much as the answer.
    """

    @pytest.mark.parametrize(("name", "args", "body", "expected"), CALLS, ids=[c[0] for c in CALLS])
    def test_same_value_and_same_request(
        self, name: str, args: tuple[Any, ...], body: dict[str, Any] | None, expected: Any
    ) -> None:
        kwargs = _kwargs_for(name, args)

        sync, sync_sent = sync_client(_response_for(body))
        asynchronous, async_sent = async_client(_response_for(body))

        from_sync = getattr(sync.identity, name)(**kwargs)
        from_async = run(getattr(asynchronous.identity, name)(**kwargs))

        assert from_sync == from_async
        if expected is None:
            # An operation whose document declares no response produces no value,
            # and "no value" is `None` on both faces rather than a model with
            # every field empty. `type(None).__name__` is "NoneType", which is a
            # true statement about the object and a useless one about the
            # contract.
            assert from_sync is None
        else:
            assert type(from_sync).__name__ == expected
        assert sync_sent[0].method == async_sent[0].method
        assert sync_sent[0].url == async_sent[0].url
        assert sync_sent[0].headers.get("authorization") == async_sent[0].headers.get(
            "authorization"
        )

    @pytest.mark.parametrize(("name", "args", "body", "expected"), CALLS, ids=[c[0] for c in CALLS])
    def test_the_body_sent_is_byte_identical(
        self, name: str, args: tuple[Any, ...], body: dict[str, Any] | None, expected: Any
    ) -> None:
        """Not just equal, not just equivalent: the same bytes.

        ``json=`` serialisation is the one place a sync and an async request could
        plausibly differ without anyone noticing, because the decoded values would
        still compare equal.
        """
        kwargs = _kwargs_for(name, args)
        sync, sync_sent = sync_client(_response_for(body))
        asynchronous, async_sent = async_client(_response_for(body))

        getattr(sync.identity, name)(**kwargs)
        run(getattr(asynchronous.identity, name)(**kwargs))
        assert sync_sent[0].content == async_sent[0].content

    @pytest.mark.parametrize(
        ("name", "args", "body"),
        [(c[0], c[1], c[2]) for c in CALLS],
        ids=[c[0] for c in CALLS],
    )
    def test_both_faces_raise_the_same_class_for_the_same_problem(
        self, name: str, args: tuple[Any, ...], body: dict[str, Any] | None
    ) -> None:
        from cafaye import CafayeUnauthenticatedError

        kwargs = _kwargs_for(name, args)
        sync, _ = sync_client(problem_response("unauthorized", 401))
        asynchronous, _ = async_client(problem_response("unauthorized", 401))

        with pytest.raises(CafayeUnauthenticatedError) as sync_error:
            getattr(sync.identity, name)(**kwargs)
        with pytest.raises(CafayeUnauthenticatedError) as async_error:
            run(getattr(asynchronous.identity, name)(**kwargs))

        assert type(sync_error.value) is type(async_error.value)
        assert sync_error.value.operation == async_error.value.operation
        assert sync_error.value.args == async_error.value.args
        assert str(sync_error.value) == str(async_error.value)
        assert sync_error.value.kind == async_error.value.kind
        assert sync_error.value.code == async_error.value.code


class TestTheCredentialIsAttachedPerRequest:
    def test_a_credential_set_after_the_client_was_built_is_used(self) -> None:
        """The reason the header is not set on the ``httpx.Client``.

        The obvious implementation puts it in ``httpx.Client(headers=...)`` once.
        It is cheaper and it is wrong for the case this package exists to serve: a
        long-lived worker holds a credential that expires, and a client that
        captured it at construction cannot be given a new one without being thrown
        away.
        """
        client, sent = sync_client(json_response(200, {"id": "u", "email": "a@b.test"}))
        client.set_token("cafaye_TESTONLY-first")
        client.identity.get_current_user()
        assert sent[0].headers["authorization"] == "Bearer cafaye_TESTONLY-first"

        client.set_token("cafaye_TESTONLY-second")
        client.identity.get_current_user()
        assert sent[1].headers["authorization"] == "Bearer cafaye_TESTONLY-second"

    def test_removing_it_stops_the_header_being_sent(self) -> None:
        client, sent = sync_client(json_response(200, {"id": "u", "email": "a@b.test"}))
        client.set_token("cafaye_TESTONLY-x")
        client.identity.get_current_user()
        client.set_token(None)
        client.identity.get_current_user()
        assert "authorization" in sent[0].headers
        assert "authorization" not in sent[1].headers

    def test_the_classified_kind_is_kept_in_step_with_the_value(self) -> None:
        client, _ = sync_client(json_response(200, {}), token="cafaye_TESTONLY-x")
        assert client.credential_kind == "api_token"
        client.set_token("TESTONLY-not-a-jwt")
        assert client.credential_kind == "session"

    def test_a_default_header_the_caller_supplied_is_kept(self) -> None:
        """A caller who passed their own ``Authorization`` has said which
        credential they mean, and the client does not overrule them."""
        import cafaye

        sent: list[httpx.Request] = []

        body: dict[str, Any] = {"id": "u", "email": "a@b.test"}

        def record(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return httpx.Response(200, json=body)

        caller_header = {"Authorization": "Bearer the-callers-own"}

        with cafaye.Cafaye(
            base_url=BASE,
            token="cafaye_TESTONLY-client",
            headers=caller_header,
            transport=httpx.MockTransport(record),
        ) as client:
            client.identity.get_current_user()
        assert sent[0].headers["authorization"] == "Bearer the-callers-own"


class TestWhereRequestsGo:
    def test_the_path_placeholders_are_completed_and_the_rest_becomes_the_query(self) -> None:
        """The mechanism, directly.

        ``httpx`` does **not** substitute ``{name}`` in a path. Given
        ``https://x/v1/accounts/{account_id}`` and ``params={"account_id": "a"}``
        it produces ``https://x/v1/accounts/%7Baccount_id%7D?account_id=a`` -- the
        braces percent-encoded and the identifier in a query string nothing reads.
        Nine of the twenty operations have a path parameter, so this is not an edge
        case, and a mock transport does not notice because a mock answers any URL.
        """
        url, query = _resolve_path("https://x/v1/accounts/{account_id}/keys", {"account_id": "a"})
        assert url == "https://x/v1/accounts/a/keys"
        assert query == {}

    def test_what_is_not_in_the_path_stays_in_the_query(self) -> None:
        url, query = _resolve_path(
            "https://x/v1/accounts/{account_id}/keys", {"account_id": "a", "limit": 10}
        )
        assert url == "https://x/v1/accounts/a/keys"
        assert query == {"limit": 10}

    def test_two_placeholders_are_both_completed(self) -> None:
        url, query = _resolve_path("https://x/{a}/{b}", {"a": "1", "b": "2"})
        assert url == "https://x/1/2"
        assert query == {}

    def test_a_path_parameter_is_percent_encoded_strictly(self) -> None:
        """``a/b`` must not become two segments, and ``a?b=c`` must not become a
        query string. Either would reach a route the caller did not name, and the
        failure would be a 404 that mentions nothing about the parameter."""
        url, _query = _resolve_path("https://x/{p}", {"p": "a/b?c=d#e"})
        assert url == "https://x/a%2Fb%3Fc%3Dd%23e"

    def test_a_parameter_named_in_neither_place_is_still_a_query_parameter(self) -> None:
        """Nothing is dropped. A name the path does not use is a query parameter,
        and guessing otherwise would lose it."""
        _url, query = _resolve_path("https://x/v1/me", {"cursor": "opaque"})
        assert query == {"cursor": "opaque"}

    def test_no_parameters_at_all(self) -> None:
        assert _resolve_path("https://x/v1/me", None) == ("https://x/v1/me", {})

    def test_an_empty_mapping_is_the_same_as_none(self) -> None:
        assert _resolve_path("https://x/v1/me", {}) == ("https://x/v1/me", {})

    def test_a_path_prefix_on_the_base_url_is_kept(self) -> None:
        """A self-hoster may serve the whole fleet under ``/cafaye``, and
        ``urlsplit(...).netloc`` would helpfully and wrongly throw it away."""
        client, sent = sync_client(
            json_response(200, {"id": "u", "email": "a@b.test"}),
            base_url="https://gateway.example.test/cafaye",
        )
        client.identity.get_current_user()
        assert sent[0].url.path == "/cafaye/v1/me"


class TestTheDeadline:
    def test_the_default_is_thirty_seconds(self) -> None:
        """Long enough that no operation in identity's document would ever reach
        it, short enough that a wedged service is reported rather than inherited."""
        assert DEFAULT_TIMEOUT == 30.0
        client, _ = sync_client(json_response(200, {}))
        assert client._client.timeout.read == 30.0

    def test_none_disables_it(self) -> None:
        client, _ = sync_client(json_response(200, {}))
        with_timeout = Cafaye(
            base_url=BASE,
            timeout=None,
            transport=httpx.MockTransport(lambda _r: json_response(200, {})),
        )
        assert with_timeout._client.timeout.read is None
        assert client is not None

    def test_zero_is_accepted_and_is_not_the_same_as_negative(self) -> None:
        """httpx reads ``0`` as "no timeout" and a negative value as a timer delay
        the platform will act on much later. Only the second is refused."""
        client = Cafaye(
            base_url=BASE,
            timeout=0,
            transport=httpx.MockTransport(lambda _r: json_response(200, {})),
        )
        assert client._client.timeout.read == 0

    @pytest.mark.parametrize("bad", [-1, -0.5, float("nan"), float("inf"), -float("inf")])
    def test_a_bad_deadline_is_refused_in_the_constructor(self, bad: float) -> None:
        """Before a request exists, which is the only moment anybody can still do
        something about it."""
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url=BASE, timeout=bad)
        assert caught.value.source == "timeout"
        assert "timeout" in str(caught.value)

    @pytest.mark.parametrize("bad", ["30", [30], {"seconds": 30}, object()])
    def test_a_non_numeric_deadline_is_refused(self, bad: object) -> None:
        with pytest.raises(CafayeConfigurationError):
            Cafaye(base_url=BASE, timeout=bad)  # type: ignore[arg-type]

    def test_a_boolean_is_not_a_number_of_seconds(self) -> None:
        """``True`` is an ``int`` and would otherwise mean one second."""
        with pytest.raises(CafayeConfigurationError):
            Cafaye(base_url=BASE, timeout=True)

    def test_the_message_never_quotes_the_value(self) -> None:
        """It is a number, so this is about the habit rather than the risk: the
        rule this package holds everywhere is that a message never quotes what a
        caller supplied."""
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url=BASE, timeout=-1)
        assert "-1" not in str(caught.value)


class TestTheContextManagers:
    def test_the_sync_face_closes_its_pool_on_exit(self) -> None:
        client, _ = sync_client(json_response(200, {}))
        with client as entered:
            assert entered is client
        assert client._client.is_closed

    def test_the_sync_face_closes_its_pool_on_an_exception_too(self) -> None:
        client, _ = sync_client(problem_response("unauthorized", 401))
        with pytest.raises(Exception), client:  # noqa: B017 - narrowed by the assert below
            client.identity.get_current_user()
        assert client._client.is_closed

    def test_the_async_face_closes_its_pool_on_exit(self) -> None:
        asynchronous, _ = async_client(json_response(200, {}))

        async def use() -> Any:
            async with asynchronous as entered:
                assert entered is asynchronous
            return asynchronous

        assert run(use()) is asynchronous
        assert asynchronous._client.is_closed

    def test_the_async_face_closes_its_pool_on_an_exception_too(self) -> None:
        asynchronous, _ = async_client(problem_response("unauthorized", 401))

        async def use() -> None:
            async with asynchronous:
                await asynchronous.identity.get_current_user()

        with pytest.raises(Exception):  # noqa: B017 - narrowed by the assert below
            run(use())
        assert asynchronous._client.is_closed

    def test_close_is_callable_directly_on_both_faces(self) -> None:
        client, _ = sync_client(json_response(200, {}))
        client.close()
        assert client._client.is_closed

        asynchronous, _ = async_client(json_response(200, {}))
        run(asynchronous.aclose())
        assert asynchronous._client.is_closed


class TestBothFacesAreTheSameClassUpToTheTransport:
    def test_they_share_the_base_and_differ_in_exactly_the_transport(self) -> None:
        from cafaye._client import _BaseCafaye

        assert issubclass(Cafaye, _BaseCafaye)
        assert issubclass(AsyncCafaye, _BaseCafaye)
        sync_only = set(vars(Cafaye)) - set(vars(_BaseCafaye)) - set(vars(AsyncCafaye))
        async_only = set(vars(AsyncCafaye)) - set(vars(_BaseCafaye)) - set(vars(Cafaye))
        # `_perform` against `_aperform`, and the context-manager protocol. The
        # point of the assertion is that there is no *third* difference hiding in
        # there: a lifecycle method that only one face has is exactly the drift
        # this package's design exists to prevent.
        assert "_perform" in sync_only
        assert "_aperform" in async_only
        assert not (sync_only & async_only) - {"__init__"}

    def test_a_sync_client_given_an_async_transport_says_so_on_the_first_request(self) -> None:
        """A caller mistake, reported with a sentence about the mistake.

        The transport is not inspected at construction -- ``httpx`` does not look
        at it until it is used -- so this surfaces on the first request rather
        than in the constructor. Asserting where it *actually* surfaces is more
        useful than asserting where it would be nicer if it surfaced.

        A transport that is genuinely async-only, rather than
        ``httpx.MockTransport`` (which implements both and therefore produces a
        coroutine the sync client never awaits -- and an unraisable-exception
        warning at interpreter shutdown, which ``filterwarnings = ["error"]``
        would turn into a confusing failure somewhere else entirely).
        """
        import httpx as _httpx

        class AsyncOnly(_httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: _httpx.Request) -> _httpx.Response:
                return _httpx.Response(200, json={})

        client = Cafaye(base_url=BASE, transport=cast("httpx.BaseTransport", AsyncOnly()))
        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()

        # The interesting half is `reason`. A transport missing the method the
        # client called is not a DNS failure, not a refused connection and not a
        # timeout, and the honest answer is `unknown` -- "this package could not
        # tell what happened". Calling it a connection failure would be a lie to
        # whatever is deciding whether to retry.
        assert caught.value.reason == "unknown"
        assert caught.value.status is None
        assert "AsyncOnly" in str(caught.value)


class TestTheReprSaysWhatItHoldsAndNotWhatItIs:
    def test_the_base_urls_are_visible_because_they_are_not_secret(self) -> None:
        client, _ = sync_client(json_response(200, {}), base_url="https://identity.example.test")
        assert "identity.example.test" in repr(client)

    def test_the_credential_is_described_and_never_quoted(self) -> None:
        for token, kind in (
            ("cafaye_TESTONLY-x", "api_token"),
            ("TESTONLY-not-a-jwt", "session"),
        ):
            client, _ = sync_client(json_response(200, {}), token=token)
            text = repr(client)
            assert token not in text
            assert kind in text
            assert "credential=<" in text

    def test_a_client_with_no_credential_says_so(self) -> None:
        client, _ = sync_client(json_response(200, {}))
        assert "no credential" in repr(client)

    def test_str_is_the_same_as_repr(self) -> None:
        """``Exception.__str__`` falls back to ``__repr__``, so a stray ``print``
        or an f-string in a log line cannot reach a different path."""
        client, _ = sync_client(json_response(200, {}), token="cafaye_TESTONLY-x")
        assert str(client) == repr(client)


class TestTheServiceListIsOneList:
    """``SERVICE_NAMES`` and the services that actually have a module.

    Stated once in ``_base_url.py`` and asserted here, because the failure this
    rules out is a six-of-six client that reports success while one service is
    missing. A name with no module resolves a base URL and then has nothing to
    send it to.
    """

    def test_every_declared_service_resolves_and_the_order_is_the_documented_one(self) -> None:
        from cafaye import SERVICE_NAMES

        assert SERVICE_NAMES == ("identity", "billing", "courier", "darkroom", "muse", "pantry")

    def test_the_only_service_with_a_module_is_identity_and_the_says_so(self) -> None:
        """One module today, and that is a stated fact rather than an accident.

        The brief asks for a typed service client "per service that has a document",
        and only identity's operations are in this package. When the second lands,
        this test is the one that has to change, which is the point: it fails in
        the place where the omission is.
        """
        import pkgutil

        import cafaye._services as services

        found = sorted(name for _finder, name, _ispkg in pkgutil.iter_modules(services.__path__))
        assert found == ["identity"]

    def test_every_service_resolves_to_a_url_whether_or_not_it_has_a_client(self) -> None:
        from cafaye import SERVICE_NAMES

        client, _ = sync_client(json_response(200, {}))
        assert set(client.base_urls) == set(SERVICE_NAMES)
        assert set(client.base_url_sources) == set(SERVICE_NAMES)


class TestTheConfigurationErrorsArriveBeforeAnyRequest:
    def test_a_blank_credential_is_refused_and_never_quoted(self) -> None:
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url=BASE, token="")
        assert caught.value.source == "token"

    def test_a_credential_with_a_control_character_is_refused(self) -> None:
        for bad in ("cafaye_a\r\nX-Evil: 1", "cafaye_a b", "cafaye_a\x00", "cafaye_a\x7f"):
            with pytest.raises(CafayeConfigurationError):
                Cafaye(base_url=BASE, token=bad)

    def test_the_refusal_names_the_character_count_and_not_the_character(self) -> None:
        """A character class is a fingerprint. How many are wrong is diagnosis;
        which ones is a hint about whatever produced them.

        Two distinct characters, so the count is two -- and the set is
        deduplicated, because five spaces are one problem.
        """
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url=BASE, token="cafaye_a b\tc")
        message = str(caught.value)
        assert "2 (names withheld" in message
        # The count is diagnosis; the *names* are a fingerprint of whatever
        # produced them. The message does discuss the class in prose -- it has to,
        # to say why it is refusing -- so the assertion is that no individual
        # character is quoted, not that the words never appear.
        assert "\t" not in message
        assert "names withheld" in message

    def test_one_bad_character_is_counted_once_however_often_it_appears(self) -> None:
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url=BASE, token="cafaye_a b")
        assert "1 (names withheld" in str(caught.value)

    def test_a_malformed_base_url_is_refused_before_a_client_exists(self) -> None:
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url="identity.example.test")
        assert caught.value.source == "the `base_url` argument"

    def test_a_timeout_error_and_a_base_url_error_are_distinguishable(self) -> None:
        """``source`` names which option was wrong, so a deployment can act on it."""
        with pytest.raises(CafayeConfigurationError) as timeout_error:
            Cafaye(base_url=BASE, timeout=-1)
        with pytest.raises(CafayeConfigurationError) as url_error:
            Cafaye(base_url="not a url")
        assert timeout_error.value.source == "timeout"
        assert url_error.value.source != "timeout"


class TestANetworkFailureCarriesTheErrnoAndNotTheMessage:
    def test_the_cause_is_the_platform_error_so_the_errno_survives(self) -> None:
        """``httpx.ConnectError("[Errno 8] connect error")`` says almost nothing,
        and the difference between a refused connection and a name that did not
        resolve is one level down."""
        failure = httpx.ConnectError("[Errno 61] Connection refused")
        failure.__cause__ = ConnectionRefusedError(61, "Connection refused")
        client, _ = sync_client(failure)

        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        assert caught.value.errno == 61

        # The errno is on the error itself, and it is *also* reachable by walking
        # the cause chain -- which is the point of keeping the cause at all. Note
        # that it is two levels down, not one: httpx's `ConnectError` carries no
        # `errno` of its own, the `ConnectionRefusedError` it wraps does, and
        # `classify_network_failure` walks the chain to find it. A client that
        # only looked one level down would find `None`.
        chain: list[BaseException] = []
        current: BaseException | None = caught.value.__cause__
        while current is not None and len(chain) < 8:
            chain.append(current)
            following = current.__cause__ or current.__context__
            current = following if isinstance(following, BaseException) else None
        assert [getattr(link, "errno", None) for link in chain] == [None, 61]

    def test_the_context_chain_is_empty_so_the_original_cannot_be_reached(self) -> None:
        """The bug this shape exists for.

        Raising from inside the ``except`` left the original ``httpx.ConnectError``
        reachable as ``__context__`` -- a fully populated object with the
        credential in its ``args``, which ``traceback`` renders in full for any
        logger configured with ``exc_info``. Redacting ``__cause__`` was not
        enough; the whole context chain has to be gone, which is why the raise
        happens outside the handler.
        """
        failure = httpx.ConnectError("[Errno 61] Connection refused")
        failure.__cause__ = ConnectionRefusedError(61, "Connection refused")
        client, _ = sync_client(failure)

        with pytest.raises(CafayeNetworkError) as caught:
            client.identity.get_current_user()
        assert caught.value.__context__ is None
        assert not isinstance(caught.value.__context__, httpx.HTTPError)

    def test_a_timeout_is_its_own_class_and_still_a_network_error(self) -> None:
        client, _ = sync_client(httpx.ReadTimeout("t"))
        with pytest.raises(CafayeTimeoutError) as caught:
            client.identity.get_current_user()
        assert isinstance(caught.value, CafayeNetworkError)
        assert caught.value.status is None

    def test_the_same_failure_on_both_faces_produces_the_same_class(self) -> None:
        sync, _ = sync_client(httpx.ConnectTimeout("t"))
        asynchronous, _ = async_client(httpx.ConnectTimeout("t"))
        with pytest.raises(CafayeTimeoutError) as sync_error:
            sync.identity.get_current_user()
        with pytest.raises(CafayeTimeoutError) as async_error:
            run(asynchronous.identity.get_current_user())
        assert type(sync_error.value) is type(async_error.value)
        assert sync_error.value.reason == async_error.value.reason


class TestAServiceThatAnswersSomethingElseEntirely:
    @pytest.mark.parametrize(
        "body",
        [["not", "an", "object"], "a string", 7],
        ids=["array", "string", "number"],
    )
    def test_a_body_that_is_not_an_object_decodes_to_an_empty_model(self, body: object) -> None:
        """Not an exception, and the reason is worth being precise about.

        ``from_mapping`` is the one shared guard, and it exists so that "a gateway
        answered a health check with a JSON array" produces an empty ``Health``
        rather than an ``AttributeError`` three frames from the mistake. A typed
        client that raised here would be stopping a caller over a *wrong answer*,
        which is a different and much rarer fault: an empty model is a legible
        "the service said nothing useful", and the caller can see that for
        themselves in ``health.status == ""``.

        The exception is reserved for the two cases where stopping is right: a
        2xx whose body is a problem document, and a 2xx with no body at all where
        one was declared. Both are elsewhere in this file and in
        ``test_errors.py``.
        """
        client, _ = sync_client(json_response(200, body))
        health = client.identity.liveness()
        assert health.status == ""
        assert health.deps is None

    def test_an_empty_health_check_body_is_a_protocol_error_rather_than_an_empty_health(
        self,
    ) -> None:
        from cafaye import CafayeProtocolError

        client, _ = sync_client(httpx.Response(200))
        with pytest.raises(CafayeProtocolError):
            client.identity.liveness()

    def test_a_json_body_that_is_not_utf8_falls_back_to_its_repr(self) -> None:
        """ "No excerpt" and "no excerpt available" are different, and the second is
        worth saying."""
        from cafaye import CafayeProtocolError

        response = httpx.Response(
            500, content=b"\xff\xfe\x00binary", headers={"content-type": "text/html"}
        )
        client, _ = sync_client(response)
        with pytest.raises(CafayeProtocolError) as caught:
            client.identity.get_current_user()
        assert caught.value.body_snippet is not None

    def test_a_redirect_is_not_followed(self) -> None:
        """Following one is how a credential reaches a host nobody vetted, and the
        credential is already attached to the request by the time a redirect is
        read."""
        client, sent = sync_client(
            httpx.Response(302, headers={"location": "https://elsewhere.test/"})
        )
        with pytest.raises(Exception):  # noqa: B017 - a 302 is not a success
            client.identity.get_current_user()
        assert sent[0].url.host == "identity.example.test"
        assert client._client.follow_redirects is False

    def test_a_response_whose_body_is_a_json_string(self) -> None:
        """A body of ``"..."`` decodes to a ``str``, and ``from_mapping`` turns that
        into an empty model rather than an ``AttributeError``."""
        client, _ = sync_client(json_response(200, "a string"))
        assert client.identity.get_current_user().id == ""


class TestTheServiceCountIsTheDocumentsCount:
    """identity's document, read here rather than vendored.

    This repository does not vendor the OpenAPI documents — ``cafaye-ts`` does,
    because a generator needs the bytes. What it does instead is state the count
    and the names, and assert the client's table against that statement. When
    identity's document grows an operation, this test is the first thing that
    should be updated, and the failure says so.
    """

    def test_twenty_operations_and_the_table_agrees(self) -> None:
        from cafaye._services.identity import IDENTITY_OPERATIONS

        assert len(IDENTITY_OPERATIONS) == 20
        assert len(CALLS) == 20, "the parity table above is missing an operation"

    def test_every_operation_in_the_table_is_exercised_by_the_parity_tests(self) -> None:
        from cafaye._services.identity import IDENTITY_OPERATIONS

        assert {c[0] for c in CALLS} == set(IDENTITY_OPERATIONS)

    def test_the_json_bodies_the_parity_table_uses_are_the_shapes_the_models_expect(self) -> None:
        """So a wrong fixture fails here, with a sentence, rather than as a
        confusing equality failure in the parity test."""
        from cafaye._services.identity import IDENTITY_OPERATIONS

        for name, _args, body, expected in CALLS:
            if body is None:
                assert IDENTITY_OPERATIONS[name].model is None, name
                continue
            decoded = json.loads(json.dumps(body))
            assert isinstance(decoded, dict), name
            assert expected is not None, name
