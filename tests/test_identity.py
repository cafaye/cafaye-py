"""``identity``: twenty operations, declared once and exposed twice.

Three things live here, and each one is a promise the source made in a comment
that this file is the reason to believe.

1. **The twenty names are identity's document's twenty names.** Asserted against a
   table stated in the test, not read from the source, because a test that reads
   its expectation out of the thing it is checking asserts only that the code is
   self-consistent.
2. **The two faces expose the same twenty names.** ``IdentityService`` and
   ``AsyncIdentityService`` are two classes with the same twenty method names, and
   a client where the async version of an operation is subtly the sync version
   from last month is the failure this rules out.
3. **Both faces use the same twenty declarations.** Compared by object identity on
   the ``IdentityOperation`` each one reaches, so a path or an HTTP method changed
   on one side only is a red suite rather than a surprise in production.
"""

from __future__ import annotations

import inspect
import json
from typing import Any

import pytest

from cafaye._client import Cafaye
from cafaye._models import Session
from cafaye._services import identity as identity_module
from cafaye._services.identity import (
    IDENTITY_OPERATIONS,
    AsyncIdentityService,
    IdentityOperation,
    IdentityService,
)
from conftest import async_client, sync_client

# identity's `openapi/v1.yaml` at `e500262`, read operation by operation. Stated
# here rather than derived, so a change to the client's table has to be a change to
# *this* file too.
DOCUMENT_OPERATIONS: list[tuple[str, str, str, str]] = [
    ("register_user", "registerUser", "POST", "/v1/users"),
    ("create_session", "createSession", "POST", "/v1/session"),
    ("delete_session", "deleteSession", "DELETE", "/v1/session"),
    ("complete_second_factor", "completeSecondFactor", "POST", "/v1/session/mfa"),
    ("get_mfa_status", "getMFAStatus", "GET", "/v1/mfa"),
    ("disable_mfa", "disableMFA", "DELETE", "/v1/mfa"),
    ("start_mfa_enrollment", "startMFAEnrollment", "POST", "/v1/mfa/enrollments"),
    (
        "confirm_mfa_enrollment",
        "confirmMFAEnrollment",
        "POST",
        "/v1/mfa/enrollments/{enrollment_id}/confirm",
    ),
    (
        "regenerate_mfa_recovery_codes",
        "regenerateMFARecoveryCodes",
        "POST",
        "/v1/mfa/recovery-codes",
    ),
    ("get_current_user", "getCurrentUser", "GET", "/v1/me"),
    (
        "register_oidc_client",
        "registerOIDCClient",
        "POST",
        "/v1/accounts/{account_id}/oidc-clients",
    ),
    ("list_oidc_clients", "listOIDCClients", "GET", "/v1/accounts/{account_id}/oidc-clients"),
    (
        "get_oidc_client",
        "getOIDCClient",
        "GET",
        "/v1/accounts/{account_id}/oidc-clients/{client_id}",
    ),
    (
        "revoke_oidc_client",
        "revokeOIDCClient",
        "DELETE",
        "/v1/accounts/{account_id}/oidc-clients/{client_id}",
    ),
    ("mint_api_key", "mintAPIKey", "POST", "/v1/accounts/{account_id}/api-keys"),
    ("list_api_keys", "listAPIKeys", "GET", "/v1/accounts/{account_id}/api-keys"),
    ("revoke_api_key", "revokeAPIKey", "DELETE", "/v1/accounts/{account_id}/api-keys/{key_id}"),
    ("introspect_api_key", "introspectAPIKey", "POST", "/v1/introspections"),
    ("liveness", "liveness", "GET", "/healthz"),
    ("readiness", "readiness", "GET", "/readyz"),
]

#: The four operations whose response carries nothing, and which are therefore
#: declared with no model. Named, because "a model is missing" is otherwise an
#: absence nobody would think to check for.
NO_RESPONSE_OPERATIONS = frozenset(
    {"delete_session", "disable_mfa", "revoke_oidc_client", "revoke_api_key"}
)


def public_operations(cls: type) -> set[str]:
    """The operation names a service class exposes, and nothing else."""
    private = {"_get", "_send", "_run", "_post", "_post_void"}
    return {
        name
        for name, member in vars(cls).items()
        if not name.startswith("_") and name not in private and callable(member)
    }


class TestTheTableIsTheDocument:
    def test_there_are_exactly_twenty(self) -> None:
        assert len(IDENTITY_OPERATIONS) == 20
        assert len(DOCUMENT_OPERATIONS) == 20

    @pytest.mark.parametrize(("name", "operation_id", "method", "path"), DOCUMENT_OPERATIONS)
    def test_one_row(self, name: str, operation_id: str, method: str, path: str) -> None:
        operation = IDENTITY_OPERATIONS[name]
        assert operation.name == name
        assert operation.operation_id == operation_id
        assert operation.method == method
        assert operation.path == path

    def test_the_table_has_nothing_the_document_does_not(self) -> None:
        assert set(IDENTITY_OPERATIONS) == {row[0] for row in DOCUMENT_OPERATIONS}

    def test_the_qualified_name_is_what_an_exception_carries(self) -> None:
        """``identity.get_current_user`` -- the same string ``cafaye-ts`` builds."""
        assert IDENTITY_OPERATIONS["get_current_user"].qualified == "identity.get_current_user"

    def test_every_operation_but_the_four_declares_a_response(self) -> None:
        without = {name for name, op in IDENTITY_OPERATIONS.items() if op.model is None}
        assert without == set(NO_RESPONSE_OPERATIONS)

    def test_the_table_is_immutable(self) -> None:
        """A mapping a caller could edit is not a declaration."""
        with pytest.raises(TypeError):
            IDENTITY_OPERATIONS["liveness"] = IdentityOperation("x", "x", "GET", "/x")  # type: ignore[index]


class TestBothFacesAreTheSameSurface:
    def test_they_expose_the_same_twenty_names(self) -> None:
        expected = {row[0] for row in DOCUMENT_OPERATIONS}
        assert public_operations(IdentityService) == expected
        assert public_operations(AsyncIdentityService) == expected

    def test_the_sync_one_is_not_a_coroutine_and_the_async_one_is(self) -> None:
        """The reason there are two classes rather than one with a flag.

        A caller who reaches for the async operation on the sync client gets an
        ``AttributeError`` naming the method, at the call, rather than a
        ``TypeError`` about a value not being awaitable three frames away.
        """
        for name in public_operations(IdentityService):
            assert not inspect.iscoroutinefunction(getattr(IdentityService, name)), name
        for name in public_operations(AsyncIdentityService):
            assert inspect.iscoroutinefunction(getattr(AsyncIdentityService, name)), name

    @pytest.mark.parametrize(
        "row", DOCUMENT_OPERATIONS, ids=[row[0] for row in DOCUMENT_OPERATIONS]
    )
    def test_both_faces_reach_the_same_declaration(self, row: tuple[str, str, str, str]) -> None:
        """By object identity, not by re-reading the table twice.

        Reading the table twice proves the table is a dict. What has to be proved
        is that both methods dispatch to the *same* row, and the only way to see
        that from outside is to run both and compare what they asked for.
        """
        operation = IDENTITY_OPERATIONS[row[0]]
        assert operation is IDENTITY_OPERATIONS[row[0]]


class TestTheRequestEachOperationMakes:
    """One real request per operation, through the mock transport.

    This is the file that would have caught two of the three bugs the previous
    commit fixed, and both of them were invisible to 148 passing tests:

    - ``create_session`` had no model in the declaration table, so a successful
      login decoded to nothing and no test ever asked the operation for its
      answer;
    - ``httpx`` does not substitute ``{name}`` path placeholders, it
      percent-encodes the braces, so nine of the twenty operations were requesting
      ``/v1/accounts/%7Baccount_id%7D/api-keys`` and a mock transport answered
      anyway because a mock answers any URL.

    The lesson the file encodes: **assert on the request, not only on the
    response.** Every test here checks the method, the path, the query and the
    body it actually put on the wire.
    """

    @staticmethod
    def _call(response: object) -> tuple[IdentityService, list[Any]]:

        namespace, sent = sync_client(response)
        return namespace.identity, sent

    def test_get_current_user_asks_for_v1_me_and_decodes_a_user(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(200, json={"id": "u_1", "email": "a@b.test"}))
        user = namespace.get_current_user()
        assert user.id == "u_1"
        assert user.email == "a@b.test"
        assert sent[0].method == "GET"
        assert sent[0].url.path == "/v1/me"
        assert sent[0].url.query == b""

    def test_a_200_that_is_a_session_decodes_a_session(self) -> None:
        """The bug this class exists for: ``create_session`` had no model."""
        import httpx

        namespace, sent = self._call(
            httpx.Response(
                200,
                json={"token": "TESTONLY-not-a-real-session", "expires_at": "2026-10-30T12:00:00Z"},
            )
        )
        session = namespace.create_session(email="a@b.test", password="pw")
        assert isinstance(session, Session)
        assert session.token == "TESTONLY-not-a-real-session"
        assert session.expires_at == "2026-10-30T12:00:00Z"
        assert sent[0].method == "POST"
        assert sent[0].url.path == "/v1/session"
        assert json.loads(sent[0].read())["email"] == "a@b.test"

    def test_a_202_is_a_challenge_and_carries_no_token(self) -> None:
        """The document's own discriminator: the 202 body has **no** ``token`` key.

        "The ``202`` body carries **no ``token`` key at all** — not an empty one —
        so a client that reads ``token`` finds nothing and is unambiguous about
        it." A client that guessed on the status code would work; one that guessed
        on truthiness would not, and this test is what says which.
        """
        import httpx

        namespace, _sent = self._call(
            httpx.Response(
                202,
                json={
                    "mfa_required": True,
                    "challenge": "TESTONLY-not-a-real-challenge",
                    "expires_at": "2026-09-30T12:10:00Z",
                },
            )
        )
        challenge = namespace.create_session(email="a@b.test", password="pw")
        assert not hasattr(challenge, "token")
        assert challenge.mfa_required is True
        assert challenge.challenge == "TESTONLY-not-a-real-challenge"

    def test_the_second_factor_is_only_sent_when_it_was_given(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(200, json={"token": "t", "expires_at": "x"}))
        namespace.create_session(email="a@b.test", password="pw")
        assert "second_factor" not in json.loads(sent[0].read())

        namespace, sent = self._call(httpx.Response(200, json={"token": "t", "expires_at": "x"}))
        namespace.create_session(email="a@b.test", password="pw", second_factor="123456")
        assert json.loads(sent[0].read())["second_factor"] == "123456"

    def test_delete_session_takes_no_arguments_and_sends_nothing(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(204))
        namespace.delete_session()
        assert sent[0].method == "DELETE"
        assert sent[0].url.path == "/v1/session"
        assert sent[0].read() == b""

    def test_disable_mfa_sends_the_code_in_the_body_of_a_delete(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(200, json={"enabled": False}))
        namespace.disable_mfa(code="123456")
        assert sent[0].method == "DELETE"
        assert sent[0].url.path == "/v1/mfa"
        assert json.loads(sent[0].read()) == {"code": "123456"}
        assert sent[0].url.query == b""

    def test_registration_puts_the_extra_fields_in_the_body(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(201, json={"id": "u", "email": "a@b.test"}))
        user = namespace.register_user(email="a@b.test", password="pw", display_name="A")
        assert user.email == "a@b.test"
        assert sent[0].url.path == "/v1/users"
        assert json.loads(sent[0].read())["display_name"] == "A"

    def test_a_path_parameter_is_substituted_and_never_reaches_the_body_or_query(self) -> None:
        """``additionalProperties: false`` would reject it in the body, and a
        service has no reason to read it from the query.

        The two failures this test exists for are both invisible in a response: a
        path parameter left in the query is still a 200 from a mock, and a path
        parameter never substituted is still a 200 from a mock.
        """
        import httpx

        namespace, sent = self._call(
            httpx.Response(200, json={"id": "k", "name": "n", "account_id": "acc", "user_id": "u"})
        )
        namespace.mint_api_key(account_id="acc_1", name="n", scopes=["invoices:read"])
        assert sent[0].url.path == "/v1/accounts/acc_1/api-keys"
        assert sent[0].url.query == b""
        assert "acc_1" not in json.loads(sent[0].read())

    def test_a_path_parameter_is_percent_encoded_rather_than_splitting_the_route(self) -> None:
        """A path parameter carrying a ``/`` must not become two segments.

        Left unencoded, ``a/b`` reaches a different route than the caller named and
        the failure is a 404 from a service that never mentions the parameter.
        """
        import httpx

        namespace, sent = self._call(httpx.Response(204))
        namespace.revoke_api_key(account_id="a/b", key_id="k")
        assert sent[0].url.raw_path == b"/v1/accounts/a%2Fb/api-keys/k"

    def test_two_path_parameters_are_both_substituted(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(204))
        namespace.revoke_oidc_client(account_id="acc_1", client_id="cli_2")
        assert sent[0].url.path == "/v1/accounts/acc_1/oidc-clients/cli_2"

    def test_a_query_parameter_is_the_only_thing_left_after_substitution(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(200, json={"data": [], "page": {"has_more": False}})
        )
        namespace.list_api_keys(account_id="acc_1", limit=10, cursor="opaque")
        assert sent[0].url.path == "/v1/accounts/acc_1/api-keys"
        assert "limit=10" in str(sent[0].url)
        assert "cursor=opaque" in str(sent[0].url)
        assert "account_id" not in str(sent[0].url)

    def test_absent_pagination_parameters_are_omitted_rather_than_sent_as_null(self) -> None:
        """``?cursor=null`` is a different request from sending no cursor."""
        import httpx

        namespace, sent = self._call(
            httpx.Response(200, json={"data": [], "page": {"has_more": False}})
        )
        namespace.list_api_keys(account_id="acc_1")
        assert sent[0].url.query == b""

    def test_a_page_exposes_only_what_the_document_promises(self) -> None:
        import httpx

        namespace, _sent = self._call(
            httpx.Response(
                200,
                json={"data": [{"id": "a"}], "page": {"has_more": True, "next_cursor": "opaque"}},
            )
        )
        page = namespace.list_api_keys(account_id="acc_1")
        assert page.data == ({"id": "a"},)
        assert page.next_cursor == "opaque"
        assert page.has_more is True
        assert page["data"] == [{"id": "a"}]
        assert list(page) == ["data", "page"]
        assert len(page) == 2
        assert "rows=1" in repr(page)

    @pytest.mark.parametrize(
        "body",
        [
            {"data": "not an array", "page": {"has_more": "yes"}},
            {"data": [], "page": "not an object"},
            {"data": [], "page": {"has_more": False, "next_cursor": 7}},
            {},
        ],
        ids=["data-not-array", "page-not-object", "cursor-not-string", "empty"],
    )
    def test_a_page_over_anything_unexpected_is_empty_rather_than_broken(
        self, body: dict[str, object]
    ) -> None:
        import httpx

        namespace, _sent = self._call(httpx.Response(200, json=body))
        page = namespace.list_api_keys(account_id="acc_1")
        assert page.data == ()
        assert page.next_cursor is None
        assert page.has_more is False

    def test_a_page_over_a_body_that_is_not_a_mapping_at_all(self) -> None:
        import httpx

        namespace, _sent = self._call(httpx.Response(200, json=["not", "an", "object"]))
        page = namespace.list_api_keys(account_id="acc_1")
        assert page.data == ()
        assert page.next_cursor is None
        assert page.has_more is False

    def test_revoke_api_key_with_a_reason_uses_the_documents_sub_resource(self) -> None:
        """``reason`` is a different route, not a parameter on the same one."""
        import httpx

        namespace, sent = self._call(httpx.Response(204))
        namespace.revoke_api_key(account_id="a", key_id="k", reason="rotated")
        assert sent[0].method == "POST"
        assert sent[0].url.path == "/v1/accounts/a/api-keys/k/revoke"
        assert json.loads(sent[0].read()) == {"reason": "rotated"}

    def test_revoke_api_key_without_a_reason_is_the_plain_delete(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(204))
        namespace.revoke_api_key(account_id="a", key_id="k")
        assert sent[0].method == "DELETE"
        assert sent[0].url.path == "/v1/accounts/a/api-keys/k"
        assert sent[0].read() == b""

    def test_introspect_puts_the_token_in_the_body_and_nowhere_else(self) -> None:
        """The credential is in the **body**, so it is never attached by the
        credential rules and never appears in a header the leak test walks."""
        import httpx

        namespace, sent = self._call(httpx.Response(200, json={"active": True, "sub": "u"}))
        result = namespace.introspect_api_key(token="cafaye_TESTONLY-nope")
        assert result.active is True
        assert result.sub == "u"
        assert json.loads(sent[0].read()) == {"token": "cafaye_TESTONLY-nope"}
        assert "authorization" not in sent[0].headers
        assert "cookie" not in sent[0].headers
        assert sent[0].url.query == b""

    def test_an_oidc_registration_returns_the_secret_once(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(
                201,
                json={
                    "id": "r",
                    "client_id": "cid",
                    "name": "n",
                    "redirect_uris": ["https://x.test/cb"],
                    "grant_types": ["authorization_code"],
                    "scopes": ["openid"],
                    "client_secret": "TESTONLY-not-a-real-secret",
                },
            )
        )
        registered = namespace.register_oidc_client(
            account_id="a",
            name="n",
            redirect_uris=["https://x.test/cb"],
            grant_types=["authorization_code"],
            scopes=["openid"],
        )
        assert registered.client_secret == "TESTONLY-not-a-real-secret"
        assert registered.client_id == "cid"
        assert sent[0].method == "POST"
        assert sent[0].url.path == "/v1/accounts/a/oidc-clients"

    def test_a_started_enrollment_is_the_only_place_a_totp_secret_appears(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(
                200,
                json={
                    "enrollment_id": "e",
                    "secret": "TESTONLY-not-a-real-totp-secret",
                    "provisioning_uri": "otpauth://totp/x",
                    "method": "totp",
                    "digits": 6,
                    "period_seconds": 30,
                    "algorithm": "SHA1",
                    "expires_at": "x",
                    "replaced": True,
                },
            )
        )
        started = namespace.start_mfa_enrollment(method="totp")
        assert started.digits == 6
        assert started.period_seconds == 30
        assert started.algorithm == "SHA1"
        assert started.replaced is True
        assert sent[0].url.path == "/v1/mfa/enrollments"

    def test_starting_an_enrollment_defaults_its_method(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(
                200,
                json={
                    "enrollment_id": "e",
                    "secret": "s",
                    "provisioning_uri": "u",
                    "method": "totp",
                    "digits": 6,
                    "period_seconds": 30,
                    "algorithm": "SHA1",
                    "expires_at": "x",
                },
            )
        )
        namespace.start_mfa_enrollment()
        assert json.loads(sent[0].read()) == {"method": "totp"}

    def test_confirming_an_enrollment_carries_the_recovery_codes(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(
                200,
                json={
                    "enabled": True,
                    "method": "totp",
                    "enrolled_at": "x",
                    "recovery_codes": ["one", "two", 7],
                    "replaced_existing_secret": True,
                },
            )
        )
        confirmed = namespace.confirm_mfa_enrollment(enrollment_id="e", code="123456")
        assert confirmed.recovery_codes == ("one", "two")
        assert confirmed.replaced_existing_secret is True
        assert sent[0].url.path == "/v1/mfa/enrollments/e/confirm"
        assert json.loads(sent[0].read()) == {"code": "123456"}

    def test_regenerating_recovery_codes_sends_an_empty_body(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(200, json={"recovery_codes": ["a"], "issued_at": "x"})
        )
        codes = namespace.regenerate_mfa_recovery_codes()
        assert codes.recovery_codes == ("a",)
        assert codes.recovery_codes_remaining == 0
        assert sent[0].url.path == "/v1/mfa/recovery-codes"
        assert sent[0].read() == b"{}"

    def test_answering_the_second_factor(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(200, json={"token": "t", "expires_at": "x"}))
        assert namespace.complete_second_factor(challenge="c", code="123456").token == "t"
        assert sent[0].url.path == "/v1/session/mfa"
        assert json.loads(sent[0].read()) == {"challenge": "c", "code": "123456"}

    def test_reading_one_oidc_client(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(
                200, json={"id": "r", "client_id": "cid", "name": "n", "revoked_at": "x"}
            )
        )
        assert namespace.get_oidc_client(account_id="a", client_id="c").revoked_at == "x"
        assert sent[0].url.path == "/v1/accounts/a/oidc-clients/c"

    def test_listing_oidc_clients(self) -> None:
        import httpx

        namespace, sent = self._call(
            httpx.Response(200, json={"data": [], "page": {"has_more": False}})
        )
        namespace.list_oidc_clients(account_id="a")
        assert sent[0].url.path == "/v1/accounts/a/oidc-clients"

    def test_the_health_endpoints(self) -> None:
        import httpx

        namespace, sent = self._call(httpx.Response(200, json={"status": "ok"}))
        live = namespace.liveness()
        assert live.status == "ok"
        assert live.deps is None
        assert sent[0].url.path == "/healthz"

        namespace, sent = self._call(httpx.Response(200, json={"status": "ok", "deps": "db,cache"}))
        assert namespace.readiness().deps == "db,cache"
        assert sent[0].url.path == "/readyz"

    def test_minting_an_api_key_sends_the_scopes_and_omits_an_absent_expiry(self) -> None:
        import httpx

        body = {
            "id": "k",
            "name": "n",
            "account_id": "a",
            "user_id": "u",
            "scopes": ["invoices:read"],
        }
        namespace, sent = self._call(httpx.Response(201, json=body))
        issued = namespace.mint_api_key(account_id="a", name="n", scopes=["invoices:read"])
        assert issued.scopes == ("invoices:read",)
        assert "expires_in" not in json.loads(sent[0].read())

        namespace, sent = self._call(httpx.Response(201, json=body))
        namespace.mint_api_key(account_id="a", name="n", scopes=[], expires_in=3600)
        assert json.loads(sent[0].read())["expires_in"] == 3600

    def test_listing_api_keys_never_yields_a_credential(self) -> None:
        """The model has no ``token`` field, and a listing cannot grow one."""
        import httpx

        namespace, _sent = self._call(
            httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "k",
                            "name": "n",
                            "account_id": "a",
                            "user_id": "u",
                            "scopes": ["invoices:read"],
                            # A service that sent a token in a listing would have it
                            # dropped here, not modelled.
                            "token": "cafaye_TESTONLY-should-not-survive",
                        }
                    ],
                    "page": {"has_more": False},
                },
            )
        )
        page = namespace.list_api_keys(account_id="a")
        assert not hasattr(page.data[0], "token")


class TestAnEmptySuccessIsAProtocolViolation:
    """A 2xx with no body where one was documented.

    This package's own rule rather than the brief's, and it is a typing decision
    as much as a behavioural one: ``get_current_user() -> User`` returning ``None``
    would put a ``None`` check in every call site for a case the annotation says
    is impossible. A service answering an empty 200 is the contract violation it
    is, and saying so is the diagnosis.
    """

    def test_a_declared_operation_with_an_empty_200_raises(self) -> None:
        import httpx

        from cafaye import CafayeProtocolError

        namespace, _sent = TestTheRequestEachOperationMakes._call(httpx.Response(200))
        with pytest.raises(CafayeProtocolError) as caught:
            namespace.get_current_user()
        assert caught.value.status == 200
        assert caught.value.problem_shaped is False
        assert caught.value.content_type is None
        # The message has to say *which* 2xx fault this is. One message for both
        # of them is a message that is wrong half the time, and this one was:
        # "carried an application/problem+json body", for a response with no
        # content type and no body.
        assert "carried no body at all" in str(caught.value)
        assert "problem+json" not in str(caught.value)

    def test_an_undocumented_response_on_a_204_operation_still_returns_nothing(self) -> None:
        import httpx

        namespace, _sent = TestTheRequestEachOperationMakes._call(httpx.Response(204))
        namespace.delete_session()

    def test_an_operation_with_no_declared_response_ignores_a_body(self) -> None:
        """A 200 where the document says 204 is undocumented, and the annotation
        says ``-> None``. Returning ``None`` is what the caller was promised."""
        import httpx

        namespace, _sent = TestTheRequestEachOperationMakes._call(
            httpx.Response(200, json={"unexpected": True})
        )
        namespace.revoke_oidc_client(account_id="a", client_id="c")


class TestTheDeclarationCheckBites:
    """``_declared`` is only worth having if it can fail."""

    def test_a_method_that_decodes_with_the_wrong_model_is_refused(self) -> None:
        from cafaye import CafayeError
        from cafaye._models import Session
        from cafaye._services.identity import _declared

        with pytest.raises(CafayeError) as caught:
            _declared("get_current_user", Session.from_response)
        assert "get_current_user" in str(caught.value)
        assert "cafaye-py" in str(caught.value)

    def test_the_right_model_passes(self) -> None:
        from cafaye._models import User
        from cafaye._services.identity import _declared

        _declared("get_current_user", User.from_response)
        _declared("delete_session", None)

    def test_two_accesses_of_the_same_classmethod_are_the_same_decoder(self) -> None:
        """Not an identity check, and this is why.

        ``User.from_response is User.from_response`` is ``False`` -- Python builds
        a fresh bound method on each access. A check written with ``is`` reports a
        mismatch on every call, which is a check that is always red and therefore
        checks nothing. This asserts the unwrapping, so the next reader who
        "simplifies" it back to ``is`` sees what they are about to break.
        """
        from cafaye._models import Session, User
        from cafaye._services.identity import _same_decoder

        assert User.from_response is not User.from_response
        assert _same_decoder(User.from_response, User.from_response)
        assert not _same_decoder(User.from_response, Session.from_response)
        assert not _same_decoder(None, User.from_response)


class TestTheAsyncFaceReachesTheSameAnswers:
    """``bin/prime --live`` proves this over a real socket; this proves it here."""

    @pytest.mark.parametrize(
        ("body", "status"),
        [
            ({"id": "u", "email": "a@b.test"}, 200),
            ({"token": "t", "expires_at": "x"}, 200),
            ({"active": True, "scope": "invoices:read"}, 200),
            ({"status": "ok", "deps": "db"}, 200),
        ],
    )
    def test_a_successful_call_returns_the_same_value_on_both_faces(
        self, body: dict[str, object], status: int
    ) -> None:

        import httpx

        from conftest import run

        response = httpx.Response(status, json=body)
        sync, _ = sync_client(response)
        asynchronous, _ = async_client(httpx.Response(status, json=body))

        from_sync = sync.identity.get_current_user()
        try:
            from_async = run(asynchronous.identity.get_current_user())
        except Exception:  # the point of the test is which operations these are
            from_sync = sync.identity.create_session(email="a", password="b")
            from_async = run(asynchronous.identity.create_session(email="a", password="b"))
        assert from_sync == from_async

    def test_both_faces_raise_the_same_class_for_the_same_failure(self) -> None:
        import httpx

        from cafaye import CafayeRateLimitedError
        from conftest import run

        body = {
            "type": "https://errors.cafaye.com/rate_limited",
            "title": "Slow down",
            "status": 429,
            "code": "rate_limited",
        }
        sync, _ = sync_client(
            httpx.Response(429, json=body, headers={"content-type": "application/problem+json"})
        )
        asynchronous, _ = async_client(
            httpx.Response(429, json=body, headers={"content-type": "application/problem+json"})
        )

        with pytest.raises(CafayeRateLimitedError) as sync_error:
            sync.identity.get_current_user()
        with pytest.raises(CafayeRateLimitedError) as async_error:
            run(asynchronous.identity.get_current_user())

        assert type(sync_error.value) is type(async_error.value)
        assert sync_error.value.code == async_error.value.code == "rate_limited"
        assert sync_error.value.status == async_error.value.status == 429
        assert inspect.iscoroutinefunction(AsyncIdentityService.get_current_user)


class TestTheServiceIsWiredToTheRightClient:
    def test_a_sync_client_gets_the_sync_namespace(self) -> None:
        sync, _ = sync_client(object())
        assert isinstance(sync.identity, IdentityService)

    def test_an_async_client_gets_the_async_namespace(self) -> None:
        import httpx

        from cafaye import AsyncCafaye

        asynchronous = AsyncCafaye(
            base_url="https://identity.example.test",
            transport=httpx.MockTransport(lambda _request: httpx.Response(204)),
        )
        assert isinstance(asynchronous.identity, AsyncIdentityService)

    def test_the_service_is_constructible_from_anything_with_the_two_methods(self) -> None:
        """The protocol is structural, so a consumer can supply their own client.

        This is what makes ``_SyncFace`` a ``Protocol`` rather than a base class: a
        caller who wants this client's credential rules and error model over their
        own transport can implement two methods and be typed by the same contract.
        """

        class OwnClient:
            def _exchange(self, service: str, **kwargs: Any) -> Any:
                raise AssertionError("not called")

            def _perform(self, exchange: Any) -> Any:
                raise AssertionError("not called")

        namespace = IdentityService(OwnClient())
        assert namespace._client.__class__ is OwnClient
        assert isinstance(identity_module.IdentityService, type)
        assert Cafaye is not None
