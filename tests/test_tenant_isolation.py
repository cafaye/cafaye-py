"""Tenant isolation, measured as negative tests. Following darkroom-09.

WHAT THIS PACKET MEASURED, AND WHAT IT FOUND
--------------------------------------------
D18 measured cross-tenant **negative** tests across the fleet: identity 7, courier
19, cafaye-py **0**. This file is the cafaye-py half of that number.

THE ENUMERATION IS STATED HERE, NOT DERIVED
-------------------------------------------
cafaye-py is a **client SDK**, not a service. There is no FastAPI route table and
no database in this repository, and pretending otherwise would produce a
test-suite about code that does not exist. The account-scoped surface here is the
**service methods** — the twenty operations ``IDENTITY_OPERATIONS`` declares, each
on two faces (``IdentityService`` and ``AsyncIdentityService``) — and the DB
queries are the service's, not ours.

So "account-scoped entry point" means: *an operation whose tenant is named in the
request*. That is a stricter definition than "has an ``account_id``", and it is the
one that matters, because a parameter that never reaches the wire scopes nothing.

The count, which a reader can check against ``IDENTITY_OPERATIONS`` directly:

    8  account-scoped entry points  (path contains ``/v1/accounts/{account_id}``)
    8  ... each on 2 faces        = 16 account-scoped call sites
    2  credential-scoped entry points (tenant named by the token, not the path)
    0  update verbs — see below

Per operation kind, on the account-scoped surface:

    read    1   get_oidc_client
    list    2   list_oidc_clients, list_api_keys
    create  2   register_oidc_client, mint_api_key
    delete  3   revoke_oidc_client, revoke_api_key, revoke_api_key(reason=…)
    update  0   FINDING, not an omission — see TestTheUpdateSlotIsEmpty

``revoke_api_key`` is counted **twice**, because it is two entry points. With a
``reason`` it posts to ``…/api-keys/{key_id}/revoke``; without one it deletes
``…/api-keys/{key_id}``. Two different methods, two different paths, two different
requests, one Python method — and it is the only account-scoped operation whose
wire shape is **not** in the declaration table. Both are enumerated and both are
tested, because an entry point that the table does not describe is an entry point
whose scoping cannot be checked against the table.

ABSENCE, NEVER 403
------------------
The rule, from core's conventions and quoted in ``_errors.CafayeNotFoundError``:
*"404 is correct there, 403 is not allowed to leak existence."* A cross-tenant read
that answers 403 tells the attacker that the row is **there**. So the negative test
for every entry point is: *account A asks for account B's row, and gets the same
answer it would get for a row that has never existed.*

A 403 anywhere in this file is a FINDING, and there are three ways one could
appear, each with its own test class:

- the client **manufactures** a 403 where the service said 404
  (``TestAbsenceIsNeverLaunderedIntoAForbidden``);
- the client **echoes** the requested account into the error, so B's id and a
  nonexistent id produce different bytes (``TestTheErrorCannotDistinguishTheTwo``);
- the client **caches** one tenant's answer under a key that omits the tenant
  (``TestNoTenantIsServedFromAnothersAnswer``).

A 403 the *service* sends, for a reason that is about the caller's own credential
and not about another tenant's row — ``DELETE /v1/session`` documented to answer
403 to a scoped API token — is faithful passthrough and is asserted as such in
``TestAForbiddenTheServiceSentIsNotHidden``. Laundering is the defect; honesty is
not.

WHAT THESE TESTS DO NOT CLAIM
-----------------------------
They cannot prove identity's server answers 404 for account B's row. There is no
server in this repository and the suite opens no socket. What they prove is the half
that is ours: that this client sends the tenant it was given, that it does not
distinguish "another tenant's row" from "no row", and that it holds no state that
could carry one tenant's answer to another. A client that dropped ``account_id``
from the path would make the service fall back to the caller's own account and
return the **wrong tenant's data** — that is a real, cross-tenant leak, it ships in
an SDK, and ``TestTheScopeParameterIsLoadBearing`` is what catches it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
import pytest

from cafaye import CafayeForbiddenError, CafayeNotFoundError
from cafaye._services.identity import IDENTITY_OPERATIONS
from conftest import async_client, json_response, problem_response, run, sync_client

# ---------------------------------------------------------------------------
# THE ENUMERATION
# ---------------------------------------------------------------------------

#: Two tenants and one id that has never existed. The negative test is always the
#: same three-way comparison: A's own row, B's row, and no row at all.
ACCOUNT_A = "acct_a_0000000000000001"
ACCOUNT_B = "acct_b_0000000000000002"
ACCOUNT_NONE = "acct_none_00000000000000"

#: A resource id deliberately identical across both tenants. A client that keyed a
#: cache on ``client_id`` without the account would serve B's answer for A. Using
#: the *same* id on both sides is what makes that bug possible, so it is the id
#: this file uses.
SHARED_CLIENT_ID = "oc_0000000000000001"
SHARED_KEY_ID = "key_00000000000000001"


@dataclass(frozen=True)
class EntryPoint:
    """One account-scoped entry point, as the enumeration counts it.

    ``method`` and ``path`` are the **document's**, restated here rather than read
    out of ``IDENTITY_OPERATIONS``. A test whose expectation is derived from the
    thing it checks asserts only that the code is self-consistent — the failure it
    would miss is a table that changed and the tests agreeing with it.
    """

    name: str
    kind: str
    method: str
    path: str
    #: The keyword arguments other than ``account_id``.
    kwargs: dict[str, Any] = field(default_factory=dict)
    #: Builds the success response. A factory, because a ``httpx.Response`` is a
    #: stream and reusing one across two sends is a different test every time.
    success: Callable[[], httpx.Response] = lambda: httpx.Response(204)
    #: The second entry point ``name`` reaches, when one method is two. ``None`` for
    #: the seven that are one-to-one.
    also_reaches: str | None = None

    def render(self, account_id: str) -> str:
        """The path this entry point must put on the wire for ``account_id``.

        Every placeholder is substituted, not only ``account_id``: a
        ``{client_id}`` left in the path would fail the ``"{" not in path``
        assertion, and rendering it means the expected path is derived the same
        way for the tenant and for the row inside the tenant.
        """
        rendered = self.path.replace("{account_id}", account_id)
        return re.sub(r"\{(\w+)\}", lambda found: str(self.kwargs[found.group(1)]), rendered)


def _oidc_client_body(account_id: str, client_id: str) -> dict[str, Any]:
    return {
        "id": client_id,
        "client_id": client_id,
        "name": f"client of {account_id}",
        "redirect_uris": ["https://rp.test/callback"],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
        "created_at": "2026-09-01T00:00:00Z",
    }


def _api_key_body(account_id: str, key_id: str) -> dict[str, Any]:
    return {
        "id": key_id,
        "name": f"key of {account_id}",
        "account_id": account_id,
        "user_id": f"usr_{account_id}",
        "scopes": ["read"],
        "created_at": "2026-09-01T00:00:00Z",
    }


def _empty_page() -> dict[str, Any]:
    return {"data": [], "page": {"has_more": False, "next_cursor": None}}


#: **The eight.** Ordered by the document, then by the undeclared variant.
ACCOUNT_SCOPED: tuple[EntryPoint, ...] = (
    EntryPoint(
        "register_oidc_client",
        "create",
        "POST",
        "/v1/accounts/{account_id}/oidc-clients",
        {
            "name": "rp",
            "redirect_uris": ["https://rp.test/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        },
        lambda: httpx.Response(
            201, json={**_oidc_client_body(ACCOUNT_A, SHARED_CLIENT_ID), "client_secret": "s"}
        ),
    ),
    EntryPoint(
        "list_oidc_clients",
        "list",
        "GET",
        "/v1/accounts/{account_id}/oidc-clients",
        success=lambda: httpx.Response(200, json=_empty_page()),
    ),
    EntryPoint(
        "get_oidc_client",
        "read",
        "GET",
        "/v1/accounts/{account_id}/oidc-clients/{client_id}",
        {"client_id": SHARED_CLIENT_ID},
        lambda: httpx.Response(200, json=_oidc_client_body(ACCOUNT_A, SHARED_CLIENT_ID)),
    ),
    EntryPoint(
        "revoke_oidc_client",
        "delete",
        "DELETE",
        "/v1/accounts/{account_id}/oidc-clients/{client_id}",
        {"client_id": SHARED_CLIENT_ID},
    ),
    EntryPoint(
        "mint_api_key",
        "create",
        "POST",
        "/v1/accounts/{account_id}/api-keys",
        {"name": "ci", "scopes": ["read"]},
        lambda: httpx.Response(
            201, json={**_api_key_body(ACCOUNT_A, SHARED_KEY_ID), "token": "cafaye_test"}
        ),
    ),
    EntryPoint(
        "list_api_keys",
        "list",
        "GET",
        "/v1/accounts/{account_id}/api-keys",
        success=lambda: httpx.Response(
            200,
            json={"data": [_api_key_body(ACCOUNT_A, SHARED_KEY_ID)], **_empty_page()},
        ),
    ),
    EntryPoint(
        "revoke_api_key",
        "delete",
        "DELETE",
        "/v1/accounts/{account_id}/api-keys/{key_id}",
        {"key_id": SHARED_KEY_ID},
    ),
    EntryPoint(
        "revoke_api_key",
        "delete",
        "POST",
        "/v1/accounts/{account_id}/api-keys/{key_id}/revoke",
        {"key_id": SHARED_KEY_ID, "reason": "rotated"},
        also_reaches="DELETE /v1/accounts/{account_id}/api-keys/{key_id}",
    ),
)

#: The two entry points whose tenant is named by the credential rather than the
#: path. They are tenant-scoped and a suite that only counted path parameters
#: would report a smaller number than the truth.
CREDENTIAL_SCOPED: tuple[EntryPoint, ...] = (
    EntryPoint(
        "get_current_user",
        "read",
        "GET",
        "/v1/me",
        success=lambda: httpx.Response(200, json={"id": "usr_a", "email": "a@b.test"}),
    ),
    EntryPoint(
        "introspect_api_key",
        "read",
        "POST",
        "/v1/introspections",
        {"token": "cafaye_test"},
        lambda: httpx.Response(
            200, json={"active": True, "account_id": ACCOUNT_A, "scopes": ["read"]}
        ),
    ),
)

FACES = ("sync", "async")


def _by_id(entry: EntryPoint) -> str:
    """A pytest id that says which entry point, which is the reportable unit."""
    return f"{entry.kind}-{entry.method}-{entry.name}"


ALL_ENTRIES = pytest.mark.parametrize("entry", ACCOUNT_SCOPED, ids=_by_id)
BOTH_FACES = pytest.mark.parametrize("face", FACES, ids=list(FACES))


def _make_client(face: str, stub: Any, **kwargs: Any) -> tuple[Any, list[httpx.Request]]:
    builder = sync_client if face == "sync" else async_client
    namespace, sent = builder(stub, **kwargs)
    return namespace.identity, sent


def _success_handler(entry: EntryPoint) -> Callable[[httpx.Request], httpx.Response]:
    """A transport handler that builds a **fresh** success response per request.

    A factory, not a ``Response``: ``httpx.Response`` carries a stream, so handing
    the same object to two sends makes the second one read a consumed body — and a
    test that then asserted on the second tenant's rows would be asserting on the
    first tenant's bytes. ``responding_with`` calls a callable with the request,
    which is exactly the hook this wants.
    """
    return lambda _request: entry.success()


def _invoke(face: str, entry: EntryPoint, account_id: str, stub: Any, **kwargs: Any) -> Any:
    """Call one entry point on one face and return what came back."""
    namespace, sent = _make_client(face, stub, **kwargs)
    call = getattr(namespace, entry.name)
    result = call(account_id=account_id, **entry.kwargs) if account_id is not None else call(**entry.kwargs)
    if face == "async":
        result = run(result)
    assert len(sent) == 1, "exactly one request per call — this client never retries"
    return result


# ---------------------------------------------------------------------------
# 1. THE ENUMERATION IS CORRECT
# ---------------------------------------------------------------------------


class TestTheEnumerationIsTheSurface:
    """The counts in the module docstring, asserted against the source.

    These are the numbers the report quotes. If a future packet adds a ninth
    account-scoped operation, this class is what makes the report's arithmetic
    wrong in a way somebody notices, rather than quietly.
    """

    def test_there_are_eight_account_scoped_entry_points(self) -> None:
        assert len(ACCOUNT_SCOPED) == 8

    def test_every_account_scoped_path_carries_the_account_placeholder(self) -> None:
        assert all("/v1/accounts/{account_id}" in entry.path for entry in ACCOUNT_SCOPED)

    @pytest.mark.parametrize(
        "kind", ["read", "list", "create", "delete", "update"], ids=lambda k: f"kind-{k}"
    )
    def test_the_per_kind_counts_are_what_the_report_says(self, kind: str) -> None:
        expected = {"read": 1, "list": 2, "create": 2, "delete": 3, "update": 0}
        assert sum(1 for entry in ACCOUNT_SCOPED if entry.kind == kind) == expected[kind]

    def test_seven_of_the_eight_are_the_documents_own_declarations(self) -> None:
        """Seven of the eight are in ``IDENTITY_OPERATIONS``; the eighth is not.

        ``revoke_api_key(reason=…)`` posts to a sub-resource the declaration table
        does not carry, so its path is asserted here and in
        ``TestTheScopeParameterIsLoadBearing`` — a scoping property the table
        cannot check is one that has to be checked against the document.
        """
        declared = {(op.method, op.path) for op in IDENTITY_OPERATIONS.values()}
        undeclared = [
            (entry.method, entry.path)
            for entry in ACCOUNT_SCOPED
            if (entry.method, entry.path) not in declared
        ]
        assert undeclared == [
            (
                "POST",
                "/v1/accounts/{account_id}/api-keys/{key_id}/revoke",
            )
        ]

    def test_the_remaining_seven_match_the_table_exactly(self) -> None:
        """Keyed on ``(method, path)``, not on path alone.

        Two of the seven share a path and differ only by verb —
        ``register_oidc_client``/``list_oidc_clients`` on the collection, and
        ``mint_api_key``/``list_api_keys`` on the other — so a path-keyed
        comparison silently accepts a create enumerated as a list. The pair is the
        operation.
        """
        declared = {(op.method, op.path) for op in IDENTITY_OPERATIONS.values()}
        for entry in ACCOUNT_SCOPED:
            if entry.also_reaches is not None:
                continue
            assert (entry.method, entry.path) in declared, entry.name
            assert entry.name in IDENTITY_OPERATIONS, entry.name
            assert IDENTITY_OPERATIONS[entry.name].method == entry.method
            assert IDENTITY_OPERATIONS[entry.name].path == entry.path

    def test_there_are_two_credential_scoped_entry_points(self) -> None:
        assert len(CREDENTIAL_SCOPED) == 2
        assert all("{account_id}" not in entry.path for entry in CREDENTIAL_SCOPED)

    def test_eight_operations_times_two_faces_is_sixteen_call_sites(self) -> None:
        call_sites = [(entry, face) for entry in ACCOUNT_SCOPED for face in FACES]
        assert len(call_sites) == 16


class TestTheUpdateSlotIsEmpty:
    """FINDING: the account-scoped surface has no update verb, so "update" cannot
    be negative-tested at the account path.

    Read plainly off the table: identity declares no ``PATCH`` and no ``PUT``, at
    any path. The account-scoped mutations are two creates and three deletes, and
    every one of them is covered above. So the honest per-operation count is
    ``update 0`` — **not** a gap in this packet, and **not** evidence that nothing
    updates tenant data, because the updates that exist (an API key's
    ``last_used_at``, a revoke reason) are fields on a row this client can only
    write by replacing the whole row through a delete and a create.

    The test is here so the empty slot is a measurement with a name rather than an
    absence nobody noticed.
    """

    def test_no_declared_operation_uses_patch_or_put(self) -> None:
        verbs = {op.method for op in IDENTITY_OPERATIONS.values()}
        assert not verbs & {"PATCH", "PUT"}

    def test_the_account_scoped_surface_is_creates_and_deletes_only(self) -> None:
        verbs = {entry.method for entry in ACCOUNT_SCOPED}
        assert verbs == {"GET", "POST", "DELETE"}


# ---------------------------------------------------------------------------
# 2. THE SCOPE PARAMETER IS LOAD-BEARING  (16 tests: 8 entry points x 2 faces)
# ---------------------------------------------------------------------------


@ALL_ENTRIES
@BOTH_FACES
class TestTheScopeParameterIsLoadBearing:
    """The tenant the caller named must reach the wire, and only there.

    This is the leak that ships in an SDK. If ``account_id`` were dropped from the
    path, the service has nothing to scope by and falls back to the caller's own
    membership — so ``list_api_keys(account_id=B)`` would return **A's keys** with
    a 200. Not a 403, not an error: a success carrying the wrong tenant's rows.
    A mock transport answers any URL, so a suite that asserts only on the response
    is green over that bug. These assert on the request.
    """

    @staticmethod
    def _one(entry: EntryPoint, face: str, account_id: str) -> httpx.Request:
        _invoke(face, entry, account_id, entry.success())
        namespace, sent = _make_client(face, entry.success())
        call = getattr(namespace, entry.name)
        outcome = call(account_id=account_id, **entry.kwargs)
        if face == "async":
            run(outcome)
        assert len(sent) == 1, "one call is one request — this client never retries"
        return sent[0]

    def test_the_account_reaches_the_path(self, entry: EntryPoint, face: str) -> None:
        request = self._one(entry, face, ACCOUNT_B)
        assert request.url.path == entry.render(ACCOUNT_B)

    def test_the_request_reaches_the_method_the_document_declares(
        self, entry: EntryPoint, face: str
    ) -> None:
        request = self._one(entry, face, ACCOUNT_B)
        assert request.method == entry.method

    def test_the_account_is_not_duplicated_into_the_query(
        self, entry: EntryPoint, face: str
    ) -> None:
        """A second copy in the query string is a scope the service may prefer.

        ``/v1/accounts/B/api-keys?account_id=B`` is two answers to the same
        question, and which one wins is the service's policy rather than the
        caller's. One place to say which tenant this is: the path.
        """
        request = self._one(entry, face, ACCOUNT_B)
        assert "account_id" not in request.url.query.decode()

    def test_the_account_is_not_put_in_the_body(self, entry: EntryPoint, face: str) -> None:
        """``_post`` keeps path parameters and JSON body apart, and this holds it.

        The failure is a 422 from a service whose request schema says
        ``additionalProperties: false`` — a refusal, not a leak, but it means the
        scope is being expressed twice and one of the two is wrong.
        """
        request = self._one(entry, face, ACCOUNT_B)
        if request.method in {"POST", "PUT", "PATCH"}:
            assert "account_id" not in json.loads(request.read())

    def test_the_path_never_keeps_the_placeholder(self, entry: EntryPoint, face: str) -> None:
        """``httpx`` does not substitute ``{name}``; it percent-encodes the braces.

        The bug this catches is real and is named in ``AGENTS.md``: nine of the
        twenty operations once requested ``/v1/accounts/%7Baccount_id%7D/api-keys``
        and 148 passing tests did not see it, because a mock answers any URL and
        asserts nothing about the path.
        """
        request = self._one(entry, face, ACCOUNT_B)
        assert "{" not in request.url.path
        assert "%7B" not in request.url.path

    def test_two_tenants_produce_two_different_paths(
        self, entry: EntryPoint, face: str
    ) -> None:
        for tenant in (ACCOUNT_A, ACCOUNT_B, ACCOUNT_NONE):
            request = self._one(entry, face, tenant)
            assert request.url.path == entry.render(tenant), tenant


# ---------------------------------------------------------------------------
# 3. ABSENCE IS NEVER LAUNDERED INTO A FORBIDDEN  (16 tests)
# ---------------------------------------------------------------------------


@ALL_ENTRIES
@BOTH_FACES
class TestAbsenceIsNeverLaunderedIntoAForbidden:
    """A 404 must arrive as a 404. A 403 is an enumeration oracle.

    core: *"404 is correct there, 403 is not allowed to leak existence."* Account
    B asking about account C's row and getting ``CafayeForbiddenError`` learns
    that the row exists, and the suite's job is to make that shape impossible to
    produce by accident.

    The class name is the assertion. ``CafayeForbiddenError`` is not a subclass of
    ``CafayeNotFoundError`` and ``CafayeNotFoundError`` is not a
    ``CafayeForbiddenError``, so ``isinstance`` is a real test rather than a
    formality.
    """

    def test_a_404_is_a_not_found_error(self, entry: EntryPoint, face: str) -> None:
        with pytest.raises(CafayeNotFoundError) as caught:
            _invoke(face, entry, ACCOUNT_B, _absent())
        assert caught.value.status == 404
        assert caught.value.code == "not_found"

    def test_a_404_is_never_a_forbidden_error(self, entry: EntryPoint, face: str) -> None:
        with pytest.raises(CafayeNotFoundError):
            _invoke(face, entry, ACCOUNT_B, _absent())
        # Spelled out rather than left to the previous test: this is the direction
        # that matters, and a reader should not have to infer it from the type
        # hierarchy.
        with pytest.raises(CafayeNotFoundError) as caught:
            _invoke(face, entry, ACCOUNT_B, _absent())
        assert not isinstance(caught.value, CafayeForbiddenError)
        assert type(caught.value) is CafayeNotFoundError

    def test_another_tenants_row_and_a_row_that_never_existed_are_the_same_shape(
        self, entry: EntryPoint, face: str
    ) -> None:
        """Account B's row and no row at all must be indistinguishable.

        Same service answer, so the only thing that could tell them apart is the
        client: a tenant it remembered, an id it echoed, a path it reached into.
        This is the negative test the whole packet exists for, stated as an
        equality of types.
        """
        shapes = []
        for account_id in (ACCOUNT_B, ACCOUNT_NONE):
            with pytest.raises(CafayeNotFoundError) as caught:
                _invoke(face, entry, account_id, _absent())
            shapes.append(type(caught.value))
        assert shapes[0] is shapes[1] is CafayeNotFoundError

    def test_the_operation_is_reported_never_the_tenant(
        self, entry: EntryPoint, face: str
    ) -> None:
        """The error names the operation, which is public, and not the account."""
        with pytest.raises(CafayeNotFoundError) as caught:
            _invoke(face, entry, ACCOUNT_B, _absent())
        assert caught.value.operation == f"identity.{entry.name}"


# ---------------------------------------------------------------------------
# 4. THE ERROR CANNOT DISTINGUISH THE TWO  (16 x 2 tests)
# ---------------------------------------------------------------------------

#: The answer for a row the caller may not see **and** the answer for a row that
#: has never existed: byte-for-byte the same document, because that is what a
#: service that honours "403 is not allowed to leak existence" sends.
#:
#: Constant rather than parameterised by account on purpose. If the body varied
#: with the requested id, then any difference between the two raised errors could
#: be attributed to the service, and this class would stop testing the client —
#: which is the only party here. One body, two requests, and the sole question is
#: what the client did with it.
ABSENT_BODY: dict[str, Any] = {
    "type": "https://errors.cafaye.com/not_found",
    "title": "Not found",
    "status": 404,
    "detail": "No such resource.",
    "instance": "/v1/accounts/an-account/resource",
    "code": "not_found",
    "trace_id": "0af7651916cd43dd8448eb211c80319c",
}


def _absent() -> httpx.Response:
    """The same document every time, for every tenant. See :data:`ABSENT_BODY`."""
    return json_response(404, ABSENT_BODY, content_type="application/problem+json")


def _echoing(account_id: str) -> httpx.Response:
    """A service that **does** put the requested account into ``instance``.

    Kept as a separate double, and tested separately, because it is a real
    service behaviour worth pinning down: RFC 9457 says ``instance`` identifies
    the specific occurrence, and the request path contains the account the
    *caller* asked about. That is not an oracle — the caller already knows which
    account id it sent. The oracle would be another tenant's id appearing there,
    and ``TestTheClientAddsNothingOfItsOwn`` is what holds the line on that.
    """
    return json_response(
        404,
        {**ABSENT_BODY, "instance": f"/v1/accounts/{account_id}/resource"},
        content_type="application/problem+json",
    )


@ALL_ENTRIES
@BOTH_FACES
class TestTheErrorCannotDistinguishTheTwo:
    """Every observable of the raised error, byte-identical across the two.

    ``TestAbsenceIsNeverLaunderedIntoAForbidden`` compares *types*. This compares
    everything a caller can read: the message, the problem type URI, the title,
    the detail, the instance, the status, the code, the trace id, the content
    type, the operation, the extensions and the per-field errors.

    A client that put the requested account into any one of those passes the type
    check and fails this one, and it would be a working enumeration oracle: an
    attacker enumerates account ids by comparing exception strings, needing no
    privilege and no tooling beyond a loop. This is the strongest form of "gets
    the same answer as nonexistent" a client-side test can make, and it is the
    form that holds.
    """

    @staticmethod
    def _observables(error: Exception) -> dict[str, Any]:
        """Everything a caller can read off the error.

        Listed field by field rather than collected with ``vars()``: deciding what
        counts as observable is the substance of this test, and a comprehension
        over an object's attributes would decide it by accident — and grow
        silently, and start passing, the next time a field was added.
        """
        assert isinstance(error, CafayeNotFoundError)
        return {
            "type": type(error),
            "message": str(error),
            "problem_type": error.type,
            "title": error.title,
            "detail": error.detail,
            "instance": error.instance,
            "status": error.status,
            "code": error.code,
            "trace_id": error.trace_id,
            "content_type": error.content_type,
            "operation": error.operation,
            "extensions": dict(error.extensions),
            "errors": error.errors,
        }

    def _observables_for_both(self, entry: EntryPoint, face: str) -> list[dict[str, Any]]:
        answers = []
        for account_id in (ACCOUNT_B, ACCOUNT_NONE):
            with pytest.raises(CafayeNotFoundError) as caught:
                _invoke(face, entry, account_id, _absent())
            answers.append(self._observables(caught.value))
        return answers

    def test_every_observable_is_identical(self, entry: EntryPoint, face: str) -> None:
        another_tenants, nonexistent = self._observables_for_both(entry, face)
        assert another_tenants == nonexistent

    def test_own_tenant_and_another_tenant_are_also_identical(
        self, entry: EntryPoint, face: str
    ) -> None:
        """The third of the three, and the one that closes the loop.

        Account A asking about account B's row and A asking about a row that does
        not exist are the two the brief names. A is also entitled to the same
        answer for **its own** absent row — a service that 404s a caller's own
        missing resource but 403s (or says anything different for) a row in
        another account has leaked the membership question through the status
        code. Three ids, one answer.
        """
        answers = self._observables_for_both(entry, face)
        own: dict[str, Any] = {}
        with pytest.raises(CafayeNotFoundError) as caught:
            _invoke(face, entry, ACCOUNT_A, _absent())
        own = self._observables(caught.value)
        assert own == answers[0] == answers[1]

    def test_the_client_adds_nothing_of_its_own(self, entry: EntryPoint, face: str) -> None:
        """When the service *does* echo the account, the client adds nothing.

        ``instance`` is the service's to set and the client's duty is to carry it
        faithfully — dropping a documented RFC 9457 member to hide a tenant would
        be a worse defect than the echo. So this asserts the error's ``instance``
        is **exactly** what the service sent, and that the two fields the client
        owns — the message and ``operation`` — name the operation and never the
        account.
        """
        with pytest.raises(CafayeNotFoundError) as caught:
            _invoke(face, entry, ACCOUNT_B, _echoing(ACCOUNT_B))
        error = caught.value
        assert error.instance == f"/v1/accounts/{ACCOUNT_B}/resource"
        assert error.operation == f"identity.{entry.name}"
        for tenant in (ACCOUNT_A, ACCOUNT_B, ACCOUNT_NONE):
            assert tenant not in error.operation
            assert tenant not in str(error)
            assert tenant not in error.detail
            assert tenant not in error.title
            assert tenant not in repr(dict(error.extensions))

    def test_no_credential_reaches_the_error(self, entry: EntryPoint, face: str) -> None:
        """AGENTS.md's one invariant, on the isolation path.

        The credential belongs to the *caller*, not to account B, so it has no
        business in a "that row is not yours" answer. This is also the reason
        nothing in this file prints a prompt, a completion or a token: the tests
        assert on ids and shapes that this repository invented, and the one string
        that looks like a secret is a literal ``TESTONLY-`` placeholder rather than
        anything a caller could hold.
        """
        token = "TESTONLY-not-a-real-token"
        namespace, _sent = _make_client(face, _absent(), token=token)
        call = getattr(namespace, entry.name)
        # The call goes INSIDE the `with`: on the sync face it runs at the call, so
        # hoisting it out would raise before the assertion was ever set up and the
        # test would fail for a reason that has nothing to do with the credential.
        with pytest.raises(CafayeNotFoundError) as caught:
            if face == "async":
                run(call(account_id=ACCOUNT_B, **entry.kwargs))
            else:
                call(account_id=ACCOUNT_B, **entry.kwargs)
        error = caught.value
        haystack = " ".join(
            [str(error), error.detail, error.title, error.instance, repr(dict(error.extensions))]
        )
        assert token not in haystack
# ---------------------------------------------------------------------------
# 5. NO TENANT IS SERVED FROM ANOTHER'S ANSWER  (cross-tenant cache bleed)
# ---------------------------------------------------------------------------


@ALL_ENTRIES
@BOTH_FACES
class TestNoTenantIsServedFromAnothersAnswer:
    """``AGENTS.md``: "No caching of anything." That rule and tenant isolation are
    the same rule, and this is the test that says so.

    A cache keyed on ``client_id`` or ``key_id`` — both of which are plausible to
    treat as globally unique, and are deliberately given the **same value on both
    sides** here — serves account B's row to account A on the second call. The
    status is 200, the model is the right model, the id matches what the caller
    asked for, and the data belongs to somebody else. No test that looks at one
    call can see it.

    Every id in this file is shared between the two tenants for this reason.
    """

    def test_a_second_tenant_gets_the_second_tenants_request(
        self, entry: EntryPoint, face: str
    ) -> None:
        """Two calls, two tenants, two requests — in that order on one client.

        One client, because a cache that is per-client is the more likely shape
        and is what this exercises; two clients would not share one.
        """
        namespace, sent = _make_client(face, _success_handler(entry))
        call = getattr(namespace, entry.name)

        for tenant in (ACCOUNT_A, ACCOUNT_B):
            outcome = call(account_id=tenant, **entry.kwargs)
            if face == "async":
                run(outcome)

        assert len(sent) == 2, "the second tenant's call must reach the wire"
        assert sent[0].url.path == entry.render(ACCOUNT_A)
        assert sent[1].url.path == entry.render(ACCOUNT_B)

    def test_a_repeated_read_of_another_tenants_row_is_asked_for_again(
        self, entry: EntryPoint, face: str
    ) -> None:
        """The same read twice, and the third time under a different tenant.

        Three requests for three asks. A memoising client produces two, and the
        second tenant is answered with the first tenant's body.
        """
        namespace, sent = _make_client(face, _success_handler(entry))
        call = getattr(namespace, entry.name)

        for tenant in (ACCOUNT_A, ACCOUNT_A, ACCOUNT_B):
            outcome = call(account_id=tenant, **entry.kwargs)
            if face == "async":
                run(outcome)

        assert [request.url.path for request in sent] == [
            entry.render(ACCOUNT_A),
            entry.render(ACCOUNT_A),
            entry.render(ACCOUNT_B),
        ]


# ---------------------------------------------------------------------------
# 6. A FORBIDDEN THE SERVICE SENT IS NOT HIDDEN
# ---------------------------------------------------------------------------


@BOTH_FACES
class TestAForbiddenTheServiceSentIsNotHidden:
    """Laundering is the defect. Dishonesty is not.

    ``DELETE /v1/session`` is documented to answer **403 to a scoped API token**:
    a machine credential has no session to end, and revoking the caller's would be
    wrong. So ``403`` is a real, correct answer about a caller's **own**
    credential — and this client reports it as ``CafayeForbiddenError`` rather
    than rewriting it to a 404 to look well-mannered.

    The distinction that keeps both rules true at once: a 403 about *who you are*
    is honest; a 403 about *whose row that is* is an oracle. Only the first exists
    on this surface, and the negative tests above say the second is not
    manufactured.

    Four tests rather than one, because the failure being guarded against is a
    well-meaning edit: someone reads "never 403", adds a coercion, and every
    account-scoped absence starts reporting as an authentication problem.
    """

    def test_a_403_the_service_sent_surfaces_as_a_forbidden_error(self, face: str) -> None:
        namespace, _sent = _make_client(face, problem_response("forbidden", 403))
        with pytest.raises(CafayeForbiddenError) as caught:
            run(namespace.delete_session()) if face == "async" else namespace.delete_session()
        assert caught.value.status == 403
        assert caught.value.code == "forbidden"

    def test_a_403_is_not_rewritten_to_a_404(self, face: str) -> None:
        namespace, _sent = _make_client(face, problem_response("forbidden", 403))
        with pytest.raises(CafayeForbiddenError) as caught:
            run(namespace.delete_session()) if face == "async" else namespace.delete_session()
        assert not isinstance(caught.value, CafayeNotFoundError)

    def test_a_404_is_not_rewritten_to_a_403(self, face: str) -> None:
        """The other direction, and the one a well-meaning edit would break.

        Somebody reads "never 403", decides a 403 is impolite, and adds a coercion
        that turns every absence into an authentication problem. Then a caller can
        no longer tell "your credential is not enough" from "that row is not
        yours", which is a worse failure than the 403 was: it sends the reader
        looking at tokens instead of at authorisation.
        """
        namespace, _sent = _make_client(face, problem_response("not_found", 404))
        with pytest.raises(CafayeNotFoundError) as caught:
            run(namespace.delete_session()) if face == "async" else namespace.delete_session()
        assert not isinstance(caught.value, CafayeForbiddenError)
        assert type(caught.value) is CafayeNotFoundError

    def test_a_404_stays_a_404(self, face: str) -> None:
        namespace, _sent = _make_client(face, problem_response("not_found", 404))
        with pytest.raises(CafayeNotFoundError) as caught:
            run(namespace.delete_session()) if face == "async" else namespace.delete_session()
        assert type(caught.value) is CafayeNotFoundError
