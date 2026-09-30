"""``identity``: twenty typed operations, in two faces.

This is the largest surface in the fleet and the one every other service's auth
depends on — it mints every credential cafaye has, which is why this client starts
here.

WHY TWO CLASSES AND NOT ONE WITH A FLAG
---------------------------------------

:class:`IdentityService` and :class:`AsyncIdentityService` are two classes with the
same twenty method names. The alternative — one class whose methods return either
a value or a coroutine — was rejected for a specific reason: the failure arrives
at the ``await`` rather than at the constructor, several frames from the line that
mixed them up, and it fails with an ``AttributeError`` about a value not being
awaitable, which is a diagnosis that costs an hour. Two classes cost one extra
method body per operation and turn that mistake into an ``AttributeError`` on the
client, at the point of construction, where the message can name the fix.

Each method is one line over a shared declaration, and
``tests/test_identity.py`` asserts the two faces expose **the same twenty names
and the same twenty declarations** — so drift is a red suite rather than a
client where the async version of an operation is subtly the sync version from
last month.

THE OPERATIONS ARE NOT THIS PACKAGE'S API
-----------------------------------------

They are what identity's document says, and a document can change. They are typed
directly from it rather than generated, because MD6 ruled that a generator for
Python "imposes a runtime dependency, a pydantic v1/v2 split, or a model layer
that does not match the problem", and because a hand-written client is the only
place the credential invariant can be held at all. What does not change is that
you reach every operation through ``cafaye.identity``.

NAMING, AND THE ONE PLACE THE TWO CLIENTS DIVERGE
--------------------------------------------------

The documents' ``operationId``s are camelCase (``getCurrentUser``) and Python's
convention is snake_case, so this client's methods are ``get_current_user``. A
camelCase method name in a Python client would be a defect, not a parity win.

What **is** kept identical across the two clients is the operation *identity*, and
that is what appears in an error message: ``identity.get_current_user`` here and
``identity.getCurrentUser`` in ``cafaye-ts``. The mapping is one line per
operation in ``README.md`` and is asserted in ``tests/test_identity.py``, so a
reader of a log line can go from one client to the other.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, TypeVar, overload

from cafaye._client import Model, _AsyncFace, _internal_bug, _SyncFace
from cafaye._models import (
    ConfirmedEnrollment,
    Health,
    Introspection,
    IssuedApiKey,
    MfaChallenge,
    MfaStatus,
    OIDCClient,
    OIDCClientWithSecret,
    RecoveryCodesResponse,
    Session,
    StartedEnrollment,
    User,
)

__all__ = ["IDENTITY_OPERATIONS", "AsyncIdentityService", "IdentityOperation", "IdentityService"]

#: The service name, stated once. The base URL, the error's operation prefix and
#: the environment all derive from it.
SERVICE: Final = "identity"

#: The type of a decoded response, as the table declares it. One TypeVar for the
#: whole module, so a method that says ``-> User`` and decodes with
#: ``User.from_response`` has its return type inferred rather than asserted.
T = TypeVar("T")


#: The decoder an operation declares, or ``None`` for one that has no response.
DeclaredModel = Callable[[Mapping[str, Any]], Any] | None


@dataclass(frozen=True, slots=True)
class IdentityOperation:
    """One operation, declared once and used by both faces.

    ``model`` is the callable that turns a decoded body into the documented type,
    or ``None`` for an operation whose response carries nothing (``DELETE
    /v1/session`` answers 204). It is stored rather than passed at each call site
    so that the parity test can compare the two faces by **object identity** rather
    than by reading twenty method bodies.
    """

    #: The document's ``operationId``, in snake_case. This is the name in an error
    #: message and the name the parity test compares.
    name: str
    #: The document's ``operationId``, verbatim. Kept so a reader of the README's
    #: mapping table and of the source can find the row in identity's document.
    operation_id: str
    method: str
    path: str
    #: The decoder for the documented response, or ``None`` for an operation whose
    #: response carries nothing. ``_declared`` holds every call site to this.
    model: DeclaredModel = None

    @property
    def qualified(self) -> str:
        """``identity.get_current_user`` — what an exception's ``operation`` says."""
        return f"{SERVICE}.{self.name}"


def _same_decoder(left: DeclaredModel, right: DeclaredModel) -> bool:
    """Are these two declarations the same decoder?

    Identity is the right test and it is **not sufficient**, which is the whole
    reason this function exists. Every model's ``from_response`` is a
    ``classmethod``, and Python builds a *fresh* bound method on every attribute
    access — so ``User.from_response is User.from_response`` is ``False`` while
    the two are the same method. An identity check here reported a mismatch on
    every single call, which is a check that is always red and therefore checks
    nothing.

    So the two halves are compared instead: the class it is bound to and the
    function behind it. That is exactly what ``==`` on a bound method does, and
    it is spelled out here rather than leaned on so the reason survives the next
    reader who is about to "simplify" it back to ``is``.
    """
    if left is right:
        return True
    return getattr(left, "__self__", None) is getattr(right, "__self__", None) and getattr(
        left, "__func__", None
    ) is getattr(right, "__func__", None)


def _declared(name: str, model: DeclaredModel) -> None:
    """Hold a call site's decoder to the one its operation declares.

    The table above is the single source of truth for what each operation
    returns, and the twenty methods below name the same decoder again — because a
    method that says ``-> User`` but decodes with something else is exactly the
    bug this check exists to make loud, and a ``cast`` would have hidden it.

    So the duplication is deliberate and the cost is one comparison per call. The
    alternative designs were both worse: a ``cast`` at every call site documents
    the annotation without checking it, and dropping ``model`` from the table
    makes the table no longer describe the service, which is the one thing it is
    for.
    """
    operation = IDENTITY_OPERATIONS[name]
    if not _same_decoder(operation.model, model):
        raise _internal_bug(
            f"{operation.qualified} is declared to return "
            f"{getattr(operation.model, '__qualname__', None) or 'nothing'} but its method "
            f"decodes with {getattr(model, '__qualname__', None) or 'nothing'}. The two "
            "disagree, and the table is the one that decides. This is a bug in cafaye-py."
        )


class _Page(Mapping[str, Any]):
    """One page of a cursor-paginated collection.

    core's conventions: ``data`` is always an array, ``page.next_cursor`` is
    ``None`` on the last page, and **the cursor is opaque** — "clients must not
    parse it, and its encoding may change without notice". So this class exposes
    ``next_cursor`` as an opaque string and nothing else, and it does not offer a
    way to fetch the next page: auto-paging is a policy the platform should own,
    and a client that pages for you is a client whose consumer cannot choose to
    stop.

    It is a ``Mapping`` because that is what a decoded JSON object is, so
    ``page["data"]`` works for anything this package's models do not cover yet.
    """

    __slots__ = ("_body",)

    def __init__(self, body: Mapping[str, Any]) -> None:
        self._body = body

    @property
    def data(self) -> tuple[Any, ...]:
        """The rows. Always an array, empty rather than absent."""
        value = self._body.get("data")
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return ()
        return tuple(value)

    @property
    def next_cursor(self) -> str | None:
        """The cursor to send as ``?cursor=``, or ``None`` on the last page.

        Opaque. Pass it back unexamined.
        """
        value = self._body.get("page", {})
        cursor = value.get("next_cursor") if isinstance(value, Mapping) else None
        return cursor if isinstance(cursor, str) else None

    @property
    def has_more(self) -> bool:
        """Whether another page exists, as the document's ``page.has_more`` says."""
        value = self._body.get("page", {})
        flag = value.get("has_more") if isinstance(value, Mapping) else None
        return flag if isinstance(flag, bool) else False

    def __getitem__(self, key: str) -> Any:
        return self._body[key]

    def __iter__(self) -> Any:
        return iter(self._body)

    def __len__(self) -> int:
        return len(self._body)

    def __repr__(self) -> str:
        return f"_Page(rows={len(self.data)}, has_more={self.has_more!r})"


def _session_or_challenge(body: Mapping[str, Any]) -> Session | MfaChallenge:
    """``POST /v1/session``'s 200 or its 202, told apart by the document.

    One operation, two response shapes, and the document says how to tell them
    apart rather than leaving it to the client: "**AN ACCOUNT WITH A SECOND FACTOR
    GETS 202 AND NO SESSION.** The password is correct and the authentication is
    not finished, which is what 202 means. The ``202`` body carries **no ``token``
    key at all** — not an empty one — so a client that reads ``token`` finds
    nothing and is unambiguous about it."

    That sentence is the discriminator, and using it is the whole reason the rule
    is not a heuristic of ours. ``mfa_required`` would also work; ``token`` is
    what the document actually promises to be absent, and an absent key is a
    stronger statement than a boolean that could one day be omitted by accident.

    Before this existed the operation had **no** model at all, which meant a
    successful login returned ``None`` and a caller with a perfectly good session
    token in hand had nothing to read it out of. No test covered it, which is the
    failure mode ``tests/test_identity.py`` now exists to prevent.
    """
    if "token" not in body:
        return MfaChallenge.from_response(body)
    return Session.from_response(body)


#: The twenty operations identity's document declares, in the document's order.
#:
#: The four ``api-keys`` routes and ``introspectAPIKey`` are identity-08's. They
#: are here because this client reads identity's **current** document rather than
#: the older vendored copy ``cafaye-ts`` holds: the vendored bytes are at
#: ``35c2576`` and those routes landed in ``bff6333``. ``cafaye-ts`` re-vendoring
#: is that repository's decision and this one is not its to make, so the two
#: clients currently differ in surface — recorded in ``REPORT-cafaye-py-01.md`` as
#: the obvious next packet, not as a defect in either.
IDENTITY_OPERATIONS: Final[Mapping[str, IdentityOperation]] = {
    operation.name: operation
    for operation in (
        IdentityOperation("register_user", "registerUser", "POST", "/v1/users", User.from_response),
        IdentityOperation(
            "create_session", "createSession", "POST", "/v1/session", _session_or_challenge
        ),
        IdentityOperation("delete_session", "deleteSession", "DELETE", "/v1/session"),
        IdentityOperation(
            "complete_second_factor",
            "completeSecondFactor",
            "POST",
            "/v1/session/mfa",
            Session.from_response,
        ),
        IdentityOperation(
            "get_mfa_status", "getMFAStatus", "GET", "/v1/mfa", MfaStatus.from_response
        ),
        IdentityOperation("disable_mfa", "disableMFA", "DELETE", "/v1/mfa"),
        IdentityOperation(
            "start_mfa_enrollment",
            "startMFAEnrollment",
            "POST",
            "/v1/mfa/enrollments",
            StartedEnrollment.from_response,
        ),
        IdentityOperation(
            "confirm_mfa_enrollment",
            "confirmMFAEnrollment",
            "POST",
            "/v1/mfa/enrollments/{enrollment_id}/confirm",
            ConfirmedEnrollment.from_response,
        ),
        IdentityOperation(
            "regenerate_mfa_recovery_codes",
            "regenerateMFARecoveryCodes",
            "POST",
            "/v1/mfa/recovery-codes",
            RecoveryCodesResponse.from_response,
        ),
        IdentityOperation(
            "get_current_user", "getCurrentUser", "GET", "/v1/me", User.from_response
        ),
        IdentityOperation(
            "register_oidc_client",
            "registerOIDCClient",
            "POST",
            "/v1/accounts/{account_id}/oidc-clients",
            OIDCClientWithSecret.from_response,
        ),
        IdentityOperation(
            "list_oidc_clients",
            "listOIDCClients",
            "GET",
            "/v1/accounts/{account_id}/oidc-clients",
            _Page,
        ),
        IdentityOperation(
            "get_oidc_client",
            "getOIDCClient",
            "GET",
            "/v1/accounts/{account_id}/oidc-clients/{client_id}",
            OIDCClient.from_response,
        ),
        IdentityOperation(
            "revoke_oidc_client",
            "revokeOIDCClient",
            "DELETE",
            "/v1/accounts/{account_id}/oidc-clients/{client_id}",
        ),
        IdentityOperation(
            "mint_api_key",
            "mintAPIKey",
            "POST",
            "/v1/accounts/{account_id}/api-keys",
            IssuedApiKey.from_response,
        ),
        IdentityOperation(
            "list_api_keys",
            "listAPIKeys",
            "GET",
            "/v1/accounts/{account_id}/api-keys",
            _Page,
        ),
        IdentityOperation(
            "revoke_api_key",
            "revokeAPIKey",
            "DELETE",
            "/v1/accounts/{account_id}/api-keys/{key_id}",
        ),
        IdentityOperation(
            "introspect_api_key",
            "introspectAPIKey",
            "POST",
            "/v1/introspections",
            Introspection.from_response,
        ),
        IdentityOperation("liveness", "liveness", "GET", "/healthz", Health.from_response),
        IdentityOperation("readiness", "readiness", "GET", "/readyz", Health.from_response),
    )
}


class IdentityService:
    """The twenty ``identity`` operations, synchronously."""

    __slots__ = ("_client",)

    def __init__(self, client: _SyncFace) -> None:
        self._client = client

    def _get(self, name: str, model: Model[T], **params: Any) -> T:
        """Run one declared operation that answers with a body.

        The decoder is named here rather than looked up by string, so the
        annotation on the calling method and the code that runs are checked
        against each other; :func:`_declared` then checks the call site against
        the table, which is the one place the truth lives.
        """
        return self._run(name, model=model, params=params)

    def _send(self, name: str, **params: Any) -> None:
        """Run one declared operation that answers with nothing."""
        self._run(name, model=None, params=params)

    @overload
    def _run(self, name: str, *, model: None, params: Mapping[str, Any]) -> None: ...

    @overload
    def _run(self, name: str, *, model: Model[T], params: Mapping[str, Any]) -> T: ...

    def _run(self, name: str, *, model: DeclaredModel, params: Mapping[str, Any]) -> Any:
        """The one body all four helpers share.

        Overloaded rather than typed ``Any`` because the two cases really do have
        different return types: an operation that declares a response always
        produces one (a 2xx with an empty body is raised as a contract violation,
        not returned as ``None``), and an operation that declares none produces
        nothing. Collapsing that to ``Any`` would put the burden back on all
        twenty methods, and collapsing it to ``T | None`` would put a ``None``
        check on every call site for a case the annotations already exclude.
        """
        _declared(name, model)
        operation = IDENTITY_OPERATIONS[name]
        return self._client._perform(
            self._client._exchange(
                SERVICE,
                method=operation.method,
                path=operation.path,
                operation=operation.qualified,
                params=params or None,
                model=model,
            )
        )

    def _post(self, name: str, model: Model[T], body: Mapping[str, Any], **params: Any) -> T:
        """POST a JSON body, keeping path parameters separate.

        Path parameters and the JSON body travel in different places, and merging
        them would put ``account_id`` in the request body where a service with
        ``additionalProperties: false`` would reject it. So ``**params`` is the
        path and the second argument is the body, with no overlap possible.
        """
        return self._run(name, model=model, params={**params, "json": dict(body)})

    def _post_void(self, name: str, body: Mapping[str, Any], **params: Any) -> None:
        self._run(name, model=None, params={**params, "json": dict(body)})

    # -- sessions ---------------------------------------------------------

    def register_user(self, *, email: str, password: str, **fields: Any) -> User:
        """``POST /v1/users``. The account's public projection: ``id`` and
        ``email``, lower-cased by the service before it is stored."""
        return self._post(
            "register_user", User.from_response, {"email": email, "password": password, **fields}
        )

    def create_session(
        self, *, email: str, password: str, second_factor: str | None = None
    ) -> Session | MfaChallenge:
        """``POST /v1/session``.

        Returns a :class:`Session` normally, and a :class:`MfaChallenge` with a
        ``200``/``202`` distinction the document makes when the account has a
        second factor. The two are different types on purpose: the challenge has no
        token in it and one that did would be the bug identity's document exists to
        prevent.
        """
        body: dict[str, Any] = {"email": email, "password": password}
        if second_factor is not None:
            body["second_factor"] = second_factor
        return self._post("create_session", _session_or_challenge, body)

    def delete_session(self) -> None:
        """``DELETE /v1/session``. 204, and nothing to return.

        identity-08's own document calls out the trap this operation sits in:
        ``DELETE /v1/session`` answers **403 to a scoped API token**, because a
        machine credential has no session to end and revoking the caller's would be
        wrong. A ``CafayeForbiddenError`` from here means "that was not a session".
        """
        self._send("delete_session")

    def complete_second_factor(self, *, challenge: str, code: str) -> Session:
        """``POST /v1/session/mfa``. The 202's challenge, answered."""
        return self._post(
            "complete_second_factor", Session.from_response, {"challenge": challenge, "code": code}
        )

    # -- the current user -------------------------------------------------

    def get_current_user(self) -> User:
        """``GET /v1/me``. The caller's own account projection."""
        return self._get("get_current_user", User.from_response)

    # -- multi-factor -----------------------------------------------------

    def get_mfa_status(self) -> MfaStatus:
        """``GET /v1/mfa``. A ``200`` with ``enabled: false``, not a 404."""
        return self._get("get_mfa_status", MfaStatus.from_response)

    def disable_mfa(self, *, code: str) -> None:
        """``DELETE /v1/mfa``. Revokes every session, this caller's included."""
        self._post_void("disable_mfa", {"code": code})

    def start_mfa_enrollment(self, *, method: str = "totp") -> StartedEnrollment:
        """``POST /v1/mfa/enrollments``.

        The response carries the only copy of the TOTP secret that will ever exist.
        Persist it immediately or start again.
        """
        return self._post(
            "start_mfa_enrollment", StartedEnrollment.from_response, {"method": method}
        )

    def confirm_mfa_enrollment(self, *, enrollment_id: str, code: str) -> ConfirmedEnrollment:
        """``POST /v1/mfa/enrollments/{enrollment_id}/confirm``.

        Every session the account holds was revoked to produce this response.
        """
        return self._post(
            "confirm_mfa_enrollment",
            ConfirmedEnrollment.from_response,
            {"code": code},
            enrollment_id=enrollment_id,
        )

    def regenerate_mfa_recovery_codes(self) -> RecoveryCodesResponse:
        """``POST /v1/mfa/recovery-codes``. The old set is destroyed in the same
        transaction that writes the new one."""
        return self._post("regenerate_mfa_recovery_codes", RecoveryCodesResponse.from_response, {})

    # -- OIDC clients -----------------------------------------------------

    def register_oidc_client(
        self,
        *,
        account_id: str,
        name: str,
        redirect_uris: Sequence[str],
        grant_types: Sequence[str],
        scopes: Sequence[str],
    ) -> OIDCClientWithSecret:
        """``POST /v1/accounts/{account_id}/oidc-clients``.

        The only response carrying a ``client_secret``. Losing it means registering
        again, which is why this client's ``repr`` for the result is redacted.
        """
        return self._post(
            "register_oidc_client",
            OIDCClientWithSecret.from_response,
            {
                "name": name,
                "redirect_uris": list(redirect_uris),
                "grant_types": list(grant_types),
                "scopes": list(scopes),
            },
            account_id=account_id,
        )

    def list_oidc_clients(
        self, *, account_id: str, limit: int | None = None, cursor: str | None = None
    ) -> _Page:
        """``GET /v1/accounts/{account_id}/oidc-clients``. Cursor-paginated.

        ``cursor`` is opaque; pass back ``page.next_cursor`` unexamined.
        """
        return self._get("list_oidc_clients", _Page, **_pagination(account_id, limit, cursor))

    def get_oidc_client(self, *, account_id: str, client_id: str) -> OIDCClient:
        """``GET /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        return self._get(
            "get_oidc_client", OIDCClient.from_response, account_id=account_id, client_id=client_id
        )

    def revoke_oidc_client(self, *, account_id: str, client_id: str) -> None:
        """``DELETE /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        self._send("revoke_oidc_client", account_id=account_id, client_id=client_id)

    # -- scoped API tokens ------------------------------------------------

    def mint_api_key(
        self,
        *,
        account_id: str,
        name: str,
        scopes: Sequence[str],
        expires_in: int | None = None,
    ) -> IssuedApiKey:
        """``POST /v1/accounts/{account_id}/api-keys``.

        The only response carrying an API token's plaintext. It is
        ``cafaye_`` plus 32 bytes, shown once and unrecoverable.
        """
        body: dict[str, Any] = {"name": name, "scopes": list(scopes)}
        if expires_in is not None:
            body["expires_in"] = expires_in
        return self._post("mint_api_key", IssuedApiKey.from_response, body, account_id=account_id)

    def list_api_keys(
        self, *, account_id: str, limit: int | None = None, cursor: str | None = None
    ) -> _Page:
        """``GET /v1/accounts/{account_id}/api-keys``. Metadata only — a listing
        can never carry a token, and :class:`ApiKey` has no field for one."""
        return self._get("list_api_keys", _Page, **_pagination(account_id, limit, cursor))

    def revoke_api_key(self, *, account_id: str, key_id: str, reason: str | None = None) -> None:
        """``DELETE /v1/accounts/{account_id}/api-keys/{key_id}``.

        ``reason`` is optional in the strongest sense: a ``DELETE`` with no body at
        all is a revoke, because "revoke this" with no explanation is the common
        request.
        """
        if reason is not None:
            self._client._perform(
                self._client._exchange(
                    SERVICE,
                    method="POST",
                    path="/v1/accounts/{account_id}/api-keys/{key_id}/revoke",
                    operation=f"{SERVICE}.revoke_api_key",
                    params={"account_id": account_id, "key_id": key_id},
                    json={"reason": reason},
                )
            )
            return
        self._send("revoke_api_key", account_id=account_id, key_id=key_id)

    def introspect_api_key(self, *, token: str) -> Introspection:
        """``POST /v1/introspections``.

        The credential is in the **body**, not the header, and it is a secret this
        method receives rather than one it holds — so it is never attached to the
        request by the credential rules and never appears in a header the
        credential-leak test walks.
        """
        return self._post("introspect_api_key", Introspection.from_response, {"token": token})

    # -- operations -------------------------------------------------------

    def liveness(self) -> Health:
        """``GET /healthz``. Is the process up."""
        return self._get("liveness", Health.from_response)

    def readiness(self) -> Health:
        """``GET /readyz``. Can the process serve. ``deps`` is present here only."""
        return self._get("readiness", Health.from_response)


class AsyncIdentityService:
    """The same twenty operations, as coroutines. See :class:`IdentityService`."""

    __slots__ = ("_client",)

    def __init__(self, client: _AsyncFace) -> None:
        self._client = client

    async def _get(self, name: str, model: Model[T], **params: Any) -> T:
        return await self._run(name, model=model, params=params)

    async def _send(self, name: str, **params: Any) -> None:
        await self._run(name, model=None, params=params)

    @overload
    async def _run(self, name: str, *, model: None, params: Mapping[str, Any]) -> None: ...

    @overload
    async def _run(self, name: str, *, model: Model[T], params: Mapping[str, Any]) -> T: ...

    async def _run(self, name: str, *, model: DeclaredModel, params: Mapping[str, Any]) -> Any:
        """The one body all four helpers share. See the sync face's ``_run``."""
        _declared(name, model)
        operation = IDENTITY_OPERATIONS[name]
        return await self._client._aperform(
            self._client._exchange(
                SERVICE,
                method=operation.method,
                path=operation.path,
                operation=operation.qualified,
                params=params or None,
                model=model,
            )
        )

    async def _post(self, name: str, model: Model[T], body: Mapping[str, Any], **params: Any) -> T:
        return await self._run(name, model=model, params={**params, "json": dict(body)})

    async def _post_void(self, name: str, body: Mapping[str, Any], **params: Any) -> None:
        await self._run(name, model=None, params={**params, "json": dict(body)})

    # -- sessions ---------------------------------------------------------

    async def register_user(self, *, email: str, password: str, **fields: Any) -> User:
        """``POST /v1/users``. See :meth:`IdentityService.register_user`."""
        return await self._post(
            "register_user", User.from_response, {"email": email, "password": password, **fields}
        )

    async def create_session(
        self, *, email: str, password: str, second_factor: str | None = None
    ) -> Session | MfaChallenge:
        """``POST /v1/session``. See :meth:`IdentityService.create_session`."""
        body: dict[str, Any] = {"email": email, "password": password}
        if second_factor is not None:
            body["second_factor"] = second_factor
        return await self._post("create_session", _session_or_challenge, body)

    async def delete_session(self) -> None:
        """``DELETE /v1/session``. See :meth:`IdentityService.delete_session`."""
        await self._send("delete_session")

    async def complete_second_factor(self, *, challenge: str, code: str) -> Session:
        """``POST /v1/session/mfa``."""
        return await self._post(
            "complete_second_factor", Session.from_response, {"challenge": challenge, "code": code}
        )

    # -- the current user -------------------------------------------------

    async def get_current_user(self) -> User:
        """``GET /v1/me``."""
        return await self._get("get_current_user", User.from_response)

    # -- multi-factor -----------------------------------------------------

    async def get_mfa_status(self) -> MfaStatus:
        """``GET /v1/mfa``."""
        return await self._get("get_mfa_status", MfaStatus.from_response)

    async def disable_mfa(self, *, code: str) -> None:
        """``DELETE /v1/mfa``."""
        await self._post_void("disable_mfa", {"code": code})

    async def start_mfa_enrollment(self, *, method: str = "totp") -> StartedEnrollment:
        """``POST /v1/mfa/enrollments``."""
        return await self._post(
            "start_mfa_enrollment", StartedEnrollment.from_response, {"method": method}
        )

    async def confirm_mfa_enrollment(self, *, enrollment_id: str, code: str) -> ConfirmedEnrollment:
        """``POST /v1/mfa/enrollments/{enrollment_id}/confirm``."""
        return await self._post(
            "confirm_mfa_enrollment",
            ConfirmedEnrollment.from_response,
            {"code": code},
            enrollment_id=enrollment_id,
        )

    async def regenerate_mfa_recovery_codes(self) -> RecoveryCodesResponse:
        """``POST /v1/mfa/recovery-codes``."""
        return await self._post(
            "regenerate_mfa_recovery_codes", RecoveryCodesResponse.from_response, {}
        )

    # -- OIDC clients -----------------------------------------------------

    async def register_oidc_client(
        self,
        *,
        account_id: str,
        name: str,
        redirect_uris: Sequence[str],
        grant_types: Sequence[str],
        scopes: Sequence[str],
    ) -> OIDCClientWithSecret:
        """``POST /v1/accounts/{account_id}/oidc-clients``."""
        return await self._post(
            "register_oidc_client",
            OIDCClientWithSecret.from_response,
            {
                "name": name,
                "redirect_uris": list(redirect_uris),
                "grant_types": list(grant_types),
                "scopes": list(scopes),
            },
            account_id=account_id,
        )

    async def list_oidc_clients(
        self, *, account_id: str, limit: int | None = None, cursor: str | None = None
    ) -> _Page:
        """``GET /v1/accounts/{account_id}/oidc-clients``."""
        return await self._get("list_oidc_clients", _Page, **_pagination(account_id, limit, cursor))

    async def get_oidc_client(self, *, account_id: str, client_id: str) -> OIDCClient:
        """``GET /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        return await self._get(
            "get_oidc_client", OIDCClient.from_response, account_id=account_id, client_id=client_id
        )

    async def revoke_oidc_client(self, *, account_id: str, client_id: str) -> None:
        """``DELETE /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        await self._send("revoke_oidc_client", account_id=account_id, client_id=client_id)

    # -- scoped API tokens ------------------------------------------------

    async def mint_api_key(
        self, *, account_id: str, name: str, scopes: Sequence[str], expires_in: int | None = None
    ) -> IssuedApiKey:
        """``POST /v1/accounts/{account_id}/api-keys``."""
        body: dict[str, Any] = {"name": name, "scopes": list(scopes)}
        if expires_in is not None:
            body["expires_in"] = expires_in
        return await self._post(
            "mint_api_key", IssuedApiKey.from_response, body, account_id=account_id
        )

    async def list_api_keys(
        self, *, account_id: str, limit: int | None = None, cursor: str | None = None
    ) -> _Page:
        """``GET /v1/accounts/{account_id}/api-keys``."""
        return await self._get("list_api_keys", _Page, **_pagination(account_id, limit, cursor))

    async def revoke_api_key(
        self, *, account_id: str, key_id: str, reason: str | None = None
    ) -> None:
        """``DELETE /v1/accounts/{account_id}/api-keys/{key_id}``.

        With a ``reason`` this uses the document's ``revoke`` sub-resource; without
        one it is the plain ``DELETE``, which the document says is itself a revoke.
        """
        if reason is not None:
            await self._client._aperform(
                self._client._exchange(
                    SERVICE,
                    method="POST",
                    path="/v1/accounts/{account_id}/api-keys/{key_id}/revoke",
                    operation=f"{SERVICE}.revoke_api_key",
                    params={"account_id": account_id, "key_id": key_id},
                    json={"reason": reason},
                )
            )
            return
        await self._send("revoke_api_key", account_id=account_id, key_id=key_id)

    async def introspect_api_key(self, *, token: str) -> Introspection:
        """``POST /v1/introspections``."""
        return await self._post("introspect_api_key", Introspection.from_response, {"token": token})

    # -- operations -------------------------------------------------------

    async def liveness(self) -> Health:
        """``GET /healthz``."""
        return await self._get("liveness", Health.from_response)

    async def readiness(self) -> Health:
        """``GET /readyz``."""
        return await self._get("readiness", Health.from_response)


def _pagination(account_id: str, limit: int | None, cursor: str | None) -> dict[str, Any]:
    """Path and pagination parameters for one collection operation.

    Absent values are omitted rather than sent as ``null``: core's conventions
    document ``?limit=50&cursor=…`` with a default of 25, and sending
    ``?cursor=null`` is a different request from sending no cursor.
    """
    params: dict[str, Any] = {"account_id": account_id}
    if limit is not None:
        params["limit"] = limit
    if cursor is not None:
        params["cursor"] = cursor
    return params
