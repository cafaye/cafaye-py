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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .._client import _BaseCafaye
from .._models import (
    ApiKey,
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

__all__ = ["AsyncIdentityService", "IdentityService", "IdentityOperation", "IDENTITY_OPERATIONS"]

#: The service name, stated once. The base URL, the error's operation prefix and
#: the environment all derive from it.
SERVICE: Final = "identity"


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
    model: Any = None

    @property
    def qualified(self) -> str:
        """``identity.get_current_user`` — what an exception's ``operation`` says."""
        return f"{SERVICE}.{self.name}"


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
        IdentityOperation("create_session", "createSession", "POST", "/v1/session"),
        IdentityOperation("delete_session", "deleteSession", "DELETE", "/v1/session"),
        IdentityOperation(
            "complete_second_factor",
            "completeSecondFactor",
            "POST",
            "/v1/session/mfa",
            Session.from_response,
        ),
        IdentityOperation("get_mfa_status", "getMFAStatus", "GET", "/v1/mfa", MfaStatus.from_response),
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
        IdentityOperation("get_current_user", "getCurrentUser", "GET", "/v1/me", User.from_response),
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

    def __init__(self, client: _BaseCafaye) -> None:
        self._client = client

    def _get(self, name: str, **params: Any) -> Any:
        """Run one declared operation.

        The one place a method body delegates, so all twenty methods are one line
        and the declaration table above is the only place a path, a method or a
        response type is written down.
        """
        operation = IDENTITY_OPERATIONS[name]
        return self._client._perform(
            self._client._exchange(
                SERVICE,
                method=operation.method,
                path=operation.path,
                operation=operation.qualified,
                params=params or None,
                model=operation.model,
            )
        )

    # -- sessions ---------------------------------------------------------

    def register_user(self, *, email: str, password: str, **fields: Any) -> User:
        """``POST /v1/users``. The account's public projection: ``id`` and
        ``email``, lower-cased by the service before it is stored."""
        return self._post_body("register_user", {"email": email, "password": password, **fields})

    def create_session(self, *, email: str, password: str, second_factor: str | None = None) -> Session | MfaChallenge:
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
        return self._post_body("create_session", body)

    def delete_session(self) -> None:
        """``DELETE /v1/session``. 204, and nothing to return.

        identity-08's own document calls out the trap this operation sits in:
        ``DELETE /v1/session`` answers **403 to a scoped API token**, because a
        machine credential has no session to end and revoking the caller's would be
        wrong. A ``CafayeForbiddenError`` from here means "that was not a session".
        """
        self._get("delete_session")

    def complete_second_factor(self, *, challenge: str, code: str) -> Session:
        """``POST /v1/session/mfa``. The 202's challenge, answered."""
        return self._post_body("complete_second_factor", {"challenge": challenge, "code": code})

    # -- the current user -------------------------------------------------

    def get_current_user(self) -> User:
        """``GET /v1/me``. The caller's own account projection."""
        return self._get("get_current_user")

    # -- multi-factor -----------------------------------------------------

    def get_mfa_status(self) -> MfaStatus:
        """``GET /v1/mfa``. A ``200`` with ``enabled: false``, not a 404."""
        return self._get("get_mfa_status")

    def disable_mfa(self, *, code: str) -> None:
        """``DELETE /v1/mfa``. Revokes every session, this caller's included."""
        self._post_body("disable_mfa", {"code": code})

    def start_mfa_enrollment(self, *, method: str = "totp") -> StartedEnrollment:
        """``POST /v1/mfa/enrollments``.

        The response carries the only copy of the TOTP secret that will ever exist.
        Persist it immediately or start again.
        """
        return self._post_body("start_mfa_enrollment", {"method": method})

    def confirm_mfa_enrollment(
        self, *, enrollment_id: str, code: str
    ) -> ConfirmedEnrollment:
        """``POST /v1/mfa/enrollments/{enrollment_id}/confirm``.

        Every session the account holds was revoked to produce this response.
        """
        return self._post_body(
            "confirm_mfa_enrollment", {"code": code}, enrollment_id=enrollment_id
        )

    def regenerate_mfa_recovery_codes(self) -> RecoveryCodesResponse:
        """``POST /v1/mfa/recovery-codes``. The old set is destroyed in the same
        transaction that writes the new one."""
        return self._post_body("regenerate_mfa_recovery_codes", {})

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
        return self._post_body(
            "register_oidc_client",
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
        return self._get("list_oidc_clients", **_pagination(account_id, limit, cursor))

    def get_oidc_client(self, *, account_id: str, client_id: str) -> OIDCClient:
        """``GET /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        return self._get("get_oidc_client", account_id=account_id, client_id=client_id)

    def revoke_oidc_client(self, *, account_id: str, client_id: str) -> None:
        """``DELETE /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        self._get("revoke_oidc_client", account_id=account_id, client_id=client_id)

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
        return self._post_body("mint_api_key", body, account_id=account_id)

    def list_api_keys(
        self, *, account_id: str, limit: int | None = None, cursor: str | None = None
    ) -> _Page:
        """``GET /v1/accounts/{account_id}/api-keys``. Metadata only — a listing
        can never carry a token, and :class:`ApiKey` has no field for one."""
        return self._get("list_api_keys", **_pagination(account_id, limit, cursor))

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
        self._get("revoke_api_key", account_id=account_id, key_id=key_id)

    def introspect_api_key(self, *, token: str) -> Introspection:
        """``POST /v1/introspections``.

        The credential is in the **body**, not the header, and it is a secret this
        method receives rather than one it holds — so it is never attached to the
        request by the credential rules and never appears in a header the
        credential-leak test walks.
        """
        return self._post_body("introspect_api_key", {"token": token})

    # -- operations -------------------------------------------------------

    def liveness(self) -> Health:
        """``GET /healthz``. Is the process up."""
        return self._get("liveness")

    def readiness(self) -> Health:
        """``GET /readyz``. Can the process serve. ``deps`` is present here only."""
        return self._get("readiness")

    # -- helpers ----------------------------------------------------------

    def _post_body(self, name: str, body: Mapping[str, Any], **params: Any) -> Any:
        """POST a JSON body to one declared operation, keeping path params separate.

        Path parameters and the JSON body travel in different places, and merging
        them would put ``account_id`` in the request body where a service with
        ``additionalProperties: false`` would reject it. So ``**params`` is the path
        and the first argument is the body, with no overlap possible.
        """
        operation = IDENTITY_OPERATIONS[name]
        return self._client._perform(
            self._client._exchange(
                SERVICE,
                method=operation.method,
                path=operation.path,
                operation=operation.qualified,
                params=params or None,
                json=dict(body),
                model=operation.model,
            )
        )


class AsyncIdentityService:
    """The same twenty operations, as coroutines. See :class:`IdentityService`."""

    __slots__ = ("_client",)

    def __init__(self, client: _BaseCafaye) -> None:
        self._client = client

    async def _get(self, name: str, **params: Any) -> Any:
        operation = IDENTITY_OPERATIONS[name]
        return await self._client._aperform(
            self._client._exchange(
                SERVICE,
                method=operation.method,
                path=operation.path,
                operation=operation.qualified,
                params=params or None,
                model=operation.model,
            )
        )

    async def _post_body(self, name: str, body: Mapping[str, Any], **params: Any) -> Any:
        operation = IDENTITY_OPERATIONS[name]
        return await self._client._aperform(
            self._client._exchange(
                SERVICE,
                method=operation.method,
                path=operation.path,
                operation=operation.qualified,
                params=params or None,
                json=dict(body),
                model=operation.model,
            )
        )

    # -- sessions ---------------------------------------------------------

    async def register_user(self, *, email: str, password: str, **fields: Any) -> User:
        """``POST /v1/users``. See :meth:`IdentityService.register_user`."""
        return await self._post_body(
            "register_user", {"email": email, "password": password, **fields}
        )

    async def create_session(
        self, *, email: str, password: str, second_factor: str | None = None
    ) -> Session | MfaChallenge:
        """``POST /v1/session``. See :meth:`IdentityService.create_session`."""
        body: dict[str, Any] = {"email": email, "password": password}
        if second_factor is not None:
            body["second_factor"] = second_factor
        return await self._post_body("create_session", body)

    async def delete_session(self) -> None:
        """``DELETE /v1/session``. See :meth:`IdentityService.delete_session`."""
        await self._get("delete_session")

    async def complete_second_factor(self, *, challenge: str, code: str) -> Session:
        """``POST /v1/session/mfa``."""
        return await self._post_body("complete_second_factor", {"challenge": challenge, "code": code})

    # -- the current user -------------------------------------------------

    async def get_current_user(self) -> User:
        """``GET /v1/me``."""
        return await self._get("get_current_user")

    # -- multi-factor -----------------------------------------------------

    async def get_mfa_status(self) -> MfaStatus:
        """``GET /v1/mfa``."""
        return await self._get("get_mfa_status")

    async def disable_mfa(self, *, code: str) -> None:
        """``DELETE /v1/mfa``."""
        await self._post_body("disable_mfa", {"code": code})

    async def start_mfa_enrollment(self, *, method: str = "totp") -> StartedEnrollment:
        """``POST /v1/mfa/enrollments``."""
        return await self._post_body("start_mfa_enrollment", {"method": method})

    async def confirm_mfa_enrollment(
        self, *, enrollment_id: str, code: str
    ) -> ConfirmedEnrollment:
        """``POST /v1/mfa/enrollments/{enrollment_id}/confirm``."""
        return await self._post_body(
            "confirm_mfa_enrollment", {"code": code}, enrollment_id=enrollment_id
        )

    async def regenerate_mfa_recovery_codes(self) -> RecoveryCodesResponse:
        """``POST /v1/mfa/recovery-codes``."""
        return await self._post_body("regenerate_mfa_recovery_codes", {})

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
        return await self._post_body(
            "register_oidc_client",
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
        return await self._get("list_oidc_clients", **_pagination(account_id, limit, cursor))

    async def get_oidc_client(self, *, account_id: str, client_id: str) -> OIDCClient:
        """``GET /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        return await self._get("get_oidc_client", account_id=account_id, client_id=client_id)

    async def revoke_oidc_client(self, *, account_id: str, client_id: str) -> None:
        """``DELETE /v1/accounts/{account_id}/oidc-clients/{client_id}``."""
        await self._get("revoke_oidc_client", account_id=account_id, client_id=client_id)

    # -- scoped API tokens ------------------------------------------------

    async def mint_api_key(
        self, *, account_id: str, name: str, scopes: Sequence[str], expires_in: int | None = None
    ) -> IssuedApiKey:
        """``POST /v1/accounts/{account_id}/api-keys``."""
        body: dict[str, Any] = {"name": name, "scopes": list(scopes)}
        if expires_in is not None:
            body["expires_in"] = expires_in
        return await self._post_body("mint_api_key", body, account_id=account_id)

    async def list_api_keys(
        self, *, account_id: str, limit: int | None = None, cursor: str | None = None
    ) -> _Page:
        """``GET /v1/accounts/{account_id}/api-keys``."""
        return await self._get("list_api_keys", **_pagination(account_id, limit, cursor))

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
        await self._get("revoke_api_key", account_id=account_id, key_id=key_id)

    async def introspect_api_key(self, *, token: str) -> Introspection:
        """``POST /v1/introspections``."""
        return await self._post_body("introspect_api_key", {"token": token})

    # -- operations -------------------------------------------------------

    async def liveness(self) -> Health:
        """``GET /healthz``."""
        return await self._get("liveness")

    async def readiness(self) -> Health:
        """``GET /readyz``."""
        return await self._get("readiness")


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