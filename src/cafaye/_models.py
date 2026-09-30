"""The response shapes ``identity``'s document declares, as frozen dataclasses.

WHY DATACLASSES AND NOT A VALIDATION LAYER
--------------------------------------------

Every model here is built from the fields the document names, in the document's
order, with the document's types — and it **ignores** anything else in the body.

That last part is the decision, and it is deliberate. A validating model layer
(pydantic and its relatives) raises on a field the client does not know about when
the model's config says ``extra="forbid"``, and silently drops it when it says
``"allow"`` — and either way a **consumer's** code fails because **identity**
added a field, which inverts the direction of responsibility. It also drags in a
pydantic v1-versus-v2 dependency question for a client whose selling point is
that it has one runtime dependency.

So: the models are as precise as the documents and no more demanding than a
service's own contract. An unknown member is dropped here and a new field is a
new release, not an outage.

``frozen=True`` and ``slots=True`` throughout, for the same reason the credential
is not readable: an object a caller can mutate after the client handed it over is
an object whose invariants somebody else can break. ``slots=True`` also means a
model has no ``__dict__``, so there is nowhere for a credential to hide by
accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence, TypeVar

__all__ = [
    "ApiKey",
    "ConfirmedEnrollment",
    "Health",
    "Introspection",
    "IssuedApiKey",
    "MfaChallenge",
    "MfaStatus",
    "OIDCClient",
    "OIDCClientWithSecret",
    "RecoveryCodesResponse",
    "Session",
    "StartedEnrollment",
    "User",
    "from_mapping",
]

ModelT = TypeVar("ModelT", bound="_Model")


@dataclass(frozen=True, slots=True)
class _Model:
    """The one thing every model here shares: build from a mapping, ignore the rest."""

    @classmethod
    def from_response(cls: type[ModelT], body: Mapping[str, Any]) -> ModelT:
        """Build from a decoded JSON object.

        Each model does its own field-by-field coercion, because the coercions
        differ per field and a generic helper that hid them would be a place where
        a service's real shape quietly stopped mattering.
        """
        return cls.from_mapping(body)


def _str(body: Mapping[str, Any], key: str, *, default: str = "") -> str:
    value = body.get(key)
    return value if isinstance(value, str) else default


def _opt_str(body: Mapping[str, Any], key: str) -> str | None:
    value = body.get(key)
    return value if isinstance(value, str) else None


def _bool(body: Mapping[str, Any], key: str, *, default: bool = False) -> bool:
    value = body.get(key)
    return value if isinstance(value, bool) else default


def _int(body: Mapping[str, Any], key: str, *, default: int = 0) -> int:
    value = body.get(key)
    # `bool` is an `int`, and `{"digits": true}` is a service bug rather than a
    # TOTP parameter.
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _opt_int(body: Mapping[str, Any], key: str) -> int | None:
    value = body.get(key)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _str_list(body: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = body.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def from_mapping(body: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return ``body`` unchanged, or ``{}`` when it is not a mapping.

    The one shared guard. Every ``from_response`` calls it, so a service that
    answers ``200 application/json`` with a JSON array — a gateway's idea of a
    health check — produces an empty model rather than an ``AttributeError`` three
    frames away.
    """
    return body if isinstance(body, Mapping) else {}


@dataclass(frozen=True, slots=True)
class User(_Model):
    """identity's ``User``: the public projection of an account.

    Exactly two fields, always: there is no password digest, no lockout state and
    no timestamp here, and adding one is a contract change.
    """

    #: The account's identifier, and the ``subject`` of its events.
    id: str
    #: Always lower case. Registration normalizes before storing.
    email: str

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> User:
        data = from_mapping(body)
        return cls(id=_str(data, "id"), email=_str(data, "email"))


@dataclass(frozen=True, slots=True)
class Session(_Model):
    """identity's ``Session``: the token and when it stops working.

    The token itself is 256 bits from ``crypto/rand``, base64url without padding,
    and only its SHA-256 is stored. It is returned **once** and never re-read, so
    losing it means signing in again.
    """

    #: The session token, 43 base64url characters. Hand it to
    #: :meth:`Cafaye.set_token` and nowhere else.
    token: str
    #: RFC 3339 UTC. Judged against the service's clock, not the database's.
    expires_at: str

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> Session:
        data = from_mapping(body)
        return cls(token=_str(data, "token"), expires_at=_str(data, "expires_at"))


@dataclass(frozen=True, slots=True)
class MfaChallenge(_Model):
    """The ``202`` from ``POST /v1/session``: a correct password, an unfinished
    authentication, and nothing else.

    There is no ``token`` on this model and there could not be one: the challenge
    is what ``POST /v1/session/mfa`` is answered with, and it is worthless on its
    own. A model that could express "the login response" without saying which kind
    it is would make that bug easy to write.
    """

    #: Always ``True`` on this model. Its presence *is* the signal.
    mfa_required: bool
    #: What to send to ``POST /v1/session/mfa``.
    challenge: str
    #: RFC 3339 UTC.
    expires_at: str

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> MfaChallenge:
        data = from_mapping(body)
        return cls(
            mfa_required=_bool(data, "mfa_required"),
            challenge=_str(data, "challenge"),
            expires_at=_str(data, "expires_at"),
        )


@dataclass(frozen=True, slots=True)
class MfaStatus(_Model):
    """Whether the caller has a second factor.

    A ``200`` with ``enabled: false``, **not** a 404, when there is none: the
    question has an answer for every signed-in user, and a settings page should not
    have to distinguish "you have none" from "this is not your account".

    The three optional fields are absent when ``enabled`` is false, which is why
    they are ``| None`` and not defaults: ``"totp"`` and "no method yet" are
    different answers.
    """

    #: Whether a second factor is enrolled.
    enabled: bool
    #: ``"totp"``. Absent when ``enabled`` is false.
    method: str | None = None
    #: When the credential was confirmed. Absent when ``enabled`` is false.
    enrolled_at: str | None = None
    #: How many unused recovery codes are left. Absent when ``enabled`` is false.
    recovery_codes_remaining: int | None = None

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> MfaStatus:
        data = from_mapping(body)
        return cls(
            enabled=_bool(data, "enabled"),
            method=_opt_str(data, "method"),
            enrolled_at=_opt_str(data, "enrolled_at"),
            recovery_codes_remaining=_opt_int(data, "recovery_codes_remaining"),
        )


@dataclass(frozen=True, slots=True)
class StartedEnrollment(_Model):
    """A pending TOTP enrollment, and the only response in identity's document
    that contains a TOTP secret.

    **The secret is here and nowhere else.** There is no endpoint that re-reads
    it, so a client that loses this body starts a new enrollment, which mints a new
    secret. The reasoning is the one an OIDC ``client_secret`` follows: a secret
    this service can produce again is a secret this service is storing.
    """

    enrollment_id: str
    #: The base32 TOTP shared secret. **Never log it.**
    secret: str
    provisioning_uri: str
    #: ``"totp"``.
    method: str
    digits: int
    period_seconds: int
    #: ``"SHA1"``/``"SHA256"``/``"SHA512"``.
    algorithm: str
    expires_at: str
    #: Whether this enrollment replaced an unfinished one.
    replaced: bool = False

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> StartedEnrollment:
        data = from_mapping(body)
        return cls(
            enrollment_id=_str(data, "enrollment_id"),
            secret=_str(data, "secret"),
            provisioning_uri=_str(data, "provisioning_uri"),
            method=_str(data, "method"),
            digits=_int(data, "digits"),
            period_seconds=_int(data, "period_seconds"),
            algorithm=_str(data, "algorithm"),
            expires_at=_str(data, "expires_at"),
            replaced=_bool(data, "replaced"),
        )

    def __repr__(self) -> str:
        """Redacted, and this is the only reason the method exists.

        A ``StartedEnrollment`` is a credential: the secret in it is the account's
        second factor and it is never re-readable. The default dataclass ``repr``
        would print it, and the default dataclass ``repr`` is what lands in a
        debugger, a ``pytest`` assertion failure, a traceback with local variables,
        and a bug report somebody pastes into a chat.
        """
        return (
            f"StartedEnrollment(enrollment_id={self.enrollment_id!r}, "
            f"secret=[redacted: a credential-shaped value was present], "
            f"method={self.method!r}, digits={self.digits!r}, "
            f"period_seconds={self.period_seconds!r}, algorithm={self.algorithm!r}, "
            f"expires_at={self.expires_at!r}, replaced={self.replaced!r})"
        )


@dataclass(frozen=True, slots=True)
class ConfirmedEnrollment(_Model):
    """MFA is live, and here are the recovery codes, **once**.

    Every session this account holds was revoked to produce this response,
    including the caller's. The response is therefore ``200`` and not ``204``:
    there is real content, and that content exists exactly once.
    """

    enabled: bool
    #: ``"totp"``.
    method: str
    enrolled_at: str
    #: Printed once. There is no endpoint that re-reads them.
    recovery_codes: tuple[str, ...] = field(default_factory=tuple)
    replaced_existing_secret: bool = False

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> ConfirmedEnrollment:
        data = from_mapping(body)
        return cls(
            enabled=_bool(data, "enabled"),
            method=_str(data, "method"),
            enrolled_at=_str(data, "enrolled_at"),
            recovery_codes=_str_list(data, "recovery_codes"),
            replaced_existing_secret=_bool(data, "replaced_existing_secret"),
        )


@dataclass(frozen=True, slots=True)
class RecoveryCodesResponse(_Model):
    """A fresh set of recovery codes. The old set is destroyed in the same
    transaction that writes the new one — a partial write would leave two live
    sets, which is a second recovery path through codes nobody audited."""

    recovery_codes: tuple[str, ...]
    issued_at: str
    recovery_codes_remaining: int = 0

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> RecoveryCodesResponse:
        data = from_mapping(body)
        return cls(
            recovery_codes=_str_list(data, "recovery_codes"),
            issued_at=_str(data, "issued_at"),
            recovery_codes_remaining=_int(data, "recovery_codes_remaining"),
        )


@dataclass(frozen=True, slots=True)
class OIDCClient(_Model):
    """One OpenID Connect registration.

    ``client_secret`` and ``secret_digest`` are both absent and always will be:
    the secret exists once, in the 201, and the digest is what the row holds.
    """

    #: The row's identifier, and the ``subject`` of its events. **Not** the
    #: ``client_id`` the product presents to a relying party.
    id: str
    #: The identifier presented to a relying party.
    client_id: str
    name: str
    redirect_uris: tuple[str, ...] = field(default_factory=tuple)
    grant_types: tuple[str, ...] = field(default_factory=tuple)
    scopes: tuple[str, ...] = field(default_factory=tuple)
    created_at: str = ""
    #: Absent until revoked.
    revoked_at: str | None = None

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> OIDCClient:
        data = from_mapping(body)
        return cls(
            id=_str(data, "id"),
            client_id=_str(data, "client_id"),
            name=_str(data, "name"),
            redirect_uris=_str_list(data, "redirect_uris"),
            grant_types=_str_list(data, "grant_types"),
            scopes=_str_list(data, "scopes"),
            created_at=_str(data, "created_at"),
            revoked_at=_opt_str(data, "revoked_at"),
        )


@dataclass(frozen=True, slots=True)
class OIDCClientWithSecret(OIDCClient):
    """The ``201`` from registering an OIDC client: the registration **and** its
    secret.

    A subclass rather than an ``Optional[str]`` on :class:`OIDCClient`, because
    "this registration has a secret and you should print it once" and "this one
    does not" are different facts about the response, and a field whose presence
    depends on the endpoint makes the reader of a ``list`` call wonder whether it
    is missing or empty.

    ``client_secret`` is 32 random bytes, base64url, returned in this 201 and
    never again. Losing it means registering again.
    """

    client_secret: str = ""

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> OIDCClientWithSecret:
        data = from_mapping(body)
        return cls(
            id=_str(data, "id"),
            client_id=_str(data, "client_id"),
            name=_str(data, "name"),
            redirect_uris=_str_list(data, "redirect_uris"),
            grant_types=_str_list(data, "grant_types"),
            scopes=_str_list(data, "scopes"),
            created_at=_str(data, "created_at"),
            revoked_at=_opt_str(data, "revoked_at"),
            client_secret=_str(data, "client_secret"),
        )

    def __repr__(self) -> str:
        """Redacted, for the same reason :class:`StartedEnrollment` redacts its
        secret: an OIDC ``client_secret`` is a credential and the default
        dataclass ``repr`` prints it."""
        return (
            f"OIDCClientWithSecret(id={self.id!r}, client_id={self.client_id!r}, "
            "client_secret=[redacted: a credential-shaped value was present], "
            f"name={self.name!r}, created_at={self.created_at!r})"
        )


@dataclass(frozen=True, slots=True)
class Health(_Model):
    """A liveness or readiness answer.

    ``deps`` is present on ``/readyz`` only — it is the difference between "the
    process is up" and "the process can serve", and collapsing them is how a load
    balancer sends traffic to a service whose database is unreachable.
    """

    #: ``"ok"`` or ``"unavailable"``.
    status: str
    #: The dependencies probed, comma separated, or ``"none"``. ``/readyz`` only.
    deps: str | None = None

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> Health:
        data = from_mapping(body)
        return cls(status=_str(data, "status"), deps=_opt_str(data, "deps"))


# ---------------------------------------------------------------------------
# SCOPED API TOKENS (identity-08)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApiKey(_Model):
    """One scoped API token's metadata.

    Deliberately has **no** ``token`` field. The plaintext credential appears in
    exactly one response — :class:`IssuedApiKey` — and a model for the listing
    endpoints that could carry one would make it possible to hold a credential in
    a list, which is a credential that ends up in a log.
    """

    id: str
    #: The human label the caller gave it.
    name: str
    account_id: str
    user_id: str
    #: core's ``resource:action`` names. The set is closed.
    scopes: tuple[str, ...] = field(default_factory=tuple)
    expires_at: str = ""
    created_at: str = ""
    last_used_at: str | None = None
    revoked_at: str | None = None
    revoke_reason: str | None = None

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> ApiKey:
        data = from_mapping(body)
        return cls(
            id=_str(data, "id"),
            name=_str(data, "name"),
            account_id=_str(data, "account_id"),
            user_id=_str(data, "user_id"),
            scopes=_str_list(data, "scopes"),
            expires_at=_str(data, "expires_at"),
            created_at=_str(data, "created_at"),
            last_used_at=_opt_str(data, "last_used_at"),
            revoked_at=_opt_str(data, "revoked_at"),
            revoke_reason=_opt_str(data, "revoke_reason"),
        )


@dataclass(frozen=True, slots=True)
class IssuedApiKey(ApiKey):
    """The create response, and the **only** place a credential's plaintext
    appears.

    ``token`` is ``cafaye_`` plus 43 base64url characters, shown once here and
    unrecoverable afterwards — not because an endpoint is missing but because the
    row holds a SHA-256 of a 256-bit value. A caller that loses it mints another.

    The prefix is a feature and the feature is recognition: a secret that leaks
    into a CI log, a shell history or a support ticket is recognised as a cafaye
    credential by its first seven characters, which turns "somebody has to work
    out which of these strings is working" into a ``grep``. That makes printing it
    worse rather than better, which is why this model's ``repr`` is redacted and
    the credential-leak test asserts it.
    """

    #: The credential. Hand it to ``Cafaye.set_token`` and nowhere else.
    token: str = ""

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> IssuedApiKey:
        data = from_mapping(body)
        return cls(
            id=_str(data, "id"),
            name=_str(data, "name"),
            account_id=_str(data, "account_id"),
            user_id=_str(data, "user_id"),
            scopes=_str_list(data, "scopes"),
            expires_at=_str(data, "expires_at"),
            created_at=_str(data, "created_at"),
            last_used_at=_opt_str(data, "last_used_at"),
            revoked_at=_opt_str(data, "revoked_at"),
            revoke_reason=_opt_str(data, "revoke_reason"),
            token=_str(data, "token"),
        )

    def __repr__(self) -> str:
        """Redacted, for the reason in the class docstring: an API token is a
        credential, and the default dataclass ``repr`` prints it."""
        return (
            f"IssuedApiKey(id={self.id!r}, name={self.name!r}, "
            f"account_id={self.account_id!r}, scopes={self.scopes!r}, "
            "token=[redacted: a credential-shaped value was present])"
        )


@dataclass(frozen=True, slots=True)
class Introspection(_Model):
    """What identity knows about a presented credential.

    Two members are deliberately both present and both optional: ``scope`` and
    ``scopes``. identity-08 publishes **both** spellings of the scope claim because
    core has not settled which one is canonical (MD7 is open), and this client
    reports whichever arrived rather than picking a winner and hiding half the
    claim. Which one a service populates is a platform question; what a consumer
    reads is not this package's to decide.
    """

    #: ``False`` for an unknown, expired or revoked credential.
    active: bool
    #: The user id the credential authenticates as.
    sub: str | None = None
    account_id: str | None = None
    #: The scope claim, space separated.
    scopes: str | None = None
    #: The other spelling of the scope claim. See the class docstring.
    scope: str | None = None
    #: The token's unique id.
    jti: str | None = None
    name: str | None = None
    role: str | None = None
    #: Issued-at, as a unix timestamp.
    iat: int | None = None
    #: Expiry, as a unix timestamp.
    exp: int | None = None
    last_used_at: int | None = None

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> Introspection:
        data = from_mapping(body)
        return cls(
            active=_bool(data, "active"),
            sub=_opt_str(data, "sub"),
            account_id=_opt_str(data, "account_id"),
            scopes=_opt_str(data, "scopes"),
            scope=_opt_str(data, "scope"),
            jti=_opt_str(data, "jti"),
            name=_opt_str(data, "name"),
            role=_opt_str(data, "role"),
            iat=_opt_int(data, "iat"),
            exp=_opt_int(data, "exp"),
            last_used_at=_opt_int(data, "last_used_at"),
        )