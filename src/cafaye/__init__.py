"""cafaye-py — the cafaye Python client.

WHAT THIS FILE IS, AND WHAT IT IS NOT
-------------------------------------

This is the package's public entrypoint, and it is the whole of the public
surface: the two client classes, the exception hierarchy, the credential and
base-URL constants, and the response models. It holds no credential, no base-URL
logic and no error mapping — all of that is in the private modules behind it, and
the point of having a package behind this file is that the entrypoint itself stays
a list of names.

MD6 ruled the structure for the clients together: "Structure: generated types and
per-service transport, wrapped by one hand-written client. … Generated code stays
an implementation detail, so a generator upgrade can never break the public API."
cafaye-ts generates its six service namespaces and wraps them. **This client does
not generate anything** — its brief ruled that out for Python specifically
(``openapi-python-client`` and its relatives "each impose a runtime dependency, a
pydantic v1/v2 split, or a model layer that does not match the problem") — and the
hand-written half is therefore the whole half. The consequence a consumer sees is
the same one either way: you construct ``Cafaye`` and reach every operation
through a property.

WHY THE ENTRYPOINT HAS NO SERVICES IN IT
---------------------------------------

``cafaye-ts`` re-exports its six namespaces from its entrypoint. This one does
not, because it has exactly one service module and a re-export of a single symbol
is an indirection with nothing behind it. When the second service lands the
pattern appears here, and this file grows with it.

The naming rule, and the one place the two clients differ
---------------------------------------------------------

Python names are snake_case; the documents' ``operationId``s are camelCase. So
``get_current_user`` here is ``getCurrentUser`` in ``cafaye-ts``. A camelCase
method name in a Python client would be a defect rather than a parity win. What is
identical is the **error-model and credential behaviour**, the RFC 9457 mapping,
the ``kind``/``status``/``code`` accessors, and the operation's identity as it
appears in an exception's ``operation``. The full mapping is in ``README.md``.

WHAT IS NOT HERE
----------------

Nothing that composes two services, refreshes a token, retries, paginates, or
caches. Its absence is deliberate rather than pending, and the reasoning is in
``AGENTS.md``: each is a place to put a policy the platform should own, and putting
one here would make the fleet's current shape a thing a consumer's application
depends on.
"""

from __future__ import annotations

from ._base_url import (
    BASE_URL_ENV,
    DEFAULT_BASE_URLS,
    SERVICE_NAMES,
    SOURCE_ARGUMENT,
    SOURCE_DEFAULT,
    SOURCE_ENV,
    ResolvedBaseUrl,
    resolve_base_url,
)
from ._client import DEFAULT_TIMEOUT, AsyncCafaye, Cafaye
from ._credentials import (
    API_TOKEN_PREFIX,
    SESSION_COOKIE_NAME,
    CredentialKind,
    classify_credential,
)
from ._errors import (
    CafayeConfigurationError,
    CafayeConflictError,
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
    ErrorKind,
    FieldError,
    NetworkFailureReason,
    is_cafaye_error,
    network_error_from,
    problem_error_from,
    protocol_error_from,
)
from ._models import (
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
from ._redact import REDACTED, redact_text

__all__ = [
    "API_TOKEN_PREFIX",
    "BASE_URL_ENV",
    "DEFAULT_BASE_URLS",
    "DEFAULT_TIMEOUT",
    "REDACTED",
    "SERVICE_NAMES",
    "SESSION_COOKIE_NAME",
    "SOURCE_ARGUMENT",
    "SOURCE_DEFAULT",
    "SOURCE_ENV",
    "ApiKey",
    "AsyncCafaye",
    "Cafaye",
    "CafayeConfigurationError",
    "CafayeConflictError",
    "CafayeError",
    "CafayeForbiddenError",
    "CafayeIdempotencyKeyReusedError",
    "CafayeNetworkError",
    "CafayeNotFoundError",
    "CafayeProblemError",
    "CafayeProtocolError",
    "CafayeRateLimitedError",
    "CafayeTimeoutError",
    "CafayeUnauthenticatedError",
    "CafayeValidationError",
    "ConfirmedEnrollment",
    "CredentialKind",
    "ErrorKind",
    "FieldError",
    "Health",
    "Introspection",
    "IssuedApiKey",
    "MfaChallenge",
    "MfaStatus",
    "NetworkFailureReason",
    "OIDCClient",
    "OIDCClientWithSecret",
    "RecoveryCodesResponse",
    "ResolvedBaseUrl",
    "Session",
    "StartedEnrollment",
    "User",
    "classify_credential",
    "is_cafaye_error",
    "network_error_from",
    "problem_error_from",
    "protocol_error_from",
    "redact_text",
    "resolve_base_url",
]
