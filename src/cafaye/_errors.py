"""RFC 9457 problem documents, and the ways a request can fail.

Every non-2xx response from every cafaye service is
``application/problem+json`` — core's ``docs/openapi-conventions.md`` says "Every
non-2xx response is ``application/problem+json`` (RFC 9457) with the cafaye
extensions below. No service invents its own error body". That uniformity is the
opportunity: one shape means one place to turn a failure into a value a caller
can catch by type.

THE HIERARCHY, AND WHY THERE IS A FALLBACK
------------------------------------------

::

    CafayeError                        kind: problem | protocol | network | configuration
    ├── CafayeProblemError             a problem document arrived
    │   ├── CafayeUnauthenticatedError    401 unauthorized
    │   ├── CafayeForbiddenError          403 forbidden
    │   ├── CafayeNotFoundError           404 not_found
    │   ├── CafayeRateLimitedError        429 rate_limited
    │   ├── CafayeConflictError           409 conflict
    │   │   └── CafayeIdempotencyKeyReusedError   409 idempotency_key_reused
    │   └── CafayeValidationError         422 validation_failed
    ├── CafayeProtocolError          an HTTP response that is not what the contract says
    ├── CafayeNetworkError           no HTTP response at all
    │   └── CafayeTimeoutError        the network failure was a timeout
    └── CafayeConfigurationError     the options were wrong; no request was made

``CafayeProblemError`` is instantiable and **is** the fallback. A service that
adds a code tomorrow produces a ``CafayeProblemError`` carrying that code, not a
bare ``Exception`` — the brief's phrasing is the requirement: "a client that
raises a bare ``Error`` on an unrecognised problem type has moved the problem, not
solved it." A caller can therefore always write::

    try:
        ...
    except CafayeError as error:
        print(error.kind, error.status, error.code, error.trace_id)

and have it work against every failure this package can produce, including the
ones nobody has seen yet.

WHY ``status`` IS ``int | None`` RATHER THAN TWO ERROR TYPES
------------------------------------------------------------

The brief offers the choice — "One error type that covers both, with the
distinction queryable — or two types and a stated rule for which one you throw" —
and this takes the first, because the two are not disjoint in the way a ``match``
wants. A network failure and an HTTP failure are different in kind but identical
in handling: both mean "this call did not produce a result", both want the same
log line, and both are retried by the same code for most statuses. Making them
one type with a queryable ``kind`` and a ``status`` that is ``None`` when there
was no response means the common handler is ``error.status is not None`` rather
than an ``isinstance`` ladder, and a caller who does care can still branch on
``isinstance(error, CafayeNetworkError)``. The distinction is therefore **both**
queryable and subclassable, which is strictly more than either option alone.

A TIMEOUT IS NOT A DNS FAILURE, and they do not collapse here
------------------------------------------------------------

``CafayeTimeoutError`` extends ``CafayeNetworkError``, so
``except CafayeNetworkError: retry()`` catches both, and ``reason``
distinguishes them without the caller having to know that httpx reports a read
timeout as ``httpx.ReadTimeout`` while a name failure is ``httpx.ConnectError``
with a ``socket.gaierror`` in its ``__cause__``.
:func:`classify_network_failure` is where that knowledge lives, and it is a pure
function precisely so it can be tested without a socket, a DNS server or a timer.

Classification is by **type and errno**, never by message. A message is prose
written for a human by a library that had the same information and chose to
flatten it: httpx raises ``ConnectError("All connection attempts failed")`` for
*both* a refused connection and a name that did not resolve, so the difference
that matters is one level down.

THE THIRD WAY A REQUEST FAILS
-----------------------------

``CafayeProtocolError`` exists because the contract has two edges the problem
hierarchy does not cover, and both are judgement calls:

- A non-2xx response whose body is **not** a problem document. Something between
  the client and the service answered: a reverse proxy's HTML 502, a WAF's
  challenge, a rate limiter that is not cafaye. There is a status and there is no
  problem, so ``CafayeProblemError`` would be a lie about ``type`` and ``title``.
  The snippet of the body is kept — it is the single most useful thing when
  diagnosing a proxy — but redacted, and dropped entirely if anything
  credential-shaped is in it.

- A 2xx response whose body **is** a problem document. Handing a caller a
  ``Problem`` where its annotation promised a ``User`` is worse than stopping:
  the first produces an ``AttributeError`` three frames from the mistake, the
  second produces a diagnosis at the mistake.

WHY ``code`` CHOOSES THE CLASS AND ``status`` IS THE FALLBACK
-------------------------------------------------------------

core's conventions: "``type`` is a stable ``https://errors.cafaye.com/<code>``
URI — the machine-readable contract" and "``code`` is the same slug as the last
segment of ``type``". So ``code`` is the contract and ``status`` is a fact about
one response that a service could get wrong, or omit, since RFC 9457 makes
``status`` advisory. Mapping on ``code`` first and falling back to ``status``
means a service that answers 403 with ``code: "forbidden"`` is a
``CafayeForbiddenError`` even if the number drifts, and a service that omits
``code`` entirely is still mapped from the number.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import httpx

from ._redact import REDACTED, Redactor, redact_text

__all__ = [
    "CafayeConflictError",
    "CafayeConfigurationError",
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
    "ErrorKind",
    "FieldError",
    "NetworkFailureReason",
    "classify_network_failure",
    "is_cafaye_error",
    "looks_like_problem",
    "network_error_from",
    "problem_error_from",
    "protocol_error_from",
]


class ErrorKind(StrEnum):
    """What kind of failure this is. Present on every error in this module."""

    PROBLEM = "problem"
    PROTOCOL = "protocol"
    NETWORK = "network"
    CONFIGURATION = "configuration"


class NetworkFailureReason(StrEnum):
    """Why a request failed without producing a response.

    ``UNKNOWN`` is an answer, not a shrug. It means this package could not tell
    what happened, and a caller is better off knowing that than being told
    "connection" for something that was not. The usual cause is a transport the
    consumer supplied: the shapes recognised below are the ones httpx produces,
    and a transport that raises an ``Exception`` of its own is by definition not
    one of them.
    """

    TIMEOUT = "timeout"
    DNS = "dns"
    CONNECTION = "connection"
    TLS = "tls"
    PROTOCOL = "protocol"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FieldError:
    """A per-field failure. Present on a 422 and nowhere else, per core."""

    #: The request field that failed.
    field: str
    #: A stable slug, safe to switch on. ``required``, ``invalid_format``, …
    code: str


#: A dunder, so two installed copies of this package — a workspace link beside a
#: version, a transitive duplicate — agree. It is a *class* attribute, so it
#: never appears in ``vars()`` of an instance and therefore never in a serialised
#: log record. Two trailing underscores also mean Python does not mangle it.
_ERROR_MARKER = "__cafaye_error__"


class CafayeError(Exception):
    """The base of everything this package raises.

    ``kind`` and ``status`` are the queryable half of the "one type or two"
    question; ``status`` is ``None`` for everything that did not come with an HTTP
    response, which is the check a caller writes to tell "the service said no"
    from "the request never got there".

    ``code`` is a class attribute rather than a property so that a subclass can
    shadow it with an instance attribute. A property here would be a data
    descriptor, and assigning to one raises ``AttributeError`` — which would make
    ``CafayeProblemError`` impossible to construct.
    """

    __cafaye_error__: ClassVar[bool] = True

    #: The cafaye problem code, when this failure has one. ``None`` on every
    #: failure that did not arrive as a problem document, so the common handler
    #: can read it without branching.
    code: str | None = None
    #: Which of the four failure modes this is.
    kind: ErrorKind
    #: The HTTP status, or ``None`` when no HTTP response was involved.
    status: int | None

    def __init__(self, message: str, *, kind: ErrorKind, status: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status


class CafayeConfigurationError(CafayeError):
    """The options were wrong. No request was made, and none will be.

    Raised **before** anything is sent, so a misconfiguration is reported at the
    moment somebody can still do something about it rather than as a 401 from a
    service hours later. The option that was wrong is named by ``source``; its
    value is never quoted, because a credential that reached an exception message
    has leaked.
    """

    def __init__(self, message: str, *, source: str | None = None) -> None:
        super().__init__(message, kind=ErrorKind.CONFIGURATION)
        #: Which configuration source was consulted, when that is knowable.
        self.source = source


class CafayeProblemError(CafayeError):
    """An RFC 9457 problem document, as a thrown value.

    Every string the document contributed has been through the redactor before it
    got here, including the extension members and the per-field ``errors``. That
    is the mechanism behind "a token string appears in no … thrown object's
    serialised form": a service that echoes a caller's own credential back inside
    ``detail`` produces an exception whose ``detail`` is ``[redacted: …]``, not a
    credential in a log line four frames later.
    """

    #: Subclasses that must report "no field errors" as an empty tuple rather
    #: than ``None`` set this. One mechanism, rather than a second constructor
    #: per subclass that only differs by a default.
    _field_errors_default: ClassVar[tuple[FieldError, ...] | None] = None

    def __init__(
        self,
        message: str,
        *,
        type: str,  # noqa: A002 - RFC 9457 names the member `type`, and so do we
        title: str,
        status: int,
        detail: str = "",
        instance: str = "",
        code: str | None = None,
        trace_id: str | None = None,
        errors: Sequence[FieldError] | None = None,
        extensions: Mapping[str, object] | None = None,
        operation: str | None = None,
    ) -> None:
        super().__init__(message, kind=ErrorKind.PROBLEM, status=status)
        #: ``https://errors.cafaye.com/<code>`` — the machine-readable contract.
        self.type = type
        #: A fixed human-readable summary for the code.
        self.title = title
        #: Specific to this occurrence, and not parsed by clients.
        self.detail = detail
        #: The request path. Never includes the query string, which can carry an
        #: address.
        self.instance = instance
        #: The last segment of ``type``, in ``snake_case``. ``None`` if the
        #: service omitted it.
        self.code = code
        #: Always equal to the ``X-Trace-Id`` response header, and where support
        #: starts.
        self.trace_id = trace_id
        #: Per-field failures. ``None`` means the document carried none, which is
        #: different from an empty sequence on a class that promises the field.
        self.errors: tuple[FieldError, ...] | None = (
            self._field_errors_default if errors is None else tuple(errors)
        )
        #: Every member that is not one of the eight the fleet defines.
        self.extensions: Mapping[str, object] = dict(extensions or {})
        #: The service and operation the call was made through, for the log line.
        self.operation = operation


class CafayeUnauthenticatedError(CafayeProblemError):
    """401. The credential was absent, expired or revoked — core's ``unauthorized``."""


class CafayeForbiddenError(CafayeProblemError):
    """403. The credential is valid and not enough. core's ``forbidden``."""


class CafayeNotFoundError(CafayeProblemError):
    """404. core is careful about this one: "Never 404 for authorization failures
    on a resource the caller cannot see — 404 is correct there, 403 is not allowed
    to leak existence." So a 404 can mean "not a member of that account" and not
    only "no such account", and a caller must not read it either way."""


class CafayeRateLimitedError(CafayeProblemError):
    """429. core's ``rate_limited``."""


class CafayeConflictError(CafayeProblemError):
    """409. core's ``conflict``."""


class CafayeIdempotencyKeyReusedError(CafayeConflictError):
    """409 ``idempotency_key_reused`` — the same key with a different body.

    A subclass of :class:`CafayeConflictError` rather than a sibling, because it
    is one: "Replay with the same key but a different body returns 409
    ``idempotency_key_reused``", and a caller retrying a conflict has to check
    this one specifically before retrying anything, because the retry cannot
    succeed.
    """


class CafayeValidationError(CafayeProblemError):
    """422 ``validation_failed``, with the per-field failures core documents.

    ``errors`` is ``()`` rather than ``None`` when the service sent no array,
    because "a 422 that carried no field errors" is a service bug and an empty
    tuple is the truthful thing to say about one. Everywhere else it stays
    ``None``, so "no field errors" is distinguishable from "none to report".
    """

    _field_errors_default: ClassVar[tuple[FieldError, ...]] = ()


class CafayeProtocolError(CafayeError):
    """An HTTP response that is not what the contract says it is.

    ``problem_shaped`` says which of the two edges this is: a failure that did
    not arrive as a problem document, or a success that did. ``status`` is always
    a number here, because there was always a response — that is the difference
    from :class:`CafayeNetworkError` and the reason this is not a subclass of it.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        content_type: str | None = None,
        problem_shaped: bool = False,
        body_snippet: str | None = None,
        operation: str | None = None,
    ) -> None:
        super().__init__(message, kind=ErrorKind.PROTOCOL, status=status)
        #: The ``Content-Type`` the service sent, or ``None`` if it sent none.
        self.content_type = content_type
        #: Whether the body looked like a problem document but was not usable.
        self.problem_shaped = problem_shaped
        #: A redacted, truncated excerpt. ``None`` when redaction removed all of it.
        self.body_snippet = body_snippet
        #: The service and operation the call was made through.
        self.operation = operation


class CafayeNetworkError(CafayeError):
    """No HTTP response arrived.

    ``status`` is ``None`` — inherited, not overridden — and that is the whole
    point of keeping it on the base class. ``reason`` is what makes a timeout and
    a DNS failure different problems rather than the same one with different
    timings.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: NetworkFailureReason = NetworkFailureReason.UNKNOWN,
        errno: int | None = None,
    ) -> None:
        super().__init__(message, kind=ErrorKind.NETWORK)
        #: Which network failure this was.
        self.reason = reason
        #: The underlying platform errno, when the OS provided one. This is the
        #: difference between a refused connection and a name that did not
        #: resolve, and it is kept on the error itself so that withholding a
        #: ``__cause__`` never costs the caller the one thing they needed.
        self.errno = errno


class CafayeTimeoutError(CafayeNetworkError):
    """The request was given up on because it took too long.

    A subclass of :class:`CafayeNetworkError` rather than a sibling, and the
    reason is stated here rather than left implied: "the service did not answer in
    time" and "the name did not resolve" are both retryable, and only the second
    is worth retrying immediately. The two are chosen together in
    :func:`network_error_from` so the class and the ``reason`` can never disagree —
    a disagreement would be read by a caller as a retryability claim.
    """


def is_cafaye_error(value: object) -> bool:
    """Is this a cafaye error, including one thrown by a different copy of this
    package?

    ``isinstance`` alone is not enough. Two copies of ``cafaye-py`` in one
    dependency tree give two distinct ``CafayeError`` classes, and ``isinstance``
    returns ``False`` for an error thrown across the boundary. The failure is
    silent and looks like a bug in the consumer's error handling, which is the
    worst place to go looking for the cause.
    """
    return isinstance(value, CafayeError) or getattr(value, _ERROR_MARKER, False) is True


# ---------------------------------------------------------------------------
# CLASSIFICATION, AS PURE FUNCTIONS
# ---------------------------------------------------------------------------


def looks_like_problem(value: object) -> bool:
    """Does this body look like an RFC 9457 problem document?

    Structural, and deliberately so: ``type`` and ``title`` are the two members
    RFC 9457 requires, ``status`` is what every cafaye service repeats, and
    requiring three of them means an arbitrary JSON error body from a gateway does
    not get mistaken for a contract. The check is on the **body** rather than on
    the ``Content-Type``, because a mislabelled content type behind a proxy is
    common and the body is the thing that decides what a caller has to handle.
    """
    if not isinstance(value, Mapping):
        return False
    status = value.get("status")
    return (
        isinstance(value.get("type"), str)
        and isinstance(value.get("title"), str)
        # `bool` is an `int`, and `{"status": true}` is not a problem document.
        and isinstance(status, int)
        and not isinstance(status, bool)
    )


#: errno values that mean the name did not resolve. ``socket.gaierror`` carries
#: these and they are negative by POSIX convention, so they do not collide with
#: the connection errnos below.
_DNS_ERRNOS = frozenset({-2, -3, -5, -6, -8})

#: errno values that mean the connection never happened or was lost. All of these
#: are worth retrying; the TLS ones are not, which is why they are classified by
#: type rather than by a code list that would have to stay in step with OpenSSL.
_CONNECTION_ERRNOS = frozenset(
    {
        32,  # EPIPE        (Linux and the BSDs agree)
        51,  # ENETUNREACH  (Darwin/BSD)
        54,  # ECONNRESET   (Darwin/BSD)
        60,  # ETIMEDOUT    (Darwin/BSD)
        61,  # ECONNREFUSED (Darwin/BSD)
        65,  # EHOSTUNREACH (Darwin/BSD)
        101,  # ENETUNREACH  (Linux)
        104,  # ECONNRESET   (Linux)
        110,  # ETIMEDOUT    (Linux)
        113,  # EHOSTUNREACH (Linux)
    }
)


def classify_network_failure(error: BaseException) -> tuple[NetworkFailureReason, int | None]:
    """Work out why a request failed without producing a response.

    A pure function of the exception, and that is a deliberate constraint rather
    than an accident of factoring: the interesting cases are a timeout versus a
    name that did not resolve versus a certificate that did not verify, and the
    only way to test all three without a socket, a DNS server and a timer is to
    hand it the shapes httpx produces and assert what comes back.
    """
    errno: int | None = None
    for candidate in cause_chain(error):
        candidate_errno = getattr(candidate, "errno", None)
        if isinstance(candidate_errno, int):
            errno = candidate_errno
            break

    # httpx's own types first: they are unambiguous, and they are the shapes a
    # caller will actually see most often.
    if isinstance(
        error,
        httpx.ReadTimeout | httpx.ConnectTimeout | httpx.WriteTimeout | httpx.PoolTimeout,
    ):
        return NetworkFailureReason.TIMEOUT, errno
    if isinstance(error, httpx.UnsupportedProtocol):
        return NetworkFailureReason.PROTOCOL, errno

    for candidate in cause_chain(error):
        if isinstance(candidate, asyncio.CancelledError):
            # Not a network fault, and this is why the client re-raises a
            # cancellation untouched rather than wrapping it: the caller that
            # cancelled the task — usually a runtime shutting down — has to be
            # the one that handles it, or a cancelled request becomes a retried
            # request during shutdown.
            return NetworkFailureReason.TIMEOUT, errno
        if isinstance(candidate, socket.gaierror):
            return NetworkFailureReason.DNS, errno
        if isinstance(candidate, ssl.SSLError):
            return NetworkFailureReason.TLS, errno
        if isinstance(candidate, TimeoutError | socket.timeout):
            return NetworkFailureReason.TIMEOUT, errno
        if isinstance(
            candidate, ConnectionRefusedError | ConnectionResetError | ConnectionAbortedError
        ):
            return NetworkFailureReason.CONNECTION, errno
        if isinstance(candidate, BrokenPipeError):
            return NetworkFailureReason.CONNECTION, errno

    if errno is not None:
        if errno in _DNS_ERRNOS:
            return NetworkFailureReason.DNS, errno
        if errno in _CONNECTION_ERRNOS:
            return NetworkFailureReason.CONNECTION, errno

    if isinstance(error, httpx.TransportError):
        return NetworkFailureReason.CONNECTION, errno
    return NetworkFailureReason.UNKNOWN, errno


def cause_chain(error: BaseException, limit: int = 8) -> list[BaseException]:
    """The exception and its causes, outermost first, cycle-safe.

    A chain of eight is a library that wrapped five times over; anything deeper is
    a loop, and an unbounded walk over a structure a caller controls is a way to
    hang this package inside somebody's error handler.
    """
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and len(chain) < limit and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        following = current.__cause__ or current.__context__
        current = following if isinstance(following, BaseException) else None
    return chain


# ---------------------------------------------------------------------------
# BUILDING THE EXCEPTIONS
# ---------------------------------------------------------------------------

#: The five RFC 9457 members, plus cafaye's two extensions and the per-field
#: array. Anything outside this set is an extension, which is where a field a
#: service added yesterday ends up instead of being dropped.
_KNOWN_PROBLEM_MEMBERS = frozenset(
    {"type", "title", "status", "detail", "instance", "code", "trace_id", "errors"}
)

#: The classes a problem's ``code`` maps to. Stated as data rather than as a
#: chain of ``if``s so the mapping is one readable table and the **fallback is
#: visible next to it** — the ``or CafayeProblemError`` at the end of
#: :func:`problem_error_from` is the load-bearing line in this module.
_PROBLEM_CLASSES: Mapping[str, type[CafayeProblemError]] = {
    "unauthorized": CafayeUnauthenticatedError,
    "forbidden": CafayeForbiddenError,
    "not_found": CafayeNotFoundError,
    "rate_limited": CafayeRateLimitedError,
    "conflict": CafayeConflictError,
    "idempotency_key_reused": CafayeIdempotencyKeyReusedError,
    "validation_failed": CafayeValidationError,
}

_STATUS_CLASSES: Mapping[int, type[CafayeProblemError]] = {
    401: CafayeUnauthenticatedError,
    403: CafayeForbiddenError,
    404: CafayeNotFoundError,
    409: CafayeConflictError,
    422: CafayeValidationError,
    429: CafayeRateLimitedError,
}


def problem_error_from(
    *,
    body: object,
    status: int,
    content_type: str | None = None,
    operation: str | None = None,
    trace_id: str | None = None,
    secrets: Sequence[str] = (),
) -> CafayeProblemError:
    """Build the right exception for a problem document.

    ``code`` chooses the class and ``status`` breaks the tie, for the reason in
    the module docstring: ``code`` is the documented machine-readable contract and
    ``status`` is one response's opinion about itself. A code this package has
    never heard of lands on ``CafayeProblemError`` with that code intact — which
    is the fallback, and the reason the fleet can grow.
    """
    redact = redact_text(secrets)
    members: Mapping[str, object] = body if looks_like_problem(body) else {}

    raw_code = members.get("code")
    code = redact(raw_code) if isinstance(raw_code, str) else None

    body_status = members.get("status")
    resolved_status = (
        body_status
        if isinstance(body_status, int) and not isinstance(body_status, bool)
        else status
    )

    extensions = {
        key: _redact_value(redact, value)
        for key, value in members.items()
        if key not in _KNOWN_PROBLEM_MEMBERS
    }

    field_errors: tuple[FieldError, ...] | None = None
    raw_errors = members.get("errors")
    if isinstance(raw_errors, Sequence) and not isinstance(raw_errors, (str, bytes)):
        field_errors = tuple(_field_error_from(redact, entry) for entry in raw_errors)

    title = _string_member(redact, members, "title") or "Request failed"
    detail = _string_member(redact, members, "detail")
    type_uri = _string_member(redact, members, "type") or "about:blank"
    instance = _string_member(redact, members, "instance")
    body_trace = _string_member(redact, members, "trace_id")
    resolved_trace = body_trace if body_trace is not None else trace_id

    klass: type[CafayeProblemError] = (
        (_PROBLEM_CLASSES.get(code) if code is not None else None)
        or _STATUS_CLASSES.get(resolved_status)
        or CafayeProblemError
    )

    where = f"{operation}: " if operation else ""
    suffix = f" {code}" if code is not None else ""
    message = redact(f"{where}{resolved_status}{suffix} — {title}{'' if not detail else f': {detail}'}")

    return klass(
        message,
        type=type_uri,
        title=title,
        status=resolved_status,
        detail=detail,
        instance=instance,
        code=code,
        trace_id=resolved_trace,
        errors=field_errors,
        extensions=extensions,
        operation=operation,
    )


def protocol_error_from(
    *,
    status: int,
    body_text: str,
    problem_shaped: bool = False,
    content_type: str | None = None,
    operation: str | None = None,
    secrets: Sequence[str] = (),
) -> CafayeProtocolError:
    """Build the exception for a response that broke the contract in either
    direction.

    The body excerpt is kept because a reverse proxy's HTML 502 is otherwise
    undiagnosable from the client side, and dropped entirely when redaction
    removed all of it — ``redact`` returns one marker for the whole string, so a
    snippet equal to :data:`REDACTED` means "there was something credential-shaped
    in there and none of it is going in an exception".
    """
    redact = redact_text(secrets, max_length=200)
    where = f"{operation}: " if operation else ""

    if 200 <= status < 300:
        return CafayeProtocolError(
            redact(
                f"{where}HTTP {status} carried an application/problem+json body, which "
                "core's conventions reserve for failures. Treating it as a success would hand "
                "the caller a problem document where its annotation promised a result, so "
                "this is raised instead. The service is not following its own contract."
            ),
            status=status,
            content_type=content_type,
            problem_shaped=problem_shaped,
            operation=operation,
        )

    redacted = redact(body_text)
    media = "(no Content-Type)" if content_type is None else f"(Content-Type: {content_type})"
    return CafayeProtocolError(
        redact(
            f"{where}HTTP {status} did not return an RFC 9457 problem document{media}. "
            "Something between this client and the service answered — a proxy, a gateway, a "
            "rate limiter — so there is no problem document to map and no cafaye code to "
            "branch on."
        ),
        status=status,
        content_type=content_type,
        problem_shaped=problem_shaped,
        # `REDACTED` means the whole excerpt went, so there is nothing worth
        # showing and a marker in a `body_snippet` field would only be noise.
        body_snippet=None if redacted in {"", REDACTED} else redacted,
        operation=operation,
    )


def network_error_from(
    *,
    reason: NetworkFailureReason,
    message: str,
    errno: int | None = None,
) -> CafayeNetworkError:
    """Build the exception for a failure that produced no HTTP response.

    The class follows from ``reason`` here rather than at the call site, so the
    two can never disagree. The message is redacted by the caller, which is the
    one holding the credential this package must not print; there is nothing
    secret about a reason or an errno.
    """
    klass: type[CafayeNetworkError] = (
        CafayeTimeoutError if reason is NetworkFailureReason.TIMEOUT else CafayeNetworkError
    )
    return klass(message, reason=reason, errno=errno)


def _string_member(redact: Redactor, members: Mapping[str, object], key: str) -> str | None:
    value = members.get(key)
    return redact(value) if isinstance(value, str) else None


def _field_error_from(redact: Redactor, entry: object) -> FieldError:
    field = entry.get("field") if isinstance(entry, Mapping) else None
    code = entry.get("code") if isinstance(entry, Mapping) else None
    return FieldError(
        field=redact(field) if isinstance(field, str) else "",
        code=redact(code) if isinstance(code, str) else "",
    )


def _redact_value(redact: Redactor, value: object) -> object:
    """Redact every string inside a value, without losing its shape.

    Recursive on purpose and total on purpose: an extension member the fleet has
    never declared could be an object three levels down holding the credential,
    and a scrubber that only walked the top level would ship it.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, Mapping):
        return {str(key): _redact_value(redact, item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_redact_value(redact, item) for item in value]
    return value