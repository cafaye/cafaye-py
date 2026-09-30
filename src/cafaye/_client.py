"""The hand-written half of the client, and the jobs it owns.

MD6 ruled the structure of the two TypeScript and Python clients together:
"Structure: generated types and per-service transport, wrapped by one
hand-written client. … A single hand-written ``Cafaye`` class owns credential
handling, base-URL resolution for self-hosting, and RFC 9457
problem-to-exception mapping."

So this file is that class, and the reason it is hand-written is spelled out in
the brief: a generator imposes a runtime dependency, a pydantic v1/v2 split, or a
model layer that does not match the problem, and none of those is a better place
to hold the invariant that matters most here — **never log a credential**. A hand
-written client is also dependency-light: exactly one, `httpx`.

FOUR JOBS, IN THE ORDER THEY HAPPEN TO A REQUEST
-------------------------------------------------

1. **Where does it go?** — resolved once, in the constructor, and a
   misconfiguration is raised before a request exists.
2. **What proves who you are?** — attached per request, from current state, so a
   rotated credential takes effect on the next call.
3. **How long will we wait?** — one deadline, applied by httpx.
4. **What went wrong?** — the response becomes a value or a typed exception.

ONE IMPLEMENTATION, TWO FACES
-----------------------------

``httpx`` ships both a sync and an async client over one transport, and the brief
is explicit: "``httpx`` supports both from one implementation. Provide both; do
not write two clients."

The obvious way to honour that in Python is to write the request lifecycle twice,
which is what httpx itself does and what every SDK built on it ends up doing —
and the two copies drift, because nothing makes them the same code. So the
lifecycle here is written **once**, as a generator that yields the request it
wants sent and receives the response:

    pending = exchange.send(None)          # build
    response = transport.send(pending)     # I/O  <- the only line that differs
    value = exchange.send(response)        # map or raise

:class:`Cafaye` drives it synchronously and :class:`AsyncCafaye` drives it with
one ``await`` between those two lines. Everything that can be wrong — building
the URL, attaching the credential, deciding whether a body is a problem,
constructing the exception, redacting it — is one implementation, and the test
that the two faces produce identical results for identical responses is what keeps
it that way.

The credential is attached **per request**, not per client. The obvious
implementation puts the header in ``httpx.Client(headers=…)`` once. It is cheaper
and it is wrong for the case this package exists to serve: a long-lived worker
holds a credential that expires, and a client that captured it at construction
cannot be given a new one without being thrown away. :meth:`Cafaye.set_token`
exists for that.

WHY NO `__init__`-ONLY TIMEOUT
------------------------------

``timeout`` is an ``httpx`` client option, so setting it is one argument and
there is nothing to wrap. A non-positive value is refused rather than passed on,
because httpx's meaning for ``0`` ("no timeout") and ``-1`` differ and a negative
value reaches the platform as a timer delay long after the mistake that caused it.

NOTHING IS LOGGED
-----------------

This module does not import ``logging`` and never will. The brief's constraint is
"Never log a token, a cookie, or a JWT. Not at debug level, not in an error
message, not in a thrown exception", and the only way to *guarantee* that for a
library is to emit nothing: a debug log is a log level somebody turns off in
production and pastes into a bug report. ``tests/test_credential_leak.py``
asserts both halves — that no output is produced, and that a credential appears in
no message, no attribute and no serialised form of anything raised.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self, TypeVar, cast

import httpx

from ._base_url import SERVICE_NAMES, resolve_base_url
from ._credentials import CredentialKind, attach_credential, classify_credential
from ._errors import (
    CafayeConfigurationError,
    CafayeError,
    NetworkFailureReason,
    classify_network_failure,
    looks_like_problem,
    network_error_from,
    problem_error_from,
    protocol_error_from,
)
from ._redact import redact_text, safe_cause

__all__ = ["AsyncCafaye", "Cafaye", "DEFAULT_TIMEOUT"]

#: The default request timeout, in seconds.
#:
#: A judgement call the brief did not make. A client with no timeout can hang for
#: as long as the platform's own socket timeout allows, and a caller that wanted a
#: 200 gets nothing instead. Thirty seconds is long enough that no operation in
#: identity's document — all of which are ordinary request/response, with no
#: streaming and no long polling — would ever reach it, and short enough that a
#: wedged service is reported as a failure rather than inherited by the next
#: caller. Pass ``timeout=None`` to disable it.
DEFAULT_TIMEOUT = 30.0

T = TypeVar("T")

#: One operation's whole lifecycle, minus the I/O. Yields the request to send,
#: receives the response, returns the decoded value or raises. The two faces of
#: the client differ only in what they do between those two points.
Exchange = Generator["PendingRequest", httpx.Response, T]


@dataclass(frozen=True, slots=True)
class PendingRequest:
    """A request that has not been built by httpx yet.

    Deliberately a description rather than an ``httpx.Request``: building the
    request is httpx's job, and it needs its own client to do it — a
    ``Request`` constructed here would carry none of the transport extensions httpx
    puts on one and would be rejected at send time. The generator produces this,
    the driver lets httpx build it, and the only thing this package decides is
    which method, which URL, which headers.
    """

    method: str
    url: str
    headers: Mapping[str, str]
    #: Path parameters and query parameters, merged. httpx substitutes ``{name}``
    #: placeholders in the path from the same mapping it builds the query from,
    #: which is why one dict carries both.
    params: Mapping[str, object] | None = None
    json_body: object | None = None


def _decode(response: httpx.Response) -> object:
    """The body as a Python value, or ``None`` when it is not JSON.

    ``None`` for a body that will not parse is the honest answer and it is what
    keeps a reverse proxy's HTML 502 from becoming a ``JSONDecodeError`` with no
    mention of which service answered.
    """
    try:
        response.read()
    except httpx.ResponseNotRead:  # pragma: no cover - defensive; httpx raises this only for a streaming response mid-flight
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _body_text(body: object, response: httpx.Response) -> str:
    """The body as text, for a protocol error's excerpt.

    Falls back to the raw bytes for a body that is not JSON at all, because an
    HTML error page is the case this exists for. A body that cannot be decoded as
    UTF-8 is shown as its repr rather than dropped, since "no excerpt" and "no
    excerpt available" are different and the second is worth saying.
    """
    if isinstance(body, str):
        return body
    try:
        return response.text
    except (UnicodeDecodeError, httpx.ResponseNotRead):
        return repr(response.content)


class _BaseCafaye:
    """Everything both faces share: configuration, credentials, and the request
    lifecycle.

    Not public. A consumer instantiates :class:`Cafaye` or
    :class:`AsyncCafaye`; a third class that is neither is a thing with no meaning.
    """

    __slots__ = ("_base_url_sources", "_base_urls", "_default_headers", "_token", "_token_kind")

    def __init__(
        self,
        *,
        base_url: str | None,
        token: str | None,
        timeout: float | None,
        headers: Mapping[str, str] | None,
    ) -> None:
        resolved = {
            service: resolve_base_url(service, explicit=base_url)
            for service in SERVICE_NAMES
        }
        #: Where each of the six services is pointed, after resolution.
        self._base_urls: dict[str, str] = {
            service: value.url for service, value in resolved.items()
        }
        #: Which source answered for each, so a default is never invisible.
        self._base_url_sources: dict[str, str] = {
            service: value.source for service, value in resolved.items()
        }
        self._default_headers = dict(headers or {})
        self._token: str | None = None
        self._token_kind: CredentialKind | None = None
        # Classified before anything is stored, so a credential that would break
        # a header is refused by the setter rather than by a request hours later.
        self.set_token(token)

    # -- public surface ----------------------------------------------------

    @property
    def base_urls(self) -> Mapping[str, str]:
        """Where each of the six services is pointed.

        The URL as it goes on the wire — trailing slashes already stripped, a path
        prefix kept.
        """
        return dict(self._base_urls)

    @property
    def base_url_sources(self) -> Mapping[str, str]:
        """Which source answered for each service.

        One of three strings: ``"the `base_url` argument"``,
        ``"$CAFAYE_BASE_URL"``, or ``"the documented default"``. Public and closed
        so that a deployment can assert nothing resolved to the default without
        reaching into the client.
        """
        return dict(self._base_url_sources)

    @property
    def credential_kind(self) -> CredentialKind | None:
        """What kind of credential this client holds, or ``None``.

        The value is deliberately not exposed. A consumer that wants to know
        whether it handed over an API token or a session token gets the answer; a
        consumer that wants to read the token back out of its own client does not,
        because the moment an object can hand the credential out is the moment it
        ends up in a log through some code path nobody was thinking about.
        """
        return self._token_kind

    def set_token(self, token: str | None) -> None:
        """Replace the credential, or remove it with ``None``.

        It takes effect on the next request, which is the point: a process that
        outlives a token needs to hand over a new one, and a client that captured
        its credential at construction cannot be given one.

        Raises:
            CafayeConfigurationError: for an empty or control-character value.
                The value itself is never quoted back.
        """
        if token is None:
            self._token = None
            self._token_kind = None
            return
        self._token_kind = classify_credential(token)
        self._token = token

    # -- the request lifecycle, written once -------------------------------

    def _exchange(
        self,
        service: str,
        *,
        method: str,
        path: str,
        operation: str,
        params: Mapping[str, object] | None = None,
        json: object | None = None,
        model: Callable[[Mapping[str, Any]], T] | None = None,
    ) -> Exchange[T]:
        """Build one operation's exchange. No I/O happens here.

        A generator rather than a coroutine on purpose: a coroutine would force
        the sync face to run an event loop to drive it, and ``asyncio.run`` inside
        a synchronous method is a far worse answer than a generator that yields a
        request and receives a response.
        """
        headers: dict[str, str] = dict(self._default_headers)
        attach_credential(headers, self._token)
        return self._run(
            PendingRequest(
                method=method,
                url=f"{self._base_urls[service]}{path}",
                headers=headers,
                params=params,
                json_body=json,
            ),
            operation=operation,
            model=model,
        )

    def _run(
        self, pending: PendingRequest, *, operation: str, model: Callable[[Mapping[str, Any]], T] | None
    ) -> Exchange[T]:
        """The generator half: yield the request, then map the response.

        Split out from :meth:`_exchange` so that :meth:`_exchange` reads as a
        description of the call while this holds the protocol.
        """
        response: httpx.Response = yield pending
        return self._finish(response, operation=operation, model=model)

    def _finish(
        self, response: httpx.Response, *, operation: str, model: Callable[[Mapping[str, Any]], T] | None
    ) -> T | None:
        """Turn a response into a value, or raise. The five outcomes, in order:

        ==========  ==================================  ==========================
        outcome     when                                  raised
        ==========  ==================================  ==========================
        success     2xx, not problem-shaped               —
        no content  204, or an empty body, no model       —
        problem     2xx carrying a problem document        ``CafayeProtocolError``
        problem     non-2xx carrying a problem document   ``CafayeProblemError``
        protocol    non-2xx without one                   ``CafayeProtocolError``
        ==========  ==================================  ==========================

        The third row is the brief's "a problem-shaped body with a 200 is not a
        success", and it is the one most clients get wrong. Handing a caller a
        ``Problem`` where its annotation promised a ``User`` produces an
        ``AttributeError`` three frames from the mistake; raising here produces a
        diagnosis *at* the mistake.
        """
        secrets = [self._token] if self._token is not None else []
        content_type = response.headers.get("content-type")
        body = _decode(response)
        problem_shaped = looks_like_problem(body)

        if response.is_success:
            if _is_problem_media_type(content_type) or problem_shaped:
                raise protocol_error_from(
                    status=response.status_code,
                    body_text=_body_text(body, response),
                    problem_shaped=problem_shaped,
                    content_type=content_type,
                    operation=operation,
                    secrets=secrets,
                )
            if model is None or not response.content:
                return None
            return model(_as_mapping(body))

        if problem_shaped:
            raise problem_error_from(
                body=body,
                status=response.status_code,
                content_type=content_type,
                operation=operation,
                trace_id=response.headers.get("x-trace-id"),
                secrets=secrets,
            )
        raise protocol_error_from(
            status=response.status_code,
            body_text=_body_text(body, response),
            problem_shaped=False,
            content_type=content_type,
            operation=operation,
            secrets=secrets,
        )

    def _network_error(self, error: BaseException, operation: str) -> tuple[CafayeError, BaseException]:
        """Turn "no response arrived" into a typed exception and a safe cause.

        The message is assembled here and redacted here, because it is the one
        string in this package built out of a platform error's own text — and a
        platform error's text is caller-influenced in the case that matters: a
        URL, a hostname and an exception message are all things that can partly end
        up containing somebody's credential, because a proxy or a service that
        echoes one back is the ordinary accident this package exists to survive.

        Returns a **pair** rather than an exception, and that is the shape of a bug
        this module had and the tests caught. Raising the error from inside the
        ``except`` block left the original ``httpx.ConnectError`` reachable as
        ``__context__`` on the new one — a fully populated object with the
        credential in its ``args``, which ``traceback`` renders in full for any
        logger configured with ``exc_info`` and which ``pytest`` renders for every
        assertion failure. Redacting ``__cause__`` was not enough; the whole
        context chain has to be gone. So the caller raises this from **outside**
        the handler, where there is no active exception to inherit.
        """
        reason, errno = classify_network_failure(error)
        secrets = [self._token] if self._token is not None else []
        redact = redact_text(secrets)
        detail = str(error)
        described = reason.value if reason is not NetworkFailureReason.UNKNOWN else "failed"
        suffix = f" [errno {errno}]" if errno is not None else ""
        raised = network_error_from(
            reason=reason,
            message=redact(f"{operation}: the request {described}{suffix}: {detail}"),
            errno=errno,
        )
        return raised, cast(BaseException, safe_cause(error, redact))

    # -- the two faces ----------------------------------------------------

    def _validate_timeout(self, timeout: float | None) -> float | None:
        if timeout is None:
            return None
        if isinstance(timeout, bool) or not isinstance(timeout, int | float):
            raise CafayeConfigurationError(
                "`timeout` must be a number of seconds, or None to disable the deadline. "
                "A non-numeric value would reach httpx and fail on the first request rather "
                "than here, where the mistake is.",
                source="timeout",
            )
        if not math.isfinite(timeout) or timeout < 0:
            raise CafayeConfigurationError(
                "`timeout` must be a non-negative, finite number of seconds, or None to "
                "disable the deadline. A negative or non-finite value would make every "
                "request fail inside the transport rather than in this constructor.",
                source="timeout",
            )
        return timeout

    def __repr__(self) -> str:
        """Redacted, and there is no path by which it could not be.

        A client is the object a developer prints when something is wrong, and it
        is the object that holds the credential. This is what stops a REPL
        session, a ``pytest`` assertion failure or a debugger frame from becoming
        the place the token went.
        """
        kind = self._token_kind.value if self._token_kind is not None else "no credential"
        return (
            f"{type(self).__name__}(base_urls={self._base_urls!r}, "
            f"credential=<{kind}>)"
        )


def _is_problem_media_type(content_type: str | None) -> bool:
    """Is this ``Content-Type`` the one core reserves for failures?

    A parameter such as ``; charset=utf-8`` does not change the answer, and a
    service behind a proxy that rewrote the charset parameter is common.
    """
    if content_type is None:
        return False
    return content_type.split(";")[0].strip().lower() == "application/problem+json"


def _as_mapping(body: object) -> Mapping[str, Any]:
    from ._models import from_mapping

    return from_mapping(body)


def _drain(exchange: Exchange[T], response: httpx.Response) -> T:
    """Resume a synchronous exchange and take its value.

    ``StopIteration`` is how a generator returns, and catching it here rather than
    with ``return`` is the whole of the trampoline. The second ``StopIteration``
    arm — a generator that yielded again after receiving a response — is
    unreachable for every exchange this package builds, and is written anyway
    because the alternative is a ``TypeError: NoneType is not an async generator``
    three frames from a bug in a module that does not exist yet.
    """
    try:
        exchange.send(response)
    except StopIteration as finished:
        return finished.value  # type: ignore[no-any-return]
    raise CafayeError(
        "A cafaye request lifecycle produced more than one request. This is a bug in "
        "cafaye-py, not a failure of the call.",
    )  # pragma: no cover - unreachable for every exchange in this package


def _start(exchange: Exchange[T]) -> PendingRequest:
    """Run an exchange up to its first ``yield``."""
    try:
        return exchange.send(None)
    except StopIteration as exc:
        # A lifecycle that never asked for a request has nothing to send. Every
        # exchange this package builds yields once, so this arm is a statement
        # about the contract rather than a reachable path — and saying so beats
        # returning something the caller would then use as a request.
        raise CafayeError(
            "A cafaye request lifecycle ended without asking for a request. This is a bug in "
            "cafaye-py, not a failure of the call."
        ) from exc  # pragma: no cover


class Cafaye(_BaseCafaye):
    """The cafaye client, synchronously.

    .. code-block:: python

        from cafaye import Cafaye

        cafaye = Cafaye(base_url="https://identity.cafaye.com")
        user = cafaye.identity.get_current_user()

    One runtime dependency, one credential rule, one error model. Every operation
    on every service is reached through a property, and a failure is a typed
    exception rather than a status code to inspect.
    """

    __slots__ = ("_client", "identity")

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float | None = DEFAULT_TIMEOUT,
        headers: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Build a client.

        Args:
            base_url: Where requests go. Highest of three sources; see
                ``cafaye._base_url`` for the full order.
            token: A scoped API token (``cafaye_`` plus 32 bytes), a session
                token from ``POST /v1/session``, or a bearer JWT. Which one it is
                decides where it is sent, and the class works it out from the
                shape rather than being told.
            timeout: Seconds one request may take, or ``None`` to disable.
            headers: Headers to send with every request, e.g. a tracing header.
                An ``Authorization`` or ``Cookie`` header supplied here is
                **kept**: a caller that set one has said which credential it
                means.
            transport: The httpx transport. This is the seam the test suite
                drives, and it is how a consumer supplies an instrumented,
                proxy-aware or retrying transport of their own.

        Raises:
            CafayeConfigurationError: for an unresolvable or malformed base URL,
                a negative or non-finite timeout, or a credential that would
                break a header. All three before any request is made.
        """
        super().__init__(
            base_url=base_url,
            token=token,
            timeout=timeout,
            headers=headers,
        )
        self._client = httpx.Client(
            timeout=self._validate_timeout(timeout),
            transport=transport,
            follow_redirects=False,
        )
        # Imported here rather than at module scope because the dependency is
        # genuinely circular: a service module needs the client's base class to
        # type its operations, and the client needs the service class to expose
        # the property. One of the two has to defer, and a deferred import inside
        # the constructor is where the cycle is provably finished. `sys.modules`
        # is fully populated about twenty lines above this.
        from ._services.identity import IdentityService

        #: The ``identity`` operations. Twenty of them, from identity's document.
        self.identity = IdentityService(self)

    def _perform(self, exchange: Exchange[T]) -> T:
        """Drive one exchange. The only line that differs from the async face is
        in :meth:`_aperform`, and it is this line."""
        pending = _start(exchange)
        try:
            request = self._client.build_request(
                pending.method,
                pending.url,
                headers=dict(pending.headers),
                params=dict(pending.params) if pending.params else None,
                json=pending.json_body,
            )
            response = self._client.send(request)
        except Exception as exc:
            # `CancelledError` is a `BaseException`, so it is not caught here and
            # a cancelled coroutine stays cancelled — which is what lets a caller
            # tearing down a task not turn it into a retried request.
            failure = self._network_error(exc, pending.url)
        else:
            return _drain(exchange, response)
        # Outside the handler on purpose: see `_network_error`. Raising inside the
        # `except` would leave the original exception reachable as `__context__`.
        raise failure[0] from failure[1]

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class AsyncCafaye(_BaseCafaye):
    """The cafaye client, asynchronously.

    .. code-block:: python

        from cafaye import AsyncCafaye

        cafaye = AsyncCafaye(base_url="https://identity.cafaye.com")
        user = await cafaye.identity.get_current_user()

    The same options, the same credential rules, the same error model and the
    same operation names as :class:`Cafaye`. Two classes rather than one with an
    ``is_async`` flag, because the flag would have to be checked on every
    operation and a client that is in the wrong mode fails at the ``await`` rather
    than at the constructor.

    The lifecycle itself is not written twice: see :mod:`cafaye._client`.
    """

    __slots__ = ("_client", "identity")

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float | None = DEFAULT_TIMEOUT,
        headers: Mapping[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Build an asynchronous client. Every option means what it means on
        :meth:`Cafaye.__init__`; see there."""
        super().__init__(
            base_url=base_url,
            token=token,
            timeout=timeout,
            headers=headers,
        )
        self._client = httpx.AsyncClient(
            timeout=self._validate_timeout(timeout),
            transport=transport,
            follow_redirects=False,
        )
        from ._services.identity import AsyncIdentityService

        #: The ``identity`` operations, as coroutines.
        self.identity = AsyncIdentityService(self)

    async def _aperform(self, exchange: Exchange[T]) -> T:
        """Drive one exchange. Identical to :meth:`Cafaye._perform` with one
        ``await`` on the line that does I/O — and ``tests/test_client.py`` asserts
        the two faces agree on every outcome rather than trusting this comment."""
        pending = _start(exchange)
        try:
            request = self._client.build_request(
                pending.method,
                pending.url,
                headers=dict(pending.headers),
                params=dict(pending.params) if pending.params else None,
                json=pending.json_body,
            )
            response = await self._client.send(request)
        except Exception as exc:
            failure = self._network_error(exc, pending.url)
        else:
            return _drain(exchange, response)
        raise failure[0] from failure[1]

    async def aclose(self) -> None:
        """Close the underlying connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

