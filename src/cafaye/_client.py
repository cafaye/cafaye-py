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
from typing import Any, Protocol, Self, TypeVar, cast
from urllib.parse import quote

import httpx

from ._base_url import SERVICE_NAMES, resolve_base_url
from ._credentials import CredentialKind, attach_credential, classify_credential
from ._errors import (
    CafayeConfigurationError,
    CafayeError,
    ErrorKind,
    NetworkFailureReason,
    cancellation_in_chain,
    classify_network_failure,
    looks_like_problem,
    network_error_from,
    problem_error_from,
    protocol_error_from,
)
from ._redact import redact_text, safe_cause

__all__ = ["DEFAULT_TIMEOUT", "AsyncCafaye", "Cafaye"]

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

#: A decoder: a decoded JSON object in, the documented model out.
#:
#: Generic in its result, and that is the point. The response type of an
#: operation is named at its call site rather than looked up by string, so the
#: annotation on a public method and the decoder that runs are checked against
#: each other by the type checker instead of by a comment. The declaration table
#: in ``_services/identity.py`` stays the single source of truth, and
#: ``_declared`` is what holds the two to each other.
Model = Callable[[Mapping[str, Any]], T]

#: One operation's whole lifecycle, minus the I/O. Yields the request to send,
#: receives the response, returns the decoded value or raises. The two faces of
#: the client differ only in what they do between those two points.
Exchange = Generator["PendingRequest", httpx.Response, T]


class _SyncFace(Protocol):
    """What a **synchronous** service namespace needs from the client it holds.

    Structural rather than a base class, and it exists to make the wiring a
    checked fact. ``IdentityService`` and ``AsyncIdentityService`` take one of
    these, so ``Cafaye(…).identity`` being synchronous and
    ``AsyncCafaye(…).identity`` being a coroutine is something the type checker
    verifies at each construction site rather than something a reader has to take
    on trust from a comment.

    It is deliberately *not* ``_BaseCafaye``: that class is shared, and naming it
    here would say nothing, because the only two methods that distinguish the
    faces are exactly the two this protocol asks for.
    """

    def _exchange(
        self,
        service: str,
        *,
        method: str,
        path: str,
        operation: str,
        params: Mapping[str, Any] | None = None,
        json: object | None = None,
        model: Model[Any] | None = None,
    ) -> Exchange[Any]:
        """Build one operation's exchange. No I/O happens here."""
        ...

    def _perform(self, exchange: Exchange[Any]) -> Any:
        """Drive the exchange to completion and return its value."""
        ...


class _AsyncFace(Protocol):
    """:class:`_SyncFace`'s other half. The only differences are the two methods."""

    def _exchange(
        self,
        service: str,
        *,
        method: str,
        path: str,
        operation: str,
        params: Mapping[str, Any] | None = None,
        json: object | None = None,
        model: Model[Any] | None = None,
    ) -> Exchange[Any]:
        """Build one operation's exchange. No I/O happens here."""
        ...

    async def _aperform(self, exchange: Exchange[Any]) -> Any:
        """Drive the exchange to completion and return its value."""
        ...


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
    #: The **finished** URL. Path placeholders are already substituted, because
    #: httpx does not do it: given ``https://x/v1/accounts/{account_id}`` and
    #: ``params={"account_id": "a"}`` it produces
    #: ``https://x/v1/accounts/%7Baccount_id%7D?account_id=a``.
    url: str
    headers: Mapping[str, str]
    #: What is left after the path placeholders were consumed: the query, and only
    #: the query.
    #:
    #: ``Any`` rather than ``object`` because this mapping goes straight into
    #: httpx's ``build_request(params=...)``, whose parameter type is a closed
    #: union of the things a query value may be. ``object`` is not assignable to
    #: it; ``Any`` is, and narrowing it to something narrower here would mean
    #: re-deriving httpx's union in a second place to keep it in step.
    params: Mapping[str, Any] | None = None
    json_body: object | None = None


def _decode(response: httpx.Response) -> object:
    """The body as a Python value, or ``None`` when it is not JSON.

    ``None`` for a body that will not parse is the honest answer and it is what
    keeps a reverse proxy's HTML 502 from becoming a ``JSONDecodeError`` with no
    mention of which service answered.

    ONE ``ResponseNotRead`` GUARD, NOT TWO, AND THE SECOND WAS DEAD CODE
    -----------------------------------------------------------------------

    A streaming response raises ``ResponseNotRead`` from both ``read()`` **and**
    from ``json()``, because ``json()`` goes through ``self.content``. A second
    handler on the ``json()`` call therefore looked necessary and could not fire:
    if ``read()`` raised we have already returned, and if it did not, ``_content``
    is set and ``json()`` has nothing left to raise. Coverage said so, which is
    what ``fail_under = 100`` and ``--warn-unreachable`` are for -- "cannot happen"
    is a finding rather than a style note.

    What the second handler was covering, though, is real, and it is worth saying
    what actually holds the line: without the first one, the exception escaped
    ``_decode``, was caught by ``_perform``'s blanket ``except Exception``, and
    came back out as a ``CafayeNetworkError`` with ``reason="unknown"``. A
    client-side programming fault, described as the network having failed, which
    sends somebody to the wrong dashboard at three in the morning.

    So: one guard, on the call that can raise, and the body is treated as absent
    because it is.
    """
    try:
        response.read()
    except httpx.ResponseNotRead:
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
    except httpx.ResponseNotRead:
        # There is genuinely nothing to show, and the obvious fallback is wrong.
        #
        # Two things, both found by a test rather than by reading:
        #
        #   1. `UnicodeDecodeError` was in this tuple and could never fire.
        #      `httpx.Response.text` decodes with a `TextDecoder` that
        #      **replaces** undecodable bytes rather than raising, so a body of
        #      `b"\xff\xfe"` comes back as `"\ufffd\ufffd"`. A handler for an
        #      exception nothing raises is a branch the next reader has to reason
        #      about for no benefit, and this package runs mypy with
        #      `--warn-unreachable` and coverage at `fail_under = 100` precisely so
        #      that "cannot happen" is a finding rather than a style note.
        #
        #   2. `repr(response.content)` -- the fallback that was here -- raises
        #      **the same exception**, because `.content` on a streaming response
        #      nobody read is the access that failed. So the handler traded one
        #      `ResponseNotRead` for another, one frame later.
        #
        # An empty excerpt is the honest answer, and `protocol_error_from` already
        # turns an empty one into `body_snippet=None`, which is the same thing it
        # says when redaction removed everything: there is nothing here to show.
        # This package's own lifecycle never reaches it -- every response is read
        # before its text is asked for -- so it is a guard against a transport
        # that hands back a streaming response.
        return ""


class _BaseCafaye:
    """Everything both faces share: configuration, credentials, and the request
    lifecycle.

    Not public. A consumer instantiates :class:`Cafaye` or
    :class:`AsyncCafaye`; a third class that is neither is a thing with no meaning.
    """

    __slots__ = (
        "_base_url_sources",
        "_base_urls",
        "_default_headers",
        "_timeout",
        "_token",
        "_token_kind",
    )

    def __init__(
        self,
        *,
        base_url: str | None,
        token: str | None,
        timeout: float | None,
        headers: Mapping[str, str] | None,
    ) -> None:
        resolved = {
            service: resolve_base_url(service, explicit=base_url) for service in SERVICE_NAMES
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
        # Validated here rather than in each face, so there is one place that
        # decides what a valid deadline is. It was previously accepted here and
        # ignored, with each face validating its own copy -- a parameter that is
        # taken and never used is a function that lies about what it needs, and
        # `ruff`'s ARG002 was right to say so.
        self._timeout = self._validate_timeout(timeout)
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
        params: Mapping[str, Any] | None = None,
        json: object | None = None,
        model: Model[T] | None = None,
    ) -> Exchange[T]:
        """Build one operation's exchange. No I/O happens here.

        A generator rather than a coroutine on purpose: a coroutine would force
        the sync face to run an event loop to drive it, and ``asyncio.run`` inside
        a synchronous method is a far worse answer than a generator that yields a
        request and receives a response.
        """
        headers: dict[str, str] = dict(self._default_headers)
        attach_credential(headers, self._token)
        url, query = _resolve_path(f"{self._base_urls[service]}{path}", params)
        return self._run(
            PendingRequest(
                method=method,
                url=url,
                headers=headers,
                params=query,
                json_body=json,
            ),
            operation=operation,
            model=model,
        )

    def _run(
        self,
        pending: PendingRequest,
        *,
        operation: str,
        model: Model[T] | None,
    ) -> Exchange[T]:
        """The generator half: yield the request, then map the response.

        Split out from :meth:`_exchange` so that :meth:`_exchange` reads as a
        description of the call while this holds the protocol.
        """
        response: httpx.Response = yield pending
        return self._finish(response, operation=operation, model=model)

    def _finish(
        self,
        response: httpx.Response,
        *,
        operation: str,
        model: Model[T] | None,
    ) -> T:
        """Turn a response into a value, or raise. The five outcomes, in order:

        ==========  =========================================  ==========================
        outcome     when                                        raised
        ==========  =========================================  ==========================
        success     2xx, not problem-shaped, body present       —
        no content  2xx, and the operation declares no response   —
        protocol    2xx, problem-shaped                          ``CafayeProtocolError``
        protocol    2xx, empty body where one was declared       ``CafayeProtocolError``
        problem     non-2xx carrying a problem document          ``CafayeProblemError``
        protocol    non-2xx without one                          ``CafayeProtocolError``
        ==========  =========================================  ==========================

        The fourth row is the one most clients get wrong, and the brief asks for it
        by name: "a problem-shaped body with a 200 is not a success". Handing a
        caller a ``Problem`` where its annotation promised a ``User`` produces an
        ``AttributeError`` three frames from the mistake; raising here produces a
        diagnosis *at* the mistake.

        The fifth row is this package's own addition, and it is a typing decision
        as much as a behavioural one. ``GET /v1/me`` answers 200 and ``User``; a
        200 with **no body at all** is not a ``User``, and returning ``None``
        for it would mean every call site carries a ``None`` check that the
        annotation says is impossible. So the annotation and the behaviour agree,
        and a service that answers an empty 200 is reported as the contract
        violation it is.
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
            if model is None:
                # The only caller that passes no model is the service layer's
                # `_send`/`_post_void`, both declared `-> None`, which discard
                # this. Typing the return as `T | None` instead would put a `None`
                # check on all twenty operations to satisfy an annotation that is
                # already correct: a 204 for `DELETE /v1/session` returns nothing
                # because nothing was promised, not because nothing arrived.
                return cast("T", None)
            if not response.content:
                raise protocol_error_from(
                    status=response.status_code,
                    body_text="",
                    problem_shaped=False,
                    content_type=content_type,
                    operation=operation,
                    secrets=secrets,
                )
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

    def _failure(
        self, error: BaseException, operation: str
    ) -> tuple[BaseException, BaseException | None]:
        """The one place a transport failure becomes something to throw.

        Two answers, and which one applies is the whole design of this method:

        - A **cancellation** is the caller's own ``CancelledError``, returned as
          the identical object with no cause and no cafaye type. It is not
          classified, because there is nothing to classify: the party that
          cancelled the task is the only one that knows whether to re-attempt it,
          and a ``CafayeTimeoutError`` here would invite a retry loop to re-issue
          work during shutdown. Re-raising the identical object is also what
          keeps ``asyncio``'s cancellation bookkeeping — ``Task.cancelling()``
          and ``uncancel()`` — consistent with what the cancelling party did.
        - Anything else is a :class:`CafayeNetworkError` from
          :meth:`_network_error`, with a redacted cause.

        Returns a **pair** rather than raising, and that is the shape of a bug
        this module had and the tests caught. Raising from inside the ``except``
        block left the original ``httpx.ConnectError`` reachable as ``__context__``
        on the new one — a fully populated object with the credential in its
        ``args``, which ``traceback`` renders in full for any logger configured
        with ``exc_info`` and which ``pytest`` renders for every assertion
        failure. Redacting ``__cause__`` was not enough; the whole context chain
        has to be gone. So the caller raises this from **outside** the handler,
        where there is no active exception to inherit.
        """
        cancelled = cancellation_in_chain(error)
        if cancelled is not None:
            return cancelled, None
        return self._network_error(error, operation)

    def _network_error(
        self, error: BaseException, operation: str
    ) -> tuple[CafayeError, BaseException | None]:
        """Turn a failure that produced no response into a typed exception and a
        safe cause.

        The message is assembled here and redacted here, because it is the one
        string in this package built out of a platform error's own text — and a
        platform error's text is caller-influenced in the case that matters: a
        URL, a hostname and an exception message are all things that can partly end
        up containing somebody's credential, because a proxy or a service that
        echoes one back is the ordinary accident this package exists to survive.

        The reason this returns rather than raises is :meth:`_failure`'s, and the
        ``__context__`` paragraph there is the reason for the pair.
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
        return f"{type(self).__name__}(base_urls={self._base_urls!r}, credential=<{kind}>)"


def _resolve_path(url: str, params: Mapping[str, Any] | None) -> tuple[str, dict[str, Any]]:
    """Complete the path's ``{name}`` placeholders, and return what is left over.

    Two returns, and the split is derived rather than declared: **anything named in
    the path is a path parameter, and everything else is a query parameter.** The
    alternative is a second list per operation saying which is which, which is a
    second place to forget — and a service that renames a path parameter would
    then have two files to change rather than one.

    This exists because httpx does not do it. Given
    ``https://identity.cafaye.com/v1/accounts/{account_id}/api-keys`` and
    ``params={"account_id": "acc_1", "limit": 10}``, ``build_request`` produces::

        https://identity.cafaye.com/v1/accounts/%7Baccount_id%7D/api-keys?account_id=acc_1&limit=10

    The braces are percent-encoded, the identifier is in the query string where
    nothing reads it, and the request goes to a route that does not exist. Every
    operation with a path parameter in identity's document — nine of the twenty —
    was affected, and the mock transport never noticed, because a mock answers any
    URL. The unit suite asserted on ``request.url.path`` for three operations and
    read the braces as correct.

    Values are percent-encoded, and encoded strictly: a path parameter carrying a
    ``/`` or a ``?`` is a caller passing something that is not an identifier, and
    letting it through unencoded would turn one path segment into two and reach a
    different route than the caller named.
    """
    query = dict(params or {})
    for name in list(query):
        placeholder = "{" + name + "}"
        if placeholder in url:
            value = query.pop(name)
            url = url.replace(placeholder, quote(str(value), safe=""))
    return url, query


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


def _internal_bug(message: str) -> CafayeError:
    """The error for a state this package should not be able to reach.

    There are exactly three of these, and all three are internal invariants: a
    lifecycle that asked for two requests, one that asked for none, and a service
    method that decodes with a different model than the one its operation
    declares. None of them is anything the caller did.

    ``kind`` is ``CONFIGURATION``, and the choice is a precedent rather than a
    classification. The four kinds in :class:`~cafaye.ErrorKind` all describe *the
    caller's request failing*; an internal invariant is not that, and inventing a
    fifth kind would put this client's error vocabulary one member ahead of the
    one every other cafaye SDK has. ``cafaye-ts`` reports its own internal lookup
    miss — ``rawClient`` for a service it has no client for — the same way, and
    the two clients being one product is worth more than a fifth enum member.

    The message says what a caller should do about it, which is nothing except
    report it, and that is the honest advice.
    """
    return CafayeError(
        f"{message} This is a bug in cafaye-py, not a failure of the call.",
        kind=ErrorKind.CONFIGURATION,
    )


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
    raise _internal_bug(  # pragma: no cover - unreachable for every exchange here
        "A cafaye request lifecycle produced more than one request."
    )


def _start(exchange: Exchange[T]) -> PendingRequest:
    """Run an exchange up to its first ``yield``."""
    try:
        # `None` primes the generator, which yields the request before it can
        # receive a response. The `Exchange` alias declares the send type as a
        # `Response` because that is what is sent *after* priming, and this cast is
        # the one place that convention is expressed; the body of every exchange in
        # this package only ever resumes from a real response.
        return exchange.send(cast("httpx.Response", None))
    except StopIteration as exc:
        # A lifecycle that never asked for a request has nothing to send. Every
        # exchange this package builds yields once, so this arm is a statement
        # about the contract rather than a reachable path — and saying so beats
        # returning something the caller would then use as a request.
        raise _internal_bug(
            "A cafaye request lifecycle ended without asking for a request."
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
            timeout=self._timeout,
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
            # `CancelledError` is a `BaseException`, so a cancellation raised at
            # the `await` is not caught here either and a cancelled coroutine
            # stays cancelled. `_failure` handles the other case: a transport
            # that wrapped one, which is what the `cancellation_in_chain` guard is
            # for.
            failure = self._failure(exc, pending.url)
        else:
            return _drain(exchange, response)
        # Outside the handler on purpose: see `_failure`. Raising inside the
        # `except` would leave the original exception reachable as `__context__`,
        # with the credential in its `args`.
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
            timeout=self._timeout,
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
            failure = self._failure(exc, pending.url)
        else:
            return _drain(exchange, response)
        # Outside the handler, for the same reason as the sync face, and the
        # reason is in `_failure`.
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
