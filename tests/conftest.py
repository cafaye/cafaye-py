"""Shared test doubles.

Two rules this suite is built on, both from the brief:

- **No network in tests.** Every request goes through ``httpx.MockTransport``,
  which returns a canned response without a socket. ``test_suite_is_offline.py``
  enforces it at the suite level by making socket creation raise, so a test that
  reaches for the network fails loudly instead of passing on a machine that
  happens to be online.
- **No sleeps, no retries, no loosened assertions.** Nothing here waits. A test
  that needed a wait would be a test that is testing the clock.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Coroutine, Mapping
from typing import Any, TypeVar

import httpx
import pytest

from cafaye import AsyncCafaye, Cafaye

BASE = "https://identity.example.test"

T = TypeVar("T")


def problem_body(
    code: str,
    *,
    status: int | None = None,
    title: str = "Something went wrong",
    detail: str = "a detail the service chose",
    trace_id: str = "0af7651916cd43dd8448eb211c80319c",
    **extra: Any,
) -> dict[str, Any]:
    """A cafaye problem document, as core's conventions specify it."""
    body: dict[str, Any] = {
        "type": f"https://errors.cafaye.com/{code}",
        "title": title,
        "status": status if status is not None else 400,
        "detail": detail,
        "instance": "/v1/me",
        "code": code,
        "trace_id": trace_id,
    }
    body.update(extra)
    return body


Handler = Callable[[httpx.Request], httpx.Response]


def responding_with(
    response: httpx.Response | Callable[[httpx.Request], httpx.Response],
) -> Handler:
    """A handler returning ``response``, or calling it if it is a callable."""
    if callable(response):  # pragma: no cover - defensive, both forms are used
        return response
    return lambda _request: response


def sync_client(
    response: httpx.Response | Handler,
    *,
    token: str | None = None,
    base_url: str = BASE,
) -> tuple[Cafaye, list[httpx.Request]]:
    """A ``Cafaye`` wired to a mock transport, and the list of requests it sent."""
    handler = responding_with(response)
    sent: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return handler(request)

    client = Cafaye(
        base_url=base_url,
        token=token,
        transport=httpx.MockTransport(record),
    )
    return client, sent


def async_client(
    response: httpx.Response | Handler,
    *,
    token: str | None = None,
    base_url: str = BASE,
) -> tuple[AsyncCafaye, list[httpx.Request]]:
    handler = responding_with(response)
    sent: list[httpx.Request] = []

    async def record(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return handler(request)

    client = AsyncCafaye(
        base_url=base_url,
        token=token,
        transport=httpx.MockTransport(record),
    )
    return client, sent


def json_response(
    status: int,
    body: Mapping[str, Any] | list[Any] | None,
    *,
    content_type: str = "application/json",
) -> httpx.Response:
    if body is None:
        return httpx.Response(status, headers={"content-type": content_type})
    return httpx.Response(
        status,
        content=json.dumps(body).encode(),
        headers={"content-type": content_type},
    )


def problem_response(
    code: str,
    status: int,
    *,
    detail: str = "a detail the service chose",
    title: str = "Something went wrong",
    content_type: str = "application/problem+json",
    trace_id: str | None = "0af7651916cd43dd8448eb211c80319c",
    **extra: Any,
) -> httpx.Response:
    body = problem_body(code, status=status, title=title, detail=detail, **extra)
    if trace_id is not None:
        body["trace_id"] = trace_id
    return json_response(status, body, content_type=content_type)


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """Drive one coroutine to completion, on this thread, in a fresh loop.

    Async tests are **synchronous tests** that call ``asyncio.run``, and the
    reason is not brevity: an async test plugin brings a loop fixture, a session
    scope, a marker and a third runtime dependency into a package whose selling
    point is one runtime dependency. ``asyncio.run`` also makes the assertion
    shape identical to the sync case — the same ``pytest.raises`` around the same
    call — which is what lets the sync and async faces be proven equivalent
    rather than merely both present.
    """
    return asyncio.run(coroutine)