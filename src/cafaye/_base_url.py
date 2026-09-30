"""One place that decides where requests go.

THE PRECEDENCE, HIGHEST FIRST
-----------------------------

1. the ``base_url`` argument
2. ``CAFAYE_BASE_URL``
3. the **documented default** for that service — ``servers[0]`` of the service's
   committed OpenAPI document
4. (there is no fourth step: nothing else is consulted and nothing is guessed)

Each must win in turn, and the *source that answered* is recorded on the client
as :attr:`Cafaye.base_url_sources`, so "which one was it" is a fact a deployment
can assert on rather than a thing it has to infer.

Explicit beats ambient, and that is the whole rule: a value somebody passed as an
argument is a decision somebody made; an environment variable is a decision
somebody made too, but further away and easier to forget.

WHY THE DEFAULT IS THE DOCUMENT'S ``servers[0]``, AND NOT ITS LOCALHOST ENTRY
------------------------------------------------------------------------------

Every one of the six documents lists two servers. ``identity``'s reads::

    servers:
      - url: https://identity.cafaye.com
        description: production
      - url: http://localhost:8080

Taking ``servers[1]`` would make a developer's laptop work and would send a
production process to ``localhost`` — a silent misdirection whose only symptom is
a connection refused against a service nobody asked for. ``servers[0]`` is the
entry each document *labels* production, so the default is a fact from the
contract rather than a guess by this package.

WHY A DEFAULT IS NOT A SILENT DEFAULT
-------------------------------------

A default nobody can detect is indistinguishable from a default somebody chose.
Two things make this one visible:

- :attr:`Cafaye.base_url_sources` is public and every value is one of three
  strings, so a deployment can assert that nothing resolved to
  ``"the documented default"``.
- No default and no error message ever names a loopback address. The test in
  ``tests/test_base_url.py`` asserts that over every refusal this module can
  produce, and it is the same property ``cafaye-ts`` asserts for the same
  reason.

DIVERGENCE FROM ``cafaye-ts``, STATED PLAINLY
----------------------------------------------

``cafaye-ts`` resolves in five steps and **throws** when nothing is configured,
citing "a default would be a guess, and a guess about which deployment to send a
customer's credentials to is the one kind of guess this package refuses to make."
This client has a documented default, because its brief specifies
``explicit → CAFAYE_BASE_URL → the documented default`` and that default is a
value read out of a committed document rather than a guess about a deployment.

Both clients keep the property that actually matters — nothing here can resolve to
a loopback address — and both expose the source that answered. The remaining
difference is a real platform question rather than a bug in either client: should
a credential-carrying client default to a public SaaS host at all? It is recorded
in ``REPORT-cafaye-py-01.md`` as something for the platform to settle, not as
something this packet settles.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from ._errors import CafayeConfigurationError

__all__ = [
    "BASE_URL_ENV",
    "DEFAULT_BASE_URLS",
    "SERVICE_NAMES",
    "ResolvedBaseUrl",
    "resolve_base_url",
]

#: The environment variable that applies to every service.
BASE_URL_ENV: Final = "CAFAYE_BASE_URL"

#: The six services, as a name. One list, stated once, and
#: ``tests/test_services.py`` asserts it against the six service modules so a
#: seventh service fails the suite in the place where the omission is rather than
#: producing a six-of-seven client that reports success.
SERVICE_NAMES: Final[tuple[str, ...]] = (
    "identity",
    "billing",
    "courier",
    "darkroom",
    "muse",
    "pantry",
)

#: ``servers[0]`` of each service's committed OpenAPI document — the entry each
#: document labels "production". Provenance for each is in ``REPORT-cafaye-py-01.md``
#: and the shape is asserted in ``tests/test_base_url.py``: every one is
#: ``https://<service>.cafaye.com``.
DEFAULT_BASE_URLS: Final[Mapping[str, str]] = {
    "identity": "https://identity.cafaye.com",
    "billing": "https://billing.cafaye.com",
    "courier": "https://courier.cafaye.com",
    "darkroom": "https://darkroom.cafaye.com",
    "muse": "https://muse.cafaye.com",
    "pantry": "https://pantry.cafaye.com",
}

#: The three source strings a resolved base URL can carry. Public, and a closed
#: set, because a deployment asserting on them has to be able to enumerate them.
SOURCE_ARGUMENT: Final = "the `base_url` argument"
SOURCE_ENV: Final = f"${BASE_URL_ENV}"
SOURCE_DEFAULT: Final = "the documented default"


@dataclass(frozen=True, slots=True)
class ResolvedBaseUrl:
    """Where one service's requests go, and which source said so."""

    #: The URL as it will go on the wire — trailing slashes already stripped.
    url: str
    #: One of :data:`SOURCE_ARGUMENT`, :data:`SOURCE_ENV`, :data:`SOURCE_DEFAULT`.
    source: str


def _present(value: str | None) -> str | None:
    """Trim, and treat blank as absent. An empty base URL is not a base URL."""
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed or None


def _is_absolute_http_url(value: str) -> bool:
    """Is this an absolute http(s) URL?

    A bare host is refused rather than completed. ``identity.example.com``
    concatenated with ``/v1/me`` is ``identity.example.com/v1/me``, which is not a
    URL at all, and the resulting failure names neither the typo nor the cause.
    """
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


def _normalise(value: str) -> str:
    """Strip trailing slashes so the URL this reports is the URL that goes out.

    A path prefix is **kept**, because a self-hoster may serve the whole fleet
    under ``/cafaye``, and ``urlsplit(...).netloc`` would helpfully but wrongly
    throw it away.
    """
    return value.rstrip("/")


def resolve_base_url(
    service: str,
    *,
    explicit: str | None = None,
    env: Mapping[str, str] | None = None,
) -> ResolvedBaseUrl:
    """Where requests to one service go.

    ``env`` defaults to :data:`os.environ`, read **per call** rather than
    snapshotted at import time. That is not a detail: a module that snapshotted
    the environment would pass every test here and then be wrong in a worker that
    sets its own variables after import, which is how most of them are configured.

    Raises:
        CafayeConfigurationError: for an unknown service name, or for a value that
            was set and is not an absolute http(s) URL. The message names the
            source that was consulted and never suggests a host.
    """
    if service not in DEFAULT_BASE_URLS:
        raise CafayeConfigurationError(
            f"{service!r} is not a cafaye service. The services are: "
            f"{', '.join(SERVICE_NAMES)}. Refusing to resolve a base URL for anything else, "
            "because a name that is not one of the six is a typo and quietly resolving a URL "
            "for it would hide that typo until a 404 from a proxy.",
            source=f"service name {service!r}",
        )

    environment = os.environ if env is None else env

    # Highest first, and each candidate carries the source that would answer if it
    # were used — so the refusal below can name the one that was actually wrong
    # rather than listing all three.
    candidates: tuple[tuple[str | None, str], ...] = (
        (_present(explicit), SOURCE_ARGUMENT),
        (_present(environment.get(BASE_URL_ENV)), SOURCE_ENV),
        (DEFAULT_BASE_URLS[service], SOURCE_DEFAULT),
    )

    for value, source in candidates:
        if value is None:
            continue
        if not _is_absolute_http_url(value):
            raise CafayeConfigurationError(
                f"The base URL from {source} is not an absolute http(s) URL. cafaye "
                "concatenates the base URL with the operation's path rather than resolving "
                "one against the other, so a bare host would produce something that is not a "
                "URL and an error that names neither the value nor the cause. Give an "
                "absolute URL including the scheme. Set one of, in order: the `base_url` "
                f"argument, ${BASE_URL_ENV}, or rely on the documented default "
                f"{DEFAULT_BASE_URLS[service]}.",
                source=source,
            )
        return ResolvedBaseUrl(url=_normalise(value), source=source)

    # Unreachable while `DEFAULT_BASE_URLS` covers every service, which the guard
    # above enforces. Kept rather than omitted because a `resolve_base_url` that
    # could fall off the end would return `None` and be caught three frames away,
    # in a caller, as an `AttributeError` with no mention of a base URL.
    raise CafayeConfigurationError(  # pragma: no cover - unreachable by construction
        f"No base URL could be resolved for {service}.", source=service
    )