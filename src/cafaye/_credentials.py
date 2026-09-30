"""Which credential is this, and where may it go?

cafaye has **two auth models**, and a client that supports only one is useless for
half its users. identity issues an opaque server-side **session token**, which is
what a browser holds in a cookie; the other five services take a JWKS-verified
**bearer JWT**. identity-08 added a third *shape* — a scoped, revocable **API
token** — on top of those two models. Two models, three shapes.

THE PREFIX IS THE DISCRIMINATOR, and identity already decided that
------------------------------------------------------------------

identity's ``internal/httpapi/apikeys.go`` says it outright: "THE PREFIX IS THE
DISCRIMINATOR, and that is the second thing the ``cafaye_`` prefix buys. A
request arrives with either a session token or an api key, and the two live in
different tables with different lifetimes and different revocation stories.
Something has to decide which one this is before the database is asked, and the
prefix decides it without a query."

So this module reads the same prefix, for the same reason. That is a decision to
follow identity rather than to invent a parallel scheme, and it is why
:data:`API_TOKEN_PREFIX` is a module constant that can be checked against
identity's ``apikeys.Prefix`` rather than a string literal buried in a branch.

WHY THE THREE-WAY SPLIT AND NOT TWO
----------------------------------

A **session token** is the only shape that is allowed to travel in a cookie.
identity's document says so, and so does core: "No cookies for API traffic;
browser sessions use … cookies and a CSRF token, and those are a *different*
surface, not an API exception."

A **JWT** is not a session, and if the classifier cannot tell them apart it will
eventually put a fleet-wide service credential into a ``Cookie`` header, which a
browser refuses to let a script set and a reverse proxy is happy to log. The
asymmetry decides the fallback: a session misread as a JWT loses a cookie it did
not strictly need — the bearer header is still attached, and identity documents
that it prefers the header when both are present — while a JWT misread as a
session publishes itself onto the wrong surface. So an unrecognised value is a
session, and that is the safe direction to be wrong in.
"""

from __future__ import annotations

import base64
import binascii
import json
from enum import StrEnum
from typing import Final

from ._errors import CafayeConfigurationError

__all__ = [
    "API_TOKEN_PREFIX",
    "SESSION_COOKIE_NAME",
    "CredentialKind",
    "attach_credential",
    "classify_credential",
]

#: identity's ``apikeys.Prefix``. Read as the discriminator, exactly as identity
#: does; see the module docstring for the quoted reason.
API_TOKEN_PREFIX: Final = "cafaye_"

#: identity's ``httpapi.SessionCookieName``. The ``__Host-`` prefix is not
#: cosmetic: it is a browser-enforced contract requiring ``Secure``, ``Path=/``
#: and no ``Domain``, and a request that names the cookie wrongly is a request
#: that looks authenticated and is not.
SESSION_COOKIE_NAME: Final = "__Host-session"

#: The header a bearer token goes in. Named once because it appears in three
#: places and a header name is exactly the sort of thing that should not be
#: spelled out three times.
_AUTHORIZATION: Final = "Authorization"


class CredentialKind(StrEnum):
    """What a credential is, which decides where it may be sent."""

    API_TOKEN = "api_token"
    JWT = "jwt"
    SESSION = "session"


#: Characters that cannot appear in a credential.
#:
#: A safety floor, not a definition. The point is not to enumerate the alphabet —
#: which would break the first time the fleet mints something new — but to refuse
#: anything that could terminate a header line or a cookie attribute. CR, LF and
#: NUL are header injection; the other C0 controls, DEL and the space have no
#: legitimate use in any of the three shapes, and a credential containing one is
#: a configuration mistake whatever produced it. Reporting that at construction is
#: worth more than a 401 from a service three hours later.
# `range(0x21)`, not `range(0x20)`: 0x20 is the space, and the space is the one
# character above the C0 range that is forbidden here. `range(0x20)` stops at 0x1F
# and would admit it — which `tests/test_credentials.py` caught, with the case
# `"cafaye_a b"` and the docstring above promising otherwise.
_FORBIDDEN_IN_CREDENTIAL: Final = frozenset(chr(code) for code in range(0x21)) | {"\x7f"}


def _is_jws(token: str) -> bool:
    """Is this a JWS compact serialization, and does its header say so?

    The shape is necessary and not sufficient, so the header segment is decoded
    and parsed. That costs one ``base64`` decode and one ``json`` parse per
    classification — once per credential, not per request — and it is what keeps
    ``one.two.three``, which has three segments and is not a JWT, out of the JWT
    branch.

    Returns ``False`` rather than raising for anything undecodable, because
    "is this a JWT" has no failure mode: a value that is not a JWS is a session.
    """
    segments = token.split(".")
    if len(segments) != 3 or not all(segments[:2]) or not segments[2]:
        return False
    padded = segments[0] + "=" * (-len(segments[0]) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        header = json.loads(raw)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        # Not base64, not JSON, or not decodable as ASCII: whatever it is, it is
        # not a JWS.
        return False
    return isinstance(header, dict) and isinstance(header.get("alg"), str)


def classify_credential(token: str) -> CredentialKind:
    """Classify a credential, and refuse one that could break a header.

    The value itself is never quoted back in the message it raises: a credential
    that reached an exception message has leaked, and this is one of the places
    that has to be true for that not to have happened.

    Raises:
        CafayeConfigurationError: for an empty, blank or control-character value.
    """
    if not token:
        raise CafayeConfigurationError(
            "A cafaye credential must be a non-empty string. Refusing it here rather than "
            "sending it: a blank one is a configuration mistake that would otherwise surface "
            "as a 401 from a service some hours later. A value that is not a string at all is "
            "a caller type error and is left to the type checker -- the next line is a "
            "control-character check, which is the one that has security consequences.",
            source="token",
        )
    bad = sorted({character for character in token if character in _FORBIDDEN_IN_CREDENTIAL})
    if bad:
        raise CafayeConfigurationError(
            "A cafaye credential must contain no control characters and no spaces. Refusing "
            "it here rather than sending it: a value carrying CR or LF would be a "
            "header-injection attempt, and the rest have no legitimate use in any of the "
            f"three credential shapes cafaye mints. Offending characters: {len(bad)} "
            "(names withheld, because a character class is a fingerprint).",
            source="token",
        )
    if token.startswith(API_TOKEN_PREFIX):
        return CredentialKind.API_TOKEN
    if _is_jws(token):
        return CredentialKind.JWT
    return CredentialKind.SESSION


def attach_credential(headers: dict[str, str], token: str | None) -> CredentialKind | None:
    """Attach a credential to a request's headers, in the one place that does it.

    Two rules, both of them load-bearing:

    - A **session** contributes BOTH forms, and that is not redundancy.
      identity's document states how it resolves a request carrying both — "An
      ``Authorization: Bearer`` header is preferred over the cookie when both are
      present, because a client holding both has said which one it means" — so
      sending both is unambiguous by the server's own rule, and it is what lets a
      single credential work against identity (which accepts the cookie) and
      against the other five (which core says take a bearer and nothing else)
      with no choice at the call site. The tie-break is the server's, not this
      client's.

    - An **existing header is never overwritten**. A caller who passes their own
      ``Authorization`` per call gets theirs, rather than a surprise in which of
      two values wins.

    Returns the classified kind, or ``None`` when there was no credential, so the
    caller can record what was decided without re-deriving it.
    """
    if token is None:
        return None

    kind = classify_credential(token)
    lowered = {name.lower() for name in headers}

    if _AUTHORIZATION.lower() not in lowered:
        headers[_AUTHORIZATION] = f"Bearer {token}"
    if kind is CredentialKind.SESSION and "cookie" not in lowered:
        headers["Cookie"] = f"{SESSION_COOKIE_NAME}={token}"
    return kind
