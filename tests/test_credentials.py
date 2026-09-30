"""Which credential is this, and where may it go.

The brief: "a bearer token — ``Authorization: Bearer cafaye_…``; a session
cookie. Which one is used must be a decision, not a coincidence, and the decision
must be tested in both directions."

Both directions is the load-bearing phrase. A test that only asserts "the token
appears in the request" passes for a client that puts every credential in every
header, which is the failure. So every test here asserts **absence** as well as
presence: the ``Cookie`` header for an API token and for a JWT, the
``Authorization`` header for a credential that carries none, and the cookie name.

The three credential *shapes* come from the fleet, not from this package:
identity mints an opaque session token (43 base64url characters), an opaque
scoped API token (``cafaye_`` plus the same 43), and the other five services take
a JWKS-verified bearer JWT.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from cafaye import (
    API_TOKEN_PREFIX,
    SESSION_COOKIE_NAME,
    Cafaye,
    CafayeConfigurationError,
    CredentialKind,
    classify_credential,
)

# Obviously fake, and never a plausible credential. The prefix is real because the
# classifier has to see it, and the body is deliberately not a shape identity
# could mint: it is spelled out, it is 43 characters as the real thing is, and it
# cannot be produced by `crypto/rand`. `test_credential_leak.py` asserts this
# exact string appears in no log, message or serialised form.
FAKE_API_TOKEN = API_TOKEN_PREFIX + "TESTONLY-not-a-real-token-TESTONLY-000000"
FAKE_SESSION_TOKEN = "TESTONLY-not-a-real-session-000000000000000"
FAKE_JWT = "{}.{}.{}".format(
    base64.urlsafe_b64encode(json.dumps({"alg": "ES256", "kid": "cafaye-1"}).encode())
    .decode()
    .rstrip("="),
    "TESTONLY" + "0" * 78,
    "TESTONLY" + "0" * 43,
)

BASE = "https://identity.example.test"


def client_for(token: str | None) -> Cafaye:
    return Cafaye(base_url=BASE, token=token)


def kind_of(client: Cafaye) -> CredentialKind | None:
    """Read a client's credential kind **fresh**, through a call.

    Not a wrapper for tidiness. ``mypy`` narrows ``client.credential_kind`` at
    the first assertion about it and does not invalidate that narrowing after
    ``set_token``, because it assumes a property is pure. So a test that asserts
    on the attribute twice around a ``set_token`` has its second assertion
    checked against a type the checker still believes in, and mypy -- with
    ``--warn-unreachable``, which this repository turns on deliberately -- reports
    the assertion as impossible and every statement after it as unreachable.

    The narrowing is stale and the test is right. Reading through a function call
    is what stops the checker carrying it across, and the comment is here so the
    next reader does not "simplify" it back into a direct attribute access.
    """
    return client.credential_kind


def sent_headers(client: Cafaye, token: str | None = None) -> httpx.Headers:
    """Drive one request through the client and return the headers it sent.

    ``token`` is applied with :meth:`set_token` first when given, which is how the
    "a credential set after construction is used" case is driven — the point of
    that case is that the client reads the credential *per request* rather than
    holding the header set from construction.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "u", "email": "a@b.test"})

    if token is not None:
        client.set_token(token)
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    client.identity.get_current_user()
    return seen[0].headers


class TestTheDiscriminator:
    """``cafaye_`` is identity's discriminator, and this client reads it."""

    def test_the_api_token_prefix_is_identitys(self) -> None:
        """``internal/httpapi/apikeys.go`` calls it "THE PREFIX IS THE DISCRIMINATOR"."""
        assert API_TOKEN_PREFIX == "cafaye_"

    def test_an_api_token_is_an_api_token(self) -> None:
        assert classify_credential(FAKE_API_TOKEN) == "api_token"

    def test_a_session_token_is_a_session(self) -> None:
        assert classify_credential(FAKE_SESSION_TOKEN) == "session"

    def test_a_jws_is_a_jwt(self) -> None:
        assert classify_credential(FAKE_JWT) == "jwt"

    def test_the_kind_is_queryable_without_the_token_being_readable(self) -> None:
        """The kind is a decision; the credential is not a value anybody can read.

        ``credential_kind`` answers "did I hand over an API token or a session
        token" and the client has no way to hand the token back out. That is
        deliberate: the moment an object can hand the credential out is the moment
        it ends up in a log through some code path nobody was thinking about.
        """
        client = client_for(FAKE_API_TOKEN)
        assert client.credential_kind == "api_token"
        assert FAKE_API_TOKEN not in dir(client)
        assert not hasattr(client, "token")

    def test_no_credential_is_none(self) -> None:
        assert client_for(None).credential_kind is None


class TestBearerOnly:
    """An API token and a JWT go in the ``Authorization`` header and nowhere else."""

    @pytest.mark.parametrize(
        ("token", "kind"),
        [(FAKE_API_TOKEN, "api_token"), (FAKE_JWT, "jwt")],
        ids=["api_token", "jwt"],
    )
    def test_the_authorization_header_is_bearer(self, token: str, kind: str) -> None:
        headers = sent_headers(client_for(token))
        assert headers["authorization"] == f"Bearer {token}"

    @pytest.mark.parametrize("token", [FAKE_API_TOKEN, FAKE_JWT])
    def test_no_cookie_is_sent_for_them(self, token: str) -> None:
        """Both directions of the decision, stated as an absence.

        core's conventions: "No cookies for API traffic; browser sessions use …
        cookies and a CSRF token, and those are a *different* surface." A JWT in
        a ``Cookie`` header is a fleet-wide credential published onto the browser
        surface, which a script cannot set and a reverse proxy is happy to log.
        """
        headers = sent_headers(client_for(token))
        assert "cookie" not in headers
        assert SESSION_COOKIE_NAME not in str(headers)


class TestSessionCookie:
    def test_a_session_token_is_sent_as_the_host_cookie(self) -> None:
        headers = sent_headers(client_for(FAKE_SESSION_TOKEN))
        assert SESSION_COOKIE_NAME == "__Host-session"
        assert "cookie" in {key.lower() for key in headers}
        assert headers["cookie"] == f"{SESSION_COOKIE_NAME}={FAKE_SESSION_TOKEN}"

    def test_a_session_token_is_also_sent_as_a_bearer(self) -> None:
        """Both forms, and it is not redundancy.

        identity's document states how it resolves a request carrying both: "An
        `Authorization: Bearer` header is preferred over the cookie when both are
        present, because a client holding both has said which one it means." So
        sending both is unambiguous by the server's own rule, and it is what lets
        one credential work against identity (which accepts the cookie) and
        against the other five (which take a bearer and nothing else) with no
        choice at the call site.
        """
        headers = sent_headers(client_for(FAKE_SESSION_TOKEN))
        assert headers["authorization"] == f"Bearer {FAKE_SESSION_TOKEN}"

    def test_the_session_cookie_carries_the_host_prefix(self) -> None:
        """``__Host-`` is a browser-enforced contract, not decoration.

        It requires ``Secure``, ``Path=/`` and no ``Domain``. A request that
        names the cookie wrongly looks authenticated and is not.
        """
        assert SESSION_COOKIE_NAME.startswith("__Host-")


class TestNoCredential:
    def test_an_anonymous_client_sends_neither_header(self) -> None:
        """Registering and signing in happen before there is a credential."""
        headers = sent_headers(client_for(None))
        assert "authorization" not in headers
        assert "cookie" not in headers

    def test_credentials_can_be_set_and_cleared_on_a_live_client(self) -> None:
        """A long-running process outlives its token.

        Read through :func:`kind_of` rather than off the attribute, and compare
        against the **string** rather than the enum member, so the assertion is
        that ``CredentialKind``'s value is the name a caller would compare to and
        not merely that the right member came back. See :func:`kind_of` for why
        the indirection is load-bearing rather than decorative.
        """
        client = client_for(None)
        assert kind_of(client) is None

        client.set_token(FAKE_API_TOKEN)
        assert kind_of(client) == "api_token"
        assert kind_of(client) is CredentialKind.API_TOKEN

        client.set_token(FAKE_SESSION_TOKEN)
        assert kind_of(client) == "session"
        assert kind_of(client) is CredentialKind.SESSION

        client.set_token(None)
        assert kind_of(client) is None

    def test_a_credential_set_after_construction_is_used(self) -> None:
        client = client_for(None)
        headers = sent_headers(client, FAKE_API_TOKEN)
        assert headers["authorization"] == f"Bearer {FAKE_API_TOKEN}"


class TestCredentialsThatWouldBreakAHeader:
    def test_an_empty_credential_is_refused(self) -> None:
        with pytest.raises(CafayeConfigurationError):
            Cafaye(base_url=BASE, token="")

    @pytest.mark.parametrize(
        "token",
        [
            "cafaye_a\nb",
            "cafaye_a\rb",
            "cafaye_a\x00b",
            "cafaye_a b",
            "cafaye_a\tb",
            "cafaye_a\x7fb",
        ],
        ids=["LF", "CR", "NUL", "space", "TAB", "DEL"],
    )
    def test_a_credential_containing_a_control_character_is_refused(self, token: str) -> None:
        """CR and LF are header injection.

        Refused at the setter rather than sent: a value carrying CR or LF would
        otherwise be a header-injection attempt, and a blank one is a
        configuration mistake that would surface as a 401 from a service hours
        later.
        """
        with pytest.raises(CafayeConfigurationError):
            Cafaye(base_url=BASE, token=token)

    def test_the_refusal_never_quotes_the_credential_back(self) -> None:
        """A credential that reached an exception message has leaked."""
        token = "cafaye_BADVALUE-LF-00000000000000000000000000000000000"
        with pytest.raises(CafayeConfigurationError) as caught:
            Cafaye(base_url=BASE, token=token + "\n")
        assert token not in str(caught.value)
        assert token not in repr(caught.value)


class TestTheThreeWaySplitIsNotTwo:
    """Why ``jwt`` and ``session`` are separate cases, not one fallback."""

    def test_three_dot_separated_segments_that_are_not_a_jws_are_a_session(self) -> None:
        """``one.two.three`` has the shape of a JWS and is not one.

        The header segment is decoded and parsed, which is what keeps this out of
        the JWT branch. A base64url value that happens to contain dots is a
        session token, and a session token that gets the cookie is the safe
        direction to be wrong in.
        """
        assert classify_credential("one.two.three") == "session"

    def test_a_jws_whose_header_is_not_json_is_a_session(self) -> None:
        assert classify_credential("bm90anNvbg.bm90anNvbg.bm90anNvbg") == "session"

    def test_a_jws_header_without_alg_is_a_session(self) -> None:
        header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT"}).encode()).decode().rstrip("=")
        assert classify_credential(f"{header}.bbbb.cccc") == "session"
