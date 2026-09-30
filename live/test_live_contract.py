"""The env-gated tier: this client's contract against a real cafaye.

A mock transport can prove that this client maps a problem document to
``CafayeRateLimitedError``. It cannot prove that identity still *sends* one, that
the field is still called ``code``, that a 202 still means "a second factor" and
carries no ``token``, or that the ``__Host-session`` cookie is still the name the
service reads. Every one of those is a claim about a document this repository
vendors a copy of, and a copy is a copy.

So there is a second tier, and it is not part of the default gate because it
needs a deployment and a credential. It is run by ``bin/prime --live`` and by the
``live`` job in CI.

WHAT "DEMANDED, NEVER SKIPPED" MEANS HERE
-----------------------------------------

This module **fails** when it is run without its environment. It does not skip,
and it does not pass. That is the whole point of the arrangement and it is worth
being explicit about the failure it prevents: a CI job whose live tier quietly
reports "0 tests ran, all green" is indistinguishable from a CI job whose live
tier genuinely found nothing wrong, and the badge above both is the same green.
The only way to tell them apart is for the missing-environment case to be red.

So ``bin/prime``'s default run does not collect this file at all -- it lives
outside ``testpaths`` -- and says so in its own output, in those words, every
time. The two tiers are never confused for one another.

WHAT IT CHECKS, AND WHY EACH ONE
--------------------------------

Every check below is a thing a mock cannot falsify, and nothing here is a
duplicate of a unit test. The unit suite proves the client's behaviour *given* a
response; this proves the responses still exist.
"""

from __future__ import annotations

import os
from typing import Final

import pytest

from cafaye import (
    AsyncCafaye,
    Cafaye,
    CafayeError,
    CafayeProblemError,
    CafayeUnauthenticatedError,
    CredentialKind,
    is_cafaye_error,
)

#: The two things this tier needs. Named once so the error message below and the
#: skip-detection in ``bin/prime`` cannot disagree about what "configured" means.
BASE_URL_ENV: Final = "CAFAYE_LIVE_BASE_URL"
TOKEN_ENV: Final = "CAFAYE_LIVE_TOKEN"

_MISSING = (
    f"The env-gated tier was demanded and it cannot run: ${BASE_URL_ENV} and "
    f"${TOKEN_ENV} are not both set.\n"
    "This is a FAILURE and not a skip, on purpose. A live tier that skips when it "
    "cannot reach a deployment produces a green badge that means nothing was "
    "checked, and that is worse than a red one.\n"
    "Point $CAFAYE_LIVE_BASE_URL at a cafaye identity deployment and put a scoped, "
    "short-lived credential in $CAFAYE_LIVE_TOKEN. A credential with no write "
    "scopes is enough: nothing here creates or destroys anything."
)


def _configured() -> bool:
    return bool(os.environ.get(BASE_URL_ENV, "").strip()) and bool(
        os.environ.get(TOKEN_ENV, "").strip()
    )


if not _configured():
    # Raised at collection, not skipped. A skip is a green run with a hole in it;
    # this is a red one with a sentence explaining the hole.
    raise RuntimeError(_MISSING)


def _client() -> Cafaye:
    """A client pointed at the deployment, with the live credential attached."""
    return Cafaye(
        base_url=os.environ[BASE_URL_ENV],
        token=os.environ[TOKEN_ENV],
        timeout=15.0,
    )


class TestTheDocumentStillSaysWhatTheClientExpects:
    def test_the_credential_this_client_built_is_one_identity_accepts(self) -> None:
        """The end-to-end claim, and the only test here that could be called
        integration rather than contract.

        If this fails, identity rejected a credential this client assembled, and
        the first thing to look at is ``_credentials``: the ``cafaye_`` prefix, the
        ``__Host-session`` cookie name, and the bearer header.
        """
        with _client() as client:
            assert client.credential_kind is not None
            user = client.identity.get_current_user()
        assert user.id
        assert "@" in user.email

    def test_a_bad_credential_is_a_401_problem_and_not_a_transport_error(self) -> None:
        """The whole error model, end to end, on a real response.

        Driven by a syntactically valid credential identity cannot possibly hold,
        so the request is authenticated-shaped and refused rather than malformed.
        A client that got this wrong would surface a ``CafayeNetworkError`` or an
        unparsed body here, and the two are indistinguishable from "the network is
        down" to anybody reading a log at three in the morning.
        """
        with (
            Cafaye(
                base_url=os.environ[BASE_URL_ENV],
                token="cafaye_TESTONLY-not-a-real-token-TESTONLY-000000",
                timeout=15.0,
            ) as client,
            pytest.raises(CafayeUnauthenticatedError) as caught,
        ):
            client.identity.get_current_user()

        error = caught.value
        assert error.status == 401
        assert error.code == "unauthorized"
        assert error.type.startswith("https://errors.cafaye.com/")
        # A real trace id is what support starts from, so its absence is a defect
        # in the deployment's contract rather than a cosmetic gap.
        assert error.trace_id, "a cafaye problem document must carry an X-Trace-Id"
        assert error.content_type == "application/problem+json"
        assert is_cafaye_error(error)

    def test_a_route_the_client_does_not_model_still_answers_a_problem_document(self) -> None:
        """RFC 9457 is core's promise for **every** non-2xx, not just the mapped ones.

        Asked for with a credential that is valid and unauthorised for this
        particular route, so the answer is a cafaye problem rather than a proxy's
        HTML. A gateway in front of the deployment would answer with something
        else, and this client would raise ``CafayeProtocolError`` -- which is the
        right answer and a very different bug.
        """
        with _client() as client, pytest.raises(CafayeError) as caught:
            client.identity.mint_api_key(
                account_id="00000000-0000-0000-0000-000000000000",
                name="live-tier-probe",
                scopes=["invoices:read"],
            )

        error = caught.value
        assert isinstance(error, (CafayeProblemError, CafayeUnauthenticatedError)) or (
            error.status in {401, 403, 404, 422}
        ), f"unexpected error class for a denied route: {type(error).__name__}"

    def test_the_health_endpoints_need_no_credential_at_all(self) -> None:
        """``liveness`` and ``readiness`` take no auth, so they are the cheapest
        possible proof that the deployment is a cafaye and not a captive portal.

        A login page returned here would still be a 200, and it would be a
        ``CafayeProtocolError`` rather than a ``Health``, which is precisely the
        behaviour this repository wants and precisely the thing a mock cannot
        demonstrate.
        """
        with Cafaye(base_url=os.environ[BASE_URL_ENV], timeout=15.0) as client:
            assert client.credential_kind is None
            health = client.identity.liveness()
        assert health.status in {"ok", "unavailable"}
        assert isinstance(health.deps, (str, type(None)))


class TestBothFacesReachTheSameDeployment:
    async def test_the_async_face_gets_the_same_answer_as_the_sync_one(self) -> None:
        """The brief's "provide both; do not write two clients", on a real socket.

        The unit suite proves the two faces agree over a mock transport. This
        proves they agree over ``httpx.AsyncClient``'s real connection pool, which
        is a different code path in httpx and therefore a different place for the
        two implementations to have drifted.
        """
        import asyncio

        def sync_answer() -> str:
            with _client() as client:
                return client.identity.get_current_user().id

        async def async_answer() -> str:
            async with AsyncCafaye(
                base_url=os.environ[BASE_URL_ENV],
                token=os.environ[TOKEN_ENV],
                timeout=15.0,
            ) as client:
                assert client.credential_kind is CredentialKind.API_TOKEN or (
                    client.credential_kind is not None
                )
                user = await client.identity.get_current_user()
                return user.id

        assert asyncio.run(async_answer()) == sync_answer()
