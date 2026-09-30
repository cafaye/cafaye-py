"""The response models: as precise as the documents, and no more demanding.

Three properties, and each one is a decision rather than an implementation note.

1. **An unknown member is dropped.** A service that added a field must not be able
   to fail a consumer's code. The alternative — ``extra="forbid"`` — raises, and
   ``extra="allow"`` silently keeps it; either way the direction of responsibility
   inverts, and a client that breaks the day identity ships a field is a client
   that has made identity's release calendar its own problem.
2. **A member of the wrong type is the documented default, not an exception.** A
   ``200`` carrying ``{"digits": true}`` produces ``digits=0`` rather than a
   ``TypeError`` three frames from the mistake.
3. **Three models redact their own ``repr``.** A TOTP secret, an OIDC
   ``client_secret`` and an API token are each credentials, and the default
   dataclass ``repr`` is what lands in a debugger, a ``pytest`` assertion
   failure, a traceback with local variables, and a bug report somebody pastes
   into a chat.
"""

from __future__ import annotations

from typing import Any

import pytest

from cafaye import (
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
from cafaye._models import _Model, from_mapping

#: Every model, and the minimum body that decodes it. A list, so adding a model is
#: a line here and the "every model is covered" test below is automatic.
EVERY_MODEL: list[type[_Model]] = [
    User,
    Session,
    MfaChallenge,
    MfaStatus,
    StartedEnrollment,
    ConfirmedEnrollment,
    RecoveryCodesResponse,
    OIDCClient,
    OIDCClientWithSecret,
    Health,
    ApiKey,
    IssuedApiKey,
    Introspection,
]


class TestTheSharedContract:
    def test_every_model_is_frozen(self) -> None:
        import dataclasses

        """An object a caller can mutate after the client handed it over is an
        object whose invariants somebody else can break."""
        for model in EVERY_MODEL:
            instance = model.from_response({})
            with pytest.raises(dataclasses.FrozenInstanceError):
                instance.id = "tampered"  # type: ignore[attr-defined]

    def test_every_model_has_no_dict(self) -> None:
        """``slots=True`` means there is nowhere for a credential to hide by
        accident — not in an attribute, not in a ``__dict__`` a serialiser walks."""
        for model in EVERY_MODEL:
            assert not hasattr(model.from_response({}), "__dict__")

    def test_the_base_class_refuses_rather_than_guessing(self) -> None:
        """It used to call ``cls.from_mapping``, and no model has a
        ``from_mapping`` — so the one method every model inherited was an
        ``AttributeError`` with no message. It is a ``NotImplementedError`` with
        a sentence now, and it says which class was at fault."""
        with pytest.raises(NotImplementedError) as caught:
            _Model.from_response({})
        assert "_Model" in str(caught.value)
        assert "cafaye._models" in str(caught.value)

    def test_from_mapping_passes_a_mapping_through_unchanged(self) -> None:
        body = {"id": "u"}
        assert from_mapping(body) is body

    @pytest.mark.parametrize("body", [None, [], "a string", 7, ("a", "tuple")])
    def test_from_mapping_turns_anything_else_into_an_empty_mapping(self, body: object) -> None:
        """A gateway's idea of a health check, answered with a JSON array, must
        produce an empty model rather than an ``AttributeError``."""
        assert from_mapping(body) == {}

    def test_every_model_survives_a_body_that_is_not_a_mapping(self) -> None:
        """``from_response`` is typed as taking a mapping because that is what the
        client hands it, but a decoded body is only as trustworthy as the service
        that sent it."""
        for model in EVERY_MODEL:
            assert model.from_response([]) is not None  # type: ignore[arg-type]
            assert model.from_response(None) is not None  # type: ignore[arg-type]


class TestTheSimpleProjections:
    def test_user_has_exactly_two_fields_and_no_password_digest(self) -> None:
        user = User.from_response({"id": "u_1", "email": "A@B.test", "password_digest": "x"})
        assert (user.id, user.email) == ("u_1", "A@B.test")
        assert not hasattr(user, "password_digest")
        assert not hasattr(user, "created_at")

    def test_session_carries_the_token_and_the_expiry(self) -> None:
        session = Session.from_response({"token": "t", "expires_at": "2026-10-30T12:00:00Z"})
        assert session.token == "t"
        assert session.expires_at == "2026-10-30T12:00:00Z"

    def test_mfa_challenge_has_no_token_and_cannot_grow_one(self) -> None:
        """The challenge is worthless on its own, so a model that could express
        "the login response" without saying which kind it is would make the bug
        easy to write."""
        challenge = MfaChallenge.from_response(
            {"mfa_required": True, "challenge": "c", "expires_at": "x", "token": "leaked"}
        )
        assert challenge.mfa_required is True
        assert not hasattr(challenge, "token")

    def test_mfa_status_distinguishes_no_method_from_the_totp_method(self) -> None:
        """``"totp"`` and "no method yet" are different answers, which is why the
        three optional fields are ``| None`` and not defaults."""
        off = MfaStatus.from_response({"enabled": False})
        assert off.enabled is False
        assert (off.method, off.enrolled_at, off.recovery_codes_remaining) == (None, None, None)

        on = MfaStatus.from_response(
            {"enabled": True, "method": "totp", "enrolled_at": "x", "recovery_codes_remaining": 8}
        )
        assert on.method == "totp"
        assert on.recovery_codes_remaining == 8

    def test_a_bool_is_not_an_int(self) -> None:
        """``bool`` is a subclass of ``int``, so ``{"recovery_codes_remaining":
        true}`` would otherwise read as one code remaining."""
        assert (
            MfaStatus.from_response({"recovery_codes_remaining": True}).recovery_codes_remaining
            is None
        )
        assert StartedEnrollment.from_response({"digits": True}).digits == 0

    def test_health_reports_dependencies_only_where_there_are_any(self) -> None:
        """``deps`` is present on ``/readyz`` only, and collapsing the two is how a
        load balancer sends traffic to a service whose database is unreachable."""
        assert Health.from_response({"status": "ok"}).deps is None
        assert Health.from_response({"status": "ok", "deps": "db,cache"}).deps == "db,cache"


class TestTheRecoveryCodes:
    def test_confirmed_enrollment_keeps_them_in_order_and_drops_non_strings(self) -> None:
        confirmed = ConfirmedEnrollment.from_response(
            {"recovery_codes": ["a", 7, "b", None], "enabled": True, "method": "totp"}
        )
        assert confirmed.recovery_codes == ("a", "b")
        assert confirmed.replaced_existing_secret is False

    def test_a_body_with_no_codes_gives_an_empty_tuple_not_none(self) -> None:
        assert ConfirmedEnrollment.from_response({}).recovery_codes == ()
        assert RecoveryCodesResponse.from_response({"issued_at": "x"}).recovery_codes == ()

    def test_a_codes_member_that_is_not_a_list(self) -> None:
        for body in (
            {"recovery_codes": "abc"},
            {"recovery_codes": {"a": 1}},
            {"recovery_codes": 7},
        ):
            assert ConfirmedEnrollment.from_response(body).recovery_codes == ()

    def test_recovery_codes_default_the_remaining_count_to_zero(self) -> None:
        assert RecoveryCodesResponse.from_response({"issued_at": "x"}).recovery_codes_remaining == 0
        assert (
            RecoveryCodesResponse.from_response(
                {"issued_at": "x", "recovery_codes_remaining": 10}
            ).recovery_codes_remaining
            == 10
        )


class TestTheCredentialBearingModels:
    """Three models carry a secret, and all three redact their own ``repr``."""

    def test_a_started_enrollment_never_prints_its_totp_secret(self) -> None:
        started = StartedEnrollment.from_response(
            {
                "enrollment_id": "e_1",
                "secret": "JBSWY3DPEHPK3PXP",
                "provisioning_uri": "otpauth://totp/x",
                "method": "totp",
                "digits": 6,
                "period_seconds": 30,
                "algorithm": "SHA1",
                "expires_at": "x",
            }
        )
        text = repr(started)
        assert "JBSWY3DPEHPK3PXP" not in text
        assert "[redacted" in text
        # Everything that is *not* the secret is still readable, or a redacted
        # repr would be useless for the debugging it exists to support.
        assert "e_1" in text
        assert "SHA1" in text

    def test_an_oidc_registration_never_prints_its_client_secret(self) -> None:
        registered = OIDCClientWithSecret.from_response(
            {"id": "r", "client_id": "cid", "name": "n", "client_secret": "TESTONLY-not-real"}
        )
        text = repr(registered)
        assert "TESTONLY-not-real" not in text
        assert "[redacted" in text
        assert "cid" in text

    def test_an_issued_api_key_never_prints_its_token(self) -> None:
        issued = IssuedApiKey.from_response(
            {"id": "k", "name": "n", "account_id": "a", "token": "cafaye_TESTONLY-not-real"}
        )
        text = repr(issued)
        assert "cafaye_TESTONLY-not-real" not in text
        assert "[redacted" in text
        assert "k" in text

    def test_the_token_is_still_reachable_as_an_attribute(self) -> None:
        """Redaction is about printing, not about access. A caller that legitimately
        holds the response has to be able to read the credential out of it."""
        issued = IssuedApiKey.from_response({"token": "cafaye_x", "id": "k"})
        assert issued.token == "cafaye_x"

    def test_a_model_listing_can_never_carry_a_token(self) -> None:
        """``ApiKey`` has no ``token`` field on purpose: the plaintext appears in
        exactly one response, and a model for the listing endpoints that could
        hold one would make it possible to keep a credential in a list — which is
        a credential that ends up in a log."""
        key = ApiKey.from_response({"id": "k", "token": "cafaye_x"})
        assert not hasattr(key, "token")
        assert issubclass(IssuedApiKey, ApiKey)
        assert "token" in {f.name for f in IssuedApiKey.__dataclass_fields__.values()}

    def test_the_oidc_registration_is_a_subclass_rather_than_an_optional_field(self) -> None:
        """ "this registration has a secret and you should print it once" and "this
        one does not" are different facts about the response, and a field whose
        presence depends on the endpoint makes the reader of a ``list`` call wonder
        whether it is missing or empty."""
        assert issubclass(OIDCClientWithSecret, OIDCClient)


class TestIntrospectionAndMD7:
    """MD7 is open, so this client accepts **either** spelling.

    ``internal/apikeys/claims.go`` says it outright: the claim is emitted TWICE —
    as ``scopes`` and as ``scope`` — "and that is not a typo, not a compatibility
    shim somebody forgot to remove, and not this service having an opinion about
    the specification. The fleet does not agree on the name", with
    ``core/docs/openapi-conventions.md:134`` requiring ``scopes`` and
    ``guard/src/middleware/jwt.ts:32`` reading ``scope``.

    So the decision this client makes is: **report whichever arrived, and do not
    pick a winner.** `Introspection` carries both, each optional, and neither is
    derived from the other. A client that chose one would hide half the claim from
    whichever side of MD7 turns out to be right, and the cost of being wrong is a
    rotation of every credential already in a customer's hand.
    """

    def test_the_plural_spelling(self) -> None:
        result = Introspection.from_response(
            {"active": True, "scopes": "invoices:read invoices:write"}
        )
        assert result.scopes == "invoices:read invoices:write"
        assert result.scope is None

    def test_the_singular_spelling(self) -> None:
        result = Introspection.from_response({"active": True, "scope": "invoices:read"})
        assert result.scope == "invoices:read"
        assert result.scopes is None

    def test_both_at_once_are_both_reported_and_neither_is_merged(self) -> None:
        """identity emits them byte-for-byte identical and holds a test that they
        cannot drift. This client does not assume that: it reports what it was
        given, because a service that emitted two different values would be a
        finding, and merging them here would hide it."""
        result = Introspection.from_response({"active": True, "scopes": "a b", "scope": "a b"})
        assert (result.scopes, result.scope) == ("a b", "a b")

    def test_neither_is_none_rather_than_an_empty_string(self) -> None:
        """``None`` is "the service did not say", which is a different and
        answerable question from "the service said nothing"."""
        result = Introspection.from_response({"active": False})
        assert result.scopes is None
        assert result.scope is None

    def test_every_other_member_of_rfc_7662(self) -> None:
        result = Introspection.from_response(
            {
                "active": True,
                "sub": "u_1",
                "account_id": "acc_1",
                "scopes": "invoices:read",
                "jti": "jti_1",
                "name": "A",
                "role": "owner",
                "iat": 1_700_000_000,
                "exp": 1_700_003_600,
                "last_used_at": 1_700_000_100,
            }
        )
        assert result.sub == "u_1"
        assert result.account_id == "acc_1"
        assert result.jti == "jti_1"
        assert result.name == "A"
        assert result.role == "owner"
        assert result.iat == 1_700_000_000
        assert result.exp == 1_700_003_600
        assert result.last_used_at == 1_700_000_100

    def test_an_inactive_answer_is_still_a_typed_result_not_an_exception(self) -> None:
        """ "Unknown, revoked, expired, and one whose owner has been removed are all
        the same 200 with the same body, and the status is 200 rather than 404
        because the endpoint succeeded." A client that raised here would be telling
        the caller something it cannot know."""
        result = Introspection.from_response({"active": False})
        assert result.active is False


class TestTheCoercionHelpersDirectly:
    """The shared helpers, because each is a branch and each is reachable.

    Covered here rather than only through a model so that a change to one is a
    change to a named test rather than a change to whichever model happened to
    exercise it.
    """

    @pytest.mark.parametrize(
        ("body", "key", "expected"),
        [
            ({"a": "x"}, "a", "x"),
            ({"a": 7}, "a", ""),
            ({"a": None}, "a", ""),
            ({"a": True}, "a", ""),
            ({}, "a", ""),
        ],
    )
    def test_str(self, body: dict[str, Any], key: str, expected: str) -> None:
        from cafaye._models import _str

        assert _str(body, key) == expected

    def test_str_with_an_explicit_default(self) -> None:
        from cafaye._models import _str

        assert _str({}, "a", default="fallback") == "fallback"

    @pytest.mark.parametrize(
        ("body", "key", "expected"),
        [({"a": "x"}, "a", "x"), ({"a": 7}, "a", None), ({}, "a", None)],
    )
    def test_opt_str(self, body: dict[str, Any], key: str, expected: str | None) -> None:
        from cafaye._models import _opt_str

        assert _opt_str(body, key) == expected

    @pytest.mark.parametrize(
        ("body", "key", "expected"),
        [
            ({"a": True}, "a", True),
            ({"a": False}, "a", False),
            # An int is not a bool. `{"mfa_required": 1}` is a service bug rather
            # than a truthy value, and reading it as one is how a challenge
            # response turns into a session response.
            ({"a": 1}, "a", False),
            ({"a": "yes"}, "a", False),
            ({}, "a", False),
        ],
    )
    def test_bool(self, body: dict[str, Any], key: str, expected: bool) -> None:
        from cafaye._models import _bool

        assert _bool(body, key) is expected

    @pytest.mark.parametrize(
        ("body", "key", "expected"),
        [({"a": 7}, "a", 7), ({"a": True}, "a", 0), ({"a": "7"}, "a", 0), ({}, "a", 0)],
    )
    def test_int(self, body: dict[str, Any], key: str, expected: int) -> None:
        from cafaye._models import _int

        assert _int(body, key) == expected

    def test_opt_int(self) -> None:
        from cafaye._models import _opt_int

        assert _opt_int({"a": 7}, "a") == 7
        assert _opt_int({"a": True}, "a") is None
        assert _opt_int({"a": "7"}, "a") is None
        assert _opt_int({}, "a") is None

    def test_str_list(self) -> None:
        from cafaye._models import _str_list

        assert _str_list({"a": ["x", "y"]}, "a") == ("x", "y")
        assert _str_list({"a": ["x", 7, None]}, "a") == ("x",)
        assert _str_list({"a": "xy"}, "a") == ()
        assert _str_list({"a": 7}, "a") == ()
        assert _str_list({}, "a") == ()
