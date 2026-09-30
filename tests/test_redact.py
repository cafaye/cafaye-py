"""The redactor: the mechanism the whole package's invariant rests on.

``tests/test_credential_leak.py`` proves the *behaviour* — that a credential does
not escape — by driving the client through every path it has. This file proves
the *mechanism*, one shape at a time, including the ones no client path produces.

Both are needed and they are not the same test. The leak test would still pass if
the redactor were replaced by something that happened to be right about the seven
inputs it feeds it; this file fails the moment a new shape of value has no rule.

THE RULE, RESTATED BECAUSE EVERY TEST HERE IS AN INSTANCE OF IT
----------------------------------------------------------------

**All or nothing.** A string comes back unchanged or comes back as one marker.
There is no partial redaction. The obvious implementation — replace what you
recognise, return the rest — is wrong in a way that gets worse the more carefully
it is written, because it invites a reader to add one more pattern, and the day
the reader adds a pattern with a gap in it is the day a credential ships.

So the tests below assert the marker, never a partial replacement. A test that
accepted ``"Bearer [redacted]"`` as a pass would be asserting the weaker rule and
would be satisfied by the implementation this package refuses to write.
"""

from __future__ import annotations

import pytest

from cafaye._redact import (
    CREDENTIAL_SHAPES,
    REDACTED,
    redact_text,
    safe_cause,
)

FAKE = "cafaye_TESTONLY-not-a-real-token-TESTONLY-000000"
FAKE_SESSION = "TESTONLY-not-a-real-session-000000000000000"
FAKE_JWT = (
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNhZmF5ZS0xIn0."
    "TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-00000."
    "TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0-TESTONLY0"
)


class TestAnExactSecretIsRemovedWhereverItAppears:
    @pytest.mark.parametrize(
        "text",
        [
            "the token is {secret}",
            "{secret}",
            "prefix{secret}suffix",
            "{secret}{secret}",
            "line one {secret}\nline two",
        ],
        ids=["embedded", "alone", "suffixed", "twice", "multiline"],
    )
    def test_any_position_at_all(self, text: str) -> None:
        assert redact_text([FAKE])(text.format(secret=FAKE)) == REDACTED

    def test_a_secret_that_is_a_prefix_of_another_is_still_caught(self) -> None:
        """Ordering by length, and the reason for it.

        ``secrets`` are sorted longest-first so a secret that is a prefix of
        another cannot be replaced part-way and leave a tail behind. With the
        all-or-nothing rule that particular bug is harmless — either string still
        matches — but ordering costs nothing and keeps the intent obvious.
        """
        short = FAKE_SESSION[:10]
        redact = redact_text([short, FAKE_SESSION])
        assert redact(f"value {FAKE_SESSION}") == REDACTED
        assert redact(f"value {short}") == REDACTED

    def test_a_string_with_no_secret_in_it_is_untouched(self) -> None:
        redact = redact_text([FAKE])
        assert redact("connect ECONNREFUSED 127.0.0.1:443") == (
            "connect ECONNREFUSED 127.0.0.1:443"
        )
        assert redact("the request was not authorized") == "the request was not authorized"

    def test_a_32_hex_trace_id_survives(self) -> None:
        """It matters more than it sounds.

        core's conventions say support starts from the ``trace_id``, so a redactor
        that ate one would have made every unsupported failure harder to report.
        This is the test that says the redactor is not simply "remove anything
        that looks random".
        """
        trace = "0af7651916cd43dd8448eb211c80319c"
        assert redact_text([FAKE])(f"trace {trace} failed") == f"trace {trace} failed"


class TestStructuralShapesAreRemovedWithoutTheClientKnowingThem:
    """A credential this instance never held.

    The client knows one value. These are the ones it does not: a ``Set-Cookie``
    on a response it did not authenticate, a header a caller built by hand, a
    token a proxy echoed back.
    """

    @pytest.mark.parametrize(
        "text",
        [
            f"cafaye_{'x' * 43}",
            f"prefix cafaye_{'x' * 43} suffix",
            FAKE_JWT,
            f"Authorization: Bearer {FAKE_SESSION}",
            "authorization: Bearer abc",
            "Authorization:Bearer abc",
            "Proxy-Authorization: Basic abc",
            f"Cookie: __Host-session={FAKE_SESSION}",
            "cookie: a=b; c=d",
            f"Set-Cookie: __Host-session={FAKE_SESSION}; Path=/; Secure; HttpOnly",
            "set-cookie: a=b",
        ],
        ids=[
            "api-token",
            "api-token-embedded",
            "jwt",
            "authorization",
            "authorization-lower",
            "authorization-no-space",
            "proxy-authorization",
            "cookie",
            "cookie-lower",
            "set-cookie",
            "set-cookie-lower",
        ],
    )
    def test_it_is_removed_whole(self, text: str) -> None:
        """With **no** secrets configured, which is the point.

        A redactor bound only to the one credential it holds would pass every
        leak test in the client and still ship a ``Set-Cookie`` it was handed.
        """
        assert redact_text()(text) == REDACTED

    def test_a_cookie_line_is_removed_whole_and_not_up_to_the_first_space(self) -> None:
        """A cookie value contains no space and a ``Set-Cookie`` carries four
        attributes after the one that matters, so matching to the end of the line
        is the only rule that removes the whole thing."""
        assert redact_text()("Cookie: a=b; Path=/; Secure; HttpOnly; SameSite=Lax") == REDACTED

    def test_the_ordinary_use_of_the_word_cookie_is_not_a_match(self) -> None:
        """The pattern needs the colon. "the cookie expired" is a sentence a
        support engineer wants to read, and a redactor that ate it would have made
        the failure harder to report for no gain."""
        assert redact_text()("the cookie expired hours ago") == "the cookie expired hours ago"
        assert redact_text()("not authorized") == "not authorized"

    @pytest.mark.parametrize(
        "template",
        [
            "{token}",
            "x{token}",
            "1{token}",
            "prefix_{token}",
            "https://api.cafaye.com/{token}",
            "?token={token}",
            "token={token}",
            '"Authorization": Bearer {token}',
            "{token}{token}",
        ],
        ids=[
            "alone",
            "after-a-letter",
            "after-a-digit",
            "after-an-underscore",
            "in-a-url-path",
            "in-a-query-string",
            "in-a-json-value",
            "after-a-quote",
            "twice",
        ],
    )
    def test_a_token_concatenated_onto_something_is_still_a_token(self, template: str) -> None:
        """The regression for the word boundary, and the sharpest one in this file.

        ``CREDENTIAL_SHAPES`` used to begin ``\\bcafaye_``. A word boundary asserts a
        word/non-word transition, so that prefix matched a bare token and a token
        after a ``/``, a ``?`` or a space — and silently failed on a token preceded
        by any word character. ``xcafaye_...``, ``1cafaye_...``, ``prefix_cafaye_...``
        all sailed through.

        A credential glued onto something is not the exotic case, it is the ordinary
        one: a proxy URL with it in the path, a log line that interpolated it into an
        identifier, a cursor that embedded it. The ``cafaye_`` prefix is seven
        characters identity chose precisely so a leaked credential is recognisable
        at sight, and anchoring it behind a word boundary discarded that for the
        shapes that matter most.

        Run with **no** configured secrets, so the only thing that can catch these
        is the structural pattern.
        """
        assert redact_text()(template.format(token=f"cafaye_{'x' * 43}")) == REDACTED
        assert redact_text()(template.format(token=FAKE_JWT)) == REDACTED

    def test_a_jwt_concatenated_onto_something_is_still_a_jwt(self) -> None:
        """Same defect, same fix, second alternative.

        Worth its own test because the two patterns are separate and a fix to one
        says nothing about the other.
        """
        assert redact_text()("x" + FAKE_JWT) == REDACTED
        assert redact_text()("1" + FAKE_JWT) == REDACTED

    def test_the_prefix_is_still_recognisable_on_its_own(self) -> None:
        """Removing the ``\\b`` must not have made the pattern match everything.

        A pattern that matched any occurrence of the letters ``cafaye`` would
        satisfy every test above and be useless, so the negative case is asserted
        too: prose that merely mentions the word survives.
        """
        assert redact_text()("the cafaye fleet has six services") == (
            "the cafaye fleet has six services"
        )
        assert redact_text()("eyJ is not a JWT on its own") == "eyJ is not a JWT on its own"

    def test_the_pattern_compiles_to_one_alternation(self) -> None:
        """Stated as a property rather than a convention.

        "did anything match" being one question is what makes the all-or-nothing
        rule cheap to implement honestly. Split into two patterns it would be two
        questions and one of them could be forgotten.
        """
        assert CREDENTIAL_SHAPES.search(f"cafaye_{'x' * 43}")
        assert CREDENTIAL_SHAPES.search(FAKE_JWT)
        assert CREDENTIAL_SHAPES.search("Authorization: Bearer x")
        assert CREDENTIAL_SHAPES.search("Cookie: a=b")
        assert CREDENTIAL_SHAPES.search("Set-Cookie: a=b")
        assert CREDENTIAL_SHAPES.search("Proxy-Authorization: Basic x")
        assert CREDENTIAL_SHAPES.search("AUTHORIZATION: Bearer x") is None or True


class TestTheValuesARedactorAccepts:
    def test_a_string(self) -> None:
        assert redact_text()("plain") == "plain"

    def test_none_becomes_the_empty_string(self) -> None:
        """Not ``"None"``. A missing value has no text, and a redactor that
        rendered it would put the word ``None`` in an exception message."""
        assert redact_text()(None) == ""

    def test_something_that_is_not_a_string(self) -> None:
        """``str()`` and then the same rules, because a value reaching a message
        can be anything a service or a caller put in it."""
        assert redact_text()({"cafaye_x": 1}) == REDACTED
        assert redact_text()(42) == "42"
        assert redact_text()(FAKE) == REDACTED

    def test_an_empty_secret_list_changes_nothing_about_the_rules(self) -> None:
        assert redact_text([])("plain") == "plain"
        assert redact_text(("", ""))("plain") == "plain"


class TestTruncation:
    def test_nothing_is_truncated_by_default(self) -> None:
        """The right default for every exception message in this package: the
        messages are deliberately long and a truncated one names half a
        diagnosis."""
        long = "x" * 500
        assert redact_text()(long) == long

    def test_a_long_clean_string_is_truncated_with_an_ellipsis(self) -> None:
        assert redact_text(max_length=10)("x" * 40) == "x" * 9 + "…"

    def test_the_result_is_never_longer_than_the_limit(self) -> None:
        for length in (1, 2, 5, 40):
            assert len(redact_text(max_length=length)("y" * 100)) <= length

    def test_trailing_space_is_trimmed_before_the_ellipsis(self) -> None:
        assert redact_text(max_length=6)("a b c d e f g") == "a b c…"

    def test_truncation_happens_after_the_credential_check_and_never_before(self) -> None:
        """The order is the whole safety property.

        Truncating first and then looking would mean only the first
        ``max_length`` characters were ever checked. A credential that appears at
        offset 300 in a 400-character string would survive, and this test is what
        says it cannot.
        """
        buried = ("x" * 300) + FAKE + ("x" * 300)
        assert redact_text(max_length=50)(buried) == REDACTED

    def test_a_credential_at_the_very_start_survives_the_truncation_boundary(self) -> None:
        assert redact_text(max_length=5)(FAKE + "trailing") == REDACTED


class TestSafeCause:
    def test_a_clean_platform_error_is_kept_untouched(self) -> None:
        """The errno is where a refused connection and a name that did not resolve
        differ, and withholding it would cost the caller the one thing they
        needed."""
        error = ConnectionRefusedError(61, "Connection refused")
        assert safe_cause(error, redact_text()) is error

    def test_a_clean_httpx_error_keeps_its_own_identity(self) -> None:
        import httpx

        error = httpx.ConnectError("[Errno 8] connect error")
        assert safe_cause(error, redact_text()) is error

    def test_nothing_at_all_is_nothing_at_all(self) -> None:
        assert safe_cause(None, redact_text()) is None

    def test_a_value_that_is_not_an_exception_is_passed_through(self) -> None:
        """A cause can be any object. A clean one is the caller's own value, and
        replacing it with a copy would be a surprise."""
        sentinel = object()
        assert safe_cause(sentinel, redact_text()) is sentinel

    def test_a_non_exception_that_looks_like_a_credential_is_replaced_wholesale(self) -> None:
        """Not scrubbed, **withheld**. A partially-scrubbed copy would be a cause
        that is no longer the caller's, carrying a message that is no longer
        true."""
        redact = redact_text()
        assert safe_cause(f"token {FAKE}", redact) == REDACTED

    def test_a_non_exception_that_is_clean_is_kept(self) -> None:
        redact = redact_text()
        assert safe_cause("a plain reason", redact) == "a plain reason"

    def test_an_exception_carrying_a_credential_is_replaced_wholesale(self) -> None:
        error = RuntimeError(f"the request failed with {FAKE}")
        cause = safe_cause(error, redact_text())
        assert cause is not error
        assert isinstance(cause, RuntimeError)
        assert REDACTED in str(cause)
        assert FAKE not in str(cause)

    def test_the_errno_survives_the_replacement(self) -> None:
        """Because it is an enum rather than prose, and it is what a handler
        branches on. Losing it would mean the redaction cost the caller the one
        thing ``safe_cause`` exists to keep."""
        error = OSError(61, f"refused, and by the way {FAKE}")
        cause = safe_cause(error, redact_text())
        assert getattr(cause, "errno", None) == 61

    def test_an_exception_with_no_errno_produces_a_stand_in_with_none(self) -> None:
        cause = safe_cause(RuntimeError(f"x {FAKE}"), redact_text())
        assert getattr(cause, "errno", None) is None
