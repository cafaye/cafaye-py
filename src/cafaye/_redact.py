"""Removing credentials from anything this package is about to hand a human.

WHY THIS MODULE EXISTS AT ALL
-----------------------------

The failure it prevents is not hypothetical and it is not subtle. This package is
the one place in a consumer's application that touches every credential it has.
It holds a token, and a traceback is the single most likely thing in a Python
process to end up in a log file, a crash reporter, a support ticket or a terminal
somebody is looking over their shoulder — with no configuration. ``logger.error(
"request failed", exc_info=True)`` prints it, ``traceback.print_exc()`` prints
it, and a crash reporter that has not been told otherwise prints the whole
cause chain.

So the rule is not "be careful when building messages". It is that **no string
this package constructs out of anything a service or a caller supplied passes
through a redactor first**, and that the redactor's behaviour is a test
(``tests/test_credential_leak.py``) rather than a review comment.

THE RULE: ALL OR NOTHING
------------------------

A string either comes back unchanged or comes back as one marker. There is no
partial redaction, and that is the load-bearing decision. The obvious
implementation — replace the substrings you recognise, return the rest — is wrong
in a way that gets worse the more carefully it is written, because it invites a
reader to add one more pattern, and the day the reader adds a pattern with a gap
in it is the day a credential ships. There is no such day here: a string that
matched anything at all is not shown, so a pattern with a gap can only cause a
false negative for "this string is clean" — it cannot cause a leak of a matched
value. A ``Cookie:`` header line is redacted whole, so a cookie this package has
never heard of is still removed.

WHAT MATCHES
------------

1. **Exact values** the instance was constructed with. The client knows the one
   credential it holds, so it can recognise it character for character. This is
   what catches a service echoing a caller's own session token back inside a
   problem ``detail``.
2. **Structural shapes**: the ``cafaye_`` API-token prefix, a JWS compact
   serialization, and any ``Authorization`` / ``Proxy-Authorization`` / ``Cookie``
   / ``Set-Cookie`` header line. This is what catches credentials the instance
   never held — a ``Set-Cookie`` on a response it did not authenticate, or a
   header a caller built by hand.

WHAT DOES NOT MATCH, DELIBERATELY
---------------------------------

Ordinary prose that happens to contain the words. "the request was not
authorized" is a message worth having. ``connect ECONNREFUSED 127.0.0.1:443`` is
the single most useful line in a network error and nothing here touches it. A
32-hex ``trace_id`` survives, which matters more than it sounds: core's
conventions say support starts from the ``trace_id``, so a redactor that ate it
would have made every unsupported failure harder to report.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Protocol

__all__ = ["REDACTED", "Redactor", "redact_text", "safe_cause"]

#: The replacement for any string that matched. It is a module constant so that a
#: consumer can recognise it, and it is deliberately not an empty string: a
#: message that is suddenly blank reads as "the error had no detail", which is a
#: different and wrong conclusion.
REDACTED = "[redacted: a credential-shaped value was present]"

#: Anything that could carry a credential, matched structurally.
#:
#: Kept as one alternation so that "did anything match" is one question, which is
#: what makes the all-or-nothing rule cheap to implement honestly. The
#: ``cookie`` and ``authorization`` alternatives run to the end of the line
#: rather than to the first space, because a cookie value contains neither and a
#: ``Set-Cookie`` line carries four attributes after the one that matters.
CREDENTIAL_SHAPES = re.compile(
    # NO `\b` in front of the two structural token patterns, and its absence is
    # load-bearing in the other direction.
    #
    # This alternation used to begin `\bcafaye_` and `\beyJ`, on the reasonable-
    # sounding theory that a word boundary stops the pattern matching inside a
    # longer word. It does the opposite of what is wanted. `\b` asserts a
    # transition between a word and a non-word character, so `\bcafaye_` matches a
    # bare token and a token after a `/`, a `?` or a space — and silently fails on
    # a token preceded by **any** word character:
    #
    #     xcafaye_abc...   not matched
    #     1cafaye_abc...   not matched
    #     token=cafaye_... matched
    #
    # And a credential concatenated onto something is not a rarer case, it is the
    # ordinary one: a proxy URL with the credential in the path, a log line that
    # interpolated it into an identifier, a cursor that embedded it. The prefix
    # `cafaye_` is seven characters chosen by identity precisely so a leaked
    # credential is recognisable by sight; anchoring it behind a word boundary
    # threw that away for the shapes that matter most.
    r"cafaye_[A-Za-z0-9_-]+"
    r"|eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"
    r"|(?:^|[\s,;])(?:proxy-)?authorization\s*:\s*\S+"
    r"|(?:^|[\s,;])(?:set-)?cookie\s*:\s*[^\r\n]*",
    re.IGNORECASE,
)


class Redactor(Protocol):
    """A callable that returns a string safe to put in a message.

    A ``Protocol`` rather than a ``Callable[[object], str]`` alias so that the
    name means the same thing in a type annotation as it does in this module's
    prose, and so ``mypy`` will not silently accept a redactor that takes the
    wrong thing.
    """

    def __call__(self, value: object) -> str:
        """Return ``value`` as text with any credential-shaped value removed."""
        ...


def redact_text(secrets: Sequence[str] = (), max_length: int = 0) -> Redactor:
    """Build a redactor bound to a set of known secrets.

    ``secrets`` are exact credential values to remove wherever they appear, and
    are why the redactor is constructed per client rather than once per module:
    the values it knows are the values that client holds.

    ``max_length`` truncates a string that came back clean. ``0`` does not
    truncate, and is the right value for every exception message — this package's
    messages are deliberately long and a truncated one names half a diagnosis.
    """
    # Longest first, so a secret that is a prefix of another cannot be replaced
    # part-way and leave a tail behind. With the all-or-nothing rule that
    # particular bug is harmless — either string still matches — but ordering by
    # length costs nothing and keeps the intent obvious to the next reader.
    # `secrets` is `Sequence[str]`, so the only question left about each entry is
    # whether it is worth carrying, and an empty one is not: it would match
    # everywhere and redact everything.
    exact = sorted({secret for secret in secrets if secret}, key=len, reverse=True)

    def redact(value: object) -> str:
        if isinstance(value, str):
            text = value
        elif value is None:
            text = ""
        else:
            text = str(value)

        # FIRST, before anything else, including truncation. Truncating first and
        # then looking would mean only the first ``max_length`` characters were
        # ever checked, which is a hole rather than an optimisation.
        for secret in exact:
            if secret in text:
                return REDACTED
        if CREDENTIAL_SHAPES.search(text):
            return REDACTED

        if max_length > 0 and len(text) > max_length:
            return text[: max_length - 1].rstrip() + "…"
        return text

    return redact


def safe_cause(error: object, redact: Redactor) -> object:
    """Keep a platform error as a ``__cause__``, unless there is something in it
    to keep out of one.

    A cause is how the errno survives: httpx's ``ConnectError: [Errno 8] connect
    error`` says almost nothing, and the difference between a refused connection
    and a name that did not resolve is one level down. So the original object is
    normally preserved untouched, and a caller who wants
    ``error.__cause__.errno`` has it.

    Except when the redactor finds a credential in it. A cause is a real object
    this package does not own, and it is reachable — ``traceback`` walks the whole
    chain, and every crash reporter walks it. Passing a partially-scrubbed copy
    would be the worst of both: a cause that is no longer the platform's, carrying
    a message that is no longer true. So when there is anything to withhold, the
    original is withheld **entirely** and replaced with a stand-in that says so,
    keeping ``type`` and ``errno`` because those are enums rather than prose and
    are the part a handler branches on.

    This is the same all-or-nothing rule as :func:`redact_text` itself, applied
    one level out.
    """
    if error is None:
        return error
    if not isinstance(error, BaseException):
        return REDACTED if redact(error) != str(error) else error

    message = str(error)
    if redact(message) == message:
        return error

    stand = RuntimeError(
        f"{REDACTED} — the original platform error carried a credential-shaped value, "
        "so it is not attached. Its type and errno are kept because those are enums "
        "and are what a handler branches on."
    )
    errno = getattr(error, "errno", None)
    if isinstance(errno, int):
        stand.errno = errno  # type: ignore[attr-defined]
    return stand
