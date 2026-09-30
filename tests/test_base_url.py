"""Base-URL resolution: three sources, in a stated order, each proven to win.

The brief: "an explicit argument, then ``CAFAYE_BASE_URL``, then the documented
default. Each of the three must win in turn, with a test that proves the others
did not."

The second half of that sentence is the part that is easy to skip and the part
that makes the test worth having. Asserting ``client.base_urls["identity"] ==
"https://explicit.example"`` does not prove the environment variable was ignored
— it only proves the argument beat *something*. These tests assert the **source**
that answered, which is the property that actually distinguishes the three, and
several of them set the other two sources to values that would be obvious if they
had been consulted.
"""

from __future__ import annotations

import pytest

from cafaye import (
    BASE_URL_ENV,
    DEFAULT_BASE_URLS,
    SERVICE_NAMES,
    Cafaye,
    CafayeConfigurationError,
    resolve_base_url,
)

EXPLICIT = "https://explicit.example.test"
FROM_ENV = "https://from-env.example.test"

# A loopback address, used as a value that must never be *produced* by
# resolution. It is a trap value: if any code path fell back to a local default,
# this is what would come out.
LOOPBACKS = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1")


# The three precedence tests are three separate classes because the brief asks for
# one per step, and because a failure should say which step broke.


class TestExplicitWins:
    def test_explicit_beats_the_environment_and_the_default(self) -> None:
        resolved = resolve_base_url(
            "identity",
            explicit=EXPLICIT,
            env={BASE_URL_ENV: FROM_ENV},
        )
        assert resolved.url == EXPLICIT
        # The proof that the others did not win: the recorded source is the
        # argument, and the other two answers are not anywhere in it.
        assert resolved.source == "the `base_url` argument"

    def test_the_environment_answer_is_absent_from_the_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(BASE_URL_ENV, FROM_ENV)
        client = Cafaye(base_url=EXPLICIT)
        for service in SERVICE_NAMES:
            assert client.base_urls[service] == EXPLICIT
            assert client.base_url_sources[service] == "the `base_url` argument"
        assert FROM_ENV not in "".join(client.base_urls.values())


class TestEnvironmentWinsOverTheDefault:
    def test_environment_beats_the_default(self) -> None:
        resolved = resolve_base_url("identity", env={BASE_URL_ENV: FROM_ENV})
        assert resolved.url == FROM_ENV
        assert resolved.source == f"${BASE_URL_ENV}"
        assert DEFAULT_BASE_URLS["identity"] != resolved.url

    def test_the_default_answer_is_absent_from_a_constructed_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(BASE_URL_ENV, FROM_ENV)
        client = Cafaye()
        assert client.base_urls["identity"] == FROM_ENV
        assert client.base_url_sources["identity"] == f"${BASE_URL_ENV}"
        assert DEFAULT_BASE_URLS["identity"] not in client.base_urls.values()

    def test_every_service_gets_the_one_environment_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One origin for all six, which is what a single-variable name means."""
        monkeypatch.setenv(BASE_URL_ENV, FROM_ENV)
        client = Cafaye()
        assert set(client.base_urls) == set(SERVICE_NAMES)
        assert set(client.base_urls.values()) == {FROM_ENV}


class TestTheDocumentedDefault:
    def test_default_is_used_when_nothing_else_is(self) -> None:
        resolved = resolve_base_url("identity", env={})
        assert resolved.url == DEFAULT_BASE_URLS["identity"]
        assert resolved.source == "the documented default"

    def test_every_service_has_a_documented_default(self) -> None:
        assert set(DEFAULT_BASE_URLS) == set(SERVICE_NAMES)
        client = Cafaye()
        for service in SERVICE_NAMES:
            assert client.base_url_sources[service] == "the documented default"
            assert client.base_urls[service] == DEFAULT_BASE_URLS[service]

    def test_the_default_is_read_from_the_documents(self) -> None:
        """The defaults are ``servers[0]`` of the six committed documents.

        Not a restatement of the constant — a check that each one is an
        ``https://`` host under ``cafaye.com`` and names the service, which is
        the shape of every ``servers:`` entry in the fleet's six documents. A
        default that stopped matching its service would be caught here rather
        than by somebody's production traffic.
        """
        for service, url in DEFAULT_BASE_URLS.items():
            assert url == f"https://{service}.cafaye.com"

    def test_the_default_is_never_a_loopback(self) -> None:
        """core's conventions list a localhost ``servers`` entry second.

        Taking ``servers[0]`` rather than "the localhost one" is the whole
        point, and this is the test for the mistake of picking the entry a
        developer would rather than the entry a document means by "production".
        """
        for url in DEFAULT_BASE_URLS.values():
            assert not any(host in url for host in LOOPBACKS), url

    def test_the_source_is_visible_so_a_default_is_never_silent(self) -> None:
        """A default that cannot be detected is a default nobody can audit.

        ``client.base_url_sources`` is public and every value is one of four
        strings. A deployment can therefore assert that nothing resolved to
        ``"the documented default"`` without reaching into the client.
        """
        client = Cafaye()
        for source in client.base_url_sources.values():
            assert source in {
                "the `base_url` argument",
                f"${BASE_URL_ENV}",
                "the documented default",
            }


class TestBlankAndMalformedValues:
    def test_a_blank_environment_variable_counts_as_unset(self) -> None:
        """Whitespace is not a URL, and an empty one is a silent default.

        Concatenating ``""`` with ``/v1/me`` produces a relative path, which is
        the same "resolved to something nobody chose" failure one indirection
        further out.
        """
        for blank in ("", "   ", "\t", "\n"):
            resolved = resolve_base_url("identity", env={BASE_URL_ENV: blank})
            assert resolved.url == DEFAULT_BASE_URLS["identity"], blank
            assert resolved.source == "the documented default", blank

    def test_a_blank_argument_counts_as_unset(self) -> None:
        resolved = resolve_base_url("identity", explicit="   ", env={})
        assert resolved.source == "the documented default"

    def test_a_relative_value_is_refused(self) -> None:
        with pytest.raises(CafayeConfigurationError) as caught:
            resolve_base_url("identity", explicit="identity.example.test", env={})
        assert "absolute" in str(caught.value)

    def test_a_non_http_scheme_is_refused(self) -> None:
        for bad in (
            "file:///etc/passwd",
            "chrome-extension://abc/",
            "ftp://identity.example.test",
            "data:text/plain,hi",
        ):
            with pytest.raises(CafayeConfigurationError, match="absolute"):
                resolve_base_url("identity", explicit=bad, env={})

    def test_a_non_http_scheme_in_the_environment_is_refused_not_ignored(self) -> None:
        """It must raise, not fall through to the default.

        A value that was *set* and is unusable is a mistake somebody made, and
        silently replacing it with the default would send the mistake's traffic
        somewhere the operator did not choose.
        """
        with pytest.raises(CafayeConfigurationError, match="absolute"):
            resolve_base_url("identity", env={BASE_URL_ENV: "file:///etc/passwd"})

    def test_the_refusal_names_the_source_that_was_consulted(self) -> None:
        with pytest.raises(CafayeConfigurationError) as caught:
            resolve_base_url("identity", env={BASE_URL_ENV: "identity.example.test"})
        assert BASE_URL_ENV in str(caught.value)


class TestNormalisation:
    def test_trailing_slashes_are_stripped(self) -> None:
        resolved = resolve_base_url("identity", explicit="https://a.example.test///", env={})
        assert resolved.url == "https://a.example.test"

    def test_a_path_prefix_is_kept(self) -> None:
        """A self-hoster may serve the fleet under a sub-path."""
        resolved = resolve_base_url("identity", explicit="https://a.example.test/cafaye/", env={})
        assert resolved.url == "https://a.example.test/cafaye"

    def test_the_reported_url_is_the_url_that_goes_on_the_wire(self) -> None:
        client = Cafaye(base_url="https://a.example.test/cafaye/")
        assert client.base_urls["identity"] == "https://a.example.test/cafaye"
        assert not client.base_urls["identity"].endswith("/")


class TestServiceNames:
    def test_an_unknown_service_is_refused(self) -> None:
        with pytest.raises(CafayeConfigurationError, match="service"):
            resolve_base_url("paymentz", env={})

    def test_the_six_names_are_the_documented_ones(self) -> None:
        assert SERVICE_NAMES == ("identity", "billing", "courier", "darkroom", "muse", "pantry")


class TestErrorsNeverNameALoopback:
    """The TS client's equivalent test, and it exists for the same reason.

    cafaye-ts refuses a base URL it cannot resolve and throws. This client has a
    documented default, so there is no "cannot resolve" branch — but the failure
    that a loopback default causes is identical, and the guard belongs in both
    clients. A message that suggested ``http://localhost:8080`` would be
    actively harmful advice.
    """

    def test_no_configuration_error_suggests_a_loopback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(BASE_URL_ENV, raising=False)
        for bad in ("identity.example.test", "file:///x", "ftp://x", "://x"):
            try:
                resolve_base_url("identity", explicit=bad, env={})
            except CafayeConfigurationError as error:
                message = str(error)
                for host in LOOPBACKS:
                    assert host not in message, (bad, host, message)
            else:  # pragma: no cover - a value that unexpectedly resolved
                pytest.fail(f"{bad!r} resolved instead of raising")
