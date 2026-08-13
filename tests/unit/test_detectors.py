"""Unit tests for secret detectors.

Security guarantee under test: the full secret value never appears in any
``DetectorResult`` — only prefix/suffix (redacted) and a fingerprint.
"""

from __future__ import annotations

from refhound.detectors.cloud import AWSDetector
from refhound.detectors.database import DatabaseURIDetector
from refhound.detectors.github import GitHubDetector
from refhound.detectors.gitlab import GitLabDetector
from refhound.detectors.jwt import JWTDetector
from refhound.detectors.passwords import GenericPasswordDetector
from refhound.detectors.private_keys import PrivateKeyDetector
from refhound.detectors.registry import default_detectors
from refhound.util.hashing import MIN_SECRET_LENGTH, redact_secret


def _secrets(detector, content: bytes) -> list[str]:
    return [r.secret_fingerprint for r in detector.detect(content)]


def test_github_token_detected_and_redacted() -> None:
    detector = GitHubDetector()
    content = b"key = ghp_1234567890ABCDEFghij1234567890ABCDEF\n"
    results = list(detector.detect(content))
    assert len(results) == 1
    result = results[0]
    assert result.prefix == "ghp_"
    assert result.suffix == "CDEF"
    # The full value must not be reconstructable from the result.
    assert "ghp_1234567890ABCDEFghij1234567890ABCDEF" not in (result.prefix + result.suffix)


def test_github_token_line_and_offset() -> None:
    detector = GitHubDetector()
    content = b"a\nb\nTOKEN = ghp_1234567890ABCDEFghij1234567890ABCDEF\n"
    results = list(detector.detect(content))
    assert results[0].line == 3
    assert results[0].char_offset == content.index(b"ghp_")


def test_aws_access_key_shape() -> None:
    detector = AWSDetector()
    content = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    results = list(detector.detect(content))
    assert len(results) == 1
    assert results[0].key == "access_key"


def test_database_uri_redacted() -> None:
    detector = DatabaseURIDetector()
    content = b"postgres://user:hunter2secret@db.example.com:5432/app\n"
    results = list(detector.detect(content))
    assert len(results) == 1
    assert "hunter2secret" not in results[0].extra.get("user", "")


def test_private_key_detected() -> None:
    pem = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n"
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX\n"
        b"-----END PRIVATE KEY-----\n"
    )
    results = list(PrivateKeyDetector().detect(pem))
    assert len(results) == 1


def test_no_match_returns_empty() -> None:
    assert _secrets(GitHubDetector(), b"just a normal file") == []


def test_entropy_only_candidate_never_yields_full_value() -> None:
    from refhound.detectors.entropy import EntropyDetector

    detector = EntropyDetector()
    content = b"token = 3F7b9cQ2xLm8vZk5rTs1nWp4jH6dAy0eBg2uIo9Cq7nVxZ3sDf8gHj1kLm4"
    results = list(detector.detect(content))
    for result in results:
        assert "3F7b9cQ2xLm8vZk5rTs1nWp4jH6dAy0eBg2uIo9Cq7nVxZ3sDf8gHj1kLm4" not in (
            result.prefix + result.suffix
        )


def test_redaction_boundaries_never_expose_short_secret_fragments() -> None:
    detector = GenericPasswordDetector()
    for length in (0, 1, 2, 4, 7, 8, 9, 12, 20, 41):
        value = "X" * length
        result = detector.result(value)
        if length <= MIN_SECRET_LENGTH:
            assert result.prefix == ""
            assert result.suffix == ""
        else:
            assert result.prefix == value[:4]
            assert result.suffix == value[-4:]
        assert (
            value not in redact_secret(value)
            if value
            else redact_secret(value).startswith("<redacted:")
        )


def test_eight_character_password_is_detected_without_fragments() -> None:
    secret = "Ab1xY2zQ"
    results = list(GenericPasswordDetector().detect(f"password={secret}".encode()))
    assert results
    assert all(result.prefix == result.suffix == "" for result in results)
    assert secret not in str([result.model_dump() for result in results])


def test_gitlab_and_jwt_synthetic_values() -> None:
    assert list(GitLabDetector().detect(b"token=glpat-ABCDEFGHIJKLMNOPQRST"))
    jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGljc2lnbmF0dXJl"
    assert list(JWTDetector().detect(jwt))


def test_synthetic_corpus_has_expected_signal_and_no_raw_result_values() -> None:
    from pathlib import Path

    root = Path(__file__).parents[1] / "corpus" / "secrets"
    positive = (root / "positive" / "synthetic.txt").read_bytes()
    negative = (root / "negative" / "ordinary.txt").read_bytes()
    hits = {detector.id: list(detector.detect(positive)) for detector in default_detectors()}
    for detector_id in (
        "github",
        "gitlab",
        "aws",
        "gcp",
        "private-key",
        "jwt",
        "database-uri",
        "generic-password",
    ):
        assert hits[detector_id], detector_id
    for detector in default_detectors():
        for result in detector.detect(negative):
            assert result.severity.value in {"info", "low"}
