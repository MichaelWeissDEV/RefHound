"""Executable scan-profile specification."""

from __future__ import annotations

from refhound.config import PROFILES


def test_profile_matrix_is_intentionally_distinct() -> None:
    assert not PROFILES["quick"].entropy_scan
    assert PROFILES["standard"].entropy_scan
    assert not PROFILES["standard"].unreachable_objects
    assert PROFILES["deep"].unreachable_objects
    assert PROFILES["deep"].reflogs
    assert PROFILES["deep"].stash
    assert not PROFILES["deep"].notes
    assert PROFILES["forensic"].notes


def test_every_profile_field_varies_or_is_a_required_common_stage() -> None:
    values = {
        field: {getattr(profile, field) for profile in PROFILES.values()}
        for field in (
            "unreachable_objects",
            "reflogs",
            "secret_scan",
            "entropy_scan",
            "binary_scan",
            "stash",
            "notes",
        )
    }
    assert values["secret_scan"] == {True}
    assert all(len(states) > 1 for field, states in values.items() if field != "secret_scan")
