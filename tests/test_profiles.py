"""DroidCustos acquisition profile tests.

Author: h3st4k3r
"""

from argparse import Namespace

from droidcustos.profiles import resolve_profile


def args(**overrides):
    """Build a profile argument namespace."""
    values = {
        "deep": False,
        "backup": None,
        "download": None,
        "remove_trusted": "no",
        "intrusion_logs": "yes",
        "androidqf_hash_files": "no",
        "no_adb_extra": False,
        "collect_connections": False,
        "collect_web": False,
        "collect_chats": False,
        "hash_user_files": False,
        "copy_user_files": False,
        "root_mode": "never",
    }
    values.update(overrides)
    return Namespace(**values)


def test_standard_profile_avoids_deep_user_data() -> None:
    """Confirm that standard mode avoids deep personal data."""
    profile = resolve_profile(args())
    assert profile.name == "standard"
    assert profile.backup == "sms"
    assert profile.hash_user_files is False


def test_deep_profile_enables_extended_categories() -> None:
    """Confirm that deep mode enables extended categories."""
    profile = resolve_profile(args(deep=True))
    assert profile.name == "deep"
    assert profile.backup == "all"
    assert profile.collect_web is True
    assert profile.collect_chats is True
    assert profile.collect_connections is True
    assert profile.hash_user_files is True
    assert profile.copy_user_files is False
