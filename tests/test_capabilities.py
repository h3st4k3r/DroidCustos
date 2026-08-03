from droidcustos.capabilities import detect_rom_family, parse_storage_volumes, parse_users


def test_parse_users_and_profiles():
    """Validate multi-user and profile parsing."""
    users = parse_users("Users:\n\tUserInfo{0:Owner:13} running\n\tUserInfo{10:Work profile:30}")
    assert [user.user_id for user in users] == [0, 10]
    assert users[0].running is True
    assert users[1].user_type == "work-profile"


def test_parse_storage_volumes():
    """Validate emulated and public volume parsing."""
    volumes = parse_storage_volumes("emulated;0 mounted null\npublic:179,65 mounted ABCD-1234")
    assert volumes[0].kind == "emulated"
    assert volumes[1].path == "/storage/ABCD-1234"


def test_rom_family_mapping():
    """Validate common OEM family detection."""
    assert detect_rom_family("ASUS", "asus/AI2501") == "asus"
    assert detect_rom_family("samsung", "samsung/e3q") == "samsung"
    assert detect_rom_family("unknown", "aosp/generic") == "aosp"
