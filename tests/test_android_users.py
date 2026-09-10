from droidcustos.capabilities import parse_user_sources


def test_merge_users_from_multiple_android_sources() -> None:
    """Merge profile metadata without trusting one command output."""
    users = parse_user_sources(
        "Users:\n UserInfo{0:Owner:13} running\n UserInfo{10:Work profile:30}",
        "Users:\n UserInfo{10:Work profile:30} running unlocked quiet_mode profileGroupId=0",
        "UserInfo{11:Private Space:40} running unlocked clone=false parentId=0",
    )
    assert [item.user_id for item in users] == [0, 10, 11]
    work = users[1]
    assert work.running is True
    assert work.unlocked is True
    assert work.profile_group_id == 0
    assert work.managed is True
    assert work.quiet_mode is True
    private = users[2]
    assert private.private is True
    assert private.parent_id == 0
