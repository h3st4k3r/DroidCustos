from droidcustos.apk_inventory import compare_inventories, parse_package_list


def test_package_list_parser():
    """Parse package path, installer, UID and version code."""
    records = parse_package_list(
        "package:/data/app/~~x/base.apk=com.example.app installer=com.android.vending uid:10123 versionCode:42",
        0,
    )
    assert records[0].package == "com.example.app"
    assert records[0].installer == "com.android.vending"
    assert records[0].version_code == "42"


def test_inventory_diff():
    """Detect package additions and version changes."""
    base = {"records": [{"package": "a", "user_id": 0, "version_code": "1"}]}
    current = {"records": [{"package": "a", "user_id": 0, "version_code": "2"}, {"package": "b", "user_id": 0}]}
    result = compare_inventories(base, current)
    assert result["summary"] == {"added": 1, "removed": 0, "changed": 1}
