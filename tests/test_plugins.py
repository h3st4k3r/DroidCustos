from droidcustos.capabilities import DeviceCapabilities
from droidcustos.plugins import load_plugins


def test_packaged_plugins_load():
    """Ensure core and OEM plugin definitions are packaged."""
    plugins = load_plugins()
    ids = {plugin.plugin_id for plugin in plugins}
    assert {"core", "asus", "samsung", "xiaomi", "google"}.issubset(ids)


def test_capability_payload_shape():
    """Ensure capability records serialize predictably."""
    capability = DeviceCapabilities(
        serial="ABC",
        sdk=36,
        android_version="16",
        manufacturer="ASUS",
        model="ROG Phone 9",
        build_fingerprint="asus/test",
        rom_family="asus",
    )
    assert capability.to_dict()["rom_family"] == "asus"
