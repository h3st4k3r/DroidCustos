import io
import zipfile
from pathlib import Path

from droidcustos.apk_analysis import _manifest_from_aapt, analyze_apk, analyze_apk_tree


def test_static_apk_analysis_inventory(tmp_path: Path) -> None:
    """Collect manifest, DEX, native ABI and passive observable details."""
    apk = tmp_path / "sample.apk"
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.suspicious">
  <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
  <application android:debuggable="true" android:allowBackup="false"
      android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".MainActivity" android:exported="true" />
    <service android:name=".AssistService" android:exported="false">
      <intent-filter><action android:name="android.accessibilityservice.AccessibilityService" /></intent-filter>
    </service>
    <receiver android:name=".BootReceiver">
      <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED" /></intent-filter>
    </receiver>
  </application>
</manifest>
"""
    with zipfile.ZipFile(apk, "w") as package:
        package.writestr("AndroidManifest.xml", manifest)
        package.writestr("classes.dex", b"dex-one")
        package.writestr("classes2.dex", b"dex-two")
        package.writestr("lib/arm64-v8a/libnative.so", b"native")
        package.writestr("assets/config.txt", "https://C2.Example/collect 203.0.113.7")
    result = analyze_apk(apk)
    assert result["package"] == "com.example.suspicious"
    assert result["manifest_source"] == "plaintext-xml"
    assert result["manifest_status"] == "parsed"
    assert len(result["dex"]) == 2
    assert result["abis"] == ["arm64-v8a"]
    assert result["manifest"]["debuggable"] is True
    assert result["manifest"]["uses_cleartext_traffic"] is True
    assert "accessibility-service" in result["manifest"]["special_capabilities"]
    assert "boot-completed" in result["manifest"]["special_capabilities"]
    assert "https://C2.Example/collect" in result["observables"]["urls"]
    assert "203.0.113.7" in result["observables"]["ipv4"]


def test_apk_analysis_does_not_classify_url_as_malicious(tmp_path: Path) -> None:
    """Keep passive URL extraction separate from maliciousness decisions."""
    apk = tmp_path / "benign.apk"
    with zipfile.ZipFile(apk, "w") as package:
        package.writestr("assets/readme.txt", "https://example.org/documentation")
    result = analyze_apk(apk)
    assert result["observables"]["urls"] == ["https://example.org/documentation"]
    assert "malicious" not in result


def test_binary_manifest_is_reported_without_inventing_metadata(tmp_path: Path) -> None:
    """Report binary XML limitations while preserving the APK hash and evidence path."""
    apk = tmp_path / "binary-manifest.apk"
    with zipfile.ZipFile(apk, "w") as package:
        package.writestr("AndroidManifest.xml", b"AXML\x00\x00not-plaintext")
    result = analyze_apk(apk)
    assert result["manifest"] == {}
    assert result["manifest_source"] == "binary-or-invalid-xml"
    assert result["manifest_status"] == "requires-aapt"
    assert len(result["sha256"]) == 64


def test_aapt_manifest_fallback_is_explicit_and_partial() -> None:
    """Convert only the metadata aapt can prove when binary XML is unavailable."""
    manifest = _manifest_from_aapt(
        {
            "package": "com.example.binary",
            "permissions": ["android.permission.INTERNET"],
            "launchable_activities": ["com.example.MainActivity"],
            "version_code": "7",
            "version_name": "1.2.3",
        }
    )
    assert manifest["source"] == "aapt-badging"
    assert manifest["parse_status"] == "partial"
    assert manifest["package"] == "com.example.binary"
    assert manifest["components"]["activities"][0]["name"] == "com.example.MainActivity"


def test_apk_tree_keeps_corrupt_apk_as_an_error_record(tmp_path: Path) -> None:
    """Keep one corrupt APK from aborting analysis of the complete tree."""
    apk = tmp_path / "broken.apk"
    apk.write_bytes(b"not a zip archive")
    results = analyze_apk_tree(tmp_path)
    assert results == [
        {
            "format": "droidcustos-apk-analysis-v1",
            "analysis_status": "ERROR",
            "path": str(apk),
            "error": "BadZipFile: File is not a zip file",
        }
    ]
