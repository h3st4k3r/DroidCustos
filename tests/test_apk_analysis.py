import io
import zipfile
from pathlib import Path

from droidcustos.apk_analysis import analyze_apk


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
