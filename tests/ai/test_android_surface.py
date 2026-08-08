from __future__ import annotations

from pathlib import Path

import pytest

from aegis.ai.jarvis.android_static import AndroidDerivedTree
from aegis.ai.jarvis.android_surface import AndroidSurfaceError, analyze_android_derived_tree


def _tree(tmp_path):
    root = tmp_path / "derived"
    root.mkdir()
    manifest = root / "AndroidManifest.xml"
    manifest.write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app">
          <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />
          <application android:debuggable="true" android:allowBackup="true"
            android:usesCleartextTraffic="true">
            <activity android:name=".ExportedActivity" android:exported="true">
              <intent-filter android:autoVerify="false">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="demo" android:host="open" android:pathPrefix="/account" />
              </intent-filter>
            </activity>
            <service android:name=".ProtectedService" android:exported="true"
              android:permission="com.example.PRIVATE" />
          </application>
        </manifest>""",
        encoding="utf-8",
    )
    source = root / "sources/com/example/Security.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        """class Security {
          void setup(WebView web) {
            web.getSettings().setJavaScriptEnabled(true);
            web.addJavascriptInterface(new Bridge(), "native");
            web.getSettings().setAllowUniversalAccessFromFileURLs(true);
          }
          void onReceivedSslError(WebView v, SslErrorHandler handler, SslError e) {
            handler.proceed();
          }
        }
        class TrustAll implements X509TrustManager {
          public void checkServerTrusted(X509Certificate[] c, String a) { }
        }
        """,
        encoding="utf-8",
    )
    return AndroidDerivedTree(
        tool="jadx",
        method="android-decompile",
        apk_sha256="a" * 64,
        root=str(root),
        tree_digest="b" * 64,
        file_count=2,
        total_bytes=sum(path.stat().st_size for path in root.rglob("*") if path.is_file()),
        runtime_provenance={},
    )


def test_manifest_exposure_is_hypothesis_and_protected_component_is_not_flagged(tmp_path):
    analysis = analyze_android_derived_tree(_tree(tmp_path))
    kinds = [row["scanner_metadata"]["analysis_kind"] for row in analysis.candidates]
    assert "exported_component" in kinds
    exported = next(
        row for row in analysis.candidates
        if row["scanner_metadata"]["analysis_kind"] == "exported_component"
    )
    assert exported["validation_status"] == "unverified"
    assert exported["severity"] == "medium"
    assert exported["scanner_metadata"]["component_name"] == ".ExportedActivity"
    assert "ProtectedService" not in exported["json_answer"]["summary"]
    observation = analysis.observation["manifest"]
    assert observation["target_sdk"] == "35"
    assert observation["components"][1]["permission"] == "com.example.PRIVATE"
    assert observation["deep_links"][0]["scheme"] == "demo"
    assert observation["deep_links"][0]["host"] == "open"


def test_debug_backup_cleartext_and_webview_tls_patterns_are_unverified_candidates(tmp_path):
    analysis = analyze_android_derived_tree(_tree(tmp_path))
    kinds = {row["scanner_metadata"]["analysis_kind"] for row in analysis.candidates}
    assert {
        "manifest_debuggable",
        "manifest_backup",
        "manifest_cleartext",
        "webview_javascript_bridge",
        "webview_universal_file_access",
        "ssl_error_proceed",
        "empty_trust_manager",
    } <= kinds
    assert all(row["validation_status"] == "unverified" for row in analysis.candidates)
    assert all(row["scanner_metadata"]["context_required"] is True for row in analysis.candidates)
    webview = next(
        row for row in analysis.candidates
        if row["scanner_metadata"]["analysis_kind"] == "webview_javascript_bridge"
    )
    assert webview["json_answer"]["line"] > 0
    assert analysis.observation["source"]["javascript_bridge_files"] == 1


def test_app_level_permission_protects_exported_component(tmp_path):
    tree = _tree(tmp_path)
    manifest = Path(tree.root) / "AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8")
    text = text.replace(
        '<application android:debuggable="true"',
        '<application android:permission="com.example.APP_PRIVATE" android:debuggable="true"',
    )
    manifest.write_text(text, encoding="utf-8")
    analysis = analyze_android_derived_tree(tree)
    assert not any(
        row["scanner_metadata"]["analysis_kind"] == "exported_component"
        for row in analysis.candidates
    )


def test_manifest_parse_failure_is_observation_not_crash(tmp_path):
    root = tmp_path / "derived"
    root.mkdir()
    (root / "AndroidManifest.xml").write_text("<manifest", encoding="utf-8")
    tree = AndroidDerivedTree(
        "apktool", "android-resource-decode", "a" * 64, str(root), "b" * 64, 1, 9, {}
    )
    analysis = analyze_android_derived_tree(tree)
    assert analysis.candidates == ()
    assert analysis.observation["manifest"]["manifest_parse_error"] == "ParseError"


def test_symlink_in_derived_tree_is_rejected(tmp_path):
    tree = _tree(tmp_path)
    link = Path(tree.root) / "sources/escape"
    try:
        link.symlink_to("/etc/passwd")
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(AndroidSurfaceError, match="symlink"):
        analyze_android_derived_tree(tree)
