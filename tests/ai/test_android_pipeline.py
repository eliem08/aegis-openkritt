from __future__ import annotations

from pathlib import Path

import httpx

from aegis.ai.jarvis.android_pipeline import cleanup_android_pipeline, run_android_static_pipeline
from aegis.ai.jarvis.android_static import ANDROID_JADX
from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.mobsf_adapter import MobSFConfig
from aegis.ai.tool_runtime import ToolRuntimeManager


def _apk(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04authorized")
    return apk


def _manager(tmp_path, available=True):
    jadx = tmp_path / "jadx"
    bwrap = tmp_path / "bwrap"
    if available:
        jadx.write_bytes(b"jadx")
        bwrap.write_bytes(b"bwrap")

    def resolver(name):
        if not available:
            return None
        return {"jadx": str(jadx), "bwrap": str(bwrap)}.get(name)

    def version(argv, timeout):
        if available and argv[0] == str(jadx):
            return 0, "jadx 1.5", ""
        if available and argv[0] == str(bwrap):
            return 0, "bubblewrap 0.11", ""
        return 1, "", ""

    return ToolRuntimeManager(resolver=resolver, runner=version)


def _decompile_runner(argv, workspace, timeout, env, maximum_output_bytes):
    scanner = argv[argv.index("--") + 1 :]
    output = Path(scanner[scanner.index("-d") + 1])
    output.mkdir(parents=True, exist_ok=True)
    (output / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="demo">
        <application><activity android:name=".Open" android:exported="true" /></application>
        </manifest>""",
        encoding="utf-8",
    )
    source = output / "sources/demo/Web.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "web.getSettings().setJavaScriptEnabled(true);\nweb.addJavascriptInterface(x, \"n\");\n",
        encoding="utf-8",
    )
    return CliProcessResult(0, b"done", b"")


def _mobsf_client():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "e" * 32, "scan_type": "apk"})
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(
                200,
                json={
                    "code_analysis": {
                        "rule": {
                            "title": "Potential insecure random use",
                            "description": "Review cryptographic use",
                            "severity": "warning",
                            "file": "sources/demo/Crypto.java",
                        }
                    }
                },
            )
        if request.url.path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"deleted": "yes"})
        raise AssertionError(request.url.path)

    return httpx.Client(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(handler),
    )


def test_pipeline_combines_mobsf_and_networkless_derived_hypotheses(tmp_path):
    apk = _apk(tmp_path)
    client = _mobsf_client()
    try:
        report = run_android_static_pipeline(
            apk,
            scope_digest="scope:android-pipeline",
            decompilers=(ANDROID_JADX,),
            mobsf_config=MobSFConfig(api_key="key"),
            mobsf_client=client,
            workspace_root=tmp_path / "work",
            runtime_manager=_manager(tmp_path),
            pins={},
            process_runner=_decompile_runner,
        )
    finally:
        client.close()
    assert {stage.stage: stage.status for stage in report.stages} == {
        "mobsf": "complete",
        "jadx/android-decompile": "complete",
    }
    assert report.engine_errors == {}
    kinds = {
        row.get("scanner_metadata", {}).get("analysis_kind")
        for row in report.candidates
    }
    assert "exported_component" in kinds
    assert "webview_javascript_bridge" in kinds
    assert any(row["source"] == "aegis:tool:mobsf" for row in report.candidates)
    assert all(row["validation_status"] == "unverified" for row in report.candidates)
    assert not list((tmp_path / "work").glob("aegis-asset-*"))


def test_pipeline_preserves_partial_results_when_decompiler_runtime_is_unavailable(tmp_path):
    apk = _apk(tmp_path)
    report = run_android_static_pipeline(
        apk,
        scope_digest="scope:android-pipeline",
        decompilers=(ANDROID_JADX,),
        mobsf_config=None,
        workspace_root=tmp_path / "work",
        runtime_manager=_manager(tmp_path, available=False),
        pins={},
    )
    statuses = {stage.stage: stage.status for stage in report.stages}
    assert statuses["mobsf"] == "skipped"
    assert statuses["jadx/android-decompile"] == "failed"
    assert "jadx/android-decompile" in report.engine_errors
    assert report.candidates == []


def test_pipeline_retains_derived_tree_only_on_explicit_request(tmp_path):
    apk = _apk(tmp_path)
    report = run_android_static_pipeline(
        apk,
        scope_digest="scope:android-pipeline",
        decompilers=(ANDROID_JADX,),
        mobsf_config=None,
        workspace_root=tmp_path / "work",
        retain_derived_trees=True,
        runtime_manager=_manager(tmp_path),
        pins={},
        process_runner=_decompile_runner,
    )
    assert len(report.retained_trees) == 1
    root = Path(report.retained_trees[0].root)
    assert root.is_dir()
    cleanup_android_pipeline(report)
    assert report.retained_trees == []
    assert not root.exists()
