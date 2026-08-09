from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from aegis.ai.jarvis.ios_static import (
    IOSStaticError,
    analyze_ios_ipa,
    cleanup_ios_static,
    issue_ios_ipa_ticket,
)


def _ipa(tmp_path, *, arbitrary_loads=True, file_sharing=True):
    ipa = tmp_path / "Demo.ipa"
    plist = {
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleDisplayName": "Demo",
        "CFBundleVersion": "42",
        "CFBundleShortVersionString": "1.2.3",
        "MinimumOSVersion": "15.0",
        "CFBundleExecutable": "DemoExec",
        "CFBundleURLTypes": [
            {"CFBundleURLSchemes": ["demo", "demo-secure"]},
        ],
        "LSApplicationQueriesSchemes": ["bankapp", "maps"],
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": arbitrary_loads,
            "NSAllowsArbitraryLoadsInWebContent": True,
            "NSAllowsLocalNetworking": True,
        },
        "UIFileSharingEnabled": file_sharing,
        "LSSupportsOpeningDocumentsInPlace": file_sharing,
        # Must never be surfaced by the allowlisted report model.
        "ThirdPartySecretToken": "DO-NOT-LEAK-THIS-VALUE",
    }
    with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(plist))
        bundle.writestr("Payload/Demo.app/DemoExec", b"\xcf\xfa\xed\xfe" + b"\x00" * 128)
        bundle.writestr("Payload/Demo.app/Frameworks/Demo.framework/Demo", b"framework")
        bundle.writestr("Payload/Demo.app/embedded.mobileprovision", b"profile-placeholder")
    return ipa


def test_ipa_report_surfaces_allowlisted_metadata_hashes_and_unverified_posture_only(tmp_path):
    ipa = _ipa(tmp_path)
    ticket = issue_ios_ipa_ticket(ipa, scope_digest="scope:ios")
    report = analyze_ios_ipa(
        ipa,
        ticket=ticket,
        scope_digest="scope:ios",
        workspace_root=tmp_path / "work",
    )
    root = Path(report.extraction.root)
    try:
        assert report.bundle_id == "com.example.demo"
        assert report.display_name == "Demo"
        assert report.bundle_version == "42"
        assert report.short_version == "1.2.3"
        assert report.minimum_os_version == "15.0"
        assert report.url_schemes == ("demo", "demo-secure")
        assert report.query_schemes == ("bankapp", "maps")
        assert report.executable is not None
        assert report.executable.path == "Payload/Demo.app/DemoExec"
        assert len(report.executable.sha256) == 64
        assert len(report.frameworks) == 1
        assert len(report.provisioning_profiles) == 1
        assert report.ats["allows_arbitrary_loads"] is True
        assert report.file_sharing["ui_file_sharing_enabled"] is True
        kinds = {row["scanner_metadata"]["analysis_kind"] for row in report.candidates}
        assert {"ats_arbitrary_loads", "ats_web_content", "file_sharing_posture"} <= kinds
        assert all(row["validation_status"] == "unverified" for row in report.candidates)
        assert all(row["scanner_metadata"]["context_required"] is True for row in report.candidates)
        assert "DO-NOT-LEAK-THIS-VALUE" not in repr(report)
        assert root.is_dir()
    finally:
        cleanup_ios_static(report)
    assert not root.exists()


def test_ipa_ticket_is_bound_to_scope_method_and_artifact_digest(tmp_path):
    ipa = _ipa(tmp_path)
    ticket = issue_ios_ipa_ticket(ipa, scope_digest="scope:one")
    with pytest.raises(IOSStaticError, match="scope digest mismatch"):
        analyze_ios_ipa(ipa, ticket=ticket, scope_digest="scope:two")

    ipa.write_bytes(ipa.read_bytes() + b"tampered")
    with pytest.raises(IOSStaticError, match="digest changed"):
        analyze_ios_ipa(ipa, ticket=ticket, scope_digest="scope:one")


def test_non_ipa_and_missing_payload_are_rejected(tmp_path):
    wrong = tmp_path / "Demo.zip"
    with zipfile.ZipFile(wrong, "w") as bundle:
        bundle.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({}))
    with pytest.raises(IOSStaticError, match=".ipa"):
        issue_ios_ipa_ticket(wrong, scope_digest="scope:ios")

    broken = tmp_path / "Broken.ipa"
    with zipfile.ZipFile(broken, "w") as bundle:
        bundle.writestr("not-payload/file", b"x")
    ticket = issue_ios_ipa_ticket(broken, scope_digest="scope:ios")
    with pytest.raises(IOSStaticError, match="Payload/\*\.app"):
        analyze_ios_ipa(broken, ticket=ticket, scope_digest="scope:ios")


def test_safe_ats_and_file_sharing_posture_does_not_create_those_candidates(tmp_path):
    ipa = _ipa(tmp_path, arbitrary_loads=False, file_sharing=False)
    ticket = issue_ios_ipa_ticket(ipa, scope_digest="scope:ios")
    report = analyze_ios_ipa(ipa, ticket=ticket, scope_digest="scope:ios")
    try:
        kinds = {row["scanner_metadata"]["analysis_kind"] for row in report.candidates}
        assert "ats_arbitrary_loads" not in kinds
        assert "file_sharing_posture" not in kinds
        # This fixture deliberately still enables the web-content ATS exception.
        assert "ats_web_content" in kinds
    finally:
        cleanup_ios_static(report)
