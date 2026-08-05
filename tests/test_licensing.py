"""License hygiene (Phase 3 §Tests: "no copied AGPL/GPL code or bundled dataset").

The clean-room reimplementations (Arjun-style parameter discovery, Kiterunner-
style route discovery) and the GPL-derived scheduler must not contain copied
AGPL/GPL source or bundled restricted datasets. This test walks the shipped
package and fails if any GPL/AGPL license text, SPDX identifier, or non-code data
file appears — and asserts the clean-room modules carry their provenance note.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "aegis"

# Text that only appears in actual GPL/AGPL-licensed source, not in our own
# clean-room disclaimers (which say things like "no AGPL Arjun source").
FORBIDDEN_LICENSE_TEXT = (
    "gnu affero general public license",
    "gnu general public license",
    "affero general public",
    "this program is free software",
    "under the terms of the gnu",
    "spdx-license-identifier: agpl",
    "spdx-license-identifier: gpl",
)

# Upstream restricted tools that must be reimplemented, never vendored.
VENDORED_NAMES = ("arjun", "kiterunner", "rengine")

# The clean-room modules and the provenance each must state.
CLEANROOM_PROVENANCE = {
    "active/parameters.py": ("clean-room", "no agpl arjun"),
    "active/routes.py": ("no agpl kiterunner",),
    "active/detectors.py": ("orchestrat",),
}


def _py_files():
    return [p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts]


def test_no_gpl_or_agpl_license_text_in_source():
    offenders = []
    for path in _py_files():
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        for marker in FORBIDDEN_LICENSE_TEXT:
            if marker in text:
                offenders.append(f"{path.relative_to(SRC)}: {marker!r}")
    assert not offenders, "GPL/AGPL license text found (copied source?):\n" + "\n".join(offenders)


def test_no_bundled_datasets_or_wordlists():
    # The package ships code only — no vendored wordlists/datasets (e.g. Arjun or
    # Kiterunner data). Anything that is not Python/type-stub, a first-party UI template,
    # or a first-party Semgrep ruleset (ai/rules/*.yml, Aegis-authored) is suspect.
    data_files = [
        p for p in SRC.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
        and p.suffix not in (".py", ".pyi", ".typed", ".html", ".yml", ".yaml")
    ]
    assert data_files == [], f"unexpected non-code files bundled: {data_files}"


def test_restricted_tools_are_not_vendored_as_modules():
    # We may *mention* these tools in clean-room notes, but must not vendor them as
    # source files/directories.
    vendored = [
        p.relative_to(SRC) for p in SRC.rglob("*")
        if p.is_file() and any(name in p.stem.lower() for name in VENDORED_NAMES)
    ]
    assert vendored == [], f"restricted tool source appears vendored: {vendored}"


@pytest.mark.parametrize("rel,markers", CLEANROOM_PROVENANCE.items())
def test_cleanroom_modules_declare_provenance(rel, markers):
    text = (SRC / rel).read_text(encoding="utf-8").lower()
    for marker in markers:
        assert marker in text, f"{rel} is missing its provenance note {marker!r}"


def test_active_package_has_no_gpl_dependency_imports():
    # Defensive: the active-testing engines are self-contained and must not import
    # a vendored restricted tool.
    for path in (SRC / "active").rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for name in VENDORED_NAMES:
            assert f"import {name}" not in text and f"from {name}" not in text, \
                f"{path.name} imports vendored tool {name!r}"
