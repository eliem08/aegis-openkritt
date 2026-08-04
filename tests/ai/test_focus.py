"""Per-language framework-guard + anchor-CWE focus."""

from __future__ import annotations

from aegis.ai.focus import focus_text, framework_note, language_of


def test_language_of():
    assert language_of("app/Controller.php") == "PHP"
    assert language_of("src/x.go") == "Go"
    assert language_of("Vault.sol") == "Solidity"
    assert language_of("README.md") == ""


def test_focus_text_names_guards_and_anchor_cwes():
    php = focus_text("core/Auth.php")
    assert "PHP" in php and "prepared statements" in php
    assert "access control" in php.lower() and "SQL injection" in php
    sol = focus_text("Vault.sol")
    assert "reentrancy" in sol and "onlyOwner" in sol


def test_focus_text_empty_for_unknown_extension():
    assert focus_text("data.csv") == ""


def test_framework_note_detects_stack_from_content():
    assert "Django" in framework_note("from django.db import models")
    assert "Spring" in framework_note("@RestController public class X {}")
    assert "Express" in framework_note("const app = express()")
    assert "OpenZeppelin" in framework_note("contract V is Ownable {}")
    assert framework_note("plain code") == ""


def test_negative_examples_list_the_rejected_shapes():
    from aegis.ai.negative_examples import negative_examples_text
    t = negative_examples_text()
    assert "Not Applicable" in t
    for label in ("intended-functionality", "pre-auth-token-gated-csrf",
                  "requires-privileged-access", "self-only-impact"):
        assert label in t
