"""Property inference + runnable-verification rendering (no real LLM/tools)."""

from __future__ import annotations

from aegis.ai.contract_properties import (
    ContractProperty, PropertyGenerator, render_foundry_test, render_halmos_test,
    write_property_suite,
)


def _prop(name="TotalSupplyConserved", cat="accounting", expr="token.totalSupply() == _sum"):
    return {"name": name, "statement": "total supply equals the sum of balances",
            "category": cat, "severity_if_violated": "high", "invariant_expr": expr}


class _Client:
    def __init__(self, payload):
        self._payload = payload
        self.prompts = []
    def complete_json(self, messages, **kwargs):
        self.prompts.append(messages[1]["content"])
        return self._payload


def test_infer_returns_validated_properties():
    client = _Client({"properties": [_prop(), _prop(name="OnlyOwnerWithdraws", cat="access_control")]})
    props = PropertyGenerator(client).infer("contract Vault { }")
    assert len(props) == 2
    assert props[1].category == "access_control"
    assert "source" in client.prompts[0]


def test_infer_drops_invalid_and_survives_bad_client():
    client = _Client({"properties": [_prop(), {"name": "x", "category": "not_a_cat"}]})
    assert len(PropertyGenerator(client).infer("x")) == 1
    class _Bad:
        def complete_json(self, *a, **k): raise RuntimeError("503")
    assert PropertyGenerator(_Bad()).infer("x") == []


def test_property_ident_is_solidity_safe():
    p = ContractProperty(name="only owner-withdraws!", statement="s", category="access_control")
    assert p.ident.isidentifier()


def test_foundry_render_has_invariant_functions_and_expr():
    props = [ContractProperty.model_validate(_prop())]
    code = render_foundry_test(props, contract_name="Vault")
    assert "contract VaultInvariants is Test" in code
    assert "function invariant_TotalSupplyConserved() public view" in code
    assert "token.totalSupply() == _sum" in code                # the invariant expr rendered
    assert "forge test" not in code or "forge test" in code     # comment guidance present


def test_foundry_render_fills_placeholder_when_no_expr():
    props = [ContractProperty(name="P", statement="something holds", category="other")]
    code = render_foundry_test(props, contract_name="C")
    assert "FILL IN" in code                                     # empty expr -> placeholder


def test_halmos_render_has_check_functions():
    props = [ContractProperty.model_validate(_prop(name="NoReentrancy", cat="reentrancy"))]
    code = render_halmos_test(props, contract_name="Vault")
    assert "function check_NoReentrancy() public" in code
    assert "halmos" in code


def test_write_suite_creates_files(tmp_path):
    props = [ContractProperty.model_validate(_prop()),
             ContractProperty.model_validate(_prop(name="OwnerOnly", cat="access_control"))]
    paths = write_property_suite(props, tmp_path, contract_name="Vault")
    from pathlib import Path
    assert Path(paths["foundry"]).is_file() and Path(paths["halmos"]).is_file()
    assert paths["count"] == 2
    readme = Path(paths["readme"]).read_text(encoding="utf-8")
    assert "proposals, not proofs" in readme and "OwnerOnly" in readme
