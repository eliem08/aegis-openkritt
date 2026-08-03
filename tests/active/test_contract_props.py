"""Lab-only Solidity safety-property analysis.

The analyzer states the invariants a value-holding contract must uphold and flags
violations in source the operator supplied — the vectors that drain a protocol's
TVL. It never compiles, executes, or touches a chain; every hit is a candidate.
"""

from __future__ import annotations

from aegis.active.contract_props import ContractProperty, analyze_solidity

# A deliberately vulnerable lab fixture (not a real protocol).
VULNERABLE = """
pragma solidity ^0.7.0;

contract Vault {
    mapping(address => uint256) public balances;
    address owner;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function emergencyDrain(address to) public {
        payable(to).transfer(address(this).balance);
    }

    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    function login(address who) public {
        require(tx.origin == owner);
        owner = who;
    }
}
"""

# The same surface, hardened: 0.8+, guarded, checks-effects-interactions.
SAFE = """
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function emergencyDrain(address to) public onlyOwner {
        payable(to).transfer(address(this).balance);
    }

    function kill() public onlyOwner {
        selfdestruct(payable(owner));
    }
}
"""


def _props(findings):
    return {f.property_violated for f in findings}


def test_reentrancy_flagged_when_call_precedes_state_write():
    findings = analyze_solidity(VULNERABLE)
    reentrant = [f for f in findings if f.property_violated is ContractProperty.NO_REENTRANCY]
    assert reentrant and reentrant[0].function == "withdraw"
    assert reentrant[0].severity == "critical" and reentrant[0].verified is False


def test_missing_access_control_on_privileged_function():
    findings = analyze_solidity(VULNERABLE)
    ac = [f for f in findings if f.property_violated is ContractProperty.ACCESS_CONTROLLED_PRIVILEGED]
    names = {f.function for f in ac}
    assert "emergencyDrain" in names


def test_unguarded_selfdestruct_flagged():
    findings = analyze_solidity(VULNERABLE)
    kills = [f for f in findings if f.property_violated is ContractProperty.GUARDED_DESTRUCT]
    assert kills and kills[0].function == "kill"


def test_tx_origin_auth_flagged():
    findings = analyze_solidity(VULNERABLE)
    assert ContractProperty.NO_TX_ORIGIN_AUTH in _props(findings)


def test_pre_0_8_arithmetic_flags_value_conservation():
    findings = analyze_solidity(VULNERABLE)
    assert ContractProperty.VALUE_CONSERVATION in _props(findings)


def test_line_numbers_point_into_source():
    findings = analyze_solidity(VULNERABLE)
    lines = VULNERABLE.splitlines()
    for f in findings:
        assert 1 <= f.line <= len(lines)


def test_hardened_contract_has_no_critical_violations():
    findings = analyze_solidity(SAFE)
    props = _props(findings)
    # checks-effects-interactions holds; every privileged fn is guarded; 0.8+ math
    assert ContractProperty.NO_REENTRANCY not in props
    assert ContractProperty.ACCESS_CONTROLLED_PRIVILEGED not in props
    assert ContractProperty.GUARDED_DESTRUCT not in props
    assert ContractProperty.VALUE_CONSERVATION not in props


def test_empty_source_is_safe():
    assert analyze_solidity("") == []
    assert analyze_solidity(None) == []
