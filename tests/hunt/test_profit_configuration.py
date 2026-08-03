from decimal import Decimal

import pytest

from aegis.hunt.__main__ import _parse_expected_bounties
from aegis.hunt import HuntConfig


def test_expected_bounty_json_is_explicit_decimal_operator_data():
    assert _parse_expected_bounties('{"program-a":"750.50"}') == {
        "program-a": Decimal("750.50"),
    }
    assert _parse_expected_bounties("") == {}


@pytest.mark.parametrize("raw", ["[]", "not-json", '{"program":-1}', '{"":"100"}'])
def test_invalid_expected_bounty_configuration_fails_closed(raw):
    with pytest.raises(ValueError):
        _parse_expected_bounties(raw)


def test_hunt_config_normalizes_and_validates_portfolio_inputs():
    config = HuntConfig(expected_bounties={" program ": "100.25"})
    assert config.expected_bounties == {"program": Decimal("100.25")}
    with pytest.raises(ValueError):
        HuntConfig(portfolio_capacity=-1)
    with pytest.raises(ValueError):
        HuntConfig(exploration_fraction=1.1)
