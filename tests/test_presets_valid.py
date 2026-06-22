"""Every bundled preset must pass installer validation."""
from __future__ import annotations

from pathlib import Path

import pytest

from installer.config import validate_preset_toml

PRESETS_DIR = Path(__file__).resolve().parent.parent / "presets"


def _preset_files() -> list[Path]:
    return sorted(PRESETS_DIR.glob("*.toml"))


def test_presets_dir_is_present_and_nonempty():
    assert PRESETS_DIR.is_dir()
    assert _preset_files(), "no bundled presets found"


@pytest.mark.parametrize("preset", _preset_files(), ids=lambda p: p.name)
def test_bundled_preset_validates(preset: Path):
    data = validate_preset_toml(preset)
    brokers = data["broker"]
    assert isinstance(brokers, list) and brokers
    for broker in brokers:
        assert broker.get("name"), f"{preset.name}: broker missing name"


def test_preset_broker_names_have_no_dots():
    """Broker names follow the hyphenated/lowercase convention (no dots)."""
    offenders = []
    for preset in _preset_files():
        for broker in validate_preset_toml(preset)["broker"]:
            name = broker.get("name", "")
            if "." in name:
                offenders.append(f"{preset.name}:{name}")
    assert not offenders, f"preset broker names contain dots: {offenders}"
