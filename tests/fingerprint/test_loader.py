import pytest

from fingerprint.loader import load_fingerprint
from fingerprint.model import Fingerprint, Probe


def test_load_fingerprint_creates_fingerprint(temp_yaml_file, sample_fingerprint_data):
    """Test that a Fingerprint object is correctly created from a YAML file."""
    fp = load_fingerprint(temp_yaml_file)

    # Check top-level fields
    assert isinstance(fp, Fingerprint)
    assert fp.fingerprint_id == sample_fingerprint_data["id"]
    assert fp.name == sample_fingerprint_data["name"]
    assert fp.version == sample_fingerprint_data["version"]
    assert fp.match_logic == sample_fingerprint_data.get("match_logic", "all")

    # Check probes
    assert isinstance(fp.probes, list)
    assert len(fp.probes) == len(sample_fingerprint_data["probes"])
    for probe, expected in zip(
        fp.probes, sample_fingerprint_data["probes"], strict=True
    ):
        assert isinstance(probe, Probe)
        assert probe.name == expected["name"]
        assert probe.protocol == expected["protocol"]
        assert probe.field == expected["field"]
        assert probe.match_type == expected["match_type"]
        assert probe.value == expected["value"]


def test_load_fingerprint_missing_match_logic(temp_yaml_file, sample_fingerprint_data):
    """If match_logic is missing in YAML, default to 'all'."""
    # Remove match_logic from sample data
    sample_fingerprint_data.pop("match_logic", None)

    # Rewrite YAML without match_logic
    import yaml

    with open(temp_yaml_file, "w") as f:
        yaml.dump(sample_fingerprint_data, f)

    fp = load_fingerprint(temp_yaml_file)
    assert fp.match_logic == "all"


def test_load_fingerprint_empty_probes(tmp_path):
    """Test that a fingerprint with no probes still loads correctly."""
    import yaml

    fp_data = {
        "id": "empty-probes",
        "name": "Empty Probes",
        "version": "1.0",
        "probes": [],
    }
    yaml_file = tmp_path / "empty.yaml"
    with open(yaml_file, "w") as f:
        yaml.dump(fp_data, f)

    fp = load_fingerprint(str(yaml_file))
    assert isinstance(fp, Fingerprint)
    assert fp.probes == []
