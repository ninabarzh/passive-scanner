import yaml

from .model import Fingerprint, Probe


def load_fingerprint(filepath: str) -> Fingerprint:
    """Load a fingerprint specification from a YAML file."""
    with open(filepath) as f:
        data = yaml.safe_load(f)

    probes = []
    for probe_data in data.get("probes", []):
        probe = Probe(
            name=probe_data["name"],
            protocol=probe_data["protocol"],
            field=probe_data["field"],
            match_type=probe_data["match_type"],
            value=probe_data["value"],
        )
        probes.append(probe)

    return Fingerprint(
        fingerprint_id=data["id"],
        name=data["name"],
        version=data["version"],
        probes=probes,
        match_logic=data.get("match_logic", "all"),
    )
