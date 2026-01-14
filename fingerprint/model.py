from dataclasses import dataclass


@dataclass
class Probe:
    """Represents a single check against a target."""

    name: str
    protocol: str  # e.g., 'http', 'tls'
    field: str  # e.g., 'headers.server'
    match_type: str  # 'exact', 'regex', 'contains'
    value: str  # The value to match against


@dataclass
class Fingerprint:
    """A complete fingerprint specification."""

    fingerprint_id: str
    name: str
    version: str
    probes: list[Probe]
    match_logic: str  # e.g., 'all', 'any', custom expression
