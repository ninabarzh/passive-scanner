"""
Evidence collection and management for fingerprint evaluations.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Evidence:
    """Represents evidence collected from a probe evaluation."""

    probe_name: str
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = False
    match: bool = False
    expected_value: str = ""
    actual_value: str = ""
    error_message: str = ""
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert evidence to dictionary representation."""
        return {
            "probe_name": self.probe_name,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "match": self.match,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "error_message": self.error_message,
            "raw_data_hash": self.raw_data_hash(),
            "summary": self.summary(),
        }

    def raw_data_hash(self) -> str:
        """Generate a hash of the raw data for deduplication."""
        if not self.raw_data:
            return ""
        data_str = json.dumps(self.raw_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]

    def summary(self) -> str:
        """Generate a human-readable summary of the evidence."""
        if not self.success:
            return f"Failed: {self.error_message}"

        if self.match:
            return f"Matched '{self.expected_value}' found as '{self.actual_value}'"
        else:
            return (
                f"No match: expected '{self.expected_value}', got '{self.actual_value}'"
            )


class EvidenceCollector:
    """Collects and manages evidence from multiple probes."""

    def __init__(self):
        self.evidence_list: list[Evidence] = []

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to the collection."""
        self.evidence_list.append(evidence)

    def add_probe_result(
        self,
        probe_name: str,
        target: str,
        success: bool,
        match: bool,
        expected_value: str = "",
        actual_value: str = "",
        error_message: str = "",
        raw_data: dict | None = None,
    ) -> Evidence:
        """Convenience method to create and add evidence from probe results."""
        evidence = Evidence(
            probe_name=probe_name,
            target=target,
            success=success,
            match=match,
            expected_value=expected_value,
            actual_value=actual_value,
            error_message=error_message,
            raw_data=raw_data or {},
        )
        self.add_evidence(evidence)
        return evidence

    def get_evidence_for_target(self, target: str) -> list[Evidence]:
        """Get all evidence for a specific target."""
        return [e for e in self.evidence_list if e.target == target]

    def get_failed_probes(self) -> list[Evidence]:
        """Get all evidence from failed probes."""
        return [e for e in self.evidence_list if not e.success]

    def get_matching_probes(self) -> list[Evidence]:
        """Get all evidence from probes that matched."""
        return [e for e in self.evidence_list if e.success and e.match]

    def to_json(self) -> str:
        """Serialize all evidence to JSON."""
        evidence_dicts = [e.to_dict() for e in self.evidence_list]
        return json.dumps(evidence_dicts, indent=2)

    def clear(self) -> None:
        """Clear all collected evidence."""
        self.evidence_list.clear()
