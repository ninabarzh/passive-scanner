import json

import pytest

from engine.evidence import Evidence, EvidenceCollector

# ==================== EVIDENCE CLASS ====================


def test_evidence_to_dict_and_hash_and_summary():
    raw = {"key": "value"}
    e = Evidence(
        probe_name="test_probe",
        target="192.0.2.1",
        success=True,
        match=True,
        expected_value="Apache",
        actual_value="Apache/2.4",
        raw_data=raw,
    )

    d = e.to_dict()
    # Check fields exist
    assert d["probe_name"] == "test_probe"
    assert d["target"] == "192.0.2.1"
    assert "timestamp" in d
    assert d["expected_value"] == "Apache"
    assert d["actual_value"] == "Apache/2.4"
    assert d["raw_data_hash"] == e.raw_data_hash()
    assert "Matched 'Apache' found as 'Apache/2.4'" in d["summary"]

    # raw_data_hash consistency
    hash1 = e.raw_data_hash()
    hash2 = e.raw_data_hash()
    assert hash1 == hash2
    assert len(hash1) == 16


def test_evidence_summary_failed_and_no_match():
    e_fail = Evidence(
        probe_name="p", target="t", success=False, error_message="timeout"
    )
    assert e_fail.summary() == "Failed: timeout"

    e_nomatch = Evidence(
        probe_name="p",
        target="t",
        success=True,
        match=False,
        expected_value="Apache",
        actual_value="Nginx",
    )
    assert "No match: expected 'Apache', got 'Nginx'" == e_nomatch.summary()


# ==================== EVIDENCE COLLECTOR ====================


@pytest.fixture
def collector():
    return EvidenceCollector()


def test_add_evidence_and_get_methods(collector):
    e1 = Evidence(probe_name="p1", target="t1", success=True, match=True)
    e2 = Evidence(probe_name="p2", target="t1", success=False, match=False)
    e3 = Evidence(probe_name="p3", target="t2", success=True, match=False)

    collector.add_evidence(e1)
    collector.add_evidence(e2)
    collector.add_evidence(e3)

    # get_evidence_for_target
    t1_evidence = collector.get_evidence_for_target("t1")
    assert e1 in t1_evidence
    assert e2 in t1_evidence
    assert e3 not in t1_evidence

    # get_failed_probes
    failed = collector.get_failed_probes()
    assert e2 in failed
    assert e1 not in failed
    assert e3 not in failed

    # get_matching_probes
    matched = collector.get_matching_probes()
    assert e1 in matched
    assert e2 not in matched
    assert e3 not in matched


def test_add_probe_result_creates_and_adds(collector):
    e = collector.add_probe_result(
        probe_name="p",
        target="t",
        success=True,
        match=True,
        expected_value="Apache",
        actual_value="Apache/2.4",
        error_message="",
        raw_data={"k": "v"},
    )
    assert e in collector.evidence_list
    assert e.expected_value == "Apache"
    assert e.actual_value == "Apache/2.4"
    assert e.raw_data["k"] == "v"


def test_to_json_and_clear(collector):
    collector.add_probe_result(probe_name="p1", target="t1", success=True, match=True)
    collector.add_probe_result(probe_name="p2", target="t2", success=False, match=False)

    json_str = collector.to_json()
    data = json.loads(json_str)
    assert isinstance(data, list)
    assert len(data) == 2
    assert all("probe_name" in d for d in data)

    collector.clear()
    assert collector.evidence_list == []
