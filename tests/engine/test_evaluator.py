import pytest

from engine.evaluator import Evaluator
from fingerprint.model import Fingerprint, Probe

# ==================== TESTS: evaluate_probe ====================


@pytest.mark.parametrize(
    "field_value, match_type, probe_value, expected",
    [
        ("Apache/2.4.41", "exact", "Apache/2.4.41", True),
        ("Apache/2.4.41", "exact", "Apache/2.4.42", False),
        ("Apache/2.4.41", "contains", "Apache", True),
        ("Apache/2.4.41", "contains", "Nginx", False),
        ("Apache/2.4.41", "regex", r"Apache/\d+\.\d+\.\d+", True),
        ("Apache/2.4.41", "regex", r"Nginx/\d+\.\d+", False),
    ],
)
def test_evaluate_probe_success(field_value, match_type, probe_value, expected):
    probe = Probe(
        name="test_probe",
        protocol="http",
        field="headers.server",
        match_type=match_type,
        value=probe_value,
    )

    probe_result = {
        "success": True,
        "data": {"items": [{"data": {"http": {"head": {"server": field_value}}}}]},
    }

    match, evidence = Evaluator.evaluate_probe(probe_result, probe)
    assert match == expected
    assert "headers.server=" in evidence


def test_evaluate_probe_failure():
    probe = Probe(
        name="test_probe",
        protocol="http",
        field="headers.server",
        match_type="exact",
        value="Apache/2.4.41",
    )

    probe_result = {"success": False, "error": "Timeout"}

    match, evidence = Evaluator.evaluate_probe(probe_result, probe)
    assert match is False
    assert "Probe failed: Timeout" == evidence


def test_evaluate_probe_field_missing():
    probe = Probe(
        name="test_probe",
        protocol="http",
        field="headers.server",
        match_type="exact",
        value="Apache/2.4.41",
    )

    probe_result = {"success": True, "data": {}}

    match, evidence = Evaluator.evaluate_probe(probe_result, probe)
    assert match is False
    assert evidence == "Field not found in response"


def test_evaluate_probe_unknown_match_type():
    probe = Probe(
        name="test_probe",
        protocol="http",
        field="headers.server",
        match_type="unknown",
        value="Apache/2.4.41",
    )

    probe_result = {
        "success": True,
        "data": {"items": [{"data": {"http": {"head": {"server": "Apache/2.4.41"}}}}]},
    }

    match, evidence = Evaluator.evaluate_probe(probe_result, probe)
    assert match is False
    assert evidence == "Unknown match type: unknown"


# ==================== TESTS: evaluate_fingerprint ====================


def test_evaluate_fingerprint_all_match():
    probes = [
        Probe(
            name="http_probe",
            protocol="http",
            field="headers.server",
            match_type="contains",
            value="Apache",
        ),
        Probe(
            name="tls_probe",
            protocol="tls",
            field="certificate.serial",
            match_type="exact",
            value="1234567890ABCDEF",
        ),
    ]

    fingerprint = Fingerprint(
        fingerprint_id="fp-001",
        name="Test Fingerprint",
        version="1.0",
        probes=probes,
        match_logic="all",
    )

    probe_results = []
    for probe in fingerprint.probes:
        if probe.protocol == "http":
            result = {
                "success": True,
                "data": {
                    "items": [{"data": {"http": {"head": {"server": "Apache/2.4.41"}}}}]
                },
            }
        elif probe.protocol == "tls":
            result = {
                "success": True,
                "data": {
                    "items": [{"data": {"certificate": {"serial": "1234567890ABCDEF"}}}]
                },
            }
        else:
            raise ValueError(f"Unsupported probe protocol in test: {probe.protocol}")
        probe_results.append((probe, result))

    evaluation = Evaluator.evaluate_fingerprint(probe_results, fingerprint)
    assert evaluation["overall_match"] is True
    assert set(evaluation["matched_probes"]) == {"http_probe", "tls_probe"}


def test_evaluate_fingerprint_any_match():
    probes = [
        Probe(
            name="http_probe",
            protocol="http",
            field="headers.server",
            match_type="exact",
            value="Apache/2.4.41",
        ),
        Probe(
            name="tls_probe",
            protocol="tls",
            field="certificate.serial",
            match_type="exact",
            value="0000",
        ),
    ]

    fingerprint = Fingerprint(
        fingerprint_id="fp-002",
        name="Test Fingerprint Any",
        version="1.0",
        probes=probes,
        match_logic="any",
    )

    probe_results = []
    for probe in fingerprint.probes:
        if probe.protocol == "http":
            result = {
                "success": True,
                "data": {
                    "items": [{"data": {"http": {"head": {"server": "Apache/2.4.41"}}}}]
                },
            }
        elif probe.protocol == "tls":
            result = {
                "success": True,
                "data": {
                    "items": [{"data": {"certificate": {"serial": "1234567890ABCDEF"}}}]
                },
            }
        else:
            raise ValueError(f"Unsupported probe protocol in test: {probe.protocol}")
        probe_results.append((probe, result))

    evaluation = Evaluator.evaluate_fingerprint(probe_results, fingerprint)
    assert evaluation["overall_match"] is True
    assert "http_probe" in evaluation["matched_probes"]
