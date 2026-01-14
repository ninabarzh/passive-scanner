"""
Test configuration and shared fixtures for the Anvil Forge Scanner.
"""

import os

# Add project root to Python path for imports
import sys
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.evidence import Evidence, EvidenceCollector
from engine.planner import ScanPlan
from fingerprint.model import Fingerprint, Probe

# ==================== FIXTURES: TEST DATA ====================


@pytest.fixture
def sample_probe_data() -> dict:
    """Sample probe data for testing."""
    return {
        "name": "http_server_test",
        "protocol": "http",
        "field": "headers.server",
        "match_type": "contains",
        "value": "Apache/2.4",
    }


@pytest.fixture
def sample_fingerprint_data() -> dict:
    """Sample fingerprint data for testing."""
    return {
        "id": "test-fp-001",
        "name": "Test Apache Server",
        "version": "1.0",
        "match_logic": "all",
        "probes": [
            {
                "name": "http_server_header",
                "protocol": "http",
                "field": "headers.server",
                "match_type": "contains",
                "value": "Apache",
            },
            {
                "name": "tls_certificate",
                "protocol": "tls",
                "field": "certificate.serial",
                "match_type": "exact",
                "value": "1234567890ABCDEF",
            },
        ],
    }


@pytest.fixture
def sample_netlas_response() -> dict:
    """Mock Netlas API response for testing."""
    return {
        "items": [
            {
                "data": {
                    "http": {"headers": {"server": "Apache/2.4.41 (Ubuntu)"}},
                    "certificate": {"serial": "1234567890ABCDEF"},
                },
                "ip": "192.0.2.1",
                "port": 80,
                "protocol": "http",
            }
        ],
        "items_count": 1,
        "total_count": 1,
        "took_ms": 15,
    }


@pytest.fixture
def targets() -> list[str]:
    """List of sample targets for planner tests."""
    return ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


@pytest.fixture
def sample_probe_tls() -> Probe:
    """A sample TLS probe."""
    return Probe(
        name="tls_cert_probe",
        protocol="tls",
        field="certificate.serial",
        match_type="exact",
        value="1234567890ABCDEF",
    )


# ==================== FIXTURES: OBJECTS ====================


@pytest.fixture
def sample_probe(sample_probe_data) -> Probe:
    """Create a Probe object from sample data."""
    return Probe(**sample_probe_data)


@pytest.fixture
def sample_fingerprint(sample_fingerprint_data) -> Fingerprint:
    """Create a Fingerprint object from sample data."""
    probes = [Probe(**probe_data) for probe_data in sample_fingerprint_data["probes"]]
    return Fingerprint(
        fingerprint_id=sample_fingerprint_data["id"],
        name=sample_fingerprint_data["name"],
        version=sample_fingerprint_data["version"],
        probes=probes,
        match_logic=sample_fingerprint_data["match_logic"],
    )


@pytest.fixture
def empty_evidence_collector() -> EvidenceCollector:
    """Create an empty EvidenceCollector."""
    return EvidenceCollector()


@pytest.fixture
def sample_evidence() -> Evidence:
    """Create sample Evidence object."""
    return Evidence(
        probe_name="test_probe",
        target="192.0.2.1",
        success=True,
        match=True,
        expected_value="Apache",
        actual_value="Apache/2.4.41",
        raw_data={"test": "data"},
    )


# ==================== FIXTURES: FILES ====================


@pytest.fixture
def temp_yaml_file(sample_fingerprint_data) -> Generator[str, None, None]:
    """Create a temporary YAML file with fingerprint data."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(sample_fingerprint_data, f)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_targets_file() -> Generator[str, None, None]:
    """Create a temporary file with test targets."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("192.0.2.1\n192.0.2.2\n192.0.2.3\n")
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_results_file() -> Generator[str, None, None]:
    """Create a temporary results file path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


# ==================== FIXTURES: PLANNER & SCAN ====================


@pytest.fixture
def sample_scan_plan(sample_fingerprint) -> ScanPlan:
    """Create a sample ScanPlan for testing."""
    plan = ScanPlan()
    targets = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]

    for target in targets:
        plan.add_target(target, sample_fingerprint.probes)

    return plan


@pytest.fixture
def mock_provider():
    """Mock provider for testing that actually uses parameters."""

    class MockProvider:
        def __init__(self):
            self.api_key = "test-key"
            self.rate_limit_delay = 0.1
            self.queries_made = []

        @staticmethod
        def can_handle(probe: Probe) -> bool:
            """Check if provider can handle this probe type."""
            return probe.protocol in ["http", "tls"]

        def query(self, target: str, probe: Probe) -> dict:
            """Mock query that uses the parameters."""
            self.queries_made.append({"target": target, "probe": probe.name})

            # Return different responses based on probe type
            if probe.protocol == "http":
                return {
                    "success": True,
                    "data": {
                        "items": [
                            {"data": {"http": {"head": {"server": "Apache/2.4.41"}}}}
                        ]
                    },
                    "error": None,
                }
            elif probe.protocol == "tls":
                return {
                    "success": True,
                    "data": {
                        "items": [
                            {"data": {"certificate": {"serial": "1234567890ABCDEF"}}}
                        ]
                    },
                    "error": None,
                }
            else:
                return {
                    "success": False,
                    "data": None,
                    "error": f"Unsupported protocol: {probe.protocol}",
                }

    return MockProvider()


# ==================== CONFIGURATION ====================


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (requires external services)",
    )
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line(
        "markers", "unit: mark test as unit test (fast, no external dependencies)"
    )


# ==================== HELPER FUNCTIONS ====================


@pytest.fixture
def create_test_fingerprint() -> Generator:
    """Factory fixture to create fingerprints with custom parameters."""

    def _create_fingerprint(
        fingerprint_id: str = "test-id",
        match_logic: str = "all",
        probes: list[Probe] | None = None,
    ) -> Fingerprint:
        if probes is None:
            probes = [
                Probe(
                    name="default_probe",
                    protocol="http",
                    field="headers.server",
                    match_type="contains",
                    value="test",
                )
            ]

        return Fingerprint(
            fingerprint_id=fingerprint_id,
            name="Test Fingerprint",
            version="1.0",
            probes=probes,
            match_logic=match_logic,
        )

    yield _create_fingerprint


@pytest.fixture
def create_test_probe() -> Generator:
    """Factory fixture to create probes with custom parameters."""

    def _create_probe(
        name: str = "test_probe",
        protocol: str = "http",
        field: str = "headers.server",
        match_type: str = "contains",
        value: str = "test",
    ) -> Probe:
        return Probe(
            name=name,
            protocol=protocol,
            field=field,
            match_type=match_type,
            value=value,
        )

    yield _create_probe


# ==================== ENVIRONMENT ====================


@pytest.fixture(autouse=True)
def clean_env() -> Generator[None, None, None]:
    """Clean environment variables before each test."""
    original_env = os.environ.copy()

    # Remove any test environment variables
    for key in list(os.environ.keys()):
        if key.startswith("TEST_") or key == "NETLAS_API_KEY":
            del os.environ[key]

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)
