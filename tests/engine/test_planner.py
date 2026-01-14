"""
Unit tests for the planner module.
"""

from unittest.mock import Mock

import pytest

from engine.evidence import EvidenceCollector
from engine.planner import Planner, ScanPlan


class TestScanPlan:
    """Test cases for the ScanPlan class."""

    def test_scanplan_initialization(self):
        """Test that ScanPlan initializes with empty data structures."""
        plan = ScanPlan()
        assert plan.target_probes == {}
        assert plan.fingerprint_providers == {}

    def test_add_target(self, sample_probe):
        """Test adding a target with probes to the plan."""
        plan = ScanPlan()
        target = "192.0.2.1"
        probes = [sample_probe]

        plan.add_target(target, probes)

        assert target in plan.target_probes
        assert plan.target_probes[target] == probes

    def test_get_targets(self, sample_probe):
        """Test retrieving all targets from the plan."""
        plan = ScanPlan()
        targets = ["192.0.2.1", "192.0.2.2"]
        probes = [sample_probe]

        for target in targets:
            plan.add_target(target, probes)

        retrieved_targets = plan.get_targets()
        assert set(retrieved_targets) == set(targets)
        assert len(retrieved_targets) == len(targets)

    def test_get_probes_for_target(self, sample_probe):
        """Test retrieving probes for a specific target."""
        plan = ScanPlan()
        target = "192.0.2.1"
        probes = [sample_probe]

        plan.add_target(target, probes)

        retrieved_probes = plan.get_probes_for_target(target)
        assert retrieved_probes == probes

    def test_get_probes_for_nonexistent_target(self):
        """Test retrieving probes for a target not in the plan."""
        plan = ScanPlan()
        probes = plan.get_probes_for_target("nonexistent.target")
        assert probes == []

    def test_validate_empty_plan(self):
        """Test validation of an empty scan plan."""
        plan = ScanPlan()
        assert plan.validate() is False

    def test_validate_valid_plan(self, sample_probe):
        """Test validation of a valid scan plan."""
        plan = ScanPlan()
        plan.add_target("192.0.2.1", [sample_probe])
        assert plan.validate() is True


class TestPlanner:
    """Test cases for the Planner class."""

    def test_planner_initialization(self):
        """Test that Planner initializes with empty provider list."""
        planner = Planner()
        assert planner.providers == []
        assert planner.evidence_collector is None

    def test_register_provider(self, mock_provider):
        """Test registering a provider with the planner."""
        planner = Planner()
        planner.register_provider(mock_provider)

        assert len(planner.providers) == 1
        assert planner.providers[0] == mock_provider

    def test_select_provider_for_probe_with_registered_provider(
        self, mock_provider, sample_probe
    ):
        """Test selecting a provider for a probe when provider is registered."""
        planner = Planner()
        planner.register_provider(mock_provider)

        selected = planner.select_provider_for_probe(sample_probe)
        assert selected == mock_provider

    def test_select_provider_for_probe_no_providers(self, sample_probe):
        """Test selecting a provider when no providers are registered."""
        planner = Planner()
        selected = planner.select_provider_for_probe(sample_probe)
        assert selected is None

    def test_select_provider_for_probe_with_multiple_providers(self, sample_probe):
        """Test provider selection with multiple registered providers."""
        planner = Planner()

        # Create mock providers with different capabilities
        http_provider = Mock()
        http_provider.can_handle = Mock(return_value=False)  # Can't handle it

        tls_provider = Mock()
        tls_provider.can_handle = Mock(return_value=True)  # Can handle it

        planner.register_provider(http_provider)
        planner.register_provider(tls_provider)

        selected = planner.select_provider_for_probe(sample_probe)
        assert selected == tls_provider
        http_provider.can_handle.assert_called_once_with(sample_probe)
        tls_provider.can_handle.assert_called_once_with(sample_probe)

    def test_create_scan_plan_basic(self, sample_fingerprint, targets, mock_provider):
        """Test creating a basic scan plan."""
        planner = Planner()
        planner.register_provider(mock_provider)

        plan = planner.create_scan_plan(
            targets=targets,
            fingerprint=sample_fingerprint,
            max_probes_per_target=10,
        )

        assert isinstance(plan, ScanPlan)
        assert plan.validate() is True

        # Check all targets are included
        for target in targets:
            assert target in plan.target_probes
            # Should have both HTTP and TLS probes
            assert len(plan.target_probes[target]) == 2

    def test_create_scan_plan_with_max_probes(
        self, sample_fingerprint, targets, mock_provider
    ):
        """Test scan plan creation with max_probes_per_target limit."""
        planner = Planner()
        planner.register_provider(mock_provider)

        plan = planner.create_scan_plan(
            targets=targets[:1],  # Only test one target
            fingerprint=sample_fingerprint,
            max_probes_per_target=1,  # Limit to 1 probe per target
        )

        target = targets[0]
        assert len(plan.target_probes[target]) == 1
        # Should be the first probe (HTTP probe)
        assert plan.target_probes[target][0].protocol == "http"

    def test_create_scan_plan_no_valid_providers(self, sample_fingerprint, targets):
        """Test scan plan creation when no providers can handle probes."""
        planner = Planner()
        # Don't register any providers

        plan = planner.create_scan_plan(
            targets=targets[:1],
            fingerprint=sample_fingerprint,
            max_probes_per_target=10,
        )

        target = targets[0]
        # Plan should be created but with no probes for the target
        assert target not in plan.target_probes

    def test_create_scan_plan_partial_provider_support(
        self, sample_fingerprint, targets
    ):
        """Test scan plan when provider only supports some probe types."""
        planner = Planner()

        # Create a provider that only supports HTTP
        http_only_provider = Mock()
        http_only_provider.can_handle = Mock(
            side_effect=lambda probe: probe.protocol == "http"
        )

        planner.register_provider(http_only_provider)

        plan = planner.create_scan_plan(
            targets=targets[:1],
            fingerprint=sample_fingerprint,
            max_probes_per_target=10,
        )

        target = targets[0]
        # Should only have HTTP probes (not TLS)
        probes = plan.target_probes[target]
        assert len(probes) == 1
        assert all(p.protocol == "http" for p in probes)

    def test_estimate_scan_time_static_method(self, sample_scan_plan):
        """Test the static method for estimating scan time."""
        estimated_time = Planner.estimate_scan_time(
            sample_scan_plan, provider_delay=0.5
        )

        # Calculate expected: 3 targets × 2 probes each × 0.5 seconds
        expected_time = 3 * 2 * 0.5
        assert estimated_time == expected_time

    def test_estimate_scan_time_with_empty_plan(self):
        """Test scan time estimation with an empty plan."""
        empty_plan = ScanPlan()
        estimated_time = Planner.estimate_scan_time(empty_plan)
        assert estimated_time == 0.0

    def test_optimize_plan(self, sample_scan_plan, mock_provider):
        """Test plan optimization."""
        planner = Planner()
        planner.register_provider(mock_provider)

        optimized_plan = planner.optimize_plan(sample_scan_plan)

        assert isinstance(optimized_plan, ScanPlan)
        assert optimized_plan.validate() is True

        # Original and optimized should have same number of targets and probes
        original_targets = sample_scan_plan.get_targets()
        optimized_targets = optimized_plan.get_targets()
        assert set(original_targets) == set(optimized_targets)

        for target in original_targets:
            original_probes = sample_scan_plan.get_probes_for_target(target)
            optimized_probes = optimized_plan.get_probes_for_target(target)
            assert len(original_probes) == len(optimized_probes)

    def test_optimize_plan_with_unhandled_probes(self, sample_fingerprint):
        """Test optimization when some probes can't be handled."""
        planner = Planner()
        # Don't register any providers

        plan = ScanPlan()
        targets = ["192.0.2.1"]
        for target in targets:
            plan.add_target(target, sample_fingerprint.probes)

        optimized_plan = planner.optimize_plan(plan)

        # Since no providers, optimized plan should have no probes
        for target in targets:
            assert len(optimized_plan.get_probes_for_target(target)) == 0

    def test_execute_plan_basic(self, sample_scan_plan, mock_provider):
        """Test basic plan execution."""
        planner = Planner()
        planner.register_provider(mock_provider)

        # Create evidence collector inline (Option 3)
        evidence_collector = EvidenceCollector()

        results = planner.execute_plan(sample_scan_plan, evidence_collector)

        assert isinstance(results, dict)
        assert len(results) == len(sample_scan_plan.get_targets())

        for target, probe_results in results.items():
            assert target in sample_scan_plan.get_targets()
            assert isinstance(probe_results, list)
            # Should have results for both probes per target
            assert len(probe_results) == 2

            for probe, result in probe_results:
                assert isinstance(
                    probe, type(sample_scan_plan.get_probes_for_target(target)[0])
                )
                assert isinstance(result, dict)
                assert "success" in result

    def test_execute_plan_invalid_plan(self):
        """Test executing an invalid (empty) plan."""
        planner = Planner()
        empty_plan = ScanPlan()

        # Create evidence collector inline (Option 3)
        evidence_collector = EvidenceCollector()

        results = planner.execute_plan(empty_plan, evidence_collector)
        assert results == {}

    def test_execute_plan_with_failing_provider(self, sample_scan_plan):
        """Test plan execution when provider fails."""
        planner = Planner()

        # Create evidence collector inline (Option 3)
        evidence_collector = EvidenceCollector()

        # Create a failing provider
        failing_provider = Mock()
        failing_provider.can_handle = Mock(return_value=True)
        failing_provider.query = Mock(side_effect=Exception("Provider failure"))

        planner.register_provider(failing_provider)

        results = planner.execute_plan(sample_scan_plan, evidence_collector)

        # Should still return results structure, but with error evidence
        assert isinstance(results, dict)
        assert len(results) == len(sample_scan_plan.get_targets())

    def test_execute_plan_no_provider_available(self, sample_scan_plan):
        """Test plan execution when no provider is available for probes."""
        planner = Planner()
        # Don't register any providers

        # Create evidence collector inline (Option 3)
        evidence_collector = EvidenceCollector()

        # Execute plan - returns dict with empty lists for each target
        results = planner.execute_plan(sample_scan_plan, evidence_collector)

        # Should return results structure with empty lists for each target
        assert results == {
            "192.0.2.1": [],
            "192.0.2.2": [],
            "192.0.2.3": [],
        }
        # Or test the structure generically:
        assert isinstance(results, dict)
        assert len(results) == len(sample_scan_plan.get_targets())
        for target_list in results.values():
            assert target_list == []

    def test_execute_plan_evidence_collection(self, sample_scan_plan, mock_provider):
        """Test that evidence is properly collected during plan execution."""
        planner = Planner()
        planner.register_provider(mock_provider)

        # Create evidence collector inline (Option 3)
        evidence_collector = EvidenceCollector()

        _results = planner.execute_plan(sample_scan_plan, evidence_collector)

        # Check evidence was collected
        assert len(evidence_collector.evidence_list) > 0

    def test_execute_plan_mixed_success(self, sample_fingerprint):
        """Test plan execution with mixed success/failure results."""
        planner = Planner()

        # Create evidence collector inline (Option 3)
        evidence_collector = EvidenceCollector()

        # Create a mock provider that sometimes fails
        mixed_provider = Mock()
        call_count = {"count": 0}

        def mock_query(target, probe):
            """Mock query that actually uses the parameters."""
            call_count["count"] += 1
            if call_count["count"] % 2 == 0:  # Every other call fails
                return {
                    "success": False,
                    "data": None,
                    "error": f"Mock failure for {probe.name} on {target}",
                }
            else:
                return {
                    "success": True,
                    "data": {
                        "items": [{"data": {"target": target, "probe": probe.name}}]
                    },
                    "error": None,
                }

        mixed_provider.can_handle = Mock(return_value=True)
        mixed_provider.query = Mock(side_effect=mock_query)

        planner.register_provider(mixed_provider)

        # Create a simple plan
        plan = ScanPlan()
        target = "192.0.2.1"
        plan.add_target(target, sample_fingerprint.probes)

        results = planner.execute_plan(plan, evidence_collector)

        # Should have results even with failures
        assert target in results
        assert len(results[target]) == 2  # Both probes attempted

        # Verify the mock was called with correct parameters
        assert mixed_provider.query.call_count == 2
        # Check first call parameters
        first_call_args = mixed_provider.query.call_args_list[0]
        assert first_call_args[0][0] == target  # target parameter
        assert first_call_args[0][1].name in [
            "http_server_header",
            "tls_certificate",
        ]  # probe name


class TestEvidenceCollection:
    """Tests for evidence collection functionality."""

    def test_empty_evidence_collector_fixture(self, empty_evidence_collector):
        """Test that the empty_evidence_collector fixture is usable."""
        assert empty_evidence_collector is not None
        assert isinstance(empty_evidence_collector, EvidenceCollector)
        assert len(empty_evidence_collector.evidence_list) == 0

    def test_evidence_integration(
        self, sample_scan_plan, mock_provider, empty_evidence_collector
    ):
        """Test full integration with evidence collection."""
        planner = Planner()
        planner.register_provider(mock_provider)

        # Use the fixture
        results = planner.execute_plan(sample_scan_plan, empty_evidence_collector)

        # Verify both results and evidence
        assert len(results) == len(sample_scan_plan.get_targets())
        assert (
            len(empty_evidence_collector.evidence_list) == len(results) * 2
        )  # 2 probes per target

        # Check evidence content
        for evidence in empty_evidence_collector.evidence_list:
            assert evidence.target in sample_scan_plan.get_targets()
            assert evidence.probe_name in ["http_server_header", "tls_certificate"]


@pytest.mark.unit
class TestIntegrationWithFixtures:
    """Integration tests using conftest fixtures."""

    def test_full_workflow_with_fixtures(
        self, sample_fingerprint, targets, mock_provider
    ):
        """Test the full planner workflow using fixtures."""
        planner = Planner()
        planner.register_provider(mock_provider)

        # Create evidence collector inline (Option 3)
        evidence_collector = EvidenceCollector()

        # 1. Create scan plan
        plan = planner.create_scan_plan(
            targets=targets,
            fingerprint=sample_fingerprint,
            max_probes_per_target=10,
        )
        assert plan.validate() is True

        # 2. Estimate scan time
        estimated_time = Planner.estimate_scan_time(plan, provider_delay=0.1)
        assert estimated_time > 0

        # 3. Optimize plan
        optimized_plan = planner.optimize_plan(plan)
        assert optimized_plan.validate() is True

        # 4. Execute plan
        results = planner.execute_plan(optimized_plan, evidence_collector)
        assert len(results) == len(targets)

        # 5. Verify mock provider was called
        assert (
            len(mock_provider.queries_made) == len(targets) * 2
        )  # 2 probes per target

    def test_scan_plan_fixture(self, sample_scan_plan):
        """Test that the sample_scan_plan fixture works correctly."""
        assert isinstance(sample_scan_plan, ScanPlan)
        assert sample_scan_plan.validate() is True

        targets = sample_scan_plan.get_targets()
        assert len(targets) == 3

        for target in targets:
            probes = sample_scan_plan.get_probes_for_target(target)
            assert len(probes) == 2  # HTTP and TLS probes
            assert {p.protocol for p in probes} == {"http", "tls"}
