"""
Planning and orchestration of fingerprint evaluation.
"""

import logging
from collections import defaultdict

from fingerprint.model import Fingerprint, Probe
from providers.base import BaseProvider

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanPlan:
    """Represents a plan for scanning targets with fingerprints."""

    def __init__(self):
        self.target_probes: dict[str, list[Probe]] = defaultdict(list)
        self.fingerprint_providers: dict[str, list[type[BaseProvider]]] = {}

    def add_target(self, target: str, probes: list[Probe]) -> None:
        """Add a target with its probes to the plan."""
        self.target_probes[target] = probes

    def get_targets(self) -> list[str]:
        """Get all targets in the plan."""
        return list(self.target_probes.keys())

    def get_probes_for_target(self, target: str) -> list[Probe]:
        """Get probes for a specific target."""
        return self.target_probes.get(target, [])

    def validate(self) -> bool:
        """Validate the scan plan."""
        if not self.target_probes:
            logger.warning("Scan plan has no targets")
            return False

        total_probes = sum(len(probes) for probes in self.target_probes.values())
        logger.info(
            f"Scan plan validated: {len(self.target_probes)} targets, {total_probes} total probes"
        )
        return True


class Planner:
    """Plans and orchestrates fingerprint scanning operations."""

    def __init__(self):
        self.providers: list[BaseProvider] = []
        self.evidence_collector = None

    def register_provider(self, provider: BaseProvider) -> None:
        """Register a data provider with the planner."""
        self.providers.append(provider)
        logger.info(f"Registered provider: {provider.__class__.__name__}")

    def create_scan_plan(
        self,
        targets: list[str],
        fingerprint: Fingerprint,
        max_probes_per_target: int = 10,
    ) -> ScanPlan:
        """
        Create a scan plan for evaluating fingerprints against targets.

        Args:
            targets: List of target addresses to scan
            fingerprint: Fingerprint specification to evaluate
            max_probes_per_target: Maximum number of probes to run per target

        Returns:
            ScanPlan object containing the scanning strategy
        """
        plan = ScanPlan()

        # For each target, select probes that can be handled by available providers
        for target in targets:
            valid_probes = []

            for probe in fingerprint.probes[:max_probes_per_target]:
                # Check if any provider can handle this probe
                if any(provider.can_handle(probe) for provider in self.providers):
                    valid_probes.append(probe)
                else:
                    logger.warning(
                        f"No provider can handle probe '{probe.name}' for target {target}"
                    )

            if valid_probes:
                plan.add_target(target, valid_probes)
            else:
                logger.warning(f"No valid probes for target {target}")

        return plan

    def select_provider_for_probe(self, probe: Probe) -> BaseProvider | None:
        """
        Select the most appropriate provider for a given probe.

        Returns the first provider that can handle the probe,
        or None if no provider is available.
        """
        for provider in self.providers:
            if provider.can_handle(probe):
                return provider

        logger.warning(
            f"No provider available for probe '{probe.name}' (protocol: {probe.protocol})"
        )
        return None

    @staticmethod
    def estimate_scan_time(plan: ScanPlan, provider_delay: float = 1.0) -> float:
        """
        Estimate total scan time based on the plan.

        Args:
            plan: ScanPlan to estimate
            provider_delay: Delay between provider requests in seconds

        Returns:
            Estimated scan time in seconds
        """
        total_probes = sum(len(probes) for probes in plan.target_probes.values())
        estimated_time = total_probes * provider_delay

        logger.info(
            f"Estimated scan time: {estimated_time:.1f}s for {total_probes} probes"
        )
        return estimated_time

    def optimize_plan(self, plan: ScanPlan) -> ScanPlan:
        """
        Optimize the scan plan for efficiency.

        Currently groups probes by provider to minimize context switching.
        """
        optimized_plan = ScanPlan()

        for target, probes in plan.target_probes.items():
            # Group probes by the provider that can handle them
            provider_probes: dict[BaseProvider, list[Probe]] = defaultdict(list)

            for probe in probes:
                provider = self.select_provider_for_probe(probe)
                if provider:
                    provider_probes[provider].append(probe)

            # Reorder probes: run all probes for a provider before moving to next
            optimized_probes = []
            for (
                _provider,
                probe_list,
            ) in provider_probes.items():  # Fixed: unused variable
                optimized_probes.extend(probe_list)

            if optimized_probes:
                optimized_plan.add_target(target, optimized_probes)

        original_count = sum(len(p) for p in plan.target_probes.values())
        optimized_count = sum(len(p) for p in optimized_plan.target_probes.values())

        if original_count != optimized_count:
            logger.warning(
                f"Optimization lost {original_count - optimized_count} probes"
            )

        return optimized_plan

    def execute_plan(
        self, plan: ScanPlan, evidence_collector
    ) -> dict[str, list[tuple[Probe, dict]]]:
        """
        Execute a scan plan and collect results.

        Args:
            plan: ScanPlan to execute
            evidence_collector: EvidenceCollector to record results

        Returns:
            Dictionary mapping targets to list of (probe, result) tuples
        """
        if not plan.validate():
            logger.error("Cannot execute invalid scan plan")
            return {}

        self.evidence_collector = evidence_collector
        results: dict[str, list[tuple[Probe, dict]]] = {}

        for target in plan.get_targets():
            target_results = []
            probes = plan.get_probes_for_target(target)

            logger.info(f"Scanning target {target} with {len(probes)} probes")

            for probe in probes:
                provider = self.select_provider_for_probe(probe)
                if not provider:
                    # Create evidence for failed probe
                    evidence_collector.add_probe_result(
                        probe_name=probe.name,
                        target=target,
                        success=False,
                        match=False,
                        error_message="No provider available",
                    )
                    continue

                try:
                    # Execute the probe
                    result = provider.query(target, probe)

                    # Record evidence
                    evidence_collector.add_probe_result(
                        probe_name=probe.name,
                        target=target,
                        success=result.get("success", False),
                        match=False,  # Will be evaluated later
                        expected_value=probe.value,
                        actual_value="",  # Will be extracted during evaluation
                        raw_data=result.get("data", {}),
                    )

                    target_results.append((probe, result))

                    if result.get("success"):
                        logger.debug(f"  Probe '{probe.name}' completed successfully")
                    else:
                        logger.warning(
                            f"  Probe '{probe.name}' failed: {result.get('error')}"
                        )

                except Exception as e:
                    logger.error(f"  Probe '{probe.name}' exception: {e}")
                    evidence_collector.add_probe_result(
                        probe_name=probe.name,
                        target=target,
                        success=False,
                        match=False,
                        error_message=str(e),
                    )

            results[target] = target_results

        logger.info(f"Scan plan execution complete: {len(results)} targets processed")
        return results
