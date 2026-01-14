import re

from fingerprint.model import Fingerprint, Probe


class Evaluator:
    """Evaluates probe results against fingerprint logic."""

    @staticmethod
    def evaluate_probe(probe_result: dict, probe: Probe) -> tuple[bool, str]:
        """
        Evaluate a single probe result.
        Returns (is_match, evidence_string)
        """
        if not probe_result.get("success", False):
            return False, f"Probe failed: {probe_result.get('error', 'Unknown error')}"

        data = probe_result.get("data", {})

        # Extract the field value from Netlas response
        field_value = None
        if "items" in data and len(data["items"]) > 0:
            item = data["items"][0]
            # Minimal extraction based on probe.field
            if probe.field == "headers.server":
                field_value = (
                    item.get("data", {}).get("http", {}).get("head", {}).get("server")
                )
            elif probe.field == "certificate.serial":
                field_value = item.get("data", {}).get("certificate", {}).get("serial")

        if field_value is None:
            return False, "Field not found in response"

        # Apply match logic
        if probe.match_type == "exact":
            match = field_value == probe.value
        elif probe.match_type == "contains":
            match = probe.value in field_value
        elif probe.match_type == "regex":
            match = bool(re.search(probe.value, field_value))
        else:
            return False, f"Unknown match type: {probe.match_type}"

        evidence = f"{probe.field}={field_value}"
        return match, evidence

    @staticmethod
    def evaluate_fingerprint(
        probe_results: list[tuple[Probe, dict]], fingerprint: Fingerprint
    ) -> dict:
        """
        Evaluate all probe results against fingerprint logic.
        Returns complete evaluation results.
        """
        individual_results = []
        all_evidence = []

        # Evaluate each probe
        for probe, result in probe_results:
            is_match, evidence = Evaluator.evaluate_probe(result, probe)
            individual_results.append(
                {"probe": probe.name, "match": is_match, "evidence": evidence}
            )
            all_evidence.append(evidence)

        # Apply match logic
        if fingerprint.match_logic == "all":
            overall_match = all(r["match"] for r in individual_results)
        elif fingerprint.match_logic == "any":
            overall_match = any(r["match"] for r in individual_results)
        else:
            # For custom logic, you'd parse the expression here
            overall_match = all(r["match"] for r in individual_results)

        return {
            "fingerprint_id": fingerprint.fingerprint_id,
            "overall_match": overall_match,
            "probe_results": individual_results,
            "evidence": "; ".join(all_evidence),
            "matched_probes": [r["probe"] for r in individual_results if r["match"]],
        }
