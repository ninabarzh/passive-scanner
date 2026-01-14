#!/usr/bin/env python3
import os

from dotenv import load_dotenv

from engine.evaluator import Evaluator
from fingerprint.loader import load_fingerprint
from providers.netlas import NetlasProvider

# Load environment variables from .env file
load_dotenv()

# Get the API key
NETLAS_API_KEY = os.getenv("NETLAS_API_KEY")
if not NETLAS_API_KEY:
    raise ValueError("❌ NETLAS_API_KEY not found in .env file")


def load_targets(filepath: str) -> list[str]:
    """Load targets from a file (one per line)."""
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip()]


def save_results(results: list[dict], filepath: str):
    """Save results to a JSON file."""
    import json

    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)


def main():
    # Configuration
    FINGERPRINT_FILE = "example_fingerprint.yaml"
    TARGETS_FILE = "targets.txt"
    NETLAS_API_KEY = os.getenv("NETLAS_API_KEY", "your_netlas_api_key_here")

    # Load fingerprint
    print(f"Loading fingerprint from {FINGERPRINT_FILE}")
    fingerprint = load_fingerprint(FINGERPRINT_FILE)

    # Load targets
    targets = load_targets(TARGETS_FILE)
    print(f"Loaded {len(targets)} targets")

    # Initialize provider
    provider = NetlasProvider(NETLAS_API_KEY)

    results = []

    # Process each target
    for target in targets:
        print(f"Processing {target}...")
        probe_results = []

        # Run each probe
        for probe in fingerprint.probes:
            if provider.can_handle(probe):
                result = provider.query(target, probe)
                probe_results.append((probe, result))
            else:
                print(f"  Warning: Provider cannot handle probe {probe.name}")

        # Evaluate fingerprint
        evaluation = Evaluator.evaluate_fingerprint(probe_results, fingerprint)

        if evaluation["overall_match"]:
            print(f"  ✓ Match found! Evidence: {evaluation['evidence']}")
            results.append({"target": target, "match": True, **evaluation})
        else:
            print("  ✗ No match")
            results.append({"target": target, "match": False, **evaluation})

    # Save results
    save_results(results, "scan_results.json")
    print("\nScan complete. Results saved to scan_results.json")


if __name__ == "__main__":
    main()
