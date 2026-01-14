# passive-scanner

Purpose: Spike implementation for a minimal passive scanner that evaluates a single `fingerprint.yaml` against a list of IPs using a public Internet dataset API (Netlas, Censys, etc.).

This repository is a proof-of-concept for the Dept. of Silent Stability’s Fingerprint Forge workflow. It focuses on data plumbing, API integration, and logic evaluation.

Structure overview:

- `parse_fingerprint/` — Fingerprint spec parsing.
- `api_client/` — API integration and data fetching.
- `evaluate/` — Applying match logic to probe results.
- `scan/` — Main CLI controller orchestrating the scan.
- `test/` — Test fingerprints, target lists, and spike validation.
- `docs/` — Architecture and reference documentation.

Usage:

```bash
python scan/scan.py --fingerprint test_fingerprint.yaml --targets test_targets.txt
```

Scope:

- Passive scanning only, no active probing.
One fingerprint at a time.

Small, defined test sets only.
