# IO

TO BE DONE LATER. Is now handled in scan.py for the spike.

The `io` directory contains all input and output handling for the passive scanner spike.

Its purpose is simple: move data in and out of the system without contaminating the engine, fingerprint logic, or 
provider behaviour. This keeps the core logic testable and prevents “just one more convenience feature” from spreading 
everywhere.

## Responsibilities

The IO layer handles:
- Reading target inputs (IP addresses or netblocks)
- Writing scan results in a structured, machine-readable form

It does **not**:
- Decide what to scan
- Decide how to match fingerprints
- Interpret or enrich results

## Files

### `targets.py`

Handles loading scan targets.

Responsibilities:
- Read a list of IPs or CIDR blocks from a file or CLI input
- Validate basic syntax
- Expand targets into a concrete list usable by the scan loop

This module assumes:
- Small, controlled target sets (spike-scale)
- No need for batching, sharding, or scheduling

If target handling becomes complex, the scope has already been exceeded.

### `output.py`

Handles writing scan results.

Responsibilities:

- Emit results in a structured, predictable format (JSON lines)
- Include timestamps, target identifier, match result, and evidence
- Ensure output is append-only and stream-friendly

The output format is intentionally boring so it can be:
- Grepped
- Parsed
- Fed into later tooling without translation

## Design constraints

- No formatting logic beyond structure
- No summarisation or reporting
- No persistence beyond writing files or stdout

IO exists to make the spike observable, not user-friendly.

## Non-Goals

- Dashboards
- Pretty tables
- CSV exports “for convenience”
- Automatic retries or buffering
