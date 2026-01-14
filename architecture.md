# Passive scanner architecture

Documenting the architecture for the passive-scanner spike project, defining components, data flow, and responsibilities. This ensures the spike is structured for future scaling while keeping the Desk → Forge → Scanner workflow intact.

## Principles

* Fingerprint logic is immutable design input: `fingerprint.yaml` defines probes and match logic. This layer never changes during provider swaps.
* Providers are replaceable services: External datasets (Netlas, Censys, etc.) are accessed via a defined interface.
* Evaluator is deterministic: Match logic is applied to observations without side effects.
* Controller orchestrates, not decides: `scan.py` sequences the flow but does not implement probe logic.

## Directory structure

```
passive-scanner/
├── scan.py                  # CLI & orchestration
├── fingerprint/
│   ├── loader.py            # fingerprint.yaml → internal model
│   └── model.py             # Probe, MatchLogic, Fingerprint classes
├── providers/
│   ├── base.py              # Abstract search provider interface
│   ├── netlas.py            # Netlas implementation
│   └── censys.py            # Optional Censys implementation
├── engine/
│   ├── planner.py           # Probe → provider query translation
│   ├── evaluator.py         # Apply match_logic
│   └── evidence.py          # Normalize and store evidence
├── io/
│   ├── targets.py           # Load IPs / netblocks
│   └── output.py            # JSONL results writer
└── FINDINGS.md              # Spike results & limitations
```

See [architecture](architecture.md).

## Component responsibilities

### Fingerprint layer

* loader.py: Parse `fingerprint.yaml` into internal data structures.
* model.py: Define `Probe`, `Fingerprint`, `MatchResult` objects.
* Responsibilities: Maintain tool-agnostic representation of probes and match logic.

### Providers

* base.py: Abstract class defining `search_probe(probe, targets)`.
* netlas.py: Implements Netlas-specific queries.
* censys.py: Optional fallback provider.
* Responsibilities: Return observations per probe without evaluating match logic.

### Planner

* planner.py: Maps probes to provider query syntax.
* Example: `http.headers.server:"DeviceOS/2.1.4"`
* Responsibilities: Keep API-specific logic isolated.

### Evaluation engine

* evaluator.py: Apply `match_logic` to grouped observations.
* evidence.py: Structure evidence per IP for JSONL output.
* Responsibilities: Ensure deterministic, testable logic evaluation.

### CLI/Controller

* scan.py: Orchestrates loading fingerprints, reading targets, calling planner/provider/evaluator, emitting results.
* Responsibilities: Glue only, no logic decisions.

### IO

Currently not used in the spike. Is for later.

* targets.py: Handle IP/netblock input.
* output.py: Emit JSONL lines: `<timestamp>, <ip>, <match_result>, <evidence_snippet>`.

## Data flow

1. scan.py loads `fingerprint.yaml` and `targets.txt`.
2. planner.py converts each probe into provider-specific queries.
3. provider executes queries and returns raw observations.
4. evaluator.py groups observations per IP, applies `match_logic`, outputs `MatchResult`.
5. output.py writes JSONL with matched IPs and evidence.

Note: No packets are sent. This is passive, internet-facing scanning.

## Spike success criteria

* CLI tool runs and consumes one `fingerprint.yaml`.
* Queries Netlas for 100 test IPs, outputs structured results.
* Findings documented in `FINDINGS.md` with API limits, data quality, and gaps.
* End-to-end flow verified; no assumptions about full-scale or active scanning.

## Scaling considerations

* Add providers: Netlas → Censys → local datasets.
* Caching & pagination: Wrap providers.
* Parallelization: Later enhancement; controller remains unchanged.
* Bulk fingerprints: Evaluator unchanged, planner handles translation.
* Active probes: Separate provider module, no effect on fingerprint model.

## Non-goals (current spike)

* GUI
* Concurrent fingerprint evaluation
* Active probing
* Optimisation for speed
* Full error handling

This document defines the backbone for the passive-scanner spike. It ensures the Desk → Forge → Scanner pipeline is 
testable, modular, and ready for incremental enhancement.
