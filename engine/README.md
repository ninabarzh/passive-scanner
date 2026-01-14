# Engine

The `engine` directory contains the core decision logic of the passive scanner spike.

This is where a fingerprint specification is turned into a concrete scan plan, evaluated against external dataset results, and reduced to a clear yes/no decision with evidence. The engine does **not** know how data is fetched, and it does **not** know where results are written. Its responsibility is logic, not I/O.

The engine assumes:
- All probing is passive.
- All observations come from third-party Internet scanning datasets.
- Fingerprints originate from the Forge process and are already logically sound.

## Responsibilities

The engine answers one question:

> Given a fingerprint specification and dataset observations for a target, does this target match the fingerprint?

Nothing more.

## Files

### `planner.py`

Translates a fingerprint specification into a concrete query plan.

Given a parsed `fingerprint.yaml`, the planner determines:
- Which probes must be evaluated
- Which provider fields are required for each probe
- Whether probes can be evaluated independently or must be correlated

The output of the planner is an execution plan that providers can act on (for example: “query HTTP banner field X and TLS field Y”).

The planner does **not**:
- Execute queries
- Apply match logic
- Optimise or merge queries for efficiency (this is a spike)

### `evaluator.py`

Applies the fingerprint’s `match_logic` to observed probe results.

Input:
- Probe results returned by providers (possibly partial or missing)
- The fingerprint’s logical rules (e.g. AND / OR conditions)

Output:
- A boolean match decision
- A structured explanation of why the decision was reached

The evaluator is intentionally strict: if required evidence is missing, this must be surfaced explicitly rather than guessed.

### `evidence.py`

Normalises and packages raw observations into explainable evidence.

This module exists to prevent “magic matches”. Every positive result must be defensible with concrete fields and values returned by the dataset provider.

Evidence objects are designed to be:
- Serializable
- Human-readable
- Traceable back to provider responses

## Non-goals

- No scoring or confidence weighting
- No machine learning
- No active probing
- No retry or enrichment logic
