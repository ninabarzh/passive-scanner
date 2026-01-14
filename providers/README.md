# Providers

The `providers` directory contains adapters for third-party Internet scanning datasets.

Providers are thin translation layers between:
- The engine’s query plan
- The reality of external APIs (Netlas, Censys, Shodan)

They are deliberately boring.

## Role in the spike

This spike exists to answer a specific uncertainty: *Can public Internet datasets supply enough passive evidence to evaluate Forge fingerprints?*

Providers exist solely to test that assumption.

## Files

### `base.py`

Defines the common provider interface.

All providers must:
- Accept a query plan derived from fingerprint probes
- Execute passive lookups only
- Return raw observations plus metadata (timestamps, source)

The base class exists to make provider behaviour comparable, not interchangeable.

### `netlas.py`

Netlas provider implementation.

Focus:
- Mapping fingerprint probes to Netlas query fields
- Discovering real API limits and quirks
- Verifying data completeness for HTTP and TLS artefacts

This is the primary provider for the spike.

### `censys.py`

Censys provider implementation.

Used as:
- A fallback
- A comparison point for data quality and field coverage

It exists to answer “is Netlas enough, or do we need alternatives?”

### `shodan.py`

Shodan provider implementation.

Included for completeness and evaluation, not preference.
Shodan’s rate limits and data granularity may make it unsuitable beyond small tests.

## Design rules

- Providers do not apply match logic
- Providers do not correlate probes
- Providers do not hide missing data

If the dataset does not contain a field, that absence must be explicit.

## Non-goals

- Provider abstraction layers
- Automatic provider selection
- Cross-provider result merging
- Caching or optimisation

Those decisions come *after* this spike proves feasibility.
