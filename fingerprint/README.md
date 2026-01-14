# Fingerprint

The `fingerprint` directory defines the data model and loading logic for fingerprint specifications.

A fingerprint is a **design artefact**, not executable code. It describes *what must be observed* on the public Internet to identify a specific vulnerable firmware version, using only static artefacts derived from the Obsidian Desk.

This directory enforces that separation.

## What a Fingerprint Is

A fingerprint:
- Targets one exact firmware version
- Is based on passive, publicly observable artefacts (HTTP headers, TLS metadata, banners)
- Contains explicit match logic
- Is independent of any specific scanner implementation

The scanner exists to execute fingerprints, not to reinterpret them.

## Files

### `model.py`

Defines the internal Python representation of a fingerprint.

This includes:
- Fingerprint identity and metadata
- Probe definitions (protocol, field, expected value)
- Match logic expressed in a machine-evaluable form

The model is intentionally minimal. It mirrors the YAML structure closely to avoid “smart” behaviour creeping in.

### `loader.py`

Loads and validates `fingerprint.yaml` files.

Responsibilities:
- Parse YAML into the fingerprint model
- Enforce required fields and structure
- Fail loudly on ambiguity or malformed logic

The loader does **not**:
- Rewrite fingerprints
- Infer missing logic
- Normalise probes across providers

If a fingerprint is unclear, it is invalid.

## Constraints

- One fingerprint file describes one target firmware
- Fingerprints must be deterministic
- Fingerprints must be explainable to a human reader

If a fingerprint cannot be reviewed line-by-line by an engineer, it does not belong here.
