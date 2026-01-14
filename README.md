# passive-scanner

[![codecov](https://codecov.io/github/ninabarzh/passive-scanner/graph/badge.svg?token=KPJQ3TV37Q)](https://codecov.io/github/ninabarzh/passive-scanner)
[![Coffee](https://img.shields.io/badge/Buy%20Me%20Coffee-%E2%98%95-ff813f)](https://www.buymeacoffee.com/ninabarzh)
![Python](https://img.shields.io/badge/python-3.12-blue)

A Spike passive scanner for fingerprinting services using Netlas (for now) for the [Fingerprint Forge](https://blue.tymyrddin.dev/docs/shadows/anvil/forge/).
Designed for safe, offline-friendly analysis of small, controlled target sets.  

## Features

- Load fingerprints from YAML files
- Scan targets (IP addresses) via HTTP/TLS probes
- Evaluate matches against fingerprints
- Output results in JSON format
- Fully testable with pytest and coverage

## Requirements

- Python 3.12+
- `pip` for installing dependencies
- `.env` file containing your Netlas API key for live scans:

```
NETLAS_API_KEY=your_api_key_here
````

*Note:* For CI/testing, you can use a dummy value for `NETLAS_API_KEY`.

## Installation

Clone the repository:

```bash
git clone https://github.com/ninabarzh/passive-scanner.git
cd passive-scanner
````

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Prepare your fingerprint YAML file (e.g., `example_fingerprint.yaml`)
2. Prepare a targets file (one IP per line, e.g., `targets.txt`)
3. Run the scanner:

```bash
python scan.py
```

Results are saved to `scan_results.json` by default.

## Testing

Run all unit tests with coverage:

```bash
pytest --cov=./ --cov-report=term-missing --cov-report=xml
```

**Note:** CI runs can set `NETLAS_API_KEY=dummy` to avoid import-time errors.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for any new functionality
4. Submit a pull request

## License

This project is licensed under the Unlicense.

## Notes

* Targets are assumed to be small and controlled; do **not** scan networks you do not own or have permission to test.
* The scanner is designed to be modular and testable. Providers and fingerprints are easily pluggable.
