# tests/test_scan.py
import json
from unittest.mock import MagicMock

import scan

# ===============================
# main() behaviour
# ===============================


def test_main_all_probes_match(
    monkeypatch,
    mock_provider,
    sample_fingerprint,
    targets,
):
    saved = {}

    monkeypatch.setattr(scan, "NetlasProvider", lambda api_key: mock_provider)
    monkeypatch.setattr(scan, "load_fingerprint", lambda _: sample_fingerprint)
    monkeypatch.setattr(scan, "load_targets", lambda _: targets)
    monkeypatch.setattr(
        scan,
        "save_results",
        lambda results, filepath: saved.update({"results": results, "file": filepath}),
    )

    evaluator = MagicMock()
    evaluator.evaluate_fingerprint.return_value = {
        "overall_match": True,
        "evidence": ["dummy"],
    }
    monkeypatch.setattr(scan, "Evaluator", evaluator)

    scan.main()

    assert len(saved["results"]) == len(targets)
    for r in saved["results"]:
        assert r["match"] is True
        assert r["evidence"] == ["dummy"]

    # all probes for all targets queried
    assert len(mock_provider.queries_made) == (
        len(targets) * len(sample_fingerprint.probes)
    )


def test_main_no_match(
    monkeypatch,
    mock_provider,
    sample_fingerprint,
    targets,
):
    saved = {}

    monkeypatch.setattr(scan, "NetlasProvider", lambda api_key: mock_provider)
    monkeypatch.setattr(scan, "load_fingerprint", lambda _: sample_fingerprint)
    monkeypatch.setattr(scan, "load_targets", lambda _: targets)
    monkeypatch.setattr(
        scan,
        "save_results",
        lambda results, filepath: saved.update({"results": results}),
    )

    evaluator = MagicMock()
    evaluator.evaluate_fingerprint.return_value = {
        "overall_match": False,
        "evidence": [],
    }
    monkeypatch.setattr(scan, "Evaluator", evaluator)

    scan.main()

    for r in saved["results"]:
        assert r["match"] is False
        assert r["evidence"] == []


def test_main_skips_unsupported_probe(
    monkeypatch,
    mock_provider,
    create_test_probe,
    sample_fingerprint,
    targets,
):
    unsupported = create_test_probe(protocol="icmp", field="type")
    sample_fingerprint.probes.append(unsupported)

    monkeypatch.setattr(scan, "NetlasProvider", lambda api_key: mock_provider)
    monkeypatch.setattr(scan, "load_fingerprint", lambda _: sample_fingerprint)
    monkeypatch.setattr(scan, "load_targets", lambda _: targets)
    monkeypatch.setattr(scan, "save_results", lambda *_: None)

    evaluator = MagicMock()
    evaluator.evaluate_fingerprint.return_value = {
        "overall_match": True,
        "evidence": ["dummy"],
    }
    monkeypatch.setattr(scan, "Evaluator", evaluator)

    scan.main()

    queried = {q["probe"] for q in mock_provider.queries_made}
    assert unsupported.name not in queried


# ===============================
# load_targets()
# ===============================


def test_load_targets_reads_file(temp_targets_file):
    targets = scan.load_targets(temp_targets_file)
    assert targets == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


def test_load_targets_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("")
    targets = scan.load_targets(str(f))
    assert targets == []


# ===============================
# save_results()
# ===============================


def test_save_results_real(tmp_path):
    f = tmp_path / "results.json"
    data = [{"target": "192.0.2.1", "match": True}]

    scan.save_results(data, str(f))

    assert f.exists()
    with open(f) as fp:
        loaded = json.load(fp)

    assert loaded == data
