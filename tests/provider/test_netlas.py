# tests/providers/test_netlas.py

from unittest.mock import MagicMock

import pytest

from fingerprint.model import Probe
from providers.netlas import NetlasProvider

# ---------------------- FIXTURES ----------------------


@pytest.fixture
def netlas_provider():
    """Create a NetlasProvider instance with a fake API key."""
    provider = NetlasProvider(api_key="test-key")
    provider.rate_limit_delay = 0  # avoid real sleep in tests
    return provider


# ---------------------- UNIT TESTS ----------------------


def test_can_handle_http_and_tls(netlas_provider, sample_probe, sample_probe_tls):
    """NetlasProvider should handle HTTP and TLS probes."""
    assert netlas_provider.can_handle(sample_probe) is True
    assert netlas_provider.can_handle(sample_probe_tls) is True

    unknown_probe = Probe(
        name="unknown",
        protocol="ftp",
        field="any.field",
        match_type="contains",
        value="test",
    )
    assert netlas_provider.can_handle(unknown_probe) is False


def test_query_http_success(
    monkeypatch, netlas_provider, sample_probe, sample_netlas_response
):
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = sample_netlas_response

    # Must accept *args, **kwargs to match requests.Session.get signature
    monkeypatch.setattr(
        netlas_provider.session, "get", lambda *args, **kwargs: fake_response
    )
    monkeypatch.setattr("time.sleep", lambda _: None)

    result = netlas_provider.query("192.0.2.1", sample_probe)

    assert result["success"] is True
    assert result["data"] == sample_netlas_response
    assert result["error"] is None


def test_query_tls_success(
    monkeypatch, netlas_provider, sample_probe_tls, sample_netlas_response
):
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = sample_netlas_response

    monkeypatch.setattr(
        netlas_provider.session, "get", lambda *args, **kwargs: fake_response
    )
    monkeypatch.setattr("time.sleep", lambda _: None)

    result = netlas_provider.query("192.0.2.1", sample_probe_tls)

    assert result["success"] is True
    assert result["data"] == sample_netlas_response
    assert result["error"] is None


def test_query_unsupported_probe(netlas_provider):
    """Return failure for unsupported probe type/field."""
    unknown_probe = Probe(
        name="ftp_probe",
        protocol="ftp",
        field="any.field",
        match_type="contains",
        value="test",
    )
    result = netlas_provider.query("192.0.2.1", unknown_probe)
    assert result["success"] is False
    assert "Unsupported probe" in result["error"]


def test_query_http_exception(monkeypatch, netlas_provider, sample_probe):
    monkeypatch.setattr(
        netlas_provider.session,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(Exception("Network error")),
    )
    monkeypatch.setattr("time.sleep", lambda _: None)

    result = netlas_provider.query("192.0.2.1", sample_probe)
    assert result["success"] is False
    assert "Network error" in result["error"]
