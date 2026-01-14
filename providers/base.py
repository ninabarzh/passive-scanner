from abc import ABC, abstractmethod

from fingerprint.model import Probe


class BaseProvider(ABC):
    """Abstract base class for all data providers."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self.rate_limit_delay = 1.0  # seconds between requests

    @abstractmethod
    def query(self, target: str, probe: Probe) -> dict:
        """
        Query the provider for information about a target.
        Returns a dict with 'success', 'data', and 'error' keys.
        """
        pass

    @abstractmethod
    def can_handle(self, probe: Probe) -> bool:
        """Check if this provider can handle the given probe type."""
        pass
