import time

import requests

from fingerprint.model import Probe

from .base import BaseProvider


class NetlasProvider(BaseProvider):
    """Netlas API provider implementation."""

    BASE_URL = "https://app.netlas.io/api"

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.session = requests.Session()
        self.session.headers.update(
            {"X-Api-Key": self.api_key, "Content-Type": "application/json"}
        )

    def can_handle(self, probe: Probe) -> bool:
        # Netlas can handle HTTP and TLS probes
        return probe.protocol in ["http", "tls"]

    def query(self, target: str, probe: Probe) -> dict:
        """Query Netlas for host data."""
        time.sleep(self.rate_limit_delay)

        try:
            # Construct Netlas query based on probe type
            if probe.protocol == "http" and probe.field == "headers.server":
                # Query for HTTP Server header
                query = f'ip:"{target}" AND http.head.server:"{probe.value}"'
            elif probe.protocol == "tls" and probe.field == "certificate.serial":
                # Query for TLS Certificate Serial
                query = f'ip:"{target}" AND certificate.serial:"{probe.value}"'
            else:
                return {
                    "success": False,
                    "data": None,
                    "error": f"Unsupported probe: {probe.protocol}.{probe.field}",
                }

            response = self.session.get(
                f"{self.BASE_URL}/responses/",  # Querying the Responses endpoint
                params={"q": query, "source_type": "include", "start": 0, "size": 1},
            )
            response.raise_for_status()
            data = response.json()
            return {"success": True, "data": data, "error": None}

        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
