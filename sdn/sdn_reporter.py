"""SDN telemetry reporter transmitting events to the ARIA Backend API."""
import json
from typing import Any, Dict, Optional
import urllib.request
import urllib.error

from sdn.config import BACKEND_TELEMETRY_URL


class SDNReporter:
    """Dispatches SDN network events to the ARIA backend REST endpoint."""

    def __init__(self, backend_url: str = BACKEND_TELEMETRY_URL, logger: Optional[Any] = None):
        self.backend_url = backend_url
        self.logger = logger

    def report_event(self, telemetry: Dict[str, Any]) -> bool:
        """Send telemetry event to the backend API via HTTP POST using standard library."""
        try:
            data_bytes = json.dumps(telemetry).encode("utf-8")
            req = urllib.request.Request(
                self.backend_url,
                data=data_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2.0) as response:
                if self.logger:
                    self.logger.debug("Successfully reported SDN telemetry to backend (status: %d)", response.status)
                return True
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, Exception) as exc:
            if self.logger:
                self.logger.debug("Backend telemetry endpoint unreachable at %s (%s)", self.backend_url, exc)
            return False
