"""Robust Cowrie JSON-lines log parser."""
import json
import os
from typing import Any, Dict, Iterator, List, Optional
from backend.app.schemas.log import CowrieEvent
from backend.app.core.logging import get_logger

logger = get_logger("honeypot.parser")


class CowrieParser:
    """Parses Cowrie JSON-lines log output into normalized CowrieEvent objects."""

    def __init__(self):
        self.malformed_lines_count = 0
        self.total_lines_parsed = 0

    def parse_line(self, line: str) -> Optional[CowrieEvent]:
        """Parse a single JSON-encoded line into a CowrieEvent.
        
        Returns None if the line is empty or cannot be parsed as valid JSON.
        """
        stripped = line.strip()
        if not stripped:
            return None

        self.total_lines_parsed += 1

        try:
            data: Dict[str, Any] = json.loads(stripped)
        except json.JSONDecodeError as exc:
            self.malformed_lines_count += 1
            logger.warning("Skipping malformed JSON line (error: %s): %s", exc, stripped[:100])
            return None

        # Cowrie logs typically require eventid, timestamp, and session
        eventid = data.get("eventid")
        timestamp = data.get("timestamp")
        session = data.get("session")

        if not eventid or not timestamp or not session:
            # Tolerant fallback if partial fields are present
            if not session:
                self.malformed_lines_count += 1
                logger.debug("Skipping event lacking session ID: %s", data)
                return None
            eventid = eventid or "cowrie.unknown"
            timestamp = timestamp or ""

        event = CowrieEvent(
            eventid=str(eventid),
            timestamp=str(timestamp),
            session=str(session),
            src_ip=data.get("src_ip"),
            src_port=data.get("src_port"),
            dst_ip=data.get("dst_ip"),
            dst_port=data.get("dst_port"),
            message=data.get("message"),
            input=data.get("input"),
            username=data.get("username"),
            password=data.get("password"),
            outfile=data.get("outfile"),
            shasum=data.get("shasum"),
            url=data.get("url"),
            raw=data,
        )
        return event

    def parse_text(self, content: str) -> List[CowrieEvent]:
        """Parse multi-line text content into a list of CowrieEvents."""
        events: List[CowrieEvent] = []
        for line in content.splitlines():
            parsed = self.parse_line(line)
            if parsed is not None:
                events.append(parsed)
        return events

    def parse_file(self, file_path: str) -> List[CowrieEvent]:
        """Parse all events from a Cowrie log file."""
        if not os.path.exists(file_path):
            logger.warning("Cowrie log file not found at: %s", file_path)
            return []

        events: List[CowrieEvent] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parsed = self.parse_line(line)
                    if parsed is not None:
                        events.append(parsed)
        except Exception as exc:
            logger.error("Error reading Cowrie log file %s: %s", file_path, exc)

        logger.info(
            "Parsed %d events (%d malformed lines skipped) from %s",
            len(events),
            self.malformed_lines_count,
            file_path,
        )
        return events

    def stream_file(self, file_path: str) -> Iterator[CowrieEvent]:
        """Stream events generator from a file line by line."""
        if not os.path.exists(file_path):
            logger.warning("Cowrie log file does not exist: %s", file_path)
            return

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                event = self.parse_line(line)
                if event is not None:
                    yield event
