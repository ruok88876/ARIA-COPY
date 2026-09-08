"""Session aggregation and state reconstruction from Cowrie events."""
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from backend.app.schemas.log import CowrieEvent
from backend.app.schemas.session import Command, Session
from backend.app.core.logging import get_logger

logger = get_logger("honeypot.session_builder")


def _parse_iso_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO8601 timestamp string safely into a datetime object."""
    if not ts:
        return None
    try:
        # Handle 'Z' suffix and microsecond variations
        clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


class SessionBuilder:
    """Reconstructs coherent attack sessions from discrete Cowrie events."""

    def __init__(self):
        # In-memory session accumulators keyed by session_id
        self.sessions: Dict[str, Session] = {}
        self._auth_attempts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def process_event(self, event: CowrieEvent) -> Session:
        """Incrementally update and return the aggregate session for an event."""
        sid = event.session

        if sid not in self.sessions:
            self.sessions[sid] = Session(
                session_id=sid,
                attacker_ip=event.src_ip or "0.0.0.0",
                attacker_port=event.src_port,
                destination_ip=event.dst_ip,
                destination_port=event.dst_port,
                start_time=event.timestamp,
                end_time=event.timestamp,
                authentication_status="none",
                commands=[],
                iocs=[],
                intents=[],
                downloaded_files=[],
                is_closed=False,
                metadata={"event_count": 0},
            )

        sess = self.sessions[sid]
        sess.metadata["event_count"] = sess.metadata.get("event_count", 0) + 1

        # Keep attacker IP and ports updated if initial connect was missing them
        if (not sess.attacker_ip or sess.attacker_ip == "0.0.0.0") and event.src_ip:
            sess.attacker_ip = event.src_ip
        if sess.attacker_port is None and event.src_port is not None:
            sess.attacker_port = event.src_port
        if sess.destination_ip is None and event.dst_ip:
            sess.destination_ip = event.dst_ip
        if sess.destination_port is None and event.dst_port is not None:
            sess.destination_port = event.dst_port

        # Update timestamps
        if not sess.start_time or event.timestamp < sess.start_time:
            sess.start_time = event.timestamp
        if not sess.end_time or event.timestamp > sess.end_time:
            sess.end_time = event.timestamp

        # Process specific Cowrie event types
        if event.eventid == "cowrie.session.connect":
            if event.timestamp:
                sess.start_time = event.timestamp

        elif event.eventid == "cowrie.login.success":
            sess.authentication_status = "success"
            if event.username:
                sess.username = event.username
            self._auth_attempts[sid].append({
                "username": event.username,
                "status": "success",
                "timestamp": event.timestamp,
            })

        elif event.eventid == "cowrie.login.failed":
            if sess.authentication_status != "success":
                sess.authentication_status = "failed"
            if event.username and not sess.username:
                sess.username = event.username
            self._auth_attempts[sid].append({
                "username": event.username,
                "status": "failed",
                "timestamp": event.timestamp,
            })

        elif event.eventid == "cowrie.command.input":
            cmd_text = event.input or ""
            if cmd_text.strip():
                sess.commands.append(
                    Command(
                        command=cmd_text.strip(),
                        timestamp=event.timestamp,
                        session_id=sid,
                    )
                )

        elif event.eventid == "cowrie.session.file_download":
            download_record = {
                "url": event.url or event.raw.get("url"),
                "outfile": event.outfile or event.raw.get("outfile"),
                "shasum": event.shasum or event.raw.get("shasum"),
                "destfile": event.raw.get("destfile"),
                "timestamp": event.timestamp,
            }
            sess.downloaded_files.append(download_record)

        elif event.eventid == "cowrie.session.closed":
            sess.is_closed = True
            sess.end_time = event.timestamp
            if "duration" in event.raw and event.raw["duration"] is not None:
                try:
                    sess.duration = float(event.raw["duration"])
                except (ValueError, TypeError):
                    pass

        # Calculate duration if not set by closed event
        if sess.duration == 0.0 and sess.start_time and sess.end_time:
            st = _parse_iso_timestamp(sess.start_time)
            et = _parse_iso_timestamp(sess.end_time)
            if st and et:
                diff = (et - st).total_seconds()
                sess.duration = max(0.0, diff)

        sess.metadata["auth_attempts"] = self._auth_attempts[sid]
        return sess

    def build_from_events(self, events: List[CowrieEvent]) -> List[Session]:
        """Aggregate a batch of Cowrie events into Session objects."""
        for event in events:
            self.process_event(event)
        return list(self.sessions.values())

    def get_session(self, session_id: str) -> Optional[Session]:
        """Retrieve aggregated session by ID."""
        return self.sessions.get(session_id)
