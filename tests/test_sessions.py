"""Tests for SessionBuilder and session aggregation logic."""
import pytest
from honeypot.parser import CowrieParser
from honeypot.session_builder import SessionBuilder


def test_session_builder_aggregation():
    parser = CowrieParser()
    events = parser.parse_file("tests/fixtures/sample_cowrie.json")
    builder = SessionBuilder()
    sessions = builder.build_from_events(events)

    assert len(sessions) == 2

    # Verify session 1 (completed session)
    s1 = builder.get_session("s_aria_001")
    assert s1 is not None
    assert s1.attacker_ip == "203.0.113.15"
    assert s1.username == "root"
    assert s1.authentication_status == "success"
    assert len(s1.commands) == 7
    assert s1.is_closed is True
    assert s1.duration > 0.0
    assert len(s1.downloaded_files) == 1
    assert s1.downloaded_files[0]["shasum"].startswith("c26b5278")

    # Verify session 2 (incomplete / ongoing session)
    s2 = builder.get_session("s_aria_002")
    assert s2 is not None
    assert s2.attacker_ip == "198.51.100.77"
    assert s2.authentication_status == "failed"
    assert len(s2.commands) == 1
    assert s2.is_closed is False


def test_session_auth_progression():
    builder = SessionBuilder()
    parser = CowrieParser()

    # Step 1: Connect
    ev1 = parser.parse_line('{"eventid": "cowrie.session.connect", "timestamp": "2026-09-06T01:00:00Z", "session": "s_auth_test", "src_ip": "1.2.3.4"}')
    s = builder.process_event(ev1)
    assert s.authentication_status == "none"

    # Step 2: Failed login
    ev2 = parser.parse_line('{"eventid": "cowrie.login.failed", "timestamp": "2026-09-06T01:00:02Z", "session": "s_auth_test", "username": "admin", "password": "123"}')
    s = builder.process_event(ev2)
    assert s.authentication_status == "failed"

    # Step 3: Succeeded login
    ev3 = parser.parse_line('{"eventid": "cowrie.login.success", "timestamp": "2026-09-06T01:00:05Z", "session": "s_auth_test", "username": "root", "password": "toor"}')
    s = builder.process_event(ev3)
    assert s.authentication_status == "success"
    assert s.username == "root"
