"""Tests for Cowrie JSON log parser."""
import pytest
from honeypot.parser import CowrieParser


def test_parse_valid_connect_line():
    parser = CowrieParser()
    line = '{"eventid": "cowrie.session.connect", "timestamp": "2026-09-06T00:00:01Z", "session": "s_test_1", "src_ip": "198.51.100.10", "src_port": 45000, "dst_ip": "10.0.0.50", "dst_port": 2222}'
    event = parser.parse_line(line)
    assert event is not None
    assert event.eventid == "cowrie.session.connect"
    assert event.session == "s_test_1"
    assert event.src_ip == "198.51.100.10"
    assert event.dst_port == 2222


def test_parse_command_line():
    parser = CowrieParser()
    line = '{"eventid": "cowrie.command.input", "timestamp": "2026-09-06T00:00:05Z", "session": "s_test_1", "src_ip": "198.51.100.10", "input": "cat /etc/passwd"}'
    event = parser.parse_line(line)
    assert event is not None
    assert event.eventid == "cowrie.command.input"
    assert event.input == "cat /etc/passwd"


def test_parse_malformed_json():
    parser = CowrieParser()
    malformed = "{INVALID_JSON_PAYLOAD_STRING::}"
    event = parser.parse_line(malformed)
    assert event is None
    assert parser.malformed_lines_count == 1


def test_parse_empty_or_whitespace_line():
    parser = CowrieParser()
    assert parser.parse_line("") is None
    assert parser.parse_line("   \n") is None
    assert parser.malformed_lines_count == 0


def test_parse_fixture_file():
    parser = CowrieParser()
    events = parser.parse_file("tests/fixtures/sample_cowrie.json")
    assert len(events) >= 14
    assert parser.malformed_lines_count >= 1
    session_ids = {e.session for e in events}
    assert "s_aria_001" in session_ids
    assert "s_aria_002" in session_ids
