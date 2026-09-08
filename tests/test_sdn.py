"""Tests for SDN packet monitor, SSH detection, and flow redirection logic."""
import logging
import socket
import struct
import pytest

from sdn.monitor import TrafficMonitor
from sdn.redirector import Redirector
from sdn.flow_manager import FlowManager


@pytest.fixture
def monitor():
    logger = logging.getLogger("test_sdn_monitor")
    return TrafficMonitor(logger, suspicious_threshold=2)


def test_packet_bytes_parser(monitor):
    # Construct raw synthetic Ethernet + IPv4 + TCP packet
    dst_mac = b"\x00\x00\x00\x00\x00\x02"
    src_mac = b"\x00\x00\x00\x00\x00\x01"
    eth_type = struct.pack("!H", 0x0800)  # IPv4
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,  # Version 4, IHL 5
        0,
        40,
        1,
        0,
        64,
        6,  # Protocol 6 (TCP)
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("10.0.0.10"),
    )
    tcp_header = struct.pack("!HHIIBBHHH", 48999, 22, 100, 0, (5 << 4), 2, 8192, 0, 0)
    raw_packet = dst_mac + src_mac + eth_type + ip_header + tcp_header

    parsed = monitor.parse_packet_bytes(raw_packet)
    assert parsed["src_ip"] == "10.0.0.1"
    assert parsed["dst_ip"] == "10.0.0.10"
    assert parsed["dst_port"] == 22
    assert parsed["protocol"] == "TCP"


def test_ssh_threshold_detection(monitor):
    packet = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.10",
        "dst_port": 22,
        "protocol": "TCP",
    }

    # Attempt 1: Observed but not yet threshold
    t1 = monitor.analyze_packet(packet)
    assert t1["ssh_detected"] is True
    assert t1["should_redirect"] is False

    # Attempt 2: Reaches threshold=2, triggers redirection flag
    t2 = monitor.analyze_packet(packet)
    assert t2["ssh_detected"] is True
    assert t2["should_redirect"] is True
    assert t2["status"] == "suspicious"


def test_redirector_logic():
    logger = logging.getLogger("test_redirector")
    fm = FlowManager(logger)
    redir = Redirector(fm, logger)

    success = redir.redirect_attacker(
        datapath=None,
        attacker_ip="10.0.0.1",
        honeypot_ip="10.0.0.50",
    )
    assert success is True
    assert redir.is_redirected("10.0.0.1") is True
