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


# ---------------------------------------------------------------------------
# Table-miss flow / switch_features_handler tests
# ---------------------------------------------------------------------------

class _FakeOFProto:
    """Mimics datapath.ofproto constants used by table-miss flow installation."""
    OFPP_CONTROLLER = 0xfffffffd
    OFPCML_NO_BUFFER = 0xffff
    OFPIT_APPLY_ACTIONS = 4


class _FakeMatch:
    """Mimics parser.OFPMatch()."""
    def __init__(self, **kwargs):
        self.fields = kwargs


class _FakeActionOutput:
    """Mimics parser.OFPActionOutput(port, max_len)."""
    def __init__(self, port, max_len=0):
        self.port = port
        self.max_len = max_len


class _FakeInstructionActions:
    """Mimics parser.OFPInstructionActions(type, actions)."""
    def __init__(self, type_, actions):
        self.type = type_
        self.actions = actions


class _FakeFlowMod:
    """Mimics parser.OFPFlowMod(...)."""
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeParser:
    """Mimics datapath.ofproto_parser with the subset used by FlowManager.add_flow."""
    OFPMatch = _FakeMatch
    OFPActionOutput = _FakeActionOutput
    OFPInstructionActions = _FakeInstructionActions
    OFPFlowMod = _FakeFlowMod


class _FakeDatapath:
    """Mimics a Ryu datapath object used during switch feature negotiation."""
    def __init__(self, dp_id=1):
        self.id = dp_id
        self.ofproto = _FakeOFProto()
        self.ofproto_parser = _FakeParser()
        self.sent_msgs = []

    def send_msg(self, msg):
        self.sent_msgs.append(msg)


class _FakeSwitchFeaturesMsg:
    """Mimics ev.msg for EventOFPSwitchFeatures."""
    def __init__(self, datapath):
        self.datapath = datapath
        self.n_buffers = 256
        self.n_tables = 254


class _FakeSwitchFeaturesEvent:
    """Mimics the EventOFPSwitchFeatures event object."""
    def __init__(self, datapath):
        self.msg = _FakeSwitchFeaturesMsg(datapath)


@pytest.fixture
def controller():
    """Construct an ARIAController without the Ryu framework."""
    from sdn.controller import ARIAController
    return ARIAController()


def test_switch_features_handler_installs_table_miss(controller):
    """switch_features_handler must install exactly one table-miss flow on the switch."""
    dp = _FakeDatapath(dp_id=1)
    ev = _FakeSwitchFeaturesEvent(dp)

    controller.switch_features_handler(ev)

    # Exactly one FlowMod should have been sent
    assert len(dp.sent_msgs) == 1
    flow_mod = dp.sent_msgs[0]
    assert isinstance(flow_mod, _FakeFlowMod)


def test_table_miss_flow_priority_zero(controller):
    """Table-miss flow must have priority 0 (lowest)."""
    dp = _FakeDatapath(dp_id=1)
    ev = _FakeSwitchFeaturesEvent(dp)

    controller.switch_features_handler(ev)

    flow_mod = dp.sent_msgs[0]
    assert flow_mod.kwargs["priority"] == 0


def test_table_miss_flow_wildcard_match(controller):
    """Table-miss flow must use an empty/wildcard OFPMatch."""
    dp = _FakeDatapath(dp_id=1)
    ev = _FakeSwitchFeaturesEvent(dp)

    controller.switch_features_handler(ev)

    flow_mod = dp.sent_msgs[0]
    match = flow_mod.kwargs["match"]
    assert isinstance(match, _FakeMatch)
    # Wildcard match has no fields
    assert match.fields == {}


def test_table_miss_flow_action_output_controller(controller):
    """Table-miss flow action must output to OFPP_CONTROLLER with OFPCML_NO_BUFFER."""
    dp = _FakeDatapath(dp_id=1)
    ev = _FakeSwitchFeaturesEvent(dp)

    controller.switch_features_handler(ev)

    flow_mod = dp.sent_msgs[0]
    instructions = flow_mod.kwargs["instructions"]
    assert len(instructions) == 1

    inst = instructions[0]
    assert isinstance(inst, _FakeInstructionActions)
    assert inst.type == _FakeOFProto.OFPIT_APPLY_ACTIONS

    actions = inst.actions
    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, _FakeActionOutput)
    assert action.port == _FakeOFProto.OFPP_CONTROLLER  # 0xfffffffd
    assert action.max_len == _FakeOFProto.OFPCML_NO_BUFFER  # 0xffff


def test_table_miss_flow_no_timeouts(controller):
    """Table-miss flow must not expire (idle_timeout=0, hard_timeout=0)."""
    dp = _FakeDatapath(dp_id=1)
    ev = _FakeSwitchFeaturesEvent(dp)

    controller.switch_features_handler(ev)

    flow_mod = dp.sent_msgs[0]
    assert flow_mod.kwargs.get("idle_timeout", 0) == 0
    assert flow_mod.kwargs.get("hard_timeout", 0) == 0


def test_switch_features_handler_multiple_switches(controller):
    """Each switch that connects gets its own table-miss flow independently."""
    dp1 = _FakeDatapath(dp_id=1)
    dp2 = _FakeDatapath(dp_id=2)

    controller.switch_features_handler(_FakeSwitchFeaturesEvent(dp1))
    controller.switch_features_handler(_FakeSwitchFeaturesEvent(dp2))

    assert len(dp1.sent_msgs) == 1
    assert len(dp2.sent_msgs) == 1
