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
    """Mimics datapath.ofproto constants."""
    OFPP_CONTROLLER = 0xfffffffd
    OFPP_FLOOD = 0xfffffffb
    OFPCML_NO_BUFFER = 0xffff
    OFP_NO_BUFFER = 0xffffffff
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


class _FakePacketOut:
    """Mimics parser.OFPPacketOut(...)."""
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeActionSetField:
    """Mimics parser.OFPActionSetField(field=value)."""
    def __init__(self, **kwargs):
        self.fields = kwargs


class _FakeParser:
    """Mimics datapath.ofproto_parser with the subset used by FlowManager and controller."""
    OFPMatch = _FakeMatch
    OFPActionOutput = _FakeActionOutput
    OFPActionSetField = _FakeActionSetField
    OFPInstructionActions = _FakeInstructionActions
    OFPFlowMod = _FakeFlowMod
    OFPPacketOut = _FakePacketOut


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


# ---------------------------------------------------------------------------
# PacketIn / MAC-learning / L2 forwarding tests
# ---------------------------------------------------------------------------

class _FakePacketInMsg:
    """Mimics a Ryu OFPPacketIn message."""
    def __init__(self, datapath, data, in_port, buffer_id=0xffffffff):
        self.datapath = datapath
        self.data = data
        self.buffer_id = buffer_id
        self.match = {'in_port': in_port}


class _FakePacketInEvent:
    """Mimics EventOFPPacketIn."""
    def __init__(self, msg):
        self.msg = msg


def _build_raw_packet(src_mac_bytes, dst_mac_bytes, src_ip, dst_ip,
                      src_port=12345, dst_port=80):
    """Build a minimal raw Ethernet + IPv4 + TCP frame for testing."""
    eth_type = struct.pack("!H", 0x0800)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 40, 1, 0, 64,
        6, 0,  # protocol=TCP
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    tcp_header = struct.pack("!HHIIBBHHH",
                             src_port, dst_port, 100, 0, (5 << 4), 2, 8192, 0, 0)
    return dst_mac_bytes + src_mac_bytes + eth_type + ip_header + tcp_header


# MAC bytes matching the ARIA topology
_ATTACKER_MAC = b"\x00\x00\x00\x00\x00\x01"
_SERVER_MAC = b"\x00\x00\x00\x00\x00\x02"
_HONEYPOT_MAC = b"\x00\x00\x00\x00\x00\x03"


def test_mac_learning(controller):
    """packet_in_handler must record src_mac → in_port in the MAC table."""
    dp = _FakeDatapath(dp_id=1)
    raw = _build_raw_packet(_ATTACKER_MAC, _SERVER_MAC,
                            "10.0.0.1", "10.0.0.10", dst_port=80)
    msg = _FakePacketInMsg(dp, data=raw, in_port=1)
    ev = _FakePacketInEvent(msg)

    controller.packet_in_handler(ev)

    assert 1 in controller.mac_to_port
    assert controller.mac_to_port[1]["00:00:00:00:00:01"] == 1


def test_known_destination_forwarding(controller):
    """When dst_mac is already learned, packet_in must output to the learned port (not flood)."""
    dp = _FakeDatapath(dp_id=1)

    # Step 1: Learn server MAC on port 2 (server sends a packet)
    pkt_from_server = _build_raw_packet(_SERVER_MAC, _ATTACKER_MAC,
                                        "10.0.0.10", "10.0.0.1", dst_port=80)
    ev1 = _FakePacketInEvent(_FakePacketInMsg(dp, data=pkt_from_server, in_port=2))
    controller.packet_in_handler(ev1)

    dp.sent_msgs.clear()  # reset so we only inspect the next round

    # Step 2: Attacker sends a packet TO the server (dst already learned)
    pkt_to_server = _build_raw_packet(_ATTACKER_MAC, _SERVER_MAC,
                                      "10.0.0.1", "10.0.0.10", dst_port=80)
    ev2 = _FakePacketInEvent(_FakePacketInMsg(dp, data=pkt_to_server, in_port=1))
    controller.packet_in_handler(ev2)

    # The last sent message should be a PacketOut
    packet_out = [m for m in dp.sent_msgs if isinstance(m, _FakePacketOut)]
    assert len(packet_out) >= 1
    out_action = packet_out[-1].kwargs["actions"][0]
    assert isinstance(out_action, _FakeActionOutput)
    # Must forward to learned port 2, NOT flood
    assert out_action.port == 2


def test_unknown_destination_flood(controller):
    """When dst_mac is NOT learned, packet_in must flood."""
    dp = _FakeDatapath(dp_id=1)

    # Send from attacker to server without server ever having sent a packet
    raw = _build_raw_packet(_ATTACKER_MAC, _SERVER_MAC,
                            "10.0.0.1", "10.0.0.10", dst_port=80)
    ev = _FakePacketInEvent(_FakePacketInMsg(dp, data=raw, in_port=1))
    controller.packet_in_handler(ev)

    packet_out = [m for m in dp.sent_msgs if isinstance(m, _FakePacketOut)]
    assert len(packet_out) >= 1
    out_action = packet_out[-1].kwargs["actions"][0]
    assert out_action.port == _FakeOFProto.OFPP_FLOOD


def test_forwarding_flow_priority_above_zero(controller):
    """Learned-MAC forwarding flows must have priority > 0 (higher than table-miss)."""
    dp = _FakeDatapath(dp_id=1)

    # Learn server MAC on port 2
    pkt1 = _build_raw_packet(_SERVER_MAC, _ATTACKER_MAC,
                             "10.0.0.10", "10.0.0.1", dst_port=80)
    controller.packet_in_handler(
        _FakePacketInEvent(_FakePacketInMsg(dp, data=pkt1, in_port=2)))
    dp.sent_msgs.clear()

    # Now send toward the server → triggers a FlowMod install
    pkt2 = _build_raw_packet(_ATTACKER_MAC, _SERVER_MAC,
                             "10.0.0.1", "10.0.0.10", dst_port=80)
    controller.packet_in_handler(
        _FakePacketInEvent(_FakePacketInMsg(dp, data=pkt2, in_port=1)))

    flow_mods = [m for m in dp.sent_msgs if isinstance(m, _FakeFlowMod)]
    assert len(flow_mods) >= 1
    fwd_flow = flow_mods[0]
    assert fwd_flow.kwargs["priority"] == 1
    assert fwd_flow.kwargs["priority"] > 0  # above table-miss


def test_table_miss_still_priority_zero_after_forwarding(controller):
    """Table-miss flow must remain priority 0 even after forwarding flows are installed."""
    dp = _FakeDatapath(dp_id=1)

    # Install table-miss
    controller.switch_features_handler(_FakeSwitchFeaturesEvent(dp))
    table_miss = dp.sent_msgs[0]
    assert table_miss.kwargs["priority"] == 0

    dp.sent_msgs.clear()

    # Generate some forwarding traffic
    pkt = _build_raw_packet(_ATTACKER_MAC, _SERVER_MAC,
                            "10.0.0.1", "10.0.0.10", dst_port=80)
    controller.packet_in_handler(
        _FakePacketInEvent(_FakePacketInMsg(dp, data=pkt, in_port=1)))

    # No message should have modified the table-miss priority
    for m in dp.sent_msgs:
        if isinstance(m, _FakeFlowMod):
            assert m.kwargs["priority"] > 0, "No flow should be installed at priority 0"


def test_suspicious_ssh_redirect_overrides_forwarding(controller):
    """SSH redirect flows (priority 200) must be installed when threshold is reached,
    taking precedence over normal forwarding flows (priority 1)."""
    # Use threshold=2 for quick triggering
    controller.monitor.threshold = 2
    dp = _FakeDatapath(dp_id=1)

    # Learn server MAC first so forwarding would normally be unicast
    pkt_server = _build_raw_packet(_SERVER_MAC, _ATTACKER_MAC,
                                   "10.0.0.10", "10.0.0.1", dst_port=80)
    controller.packet_in_handler(
        _FakePacketInEvent(_FakePacketInMsg(dp, data=pkt_server, in_port=2)))
    dp.sent_msgs.clear()

    # Send SSH packets from attacker → server (port 22)
    ssh_pkt = _build_raw_packet(_ATTACKER_MAC, _SERVER_MAC,
                                "10.0.0.1", "10.0.0.10",
                                src_port=48999, dst_port=22)

    # Attempt 1: below threshold
    controller.packet_in_handler(
        _FakePacketInEvent(_FakePacketInMsg(dp, data=ssh_pkt, in_port=1)))

    # Attempt 2: reaches threshold → redirect must trigger
    dp.sent_msgs.clear()
    controller.packet_in_handler(
        _FakePacketInEvent(_FakePacketInMsg(dp, data=ssh_pkt, in_port=1)))

    # Verify redirect flows were installed at priority 200
    flow_mods = [m for m in dp.sent_msgs if isinstance(m, _FakeFlowMod)]
    redirect_flows = [f for f in flow_mods if f.kwargs.get("priority") == 200]
    assert len(redirect_flows) == 2, "Expected 2 redirect flows (forward + reverse)"

    # Verify the attacker is now marked as redirected
    assert controller.redirector.is_redirected("10.0.0.1") is True

    # Verify forwarding flow (priority 1) also exists — redirect overrides it on the switch
    fwd_flows = [f for f in flow_mods if f.kwargs.get("priority") == 1]
    assert len(fwd_flows) >= 1, "Normal forwarding flow should still be installed"

    # Confirm priority ordering: redirect (200) > forwarding (1) > table-miss (0)
    all_priorities = sorted({f.kwargs["priority"] for f in flow_mods}, reverse=True)
    assert all_priorities[0] == 200
    assert 1 in all_priorities
