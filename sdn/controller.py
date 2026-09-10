"""ARIA OpenFlow 1.3 SDN Controller built with Ryu framework."""
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import (
        MAIN_DISPATCHER,
        DEAD_DISPATCHER,
        CONFIG_DISPATCHER,
        set_ev_cls,
    )
    from ryu.ofproto import ofproto_v1_3
    BaseControllerApp = app_manager.RyuApp
except ImportError:
    try:
        from os_ken.base import app_manager
        from os_ken.controller import ofp_event
        from os_ken.controller.handler import (
            MAIN_DISPATCHER,
            DEAD_DISPATCHER,
            CONFIG_DISPATCHER,
            set_ev_cls,
        )
        from os_ken.ofproto import ofproto_v1_3
        BaseControllerApp = app_manager.OSKenApp
    except ImportError:
        # Fallback dummy definitions for testing on environments without Ryu/OS-Ken
        app_manager = None
        ofp_event = None
        MAIN_DISPATCHER = 1
        DEAD_DISPATCHER = 2
        CONFIG_DISPATCHER = 3
        ofproto_v1_3 = None

        def set_ev_cls(*args, **kwargs):
            def decorator(func):
                return func
            return decorator

        BaseControllerApp = object

# Import SDN components supporting both package and standalone ryu-manager execution
try:
    from sdn.flow_manager import FlowManager
    from sdn.monitor import TrafficMonitor
    from sdn.redirector import Redirector
    from sdn.sdn_reporter import SDNReporter
    from sdn.config import HONEYPOT_IP, SERVER_IP, HONEYPOT_MAC, HONEYPOT_PORT
except ImportError:
    from flow_manager import FlowManager
    from monitor import TrafficMonitor
    from redirector import Redirector
    from sdn_reporter import SDNReporter
    from config import HONEYPOT_IP, SERVER_IP, HONEYPOT_MAC, HONEYPOT_PORT


class ARIAController(BaseControllerApp):
    """Ryu OpenFlow 1.3 Controller with SSH packet inspection and automatic Honeypot redirection."""

    OFP_VERSIONS = [0x04]  # OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(ARIAController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.mac_to_port = {}  # {dpid: {mac_addr: port_no}}
        # Set up logger fallback if not running inside Ryu framework
        if not hasattr(self, "logger"):
            import logging
            self.logger = logging.getLogger("ARIAController")

        self.flow_manager = FlowManager(self.logger)
        self.monitor = TrafficMonitor(self.logger)
        self.redirector = Redirector(self.flow_manager, self.logger)
        self.reporter = SDNReporter(logger=self.logger)

        self.logger.info("ARIA SDN Controller initialized successfully (OpenFlow 1.3 / Ryu)")

    # Table-miss flow installation on switch feature negotiation
    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures if ofp_event else None,
        CONFIG_DISPATCHER,
    )
    def switch_features_handler(self, ev):
        """Install table-miss flow entry when a switch completes OpenFlow handshake.

        Without this rule, the switch has no instruction to forward unmatched
        packets to the controller and PacketIn events will never fire.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(
            "Switch features received: datapath_id=%s, n_buffers=%d, n_tables=%d",
            datapath.id,
            ev.msg.n_buffers,
            ev.msg.n_tables,
        )

        # Empty match = wildcard (matches every packet)
        match = parser.OFPMatch()
        # Send full packet to controller (no buffer)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.flow_manager.add_flow(
            datapath=datapath,
            priority=0,
            match=match,
            actions=actions,
        )

        self.logger.info(
            "Table-miss flow installed on switch %s (priority=0, action=OUTPUT:CONTROLLER)",
            datapath.id,
        )

        # SSH inspection flow: TCP dst port 22 packets always reach the
        # controller for connection-attempt counting, overriding any
        # MAC-learning forwarding flows (priority 1).
        ssh_match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            tcp_dst=22,
        )
        ssh_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]

        self.flow_manager.add_flow(
            datapath=datapath,
            priority=5,
            match=ssh_match,
            actions=ssh_actions,
        )

        self.logger.info(
            "SSH inspection flow installed on switch %s "
            "(priority=5, match=tcp_dst:22, action=OUTPUT:CONTROLLER)",
            datapath.id,
        )

    # Switch connection / disconnection tracking
    @set_ev_cls(
        ofp_event.EventOFPStateChange if ofp_event else None,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def state_change_handler(self, ev):
        """Track connected OpenFlow switches in the topology."""
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("OpenFlow switch connected: datapath_id=%s", datapath.id)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("OpenFlow switch disconnected: datapath_id=%s", datapath.id)

    # Packet handling
    @set_ev_cls(
        ofp_event.EventOFPPacketIn if ofp_event else None,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):
        """L2 learning switch with SSH inspection and honeypot redirection.

        Flow priority hierarchy:
            200  – SSH redirect rules (installed by Redirector)
              5  – SSH inspection: tcp_dst=22 → controller (switch_features)
              1  – learned MAC forwarding rules (installed here)
              0  – table-miss → send to controller
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        # --- L2 MAC learning ------------------------------------------------
        pkt_parsed = self.monitor.parse_packet_bytes(msg.data)
        src_mac = pkt_parsed.get('src_mac')
        dst_mac = pkt_parsed.get('dst_mac')

        self.mac_to_port.setdefault(dpid, {})
        if src_mac:
            self.mac_to_port[dpid][src_mac] = in_port

        # Determine output: known destination → unicast, unknown → flood
        if dst_mac and dst_mac in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a forwarding flow for known unicast destinations (priority 1)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.flow_manager.add_flow(
                datapath=datapath,
                priority=1,
                match=match,
                actions=actions,
                idle_timeout=300,
            )

        # --- SSH analysis & redirection (existing ARIA logic) ----------------
        telemetry = self.monitor.analyze_packet(msg, switch_id=dpid)

        if telemetry.get("should_redirect"):
            attacker_ip = telemetry["attacker_ip"]
            if not self.redirector.is_redirected(attacker_ip):
                success = self.redirector.redirect_attacker(
                    datapath=datapath,
                    attacker_ip=attacker_ip,
                    honeypot_ip=HONEYPOT_IP,
                    server_ip=SERVER_IP,
                )
                telemetry["redirected"] = success
            else:
                telemetry["redirected"] = True

        # Transmit telemetry to ARIA Backend API
        self.reporter.report_event(telemetry)

        self.logger.info(
            "Packet inspected: %s -> %s (SSH: %s, Redirected: %s)",
            telemetry.get("attacker_ip"),
            telemetry.get("destination_ip"),
            telemetry.get("ssh_detected"),
            telemetry.get("redirected"),
        )

        # If this packet triggered redirection or is already redirected, route to honeypot
        if telemetry.get("redirected"):
            actions = [
                parser.OFPActionSetField(ipv4_dst=HONEYPOT_IP),
                parser.OFPActionSetField(eth_dst=HONEYPOT_MAC),
                parser.OFPActionOutput(HONEYPOT_PORT),
            ]

        # --- Forward / flood the current packet (packet-out) ----------------
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out_msg = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out_msg)