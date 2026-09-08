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
    from sdn.config import HONEYPOT_IP, SERVER_IP
except ImportError:
    from flow_manager import FlowManager
    from monitor import TrafficMonitor
    from redirector import Redirector
    from sdn_reporter import SDNReporter
    from config import HONEYPOT_IP, SERVER_IP


class ARIAController(BaseControllerApp):
    """Ryu OpenFlow 1.3 Controller with SSH packet inspection and automatic Honeypot redirection."""

    OFP_VERSIONS = [0x04]  # OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(ARIAController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        # Set up logger fallback if not running inside Ryu framework
        if not hasattr(self, "logger"):
            import logging
            self.logger = logging.getLogger("ARIAController")

        self.flow_manager = FlowManager(self.logger)
        self.monitor = TrafficMonitor(self.logger)
        self.redirector = Redirector(self.flow_manager, self.logger)
        self.reporter = SDNReporter(logger=self.logger)

        self.logger.info("ARIA SDN Controller initialized successfully (OpenFlow 1.3 / Ryu)")

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
        """Inspect inbound packet; trigger redirection if suspicious SSH threshold exceeded."""
        msg = ev.msg
        datapath = msg.datapath

        # Analyze packet and check for SSH activity
        telemetry = self.monitor.analyze_packet(msg, switch_id=datapath.id)

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