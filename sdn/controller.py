from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER
from os_ken.controller.handler import DEAD_DISPATCHER
from os_ken.controller.handler import set_ev_cls

from flow_manager import FlowManager
from monitor import TrafficMonitor
from redirector import Redirector

class ARIAController(app_manager.OSKenApp):

    OFP_VERSIONS = [0x04]  # OpenFlow 1.3

    def __init__(self, *args, **kwargs):

        super(ARIAController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.flow_manager = FlowManager(self.logger)
        self.monitor = TrafficMonitor(self.logger)

        self.redirector = Redirector(
            self.flow_manager,
            self.logger
)
        self.logger.info("ARIA SDN Controller started")


    # Switch connection / disconnection tracking
    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath

            self.logger.info(
                "Switch connected: %s",
                datapath.id
            )

        elif ev.state == DEAD_DISPATCHER:

            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

                self.logger.info(
                    "Switch disconnected: %s",
                    datapath.id
                )


    # Packet handling
    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    @set_ev_cls(
    ofp_event.EventOFPPacketIn,
    MAIN_DISPATCHER
)
    def packet_in_handler(self, ev):

        packet_data = {
            "switch": ev.msg.datapath.id
        }

        result = self.monitor.analyze_packet(packet_data)

        self.logger.info(
            "Packet analysis result: %s",
            result
        )