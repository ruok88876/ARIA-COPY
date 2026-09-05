from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls


class ARIAController(app_manager.OSKenApp):

    OFP_VERSIONS = [0x04]

    def __init__(self, *args, **kwargs):
        super(ARIAController, self).__init__(*args, **kwargs)
        print("ARIA SDN Controller started")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print("Packet received from switch")