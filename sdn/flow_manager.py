try:
    from ryu.ofproto import ofproto_v1_3
except ImportError:
    try:
        from os_ken.ofproto import ofproto_v1_3
    except ImportError:
        ofproto_v1_3 = None


class FlowManager:

    def __init__(self, logger):
        self.logger = logger

    def add_flow(
        self,
        datapath,
        priority: int,
        match,
        actions,
        idle_timeout: int = 0,
        hard_timeout: int = 0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )

        datapath.send_msg(flow_mod)

        self.logger.info(
            "Flow rule added to switch %s (priority=%d)",
            datapath.id,
            priority,
        )


    def delete_flow(self, datapath, match):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )

        datapath.send_msg(flow_mod)

        self.logger.info(
            "Flow rule removed from switch %s",
            datapath.id
        )