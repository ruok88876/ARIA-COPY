"""SDN Traffic Redirection Engine for OpenFlow 1.3 switches."""
from typing import Any, Dict, Optional

from sdn.config import (
    SERVER_IP,
    SERVER_MAC,
    SERVER_PORT,
    HONEYPOT_IP,
    HONEYPOT_MAC,
    HONEYPOT_PORT,
    ATTACKER_PORT,
)


class Redirector:
    """Installs OpenFlow 1.3 flow rules to redirect malicious SSH flows to the honeypot."""

    def __init__(self, flow_manager, logger):
        self.flow_manager = flow_manager
        self.logger = logger
        # Active redirection rules keyed by attacker_ip
        self.active_redirections: Dict[str, Dict[str, Any]] = {}

    def redirect_attacker(
        self,
        datapath: Any,
        attacker_ip: str,
        honeypot_ip: str = HONEYPOT_IP,
        honeypot_mac: str = HONEYPOT_MAC,
        honeypot_port: int = HONEYPOT_PORT,
        server_ip: str = SERVER_IP,
        server_mac: str = SERVER_MAC,
        attacker_port: int = ATTACKER_PORT,
        idle_timeout: int = 300,
    ) -> bool:
        """Install bi-directional flow rewriting rules to redirect an attacker to the Cowrie honeypot."""
        self.logger.info(
            "Redirecting attacker %s: targeting %s -> re-routed to honeypot %s (port %d)",
            attacker_ip,
            server_ip,
            honeypot_ip,
            honeypot_port,
        )

        rule_record = {
            "attacker_ip": attacker_ip,
            "target_server_ip": server_ip,
            "honeypot_ip": honeypot_ip,
            "honeypot_port": honeypot_port,
            "idle_timeout": idle_timeout,
            "installed_flows": 0,
        }

        # If live OpenFlow datapath is available
        if datapath is not None and hasattr(datapath, "ofproto_parser"):
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            try:
                # 1. Forward rule: Attacker -> Honeypot (rewrite dst IP & MAC)
                match_forward = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=6,  # TCP
                    ipv4_src=attacker_ip,
                    ipv4_dst=server_ip,
                    tcp_dst=22,
                )
                actions_forward = [
                    parser.OFPActionSetField(ipv4_dst=honeypot_ip),
                    parser.OFPActionSetField(eth_dst=honeypot_mac),
                    parser.OFPActionOutput(honeypot_port),
                ]
                self.flow_manager.add_flow(
                    datapath=datapath,
                    priority=200,
                    match=match_forward,
                    actions=actions_forward,
                    idle_timeout=idle_timeout,
                )

                # 2. Reverse rule: Honeypot -> Attacker (rewrite src IP & MAC to server's)
                match_reverse = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=6,  # TCP
                    ipv4_src=honeypot_ip,
                    ipv4_dst=attacker_ip,
                    tcp_src=22,
                )
                actions_reverse = [
                    parser.OFPActionSetField(ipv4_src=server_ip),
                    parser.OFPActionSetField(eth_src=server_mac),
                    parser.OFPActionOutput(attacker_port),
                ]
                self.flow_manager.add_flow(
                    datapath=datapath,
                    priority=200,
                    match=match_reverse,
                    actions=actions_reverse,
                    idle_timeout=idle_timeout,
                )
                rule_record["installed_flows"] = 2
                self.logger.info("Successfully installed 2 OpenFlow redirect flows on switch %s", datapath.id)
            except Exception as exc:
                self.logger.error("Failed to install OpenFlow redirection flow rules: %s", exc)
                return False

        self.active_redirections[attacker_ip] = rule_record
        return True

    def is_redirected(self, attacker_ip: str) -> bool:
        """Check if an attacker IP currently has an active redirection record."""
        return attacker_ip in self.active_redirections