"""Mininet OpenFlow 1.3 Topology for ARIA SDN Deception Testing.

Topology Architecture:
    [Attacker: 10.0.0.1]
            │
            ▼ (port 1)
    [OVS Switch: s1 (OpenFlow 1.3)]
       │ (port 2)              │ (port 3)
       ▼                       ▼
[Server: 10.0.0.10]    [Honeypot: 10.0.0.50]

Execution Requirements:
    - Linux OS (Ubuntu 20.04/22.04 LTS recommended)
    - Mininet 2.3+ & Open vSwitch 2.13+ installed
    - Root privileges (`sudo`)
"""
import sys

try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False
    Topo = object

from sdn.config import (
    CONTROLLER_IP,
    CONTROLLER_PORT,
    SERVER_IP,
    SERVER_MAC,
    SERVER_PORT,
    HONEYPOT_IP,
    HONEYPOT_MAC,
    HONEYPOT_PORT,
    ATTACKER_IP,
    ATTACKER_MAC,
    ATTACKER_PORT,
)


class ARIAMininetTopo(Topo):
    """ARIA Mininet topology defining Attacker, OVS Switch, Server, and Honeypot."""

    def build(self):
        # 1. Add OpenFlow 1.3 Switch
        s1 = self.addSwitch("s1", protocols="OpenFlow13")

        # 2. Add Network Hosts
        attacker = self.addHost(
            "attacker",
            ip=f"{ATTACKER_IP}/24",
            mac=ATTACKER_MAC,
        )
        server = self.addHost(
            "server",
            ip=f"{SERVER_IP}/24",
            mac=SERVER_MAC,
        )
        honeypot = self.addHost(
            "honeypot",
            ip=f"{HONEYPOT_IP}/24",
            mac=HONEYPOT_MAC,
        )

        # 3. Connect Hosts to specific Switch Ports
        self.addLink(attacker, s1, port2=ATTACKER_PORT)
        self.addLink(server, s1, port2=SERVER_PORT)
        self.addLink(honeypot, s1, port2=HONEYPOT_PORT)


def run_aria_network():
    """Launch the Mininet virtual network connected to the ARIA Ryu controller."""
    if not MININET_AVAILABLE:
        print("[!] Mininet is not available in the current environment.")
        print("    Please run this script inside an Ubuntu/Debian environment with Mininet installed:")
        print("    sudo python3 sdn/mininet_topo.py")
        sys.exit(1)

    setLogLevel("info")
    info("*** Creating ARIA Mininet Topology...\n")
    topo = ARIAMininetTopo()

    info(f"*** Connecting to Ryu Controller at {CONTROLLER_IP}:{CONTROLLER_PORT}...\n")
    controller = RemoteController(
        "c0",
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )

    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=controller,
        autoSetMacs=True,
    )

    info("*** Starting ARIA Network...\n")
    net.start()

    info("*** Network is live! Opening Mininet CLI...\n")
    info("    Test command: attacker ssh 10.0.0.10\n")
    CLI(net)

    info("*** Stopping ARIA Network...\n")
    net.stop()


# Dictionary export for `mn --custom sdn/mininet_topo.py --topo aria`
topos = {"aria": ARIAMininetTopo}

if __name__ == "__main__":
    run_aria_network()
