class ARIATopology:

    def __init__(self):
        self.nodes = {}
        self.links = []

        self.create_topology()


    def create_topology(self):

        self.nodes = {
            "attacker": {
                "type": "external"
            },

            "switch": {
                "type": "openflow_switch"
            },

            "server": {
                "type": "normal_service"
            },

            "honeypot": {
                "type": "cowrie"
            }
        }


        self.links = [
            ("attacker", "switch"),
            ("switch", "server"),
            ("switch", "honeypot")
        ]


    def show(self):

        print("ARIA Network Topology")

        print("\nNodes:")
        for node, info in self.nodes.items():
            print(
                f"{node}: {info['type']}"
            )


        print("\nLinks:")
        for link in self.links:
            print(
                f"{link[0]} <--> {link[1]}"
            )