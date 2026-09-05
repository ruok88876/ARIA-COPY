class TrafficMonitor:

    def __init__(self, logger):
        self.logger = logger


    def analyze_packet(self, packet_data):

        self.logger.info(
            "Analyzing packet: %s",
            packet_data
        )

        return {
            "status": "normal"
        }