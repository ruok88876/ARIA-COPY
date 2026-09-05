class Redirector:

    def __init__(self, flow_manager, logger):
        self.flow_manager = flow_manager
        self.logger = logger


    def redirect_attacker(self, datapath, attacker_ip, honeypot_ip):

        self.logger.info(
            "Redirecting attacker %s to honeypot %s",
            attacker_ip,
            honeypot_ip
        )

        # Flow rule creation will be added
        # when OpenFlow switch is available

        return True