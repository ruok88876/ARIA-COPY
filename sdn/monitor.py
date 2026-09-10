"""SDN Traffic Monitor with Ethernet/IP/TCP packet parsing and SSH detection."""
from collections import defaultdict
from datetime import datetime, timezone
import socket
import struct
from typing import Any, Dict, Optional, Union

from sdn.config import SUSPICIOUS_THRESHOLD, SERVER_IP


class TrafficMonitor:
    """Monitors OpenFlow traffic, detects SSH connection spikes, and extracts network telemetry."""

    def __init__(self, logger, suspicious_threshold: int = SUSPICIOUS_THRESHOLD):
        self.logger = logger
        self.threshold = suspicious_threshold
        # Track SSH connection counts per source IP
        self.ssh_attempts: Dict[str, int] = defaultdict(int)

    @staticmethod
    def parse_packet_bytes(raw_data: bytes) -> Dict[str, Any]:
        """Pure-Python Ethernet, IPv4, and TCP header parser using standard library struct.
        
        Enables testing and telemetry extraction without external C dependencies.
        """
        result = {
            "eth_type": None,
            "src_mac": None,
            "dst_mac": None,
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
        }

        if len(raw_data) < 14:
            return result

        # 1. Parse Ethernet Header (14 bytes)
        dst_mac = ":".join(f"{b:02x}" for b in raw_data[0:6])
        src_mac = ":".join(f"{b:02x}" for b in raw_data[6:12])
        eth_type = struct.unpack("!H", raw_data[12:14])[0]

        result["src_mac"] = src_mac
        result["dst_mac"] = dst_mac
        result["eth_type"] = eth_type

        # 2. Check for IPv4 (EtherType 0x0800)
        if eth_type == 0x0800 and len(raw_data) >= 34:
            ip_header = raw_data[14:34]
            version_ihl = ip_header[0]
            ihl = (version_ihl & 0x0F) * 4
            protocol_num = ip_header[9]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])

            result["src_ip"] = src_ip
            result["dst_ip"] = dst_ip
            result["protocol"] = "TCP" if protocol_num == 6 else ("UDP" if protocol_num == 17 else f"IP-{protocol_num}")

            # 3. Check for TCP (Protocol 6)
            tcp_offset = 14 + ihl
            if protocol_num == 6 and len(raw_data) >= tcp_offset + 20:
                tcp_header = raw_data[tcp_offset : tcp_offset + 20]
                src_port, dst_port = struct.unpack("!HH", tcp_header[0:4])
                flags = tcp_header[13]
                result["src_port"] = src_port
                result["dst_port"] = dst_port
                result["tcp_flags"] = flags

        return result

    def analyze_packet(
        self,
        packet_data: Union[Dict[str, Any], bytes, Any],
        switch_id: Optional[Union[int, str]] = None,
    ) -> Dict[str, Any]:
        """Analyze packet telemetry for SSH activity and malicious volume."""
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        tcp_flags = None
        protocol = "TCP"
        sid = switch_id

        # Case A: Dictionary input (e.g. from controller or mock test)
        if isinstance(packet_data, dict):
            src_ip = packet_data.get("src_ip")
            dst_ip = packet_data.get("dst_ip")
            src_port = packet_data.get("src_port")
            dst_port = packet_data.get("dst_port")
            tcp_flags = packet_data.get("tcp_flags")
            protocol = packet_data.get("protocol", "TCP")
            sid = packet_data.get("switch", switch_id)
            if "raw_data" in packet_data and isinstance(packet_data["raw_data"], bytes):
                parsed = self.parse_packet_bytes(packet_data["raw_data"])
                src_ip = src_ip or parsed.get("src_ip")
                dst_ip = dst_ip or parsed.get("dst_ip")
                src_port = src_port or parsed.get("src_port")
                dst_port = dst_port or parsed.get("dst_port")
                tcp_flags = tcp_flags if tcp_flags is not None else parsed.get("tcp_flags")
                protocol = parsed.get("protocol") or protocol

        # Case B: Raw bytes input
        elif isinstance(packet_data, bytes):
            parsed = self.parse_packet_bytes(packet_data)
            src_ip = parsed.get("src_ip")
            dst_ip = parsed.get("dst_ip")
            src_port = parsed.get("src_port")
            dst_port = parsed.get("dst_port")
            tcp_flags = parsed.get("tcp_flags")
            protocol = parsed.get("protocol") or "TCP"

        # Case C: Ryu OFPPacketIn event or object
        elif hasattr(packet_data, "data"):
            parsed = self.parse_packet_bytes(packet_data.data)
            src_ip = parsed.get("src_ip")
            dst_ip = parsed.get("dst_ip")
            src_port = parsed.get("src_port")
            dst_port = parsed.get("dst_port")
            tcp_flags = parsed.get("tcp_flags")
            protocol = parsed.get("protocol") or "TCP"
            if hasattr(packet_data, "datapath"):
                sid = packet_data.datapath.id

        src_ip = src_ip or "0.0.0.0"
        dst_ip = dst_ip or SERVER_IP
        now_ts = datetime.now(timezone.utc).isoformat()

        # SSH detection: only inbound traffic TO port 22 on the protected server
        ssh_detected = (dst_port == 22 and dst_ip == SERVER_IP and src_ip != SERVER_IP)
        suspicious = False
        should_redirect = False

        # Count only initial TCP SYN as a new SSH connection attempt:
        # - TCP SYN = set (0x02)
        # - TCP ACK = not set (0x10)
        # - TCP RST = not set (0x04)
        syn_set = bool(tcp_flags is not None and (tcp_flags & 0x02))
        ack_set = bool(tcp_flags is not None and (tcp_flags & 0x10))
        rst_set = bool(tcp_flags is not None and (tcp_flags & 0x04))
        is_syn_only = syn_set and not ack_set and not rst_set

        if ssh_detected and is_syn_only:
            self.ssh_attempts[src_ip] += 1
            attempts = self.ssh_attempts[src_ip]

            if attempts >= self.threshold:
                suspicious = True
                should_redirect = True
                self.logger.warning(
                    "Suspicious SSH activity detected from %s (%d attempts >= threshold %d)",
                    src_ip,
                    attempts,
                    self.threshold,
                )
            else:
                self.logger.info(
                    "SSH connection attempt from %s (attempt %d/%d)",
                    src_ip,
                    attempts,
                    self.threshold,
                )
        else:
            attempts = self.ssh_attempts.get(src_ip, 0)
            if ssh_detected and attempts >= self.threshold:
                suspicious = True
                should_redirect = True

        status_str = "suspicious" if suspicious else ("ssh_detected" if ssh_detected else "normal")

        telemetry = {
            "status": status_str,
            "attacker_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "switch_id": sid,
            "timestamp": now_ts,
            "ssh_detected": ssh_detected,
            "connection_count": attempts,
            "suspicious": suspicious,
            "should_redirect": should_redirect,
        }

        return telemetry

    def reset_attacker(self, ip: str) -> None:
        """Reset connection counter for an IP address."""
        if ip in self.ssh_attempts:
            del self.ssh_attempts[ip]