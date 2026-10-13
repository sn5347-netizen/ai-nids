import threading
import time
from typing import Optional
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

from app.config import settings
from app.ml.detector import detector
from app.engine.alert_manager import alert_manager

class LivePacketSniffer:
    """Captures real-time packets using Scapy with automatic fallback handling."""

    def __init__(self):
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.interface = settings.NETWORK_INTERFACE or None
        self.capture_error: Optional[str] = None

    def _packet_callback(self, pkt):
        if not self.is_running:
            return

        if not pkt.haslayer(IP):
            return

        try:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = len(pkt)

            src_port = None
            dst_port = None
            flags = ""
            proto = "OTHER"

            if pkt.haslayer(TCP):
                proto = "TCP"
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            # Check for DNS
            if dst_port == 53 or src_port == 53:
                proto = "DNS"
            elif dst_port in [80, 8080]:
                proto = "HTTP"
            elif dst_port == 443:
                proto = "HTTPS"

            packet_data = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "length": length,
                "tcp_flags": flags,
                "service": proto
            }

            result = detector.analyze_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                length=length,
                tcp_flags=flags
            )

            alert_manager.process_packet_event(packet_data, result)

        except Exception as e:
            pass

    def _sniff_worker(self):
        try:
            print(f"Starting Scapy packet capture on interface: {self.interface or 'default'}...")
            self.capture_error = None
            # Scapy sniff loop
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            self.capture_error = str(e)
            print(f"Packet capture error: {e}")
            print("Note: On Windows, Scapy requires Npcap (https://npcap.com/) and Administrator privileges.")
            self.is_running = False

    def start(self, iface: Optional[str] = None):
        if self.is_running:
            return {"status": "already_running"}

        if iface:
            self.interface = iface

        self.is_running = True
        self._thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self._thread.start()
        return {"status": "started", "interface": self.interface or "default"}

    def stop(self):
        if not self.is_running:
            return {"status": "already_stopped"}
        self.is_running = False
        return {"status": "stopped"}

    def status(self):
        return {
            "is_running": self.is_running,
            "interface": self.interface or "default",
            "capture_error": self.capture_error
        }

sniffer = LivePacketSniffer()

