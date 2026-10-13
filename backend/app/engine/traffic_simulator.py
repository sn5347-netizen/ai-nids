import asyncio
import random
import time
from app.ml.detector import detector
from app.engine.alert_manager import alert_manager

COMMON_ATTACK_TARGETS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

class TrafficSimulator:
    """Simulates realistic network traffic patterns and cyber attacks for testing."""

    def __init__(self):
        self.is_running = False
        self._background_task = None

    async def simulate_normal_traffic(self, count: int = 10, delay: float = 0.2):
        """Simulates standard enterprise web, DNS, and internal traffic."""
        user_ips = ["192.168.1.45", "192.168.1.62", "192.168.1.88", "192.168.1.102"]
        servers = [
            ("142.250.190.46", 443, "HTTPS"),
            ("1.1.1.1", 53, "DNS"),
            ("151.101.1.140", 80, "HTTP"),
            ("192.168.1.1", 53, "DNS"),
            ("10.0.0.5", 3306, "MySQL")
        ]

        for _ in range(count):
            src_ip = random.choice(user_ips)
            dst_ip, dst_port, proto = random.choice(servers)
            length = random.randint(120, 1400) if proto != "DNS" else random.randint(60, 240)
            flags = "PA" if proto in ["HTTP", "HTTPS"] else ""

            packet_data = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(49152, 65535),
                "dst_port": dst_port,
                "protocol": "TCP" if proto != "DNS" else "UDP",
                "length": length,
                "tcp_flags": flags,
                "service": proto
            }

            result = detector.analyze_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=packet_data["src_port"],
                dst_port=dst_port,
                protocol=packet_data["protocol"],
                length=length,
                tcp_flags=flags
            )

            alert_manager.process_packet_event(packet_data, result)
            await asyncio.sleep(delay)

    async def simulate_port_scan(self, attacker_ip: str = "203.0.113.88", target_ip: str = "192.168.1.100"):
        """Simulates a fast TCP SYN Port Scan attempting to enumerate open services."""
        ports_to_scan = random.sample(COMMON_ATTACK_TARGETS, 12) + [random.randint(1000, 9000) for _ in range(4)]
        
        for port in ports_to_scan:
            packet_data = {
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(40000, 60000),
                "dst_port": port,
                "protocol": "TCP",
                "length": 64,
                "tcp_flags": "S",  # SYN flag
                "service": "SCAN"
            }

            result = detector.analyze_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=packet_data["src_port"],
                dst_port=port,
                protocol="TCP",
                length=64,
                tcp_flags="S"
            )

            alert_manager.process_packet_event(packet_data, result)
            await asyncio.sleep(0.08)  # Rapid scan interval

    async def simulate_dos_attack(self, attacker_ip: str = "198.51.100.19", target_ip: str = "192.168.1.100", packet_count: int = 60):
        """Simulates a volumetric SYN flood or DoS attack."""
        for _ in range(packet_count):
            packet_data = {
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": 80,
                "protocol": "TCP",
                "length": random.randint(64, 128),
                "tcp_flags": "S",  # SYN flood
                "service": "HTTP"
            }

            result = detector.analyze_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=packet_data["src_port"],
                dst_port=80,
                protocol="TCP",
                length=packet_data["length"],
                tcp_flags="S"
            )

            alert_manager.process_packet_event(packet_data, result)
            await asyncio.sleep(0.015)  # Very high rate (60+ pps)

    async def simulate_ml_anomaly(self, attacker_ip: str = "185.220.101.5", target_ip: str = "192.168.1.100"):
        """Simulates statistical anomalies (abnormal payload, uncommon flags like XMAS or NULL)."""
        scenarios = [
            # XMAS scan
            {"port": 80, "flags": "FPU", "len": 120, "proto": "TCP"},
            # Oversized ICMP
            {"port": 0, "flags": "", "len": 1200, "proto": "ICMP"},
            # Strange backdoor port
            {"port": 4444, "flags": "PA", "len": 890, "proto": "TCP"},
            # TCP NULL scan
            {"port": 443, "flags": "", "len": 60, "proto": "TCP"}
        ]

        for s in scenarios:
            packet_data = {
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(30000, 50000),
                "dst_port": s["port"],
                "protocol": s["proto"],
                "length": s["len"],
                "tcp_flags": s["flags"],
                "service": "ANOMALY"
            }

            result = detector.analyze_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=packet_data["src_port"],
                dst_port=s["port"],
                protocol=s["proto"],
                length=s["len"],
                tcp_flags=s["flags"]
            )

            alert_manager.process_packet_event(packet_data, result)
            await asyncio.sleep(0.15)

    async def start_continuous_background_traffic(self):
        """Continuously generates pleasant background traffic to keep the dashboard live."""
        self.is_running = True
        while self.is_running:
            try:
                await self.simulate_normal_traffic(count=random.randint(2, 6), delay=random.uniform(0.3, 0.7))
                # Randomly inject occasional small anomaly every 40-60 iterations
                if random.random() < 0.04:
                    await self.simulate_port_scan()
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                await asyncio.sleep(2.0)

    def stop(self):
        self.is_running = False
        if self._background_task:
            self._background_task.cancel()

simulator = TrafficSimulator()

