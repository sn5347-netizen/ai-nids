import numpy as np

# Well-known service port mappings
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    3389: "RDP",
}

def identify_service(port: int, proto: str) -> str:
    """Classify common network service."""
    if proto == "DNS" or port == 53:
        return "DNS"
    if proto == "HTTP" or port in (80, 8080):
        return "HTTP"
    if proto == "HTTPS" or port == 443:
        return "HTTPS"
    return COMMON_PORTS.get(port, "OTHER")

def extract_features_vector(
    length: int,
    proto: str,
    dst_port: int,
    flags: str,
    packet_rate: float,
    port_diversity: int
) -> np.ndarray:
    """
    Extract a normalized numerical feature vector for the ML model.
    Features:
    0: packet_length
    1: proto_tcp (0 or 1)
    2: proto_udp (0 or 1)
    3: proto_icmp (0 or 1)
    4: is_well_known_port (0 or 1)
    5: dst_port_normalized
    6: flag_syn (0 or 1)
    7: flag_ack (0 or 1)
    8: flag_fin (0 or 1)
    9: flag_rst (0 or 1)
    10: packet_rate (recent burst speed)
    11: port_diversity (distinct ports hit by source)
    """
    proto_upper = str(proto).upper()
    proto_tcp = 1.0 if "TCP" in proto_upper else 0.0
    proto_udp = 1.0 if "UDP" in proto_upper else 0.0
    proto_icmp = 1.0 if "ICMP" in proto_upper else 0.0

    dst_p = int(dst_port) if dst_port is not None else 0
    is_well_known = 1.0 if dst_p < 1024 else 0.0
    dst_port_norm = min(dst_p / 65535.0, 1.0)

    flags_upper = str(flags or "").upper()
    flag_syn = 1.0 if "S" in flags_upper or "SYN" in flags_upper else 0.0
    flag_ack = 1.0 if "A" in flags_upper or "ACK" in flags_upper else 0.0
    flag_fin = 1.0 if "F" in flags_upper or "FIN" in flags_upper else 0.0
    flag_rst = 1.0 if "R" in flags_upper or "RST" in flags_upper else 0.0

    vector = np.array([
        float(length),
        proto_tcp,
        proto_udp,
        proto_icmp,
        is_well_known,
        dst_port_norm,
        flag_syn,
        flag_ack,
        flag_fin,
        flag_rst,
        float(packet_rate),
        float(port_diversity)
    ], dtype=np.float32)

    return vector

