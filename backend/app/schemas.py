from pydantic import BaseModel
from typing import Optional, List
import datetime

class PacketBase(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    length: int
    tcp_flags: Optional[str] = None
    service: str = "OTHER"
    risk_score: float = 0.0
    is_anomaly: bool = False
    threat_type: Optional[str] = None

class PacketResponse(PacketBase):
    id: int
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class AlertBase(BaseModel):
    attack_type: str
    severity: str
    risk_score: float
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = None
    details: str

class AlertResponse(AlertBase):
    id: int
    timestamp: datetime.datetime
    acknowledged: bool

    class Config:
        from_attributes = True

class DetectionMetrics(BaseModel):
    total_packets_analyzed: int
    total_alerts: int
    active_threat_level: str
    average_risk_score: float
    attack_breakdown: dict
    protocol_distribution: dict
    recent_packets_per_sec: float

class SnifferControlRequest(BaseModel):
    interface: Optional[str] = None

class SimulationRequest(BaseModel):
    attack_type: str  # "port_scan", "dos", "anomaly", "normal"
    intensity: Optional[int] = 50  # number of packets / pulses
    target_ip: Optional[str] = "192.168.1.100"

