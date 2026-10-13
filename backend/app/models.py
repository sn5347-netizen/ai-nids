import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from app.database import Base

class PacketRecord(Base):
    """Stores sampled or suspicious packet records."""
    __tablename__ = "packet_records"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), index=True)  # TCP, UDP, ICMP, DNS, HTTP
    length = Column(Integer)
    tcp_flags = Column(String(20), nullable=True)
    service = Column(String(20), default="OTHER")
    risk_score = Column(Float, default=0.0)
    is_anomaly = Column(Boolean, default=False)
    threat_type = Column(String(50), nullable=True)

class AlertRecord(Base):
    """Stores security alerts triggered by the detection system."""
    __tablename__ = "alert_records"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    attack_type = Column(String(50), index=True)  # Port Scan, DoS Attack, ML Anomaly, High Frequency
    severity = Column(String(20), index=True)    # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float)                    # 0.0 to 100.0
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    dst_port = Column(Integer, nullable=True)
    details = Column(Text)
    acknowledged = Column(Boolean, default=False)

