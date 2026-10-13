import os

class Settings:
    PROJECT_NAME: str = "AI-Powered Network Intrusion Detection System"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./nids.db")
    
    # Network Sniffer settings
    NETWORK_INTERFACE: str = os.getenv("NETWORK_INTERFACE", "")  # Empty string picks default
    SNIFFER_PROMISCUOUS: bool = False
    
    # ML & Anomaly Detection
    MODEL_PATH: str = os.getenv("MODEL_PATH", "app/ml/isolation_forest.joblib")
    ISOLATION_FOREST_CONTAMINATION: float = 0.04
    
    # Detection Thresholds
    PORT_SCAN_PORT_THRESHOLD: int = 8         # Distinct ports scanned in window
    PORT_SCAN_WINDOW_SECONDS: float = 8.0     # Time window for port scan
    DOS_PACKET_RATE_THRESHOLD: int = 40       # Packets per second from single IP
    UNUSUAL_FREQ_THRESHOLD: int = 25          # Packets in 2 seconds
    
    # Risk Alert Thresholds
    ALERT_RISK_THRESHOLD: float = 55.0        # Risk score (0-100) above which alert triggers
    CRITICAL_RISK_THRESHOLD: float = 85.0

settings = Settings()

