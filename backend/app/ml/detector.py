import os
import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
import joblib
import numpy as np

from app.config import settings
from app.ml.features import extract_features_vector, identify_service
from app.ml.train_baseline import train_and_save_model

class DetectionEngine:
    """
    Hybrid Intrusion Detection System combining:
    1. Isolation Forest Machine Learning (Statistical Anomaly Detection)
    2. Heuristic Signature & Rate Rules (Port Scan, DoS, Flag Anomaly, Frequency)
    3. Composite 0-100 Risk Scorer
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_or_train_model()

        # In-memory tracking structures for real-time stateful detection
        # src_ip -> deque of (timestamp, dst_port, flags)
        self.ip_traffic_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # src_ip -> deque of timestamps for rate calculation
        self.ip_packet_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def _load_or_train_model(self):
        """Loads trained Isolation Forest or trains a new baseline model."""
        if not os.path.exists(settings.MODEL_PATH):
            print(f"Model file not found at {settings.MODEL_PATH}. Auto-training initial baseline model...")
            train_and_save_model(settings.MODEL_PATH)
        
        try:
            artifact = joblib.load(settings.MODEL_PATH)
            self.model = artifact["model"]
            self.scaler = artifact["scaler"]
            print("Isolation Forest Anomaly Detector successfully loaded.")
        except Exception as e:
            print(f"Error loading model, retraining: {e}")
            self.model, self.scaler = train_and_save_model(settings.MODEL_PATH)

    def _update_ip_history(self, src_ip: str, dst_port: int, flags: str, current_time: float) -> Tuple[float, int]:
        """
        Record packet in sliding history window and calculate:
        - packet_rate (packets per second in recent 3-second window)
        - port_diversity (distinct destination ports accessed in recent 8-second window)
        """
        # Record timestamp
        ts_queue = self.ip_packet_timestamps[src_ip]
        ts_queue.append(current_time)

        # Purge timestamps older than 3 seconds
        while ts_queue and (current_time - ts_queue[0] > 3.0):
            ts_queue.popleft()
        
        # Calculate recent rate
        time_span = max(0.2, (current_time - ts_queue[0]) if len(ts_queue) > 1 else 1.0)
        packet_rate = len(ts_queue) / time_span

        # Record port & flags
        traffic_queue = self.ip_traffic_history[src_ip]
        traffic_queue.append((current_time, dst_port, flags))

        # Purge older than port scan window (default 8s)
        while traffic_queue and (current_time - traffic_queue[0][0] > settings.PORT_SCAN_WINDOW_SECONDS):
            traffic_queue.popleft()

        # Unique ports targeted in the window
        distinct_ports = {entry[1] for entry in traffic_queue if entry[1] is not None}
        port_diversity = len(distinct_ports)

        return packet_rate, port_diversity

    def analyze_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        length: int,
        tcp_flags: Optional[str] = None
    ) -> Dict:
        """
        Main entry point for packet inspection.
        Returns evaluation dict with risk score, detected anomalies, threat type, and severity.
        """
        now = time.time()
        dst_p = dst_port or 0
        flags = tcp_flags or ""
        service = identify_service(dst_p, protocol)

        packet_rate, port_diversity = self._update_ip_history(src_ip, dst_p, flags, now)

        threats_detected: List[str] = []
        rule_risk_points = 0.0

        # ==========================================
        # 1. HEURISTIC DETECTION: Port Scanning
        # ==========================================
        if port_diversity >= settings.PORT_SCAN_PORT_THRESHOLD:
            threats_detected.append("Port Scanning Attempt")
            rule_risk_points += 55.0
        elif port_diversity >= 4 and ("S" in flags or "SYN" in flags):
            threats_detected.append("Suspicious Port Probing")
            rule_risk_points += 35.0

        # ==========================================
        # 2. HEURISTIC DETECTION: DoS / Packet Flood
        # ==========================================
        if packet_rate >= settings.DOS_PACKET_RATE_THRESHOLD:
            threats_detected.append("Possible Denial-of-Service (DoS) Attack")
            rule_risk_points += 60.0
        elif packet_rate >= settings.UNUSUAL_FREQ_THRESHOLD:
            threats_detected.append("Unusual Connection Frequency")
            rule_risk_points += 30.0

        # ==========================================
        # 3. HEURISTIC DETECTION: Malicious TCP Patterns
        # ==========================================
        upper_flags = flags.upper()
        if "TCP" in protocol.upper():
            # NULL Scan: TCP packet with no flags set
            if flags == "" or flags == "0":
                threats_detected.append("TCP NULL Scan (Stealth Probe)")
                rule_risk_points += 45.0
            # XMAS Scan: FIN, PSH, and URG set
            if all(f in upper_flags for f in ["F", "P", "U"]):
                threats_detected.append("TCP XMAS Scan Attack")
                rule_risk_points += 50.0
            # SYN-FIN flag anomaly
            if "S" in upper_flags and "F" in upper_flags:
                threats_detected.append("SYN-FIN Invalid Flag Sequence")
                rule_risk_points += 45.0

        # High-risk / Trojan ports
        if dst_p in [4444, 1337, 31337, 6667]:
            threats_detected.append(f"Suspicious Backdoor Port ({dst_p})")
            rule_risk_points += 40.0

        # ICMP Large Payload (potential Ping Flood / Tunneling)
        if "ICMP" in protocol.upper() and length > 400:
            threats_detected.append("Abnormal ICMP Packet Size (Tunneling / Flood)")
            rule_risk_points += 35.0

        # ==========================================
        # 4. ML ISOLATION FOREST ANOMALY DETECTION
        # ==========================================
        vector = extract_features_vector(length, protocol, dst_p, flags, packet_rate, port_diversity)
        is_ml_anomaly = False
        ml_risk_points = 0.0
        ml_score_raw = 0.0

        try:
            X_scaled = self.scaler.transform(vector.reshape(1, -1))
            # decision_function returns negative values for anomalies, positive for normal
            score = self.model.decision_function(X_scaled)[0]
            prediction = self.model.predict(X_scaled)[0]  # -1 = anomaly, 1 = normal

            ml_score_raw = float(score)
            if prediction == -1 or score < -0.05:
                is_ml_anomaly = True
                threats_detected.append("Statistical Anomaly (Isolation Forest)")
                # Map negative score to 30 - 75 risk points
                anomaly_severity = min(abs(score) * 200, 75.0)
                ml_risk_points = max(35.0, anomaly_severity)
        except Exception as e:
            pass

        # ==========================================
        # 5. COMPOSITE RISK SCORING (0 to 100)
        # ==========================================
        # Baseline noise risk is low (0-10)
        base_risk = 5.0
        total_risk = base_risk + rule_risk_points + (ml_risk_points * 0.6 if rule_risk_points > 0 else ml_risk_points)
        final_risk_score = round(min(100.0, max(0.0, total_risk)), 1)

        # Categorize Severity
        if final_risk_score >= settings.CRITICAL_RISK_THRESHOLD:
            severity = "CRITICAL"
        elif final_risk_score >= settings.ALERT_RISK_THRESHOLD:
            severity = "HIGH"
        elif final_risk_score >= 35.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        primary_threat = threats_detected[0] if threats_detected else ("Normal Traffic" if final_risk_score < 30 else "Unusual Activity")

        return {
            "risk_score": final_risk_score,
            "severity": severity,
            "is_anomaly": is_ml_anomaly or (final_risk_score >= settings.ALERT_RISK_THRESHOLD),
            "threat_type": primary_threat,
            "threats_list": threats_detected,
            "service": service,
            "packet_rate": round(packet_rate, 2),
            "port_diversity": port_diversity,
            "ml_anomaly_score": round(ml_score_raw, 4),
            "should_alert": final_risk_score >= settings.ALERT_RISK_THRESHOLD
        }

# Global detector instance
detector = DetectionEngine()

