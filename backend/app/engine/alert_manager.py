import asyncio
from collections import defaultdict, deque
import datetime
import json
from typing import List, Dict, Set
from fastapi import WebSocket

from app.database import SessionLocal
from app.models import AlertRecord, PacketRecord

class AlertManager:
    """Manages real-time alerts, statistics, and WebSocket broadcasting."""

    def __init__(self):
        self.active_websockets: Set[WebSocket] = set()
        self.recent_alerts: deque = deque(maxlen=100)
        self.recent_packets: deque = deque(maxlen=100)
        
        # Live counters
        self.total_packets_count = 0
        self.total_alerts_count = 0
        self.attack_breakdown: Dict[str, int] = defaultdict(int)
        self.protocol_distribution: Dict[str, int] = defaultdict(int)
        self.recent_risk_scores: deque = deque(maxlen=50)

    async def connect_websocket(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)

    def disconnect_websocket(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    async def broadcast_event(self, event_type: str, data: dict):
        """Broadcasts real-time events to all active dashboard connections."""
        if not self.active_websockets:
            return

        message = json.dumps({"type": event_type, "data": data, "timestamp": datetime.datetime.utcnow().isoformat()})
        dead_connections = set()

        for ws in self.active_websockets:
            try:
                await ws.send_text(message)
            except Exception:
                dead_connections.add(ws)

        for ws in dead_connections:
            self.active_websockets.discard(ws)

    def process_packet_event(self, packet_data: dict, detection_result: dict):
        """Updates statistics, records packet, and triggers alert if necessary."""
        self.total_packets_count += 1
        proto = packet_data.get("protocol", "OTHER")
        self.protocol_distribution[proto] += 1
        
        risk = detection_result.get("risk_score", 0.0)
        self.recent_risk_scores.append(risk)

        packet_entry = {
            **packet_data,
            "risk_score": risk,
            "is_anomaly": detection_result.get("is_anomaly", False),
            "threat_type": detection_result.get("threat_type"),
            "severity": detection_result.get("severity", "LOW"),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        self.recent_packets.appendleft(packet_entry)

        # Trigger alert if threshold crossed
        if detection_result.get("should_alert", False):
            self.total_alerts_count += 1
            threat = detection_result.get("threat_type", "Unknown Anomaly")
            self.attack_breakdown[threat] += 1

            alert_entry = {
                "id": self.total_alerts_count,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "attack_type": threat,
                "severity": detection_result.get("severity", "HIGH"),
                "risk_score": risk,
                "src_ip": packet_data.get("src_ip"),
                "dst_ip": packet_data.get("dst_ip"),
                "dst_port": packet_data.get("dst_port"),
                "details": f"Detected: {', '.join(detection_result.get('threats_list', [threat]))} (PPS: {detection_result.get('packet_rate')} | Diversity: {detection_result.get('port_diversity')})",
                "acknowledged": False
            }
            self.recent_alerts.appendleft(alert_entry)

            # Persist to database in background thread
            self._save_alert_to_db(alert_entry)

            # Broadcast alert asynchronously
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self.broadcast_event("ALERT", alert_entry))
            except Exception:
                pass

        # Broadcast packet sample periodically or on threat
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.broadcast_event("PACKET", packet_entry))
        except Exception:
            pass

    def _save_alert_to_db(self, alert_data: dict):
        """Saves alert to SQLite / PostgreSQL."""
        try:
            db = SessionLocal()
            record = AlertRecord(
                attack_type=alert_data["attack_type"],
                severity=alert_data["severity"],
                risk_score=alert_data["risk_score"],
                src_ip=alert_data["src_ip"],
                dst_ip=alert_data["dst_ip"],
                dst_port=alert_data["dst_port"],
                details=alert_data["details"],
                acknowledged=False
            )
            db.add(record)
            db.commit()
            db.close()
        except Exception as e:
            print(f"Error saving alert to DB: {e}")

    def get_metrics(self) -> dict:
        """Calculates current aggregate metrics for the dashboard."""
        avg_risk = sum(self.recent_risk_scores) / max(1, len(self.recent_risk_scores)) if self.recent_risk_scores else 0.0
        
        # Threat Level
        if avg_risk >= 70 or any(a["severity"] == "CRITICAL" for a in list(self.recent_alerts)[:5]):
            threat_level = "CRITICAL"
        elif avg_risk >= 45 or any(a["severity"] == "HIGH" for a in list(self.recent_alerts)[:5]):
            threat_level = "ELEVATED"
        elif avg_risk >= 25:
            threat_level = "GUARDED"
        else:
            threat_level = "NOMINAL"

        return {
            "total_packets_analyzed": self.total_packets_count,
            "total_alerts": self.total_alerts_count,
            "active_threat_level": threat_level,
            "average_risk_score": round(avg_risk, 1),
            "attack_breakdown": dict(self.attack_breakdown),
            "protocol_distribution": dict(self.protocol_distribution),
            "recent_alerts": list(self.recent_alerts)[:15],
            "recent_packets": list(self.recent_packets)[:20]
        }

alert_manager = AlertManager()

