import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.models import AlertRecord
from app.schemas import AlertResponse, SimulationRequest, SnifferControlRequest
from app.engine.alert_manager import alert_manager
from app.engine.packet_sniffer import sniffer
from app.engine.traffic_simulator import simulator

router = APIRouter()

@router.get("/stats")
def get_dashboard_stats():
    """Retrieve aggregate statistics, threat levels, and recent alerts/packets."""
    return alert_manager.get_metrics()

@router.get("/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve historical alerts from the database."""
    query = db.query(AlertRecord)
    if severity:
        query = query.filter(AlertRecord.severity == severity.upper())
    records = query.order_by(AlertRecord.id.desc()).limit(limit).all()
    return records

@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    """Mark an alert as reviewed."""
    record = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Alert not found")
    record.acknowledged = True
    db.commit()
    return {"status": "success", "alert_id": alert_id}

@router.get("/sniffer/status")
def get_sniffer_status():
    """Get live capture sniffer state."""
    return sniffer.status()

@router.post("/sniffer/start")
def start_sniffer(req: SnifferControlRequest = None):
    """Start real-time Scapy packet capture."""
    iface = req.interface if req else None
    return sniffer.start(iface)

@router.post("/sniffer/stop")
def stop_sniffer():
    """Stop real-time packet capture."""
    return sniffer.stop()

@router.post("/simulate")
async def trigger_simulation(req: SimulationRequest):
    """
    Simulate attacks to test the intrusion detection and risk scoring systems.
    Types: port_scan, dos, anomaly, normal
    """
    attack_type = req.attack_type.lower()
    
    if attack_type == "port_scan":
        asyncio.create_task(simulator.simulate_port_scan(target_ip=req.target_ip or "192.168.1.100"))
        return {"status": "triggered", "attack": "TCP SYN Port Scan"}
    
    elif attack_type == "dos":
        asyncio.create_task(simulator.simulate_dos_attack(target_ip=req.target_ip or "192.168.1.100", packet_count=req.intensity or 60))
        return {"status": "triggered", "attack": "Denial-of-Service (SYN Flood)"}
    
    elif attack_type == "anomaly":
        asyncio.create_task(simulator.simulate_ml_anomaly(target_ip=req.target_ip or "192.168.1.100"))
        return {"status": "triggered", "attack": "ML Isolation Forest Anomaly / Abnormal Packet Patterns"}
    
    elif attack_type == "normal":
        asyncio.create_task(simulator.simulate_normal_traffic(count=req.intensity or 15))
        return {"status": "triggered", "traffic": "Normal enterprise traffic"}
    
    else:
        raise HTTPException(status_code=400, detail="Unknown simulation type. Choose: port_scan, dos, anomaly, normal")

@router.post("/simulator/toggle_bg")
async def toggle_background_traffic(enable: bool = True):
    """Enable or disable background synthetic traffic generator."""
    if enable and not simulator.is_running:
        simulator._background_task = asyncio.create_task(simulator.start_continuous_background_traffic())
        return {"background_traffic": "enabled"}
    elif not enable:
        simulator.stop()
        return {"background_traffic": "disabled"}
    return {"background_traffic": "already_in_state"}

