import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base
from app.api.routes import router as api_router
from app.engine.alert_manager import alert_manager
from app.engine.traffic_simulator import simulator
from app.ml.detector import detector

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure ML model is loaded and start gentle background simulation
    print("=" * 60)
    print(" AI-POWERED NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
    print("=" * 60)
    print("Initializing Detection Engine & Baseline Isolation Forest...")
    _ = detector.model
    print("Starting automatic baseline traffic simulation...")
    simulator._background_task = asyncio.create_task(simulator.start_continuous_background_traffic())
    yield
    # Shutdown
    print("Stopping simulator and cleanup...")
    simulator.stop()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS Middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API
app.include_router(api_router, prefix=settings.API_PREFIX)

@app.get("/")
def root():
    return {
        "status": "online",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs"
    }

@app.websocket("/ws/traffic")
async def websocket_traffic_endpoint(websocket: WebSocket):
    """
    Real-time bidirectional WebSocket stream:
    Transmits live packet flows, instant threat alerts, and aggregate risk metrics.
    """
    await alert_manager.connect_websocket(websocket)
    try:
        # Send initial state snapshot immediately upon connection
        await websocket.send_json({
            "type": "INITIAL_METRICS",
            "data": alert_manager.get_metrics()
        })
        # Keep connection open and receive any client pings
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        alert_manager.disconnect_websocket(websocket)
    except Exception:
        alert_manager.disconnect_websocket(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

