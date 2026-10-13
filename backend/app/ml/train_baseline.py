import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from app.config import settings

def generate_normal_baseline_dataset(samples: int = 5000) -> np.ndarray:
    """
    Synthesize realistic baseline normal enterprise network traffic patterns:
    HTTP/HTTPS web browsing, DNS queries, normal TCP streams, background telemetry.
    """
    np.random.seed(42)
    features = []

    for _ in range(samples):
        traffic_type = np.random.choice(["https", "http", "dns", "ssh", "api_json"], p=[0.55, 0.20, 0.15, 0.05, 0.05])
        
        if traffic_type == "https":
            length = np.random.normal(750, 400)
            proto_tcp = 1.0
            proto_udp = 0.0
            proto_icmp = 0.0
            is_well_known = 1.0
            dst_port_norm = 443 / 65535.0
            # established connection flags typically ACK, PSH
            flag_syn = 0.05 if np.random.rand() < 0.05 else 0.0
            flag_ack = 1.0
            flag_fin = 0.02 if np.random.rand() < 0.02 else 0.0
            flag_rst = 0.0
            packet_rate = np.random.uniform(1.0, 15.0)
            port_diversity = np.random.choice([1, 2], p=[0.9, 0.1])

        elif traffic_type == "http":
            length = np.random.normal(500, 300)
            proto_tcp = 1.0
            proto_udp = 0.0
            proto_icmp = 0.0
            is_well_known = 1.0
            dst_port_norm = 80 / 65535.0
            flag_syn = 0.05 if np.random.rand() < 0.05 else 0.0
            flag_ack = 1.0
            flag_fin = 0.02 if np.random.rand() < 0.02 else 0.0
            flag_rst = 0.0
            packet_rate = np.random.uniform(1.0, 10.0)
            port_diversity = 1

        elif traffic_type == "dns":
            length = np.random.uniform(50, 220)
            proto_tcp = 0.0
            proto_udp = 1.0
            proto_icmp = 0.0
            is_well_known = 1.0
            dst_port_norm = 53 / 65535.0
            flag_syn, flag_ack, flag_fin, flag_rst = 0.0, 0.0, 0.0, 0.0
            packet_rate = np.random.uniform(0.5, 4.0)
            port_diversity = 1

        elif traffic_type == "ssh":
            length = np.random.uniform(90, 350)
            proto_tcp = 1.0
            proto_udp = 0.0
            proto_icmp = 0.0
            is_well_known = 1.0
            dst_port_norm = 22 / 65535.0
            flag_syn = 0.02 if np.random.rand() < 0.02 else 0.0
            flag_ack = 1.0
            flag_fin = 0.01 if np.random.rand() < 0.01 else 0.0
            flag_rst = 0.0
            packet_rate = np.random.uniform(1.0, 8.0)
            port_diversity = 1

        else: # api_json / background
            length = np.random.uniform(200, 1200)
            proto_tcp = 1.0
            proto_udp = 0.0
            proto_icmp = 0.0
            is_well_known = 0.0
            dst_port_norm = 8080 / 65535.0
            flag_syn = 0.0
            flag_ack = 1.0
            flag_fin = 0.0
            flag_rst = 0.0
            packet_rate = np.random.uniform(2.0, 12.0)
            port_diversity = 1

        length = max(40.0, min(length, 1500.0))
        features.append([
            length, proto_tcp, proto_udp, proto_icmp, is_well_known, dst_port_norm,
            flag_syn, flag_ack, flag_fin, flag_rst, packet_rate, float(port_diversity)
        ])

    return np.array(features, dtype=np.float32)

def train_and_save_model(model_path: str = None):
    """Train Isolation Forest anomaly detector on baseline normal traffic."""
    target_path = model_path or settings.MODEL_PATH
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    print("Generating baseline network traffic dataset...")
    X_baseline = generate_normal_baseline_dataset(samples=6000)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_baseline)

    print(f"Training Isolation Forest (n_estimators=150, contamination={settings.ISOLATION_FOREST_CONTAMINATION})...")
    model = IsolationForest(
        n_estimators=150,
        contamination=settings.ISOLATION_FOREST_CONTAMINATION,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    joblib.dump({"model": model, "scaler": scaler}, target_path)
    print(f"Model saved successfully to: {target_path}")
    return model, scaler

if __name__ == "__main__":
    train_and_save_model()

