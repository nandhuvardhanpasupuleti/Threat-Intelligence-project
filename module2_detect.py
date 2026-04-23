import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

FEATURES = ["cpu_usage","mem_usage","proc_count",
            "net_bytes_sent","net_bytes_recv","disk_read","disk_write"]

# Decision scores near 0 are ambiguous; require a clearer outlier to reduce false positives.
ANOMALY_SCORE_THRESHOLD = -0.08

def train_model():
    print("[*] Loading data...")
    df = pd.read_csv("endpoint_data.csv")
    X  = df[FEATURES].fillna(0)

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
    model.fit(X_scaled)

    joblib.dump((model, scaler), "iso_forest.pkl")
    print("[✓] Model trained and saved as iso_forest.pkl")

def detect_anomalies(metrics):
    if not os.path.exists("iso_forest.pkl"):
        return {"anomaly": False, "score": 0.0, "raw_outlier": False}

    model, scaler = joblib.load("iso_forest.pkl")
    X        = [[metrics.get(f, 0) for f in FEATURES]]
    X_scaled = scaler.transform(X)
    pred     = model.predict(X_scaled)[0]
    score    = float(model.decision_function(X_scaled)[0])
    raw_outlier = pred == -1
    # Only treat as anomaly if the model is confident (reduces flicker on borderline samples).
    is_anom = raw_outlier and score < ANOMALY_SCORE_THRESHOLD
    return {
        "anomaly": bool(is_anom),
        "score": round(score, 4),
        "raw_outlier": bool(raw_outlier),
    }

if __name__ == "__main__":
    train_model()
