import datetime
from collections import Counter

alert_log = []

def classify_severity(score):
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 5: return "MEDIUM"
    return "LOW"

def generate_alert(anomaly_result, correlations, metrics):
    """
    Emit dashboard alerts when MITRE-aligned correlation rules match (threat intel layer).
    If the Isolation Forest also flags an anomaly, risk is bumped — aligns the abstract’s
    “anomalies are further analyzed through threat intelligence correlation” for prioritization.
    """
    if not correlations:
        return None

    top = correlations[0]
    base_risk = int(top["risk_score"])
    ml_hit = bool(anomaly_result.get("anomaly"))
    # Combined signal: behavioral outlier + ATT&CK context → higher priority (capped 10).
    effective_risk = min(10, base_risk + (1 if ml_hit else 0))
    severity = classify_severity(effective_risk)
    return {
        "alert_id"       : "ALT-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"),
        "timestamp"      : datetime.datetime.now().isoformat(),
        "severity"       : severity,
        "risk_score"     : effective_risk,
        "mitre_base_risk": base_risk,
        "technique_id"   : top["technique_id"],
        "technique_name" : top["technique_name"],
        "tactic"         : top["tactic"],
        "anomaly_score"  : anomaly_result.get("score", 0),
        "metrics"        : metrics,
        "ml_anomaly"     : ml_hit,
    }

def log_alert(alert):
    if alert:
        alert_log.append(alert)

def get_alert_summary():
    return dict(Counter(a["severity"] for a in alert_log))